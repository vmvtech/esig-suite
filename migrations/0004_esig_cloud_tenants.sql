-- 0004_esig_cloud_tenants.sql
--
-- Tenant, membership, entitlement, credential-hash and provisioning records
-- for the managed e-sig Cloud control plane. This migration deliberately stores
-- no API-key plaintext, Stripe payloads, payment details, documents or email
-- bodies. It may be applied to the shared project or to a dedicated project.

-- ==================================================================
-- 1. Organizations and memberships
-- ==================================================================

CREATE TABLE IF NOT EXISTS esig_organizations (
  id                      uuid PRIMARY KEY,
  slug                    text NOT NULL UNIQUE,
  display_name            text NOT NULL,
  deployment_mode         text NOT NULL CHECK (deployment_mode IN ('shared', 'dedicated')),
  status                  text NOT NULL DEFAULT 'provisioning'
                          CHECK (status IN ('provisioning', 'ready', 'suspended', 'disabled')),
  stripe_customer_id      text NOT NULL UNIQUE,
  stripe_subscription_id  text NOT NULL UNIQUE,
  storage_namespace       text NOT NULL UNIQUE,
  dedicated_stack_id      text,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
  CHECK (length(trim(display_name)) BETWEEN 1 AND 160)
);

CREATE TABLE IF NOT EXISTS esig_memberships (
  tenant_id         uuid NOT NULL REFERENCES esig_organizations(id),
  user_id           uuid REFERENCES auth.users(id),
  normalized_email  text NOT NULL,
  role              text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  status            text NOT NULL DEFAULT 'invited'
                    CHECK (status IN ('invited', 'active', 'disabled')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, normalized_email),
  CHECK (normalized_email = lower(trim(normalized_email))),
  CHECK (normalized_email LIKE '%@%')
);

CREATE UNIQUE INDEX IF NOT EXISTS esig_memberships_tenant_user_key
  ON esig_memberships(tenant_id, user_id)
  WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS esig_memberships_user_idx
  ON esig_memberships(user_id)
  WHERE user_id IS NOT NULL;

-- Replace 0001's fail-closed stub with the managed Cloud membership predicate.
-- SECURITY DEFINER avoids RLS recursion while the owner-controlled table and
-- explicit search_path keep the predicate narrow.
CREATE OR REPLACE FUNCTION esig_tenant_member(t uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.esig_memberships m
    WHERE m.tenant_id = t
      AND m.user_id = auth.uid()
      AND m.status = 'active'
  );
$$;

-- ==================================================================
-- 2. Entitlements, API-key hashes and provisioning state
-- ==================================================================

CREATE TABLE IF NOT EXISTS esig_entitlements (
  tenant_id              uuid PRIMARY KEY REFERENCES esig_organizations(id),
  plan_key               text NOT NULL CHECK (plan_key IN ('cloud_starter', 'cloud_team', 'cloud_scale')),
  subscription_status    text NOT NULL DEFAULT 'pending'
                         CHECK (subscription_status IN ('pending', 'active', 'past_due', 'canceled', 'refunded')),
  envelopes_per_month    integer NOT NULL CHECK (envelopes_per_month > 0),
  seats                  integer NOT NULL CHECK (seats > 0),
  requests_per_minute    integer NOT NULL CHECK (requests_per_minute > 0),
  current_period_end     timestamptz,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS esig_api_keys (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES esig_organizations(id),
  key_prefix     text NOT NULL,
  key_hash       text NOT NULL UNIQUE,
  scopes         text[] NOT NULL DEFAULT ARRAY['envelopes:write', 'envelopes:read', 'verify:read']::text[],
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at     timestamptz,
  UNIQUE (tenant_id, key_prefix),
  CHECK (key_prefix ~ '^esig_(test|live)_[A-Za-z0-9_-]{6,24}$'),
  CHECK (key_hash ~ '^[a-f0-9]{64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS esig_api_keys_one_active_per_tenant
  ON esig_api_keys(tenant_id)
  WHERE status = 'active';

CREATE TABLE IF NOT EXISTS esig_tenant_provisioning (
  tenant_id          uuid PRIMARY KEY REFERENCES esig_organizations(id),
  state              text NOT NULL DEFAULT 'provisioning'
                     CHECK (state IN ('provisioning', 'ready', 'suspended', 'failed', 'disabled')),
  safe_error_code    text,
  activation_sent_at timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (safe_error_code IS NULL OR safe_error_code ~ '^[a-z0-9_]{1,80}$')
);

-- ==================================================================
-- 3. Transactional, idempotent provisioning RPC
-- ==================================================================

CREATE OR REPLACE FUNCTION provision_esig_tenant(
  p_tenant_id uuid,
  p_subscription_id text,
  p_customer_id text,
  p_owner_email text,
  p_display_name text,
  p_slug text,
  p_plan_key text,
  p_deployment_mode text,
  p_dedicated_stack_id text DEFAULT NULL
)
RETURNS TABLE (
  tenant_id uuid,
  organization_status text,
  provisioning_state text,
  storage_namespace text,
  credential_id uuid,
  credential_plaintext text,
  created boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
#variable_conflict use_column
DECLARE
  existing_tenant uuid;
  existing_status text;
  normalized_owner text := lower(trim(p_owner_email));
  plan_envelopes integer;
  plan_seats integer;
  plan_rpm integer;
  tenant_created boolean := false;
  provisioned_credential_id uuid;
  generated_plaintext text;
  generated_prefix text;
BEGIN
  IF p_deployment_mode NOT IN ('shared', 'dedicated') THEN
    RAISE EXCEPTION 'invalid_deployment_mode' USING ERRCODE = '22023';
  END IF;

  IF normalized_owner = '' OR normalized_owner NOT LIKE '%@%' THEN
    RAISE EXCEPTION 'invalid_owner_email' USING ERRCODE = '22023';
  END IF;

  SELECT limits.envelopes, limits.seats, limits.rpm
    INTO plan_envelopes, plan_seats, plan_rpm
  FROM (VALUES
    ('cloud_starter'::text, 100, 1, 60),
    ('cloud_team'::text, 500, 5, 300),
    ('cloud_scale'::text, 1500, 15, 1000)
  ) AS limits(plan_key, envelopes, seats, rpm)
  WHERE limits.plan_key = p_plan_key;

  IF plan_envelopes IS NULL THEN
    RAISE EXCEPTION 'invalid_plan_key' USING ERRCODE = '22023';
  END IF;

  IF p_deployment_mode = 'shared' AND p_dedicated_stack_id IS NOT NULL THEN
    RAISE EXCEPTION 'shared_stack_id_forbidden' USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtext(p_subscription_id));

  SELECT o.id, o.status INTO existing_tenant, existing_status
  FROM esig_organizations o
  WHERE o.stripe_subscription_id = p_subscription_id;

  IF existing_tenant IS NOT NULL AND existing_tenant <> p_tenant_id THEN
    RAISE EXCEPTION 'subscription_tenant_conflict' USING ERRCODE = '23505';
  END IF;

  IF existing_status = 'disabled' THEN
    RAISE EXCEPTION 'tenant_disabled' USING ERRCODE = '55000';
  END IF;

  tenant_created := existing_tenant IS NULL;

  INSERT INTO esig_organizations (
    id, slug, display_name, deployment_mode, status, stripe_customer_id,
    stripe_subscription_id, storage_namespace, dedicated_stack_id
  ) VALUES (
    p_tenant_id, p_slug, trim(p_display_name), p_deployment_mode,
    'provisioning', p_customer_id, p_subscription_id, p_tenant_id::text || '/',
    p_dedicated_stack_id
  )
  ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    dedicated_stack_id = COALESCE(esig_organizations.dedicated_stack_id, EXCLUDED.dedicated_stack_id),
    updated_at = now()
  WHERE esig_organizations.stripe_subscription_id = EXCLUDED.stripe_subscription_id
    AND esig_organizations.stripe_customer_id = EXCLUDED.stripe_customer_id
    AND esig_organizations.deployment_mode = EXCLUDED.deployment_mode;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_identity_conflict' USING ERRCODE = '23505';
  END IF;

  INSERT INTO esig_memberships (
    tenant_id, user_id, normalized_email, role, status
  ) VALUES (
    p_tenant_id, NULL, normalized_owner, 'owner', 'invited'
  )
  ON CONFLICT (tenant_id, normalized_email) DO UPDATE SET
    role = 'owner',
    status = CASE
      WHEN esig_memberships.user_id IS NULL THEN 'invited'
      ELSE 'active'
    END,
    updated_at = now();

  INSERT INTO esig_entitlements (
    tenant_id, plan_key, subscription_status, envelopes_per_month, seats,
    requests_per_minute
  ) VALUES (
    p_tenant_id, p_plan_key, 'active', plan_envelopes, plan_seats, plan_rpm
  )
  ON CONFLICT (tenant_id) DO UPDATE SET
    plan_key = EXCLUDED.plan_key,
    subscription_status = 'active',
    envelopes_per_month = EXCLUDED.envelopes_per_month,
    seats = EXCLUDED.seats,
    requests_per_minute = EXCLUDED.requests_per_minute,
    updated_at = now();

  IF tenant_created THEN
    generated_plaintext := 'esig_live_'
      || replace(gen_random_uuid()::text, '-', '')
      || replace(gen_random_uuid()::text, '-', '');
    generated_prefix := left(generated_plaintext, 24);
    provisioned_credential_id := gen_random_uuid();

    INSERT INTO esig_api_keys (id, tenant_id, key_prefix, key_hash)
    VALUES (
      provisioned_credential_id,
      p_tenant_id,
      generated_prefix,
      encode(sha256(convert_to(generated_plaintext, 'UTF8')), 'hex')
    );
  ELSE
    SELECT k.id INTO provisioned_credential_id
    FROM esig_api_keys k
    WHERE k.tenant_id = p_tenant_id AND k.status = 'active';

    IF provisioned_credential_id IS NULL THEN
      RAISE EXCEPTION 'active_credential_not_found' USING ERRCODE = 'P0002';
    END IF;
  END IF;

  INSERT INTO esig_tenant_provisioning (tenant_id, state)
  VALUES (p_tenant_id, 'provisioning')
  ON CONFLICT (tenant_id) DO UPDATE SET
    state = CASE
      WHEN esig_tenant_provisioning.state = 'ready' THEN 'ready'
      ELSE 'provisioning'
    END,
    safe_error_code = NULL,
    updated_at = now();

  RETURN QUERY
  SELECT o.id, o.status, p.state, o.storage_namespace,
         provisioned_credential_id, generated_plaintext, tenant_created
  FROM esig_organizations o
  JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
  WHERE o.id = p_tenant_id;
END;
$$;

-- Recover from a commit-unknown or pre-handoff failure without ever storing
-- plaintext. The old credential is revoked first and the replacement is
-- returned exactly once to the caller for durable handoff.
CREATE OR REPLACE FUNCTION reissue_esig_tenant_credential(
  p_tenant_id uuid,
  p_subscription_id text
)
RETURNS TABLE (
  credential_id uuid,
  credential_plaintext text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  tenant_status text;
  generated_plaintext text;
  generated_prefix text;
  generated_id uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext(p_subscription_id));

  SELECT o.status INTO tenant_status
  FROM esig_organizations o
  WHERE o.id = p_tenant_id
    AND o.stripe_subscription_id = p_subscription_id
  FOR UPDATE;

  IF tenant_status IS NULL THEN
    RAISE EXCEPTION 'tenant_not_found' USING ERRCODE = 'P0002';
  END IF;

  IF tenant_status = 'disabled' THEN
    RAISE EXCEPTION 'tenant_disabled' USING ERRCODE = '55000';
  END IF;

  IF tenant_status = 'suspended' THEN
    RAISE EXCEPTION 'tenant_suspended' USING ERRCODE = '55000';
  END IF;

  UPDATE esig_api_keys
  SET status = 'revoked', revoked_at = COALESCE(revoked_at, now())
  WHERE tenant_id = p_tenant_id AND status = 'active';

  generated_plaintext := 'esig_live_'
    || replace(gen_random_uuid()::text, '-', '')
    || replace(gen_random_uuid()::text, '-', '');
  generated_prefix := left(generated_plaintext, 24);
  generated_id := gen_random_uuid();

  INSERT INTO esig_api_keys (id, tenant_id, key_prefix, key_hash)
  VALUES (
    generated_id,
    p_tenant_id,
    generated_prefix,
    encode(sha256(convert_to(generated_plaintext, 'UTF8')), 'hex')
  );

  RETURN QUERY SELECT generated_id, generated_plaintext;
END;
$$;

CREATE OR REPLACE FUNCTION mark_esig_tenant_ready(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  tenant_status text;
  provisioning_status text;
BEGIN
  SELECT o.status, p.state
    INTO tenant_status, provisioning_status
  FROM esig_organizations o
  JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
  WHERE o.id = p_tenant_id
  FOR UPDATE OF o, p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_not_found' USING ERRCODE = 'P0002';
  END IF;

  IF tenant_status IN ('suspended', 'disabled')
     OR provisioning_status IN ('suspended', 'disabled') THEN
    RAISE EXCEPTION 'tenant_terminal' USING ERRCODE = '55000';
  END IF;

  IF tenant_status NOT IN ('provisioning', 'ready')
     OR provisioning_status NOT IN ('provisioning', 'ready') THEN
    RAISE EXCEPTION 'tenant_not_readyable' USING ERRCODE = '55000';
  END IF;

  UPDATE esig_tenant_provisioning
  SET state = 'ready', safe_error_code = NULL, updated_at = now()
  WHERE tenant_id = p_tenant_id;

  UPDATE esig_organizations
  SET status = 'ready', updated_at = now()
  WHERE id = p_tenant_id;
END;
$$;

-- Restore a reversibly suspended tenant after billing returns to active. The
-- transition rotates a credential because suspension revoked every prior key.
-- A retry after the transition returns the active credential identity without
-- plaintext, making webhook redelivery idempotent while keeping plaintext
-- one-time only. The tenant must pass mark_esig_tenant_ready() again before it
-- can sign.
CREATE OR REPLACE FUNCTION resume_esig_tenant(
  p_tenant_id uuid,
  p_subscription_id text
)
RETURNS TABLE (
  tenant_id uuid,
  organization_status text,
  provisioning_state text,
  storage_namespace text,
  credential_id uuid,
  credential_plaintext text,
  resumed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
#variable_conflict use_column
DECLARE
  tenant_status text;
  entitlement_status text;
  tenant_storage_namespace text;
  active_credential_id uuid;
  generated_plaintext text;
  generated_prefix text;
  generated_id uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext(p_subscription_id));

  SELECT o.status, e.subscription_status, o.storage_namespace
    INTO tenant_status, entitlement_status, tenant_storage_namespace
  FROM esig_organizations o
  JOIN esig_entitlements e ON e.tenant_id = o.id
  JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
  WHERE o.id = p_tenant_id
    AND o.stripe_subscription_id = p_subscription_id
  FOR UPDATE OF o, e, p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_not_found' USING ERRCODE = 'P0002';
  END IF;

  IF tenant_status = 'disabled'
     OR entitlement_status IN ('canceled', 'refunded') THEN
    RAISE EXCEPTION 'tenant_disabled' USING ERRCODE = '55000';
  END IF;

  IF tenant_status <> 'suspended' OR entitlement_status <> 'past_due' THEN
    IF tenant_status IN ('provisioning', 'ready')
       AND entitlement_status = 'active' THEN
      SELECT k.id INTO active_credential_id
      FROM esig_api_keys k
      WHERE k.tenant_id = p_tenant_id AND k.status = 'active';

      IF active_credential_id IS NULL THEN
        RAISE EXCEPTION 'active_credential_not_found' USING ERRCODE = 'P0002';
      END IF;

      RETURN QUERY
      SELECT p_tenant_id, tenant_status, p.state, tenant_storage_namespace,
             active_credential_id, NULL::text, false
      FROM esig_tenant_provisioning p
      WHERE p.tenant_id = p_tenant_id;
      RETURN;
    END IF;

    RAISE EXCEPTION 'tenant_not_resumable' USING ERRCODE = '55000';
  END IF;

  UPDATE esig_api_keys
  SET status = 'revoked', revoked_at = COALESCE(revoked_at, now())
  WHERE esig_api_keys.tenant_id = p_tenant_id AND status = 'active';

  generated_plaintext := 'esig_live_'
    || replace(gen_random_uuid()::text, '-', '')
    || replace(gen_random_uuid()::text, '-', '');
  generated_prefix := left(generated_plaintext, 24);
  generated_id := gen_random_uuid();

  INSERT INTO esig_api_keys (id, tenant_id, key_prefix, key_hash)
  VALUES (
    generated_id,
    p_tenant_id,
    generated_prefix,
    encode(sha256(convert_to(generated_plaintext, 'UTF8')), 'hex')
  );

  UPDATE esig_entitlements
  SET subscription_status = 'active', updated_at = now()
  WHERE esig_entitlements.tenant_id = p_tenant_id;

  UPDATE esig_organizations
  SET status = 'provisioning', updated_at = now()
  WHERE id = p_tenant_id;

  UPDATE esig_tenant_provisioning
  SET state = 'provisioning', safe_error_code = NULL,
      activation_sent_at = NULL, updated_at = now()
  WHERE esig_tenant_provisioning.tenant_id = p_tenant_id;

  RETURN QUERY
  SELECT p_tenant_id, 'provisioning'::text, 'provisioning'::text,
         tenant_storage_namespace, generated_id, generated_plaintext, true;
END;
$$;

CREATE OR REPLACE FUNCTION disable_esig_tenant(
  p_tenant_id uuid,
  p_subscription_status text,
  p_safe_error_code text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  existing_tenant_status text;
  existing_subscription_status text;
BEGIN
  IF p_subscription_status NOT IN ('past_due', 'canceled', 'refunded') THEN
    RAISE EXCEPTION 'invalid_disable_status' USING ERRCODE = '22023';
  END IF;

  IF p_safe_error_code IS NOT NULL AND p_safe_error_code !~ '^[a-z0-9_]{1,80}$' THEN
    RAISE EXCEPTION 'invalid_safe_error_code' USING ERRCODE = '22023';
  END IF;

  SELECT o.status, e.subscription_status
    INTO existing_tenant_status, existing_subscription_status
  FROM esig_organizations o
  JOIN esig_entitlements e ON e.tenant_id = o.id
  JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
  WHERE o.id = p_tenant_id
  FOR UPDATE OF o, e, p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant_not_found' USING ERRCODE = 'P0002';
  END IF;

  UPDATE esig_api_keys
  SET status = 'revoked', revoked_at = COALESCE(revoked_at, now())
  WHERE tenant_id = p_tenant_id AND status = 'active';

  -- Once canceled/refunded, delayed past_due events cannot resurrect or even
  -- downgrade the terminal billing state.
  UPDATE esig_entitlements
  SET subscription_status = CASE
        WHEN existing_subscription_status IN ('canceled', 'refunded')
          THEN existing_subscription_status
        ELSE p_subscription_status
      END,
      updated_at = now()
  WHERE tenant_id = p_tenant_id;

  UPDATE esig_organizations
  SET status = CASE
        WHEN existing_tenant_status = 'disabled'
          OR existing_subscription_status IN ('canceled', 'refunded')
          OR p_subscription_status IN ('canceled', 'refunded')
          THEN 'disabled'
        ELSE 'suspended'
      END,
      updated_at = now()
  WHERE id = p_tenant_id;

  UPDATE esig_tenant_provisioning
  SET state = CASE
        WHEN existing_tenant_status = 'disabled'
          OR existing_subscription_status IN ('canceled', 'refunded')
          OR p_subscription_status IN ('canceled', 'refunded')
          THEN 'disabled'
        ELSE 'suspended'
      END,
      safe_error_code = p_safe_error_code,
      updated_at = now()
  WHERE tenant_id = p_tenant_id;
END;
$$;

-- ==================================================================
-- 4. RLS and grants
-- ==================================================================

ALTER TABLE esig_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE esig_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE esig_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE esig_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE esig_tenant_provisioning ENABLE ROW LEVEL SECURITY;

CREATE POLICY esig_organizations_member_read ON esig_organizations
  FOR SELECT TO authenticated
  USING (esig_tenant_member(id));

CREATE POLICY esig_memberships_member_read ON esig_memberships
  FOR SELECT TO authenticated
  USING (esig_tenant_member(tenant_id));

CREATE POLICY esig_entitlements_member_read ON esig_entitlements
  FOR SELECT TO authenticated
  USING (esig_tenant_member(tenant_id));

-- API-key hashes and provisioning failures are service-only. Authenticated
-- users receive no direct table grant or policy for either table.
REVOKE ALL ON esig_organizations, esig_memberships, esig_entitlements,
  esig_api_keys, esig_tenant_provisioning FROM anon, authenticated;
GRANT SELECT ON esig_organizations, esig_memberships, esig_entitlements TO authenticated;
GRANT SELECT ON org_signing_certs, esig_audit_log, org_pq_keys TO authenticated;
GRANT ALL ON esig_organizations, esig_memberships, esig_entitlements,
  esig_api_keys, esig_tenant_provisioning TO service_role;
GRANT ALL ON org_signing_certs, org_pq_keys TO service_role;
GRANT SELECT, INSERT ON esig_audit_log TO service_role;

REVOKE ALL ON FUNCTION esig_tenant_member(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION esig_tenant_member(uuid) TO authenticated, service_role;

REVOKE ALL ON FUNCTION provision_esig_tenant(uuid, text, text, text, text, text, text, text, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION reissue_esig_tenant_credential(uuid, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION mark_esig_tenant_ready(uuid)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION resume_esig_tenant(uuid, text)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION disable_esig_tenant(uuid, text, text)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION provision_esig_tenant(uuid, text, text, text, text, text, text, text, text)
  TO service_role;
GRANT EXECUTE ON FUNCTION reissue_esig_tenant_credential(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION mark_esig_tenant_ready(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION resume_esig_tenant(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION disable_esig_tenant(uuid, text, text) TO service_role;

COMMENT ON TABLE esig_api_keys IS
  'First-party e-sig API credential metadata. Plaintext keys are never persisted.';
COMMENT ON FUNCTION disable_esig_tenant(uuid, text, text) IS
  'Revokes access without deleting signed documents, audit rows, or retention-locked evidence.';
COMMENT ON FUNCTION resume_esig_tenant(uuid, text) IS
  'Resumes a past-due tenant into provisioning and returns one freshly rotated credential plaintext exactly once.';
