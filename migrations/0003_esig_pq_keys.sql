-- 0003_esig_pq_keys.sql
--
-- Managed persistence for post-quantum hybrid key bundles (Ed25519 + ML-DSA-65,
-- FIPS 204), the PQ analogue of org_signing_certs (0001). Paired with
-- SupabasePqKeyStore (@e-sig/supabase) and driven by ensureActivePqKeys /
-- rotatePqKeys (@e-sig/core).
--
-- Unlike signing certs, PQ bundles do NOT expire on a clock — there is no
-- not_before/not_after. Rotation is an explicit, deployment-driven decision
-- (suspected compromise, policy roll); documents already sealed keep verifying
-- because each seal embeds its own public key.
--
-- Column parity with StoredPqKeys (packages/esig-core/src/pq-lifecycle.ts):
--   key_bundle_encrypted  wrapPqKeyBundle() output — AES-256-GCM, app-side.
--                         PUBLIC material below is safe to expose; the bundle is
--                         the only secret and is never stored unwrapped.
--   ed25519_public / mldsa65_public  base64 raw public keys.
--   mldsa65_fpr           SHA-256 hex of the ML-DSA-65 public key (the identity
--                         to publish / pin).
--   key_id                128-bit hex over both public keys (display id).

-- ==================================================================
-- org_pq_keys — one active hybrid bundle per tenant
-- ==================================================================
CREATE TABLE IF NOT EXISTS org_pq_keys (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL,                 -- your tenant/org key (add a FK to your tenants table)
  key_bundle_encrypted  bytea NOT NULL,                -- AES-256-GCM-wrapped bundle (never the plaintext)
  ed25519_public        text NOT NULL,                 -- base64 raw Ed25519 public key (32B)
  mldsa65_public        text NOT NULL,                 -- base64 raw ML-DSA-65 public key (1952B)
  mldsa65_fpr           text NOT NULL,                 -- SHA-256 hex of the ML-DSA-65 public key
  key_id                text NOT NULL,                 -- 128-bit hex over both public keys
  created_at            timestamptz NOT NULL DEFAULT now(),
  rotated_from          uuid REFERENCES org_pq_keys(id),
  active                boolean NOT NULL DEFAULT true,
  CONSTRAINT pq_bundle_nonempty   CHECK (length(key_bundle_encrypted) > 0),
  CONSTRAINT pq_mldsa65_fpr_hex    CHECK (mldsa65_fpr ~ '^[0-9a-f]{64}$'),
  CONSTRAINT pq_key_id_hex         CHECK (key_id ~ '^[0-9a-f]{32}$')
);

-- One active bundle per tenant (rotation flips active=false then inserts anew).
CREATE UNIQUE INDEX IF NOT EXISTS one_active_pq_key_per_tenant
  ON org_pq_keys(tenant_id) WHERE active;
CREATE INDEX IF NOT EXISTS org_pq_keys_tenant_idx ON org_pq_keys(tenant_id);

ALTER TABLE org_pq_keys ENABLE ROW LEVEL SECURITY;

-- Read: tenant members (public material only is exposed to the client; the
-- encrypted bundle is opaque and useless without the app-side passphrase).
-- Reuse the esig_tenant_member() predicate defined in 0001.
CREATE POLICY org_pq_keys_read ON org_pq_keys
  FOR SELECT TO authenticated
  USING (esig_tenant_member(tenant_id));

-- Write: service_role only (the SDK runs server-side with the service key).
CREATE POLICY org_pq_keys_write_service ON org_pq_keys
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);
