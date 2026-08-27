BEGIN;

SELECT plan(63);

SELECT has_table('public', 'esig_organizations', 'organizations table exists');
SELECT has_table('public', 'esig_memberships', 'memberships table exists');
SELECT has_table('public', 'esig_entitlements', 'entitlements table exists');
SELECT has_table('public', 'esig_api_keys', 'API-key hash table exists');
SELECT has_table('public', 'esig_tenant_provisioning', 'provisioning table exists');
SELECT has_function(
  'public',
  'provision_esig_tenant',
  ARRAY['uuid', 'text', 'text', 'text', 'text', 'text', 'text', 'text', 'text'],
  'transactional provisioning RPC exists'
);
SELECT has_function(
  'public',
  'resume_esig_tenant',
  ARRAY['uuid', 'text'],
  'reversible resume RPC exists'
);

CREATE TEMP TABLE first_provision_result AS
  SELECT * FROM provision_esig_tenant(
    '00000000-0000-4000-8000-000000000001'::uuid,
    'sub_test_001',
    'cus_test_001',
    'owner@example.com',
    'Example Organization',
    'example-org',
    'cloud_team',
    'shared',
    NULL
  );

SELECT ok(
  (SELECT created AND credential_plaintext ~ '^esig_live_[a-f0-9]{64}$'
   FROM first_provision_result),
  'first shared provisioning call creates one plaintext credential'
);
SELECT results_eq(
  $sql$ SELECT key_hash FROM esig_api_keys
         WHERE id = (SELECT credential_id FROM first_provision_result) $sql$,
  $sql$ SELECT encode(sha256(convert_to(credential_plaintext, 'UTF8')), 'hex')
         FROM first_provision_result $sql$,
  'only the first credential SHA-256 is persisted'
);
SELECT results_eq(
  $sql$ SELECT storage_namespace FROM first_provision_result $sql$,
  ARRAY['00000000-0000-4000-8000-000000000001/'::text],
  'storage namespace uses the canonical tenant prefix'
);

SELECT results_eq(
  $sql$ SELECT count(*)::bigint FROM esig_organizations WHERE stripe_subscription_id = 'sub_test_001' $sql$,
  ARRAY[1::bigint],
  'one organization is created'
);
SELECT results_eq(
  $sql$ SELECT plan_key, envelopes_per_month, seats, requests_per_minute
         FROM esig_entitlements
         WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  $sql$ VALUES ('cloud_team'::text, 500, 5, 300) $sql$,
  'plan limits are server-derived'
);
SELECT results_eq(
  $sql$ SELECT normalized_email, role, status
         FROM esig_memberships
         WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  $sql$ VALUES ('owner@example.com'::text, 'owner'::text, 'invited'::text) $sql$,
  'owner invitation is normalized and recorded'
);
SELECT results_eq(
  $sql$
    SELECT credential_id, created, credential_plaintext
    FROM provision_esig_tenant(
      '00000000-0000-4000-8000-000000000001'::uuid,
      'sub_test_001',
      'cus_test_001',
      'OWNER@example.com',
      'Example Organization',
      'example-org',
      'cloud_team',
      'shared',
      NULL
    )
  $sql$,
  $sql$ SELECT credential_id, false, NULL::text FROM first_provision_result $sql$,
  'identical retry returns the same credential ID without plaintext'
);
SELECT results_eq(
  $sql$ SELECT count(*)::bigint FROM esig_organizations WHERE stripe_subscription_id = 'sub_test_001' $sql$,
  ARRAY[1::bigint],
  'retry does not duplicate the organization'
);
SELECT results_eq(
  $sql$ SELECT count(*)::bigint FROM esig_api_keys WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  ARRAY[1::bigint],
  'retry does not duplicate credentials'
);

CREATE TEMP TABLE reissued_credential_result AS
  SELECT * FROM reissue_esig_tenant_credential(
    '00000000-0000-4000-8000-000000000001'::uuid,
    'sub_test_001'
  );

SELECT isnt(
  (SELECT credential_id FROM reissued_credential_result),
  (SELECT credential_id FROM first_provision_result),
  'commit-unknown recovery rotates to a new credential ID'
);
SELECT results_eq(
  $sql$ SELECT status, count(*)::bigint
         FROM esig_api_keys
         WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid
         GROUP BY status ORDER BY status $sql$,
  $sql$ VALUES ('active'::text, 1::bigint), ('revoked'::text, 1::bigint) $sql$,
  'credential reissue leaves exactly one active key and revokes the old key'
);
SELECT results_eq(
  $sql$ SELECT key_hash FROM esig_api_keys
         WHERE id = (SELECT credential_id FROM reissued_credential_result) $sql$,
  $sql$ SELECT encode(sha256(convert_to(credential_plaintext, 'UTF8')), 'hex')
         FROM reissued_credential_result $sql$,
  'reissued credential also persists only its SHA-256'
);

SELECT throws_ok(
  $sql$
    SELECT * FROM provision_esig_tenant(
      '00000000-0000-4000-8000-000000000002'::uuid,
      'sub_test_001', 'cus_test_001', 'other@example.com',
      'Other Organization', 'other-org', 'cloud_team', 'shared',
      NULL
    );
  $sql$,
  '23505',
  'subscription_tenant_conflict',
  'a subscription cannot map to a second tenant'
);

SELECT throws_ok(
  $sql$
    SELECT * FROM provision_esig_tenant(
      '00000000-0000-4000-8000-000000000003'::uuid,
      'sub_test_003', 'cus_test_003', 'bad@example.com',
      'Bad Plan', 'bad-plan', 'cloud_unlimited', 'shared',
      NULL
    );
  $sql$,
  '22023',
  'invalid_plan_key',
  'unknown plans fail closed'
);

SELECT lives_ok(
  $sql$ SELECT mark_esig_tenant_ready('00000000-0000-4000-8000-000000000001'::uuid) $sql$,
  'tenant can be marked ready'
);
SELECT results_eq(
  $sql$ SELECT status FROM esig_organizations WHERE id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  ARRAY['ready'::text],
  'organization becomes ready'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000001'::uuid, 'canceled', NULL) $sql$,
  'tenant disable path succeeds'
);
SELECT results_eq(
  $sql$ SELECT subscription_status FROM esig_entitlements WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  ARRAY['canceled'::text],
  'cancellation removes the active entitlement'
);
SELECT results_eq(
  $sql$ SELECT status, count(*)::bigint
         FROM esig_api_keys
         WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid
         GROUP BY status $sql$,
  $sql$ VALUES ('revoked'::text, 2::bigint) $sql$,
  'cancellation revokes every issued API key'
);
SELECT results_eq(
  $sql$ SELECT state FROM esig_tenant_provisioning WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  ARRAY['disabled'::text],
  'cancellation disables provisioning state'
);
SELECT throws_ok(
  $sql$ SELECT mark_esig_tenant_ready('00000000-0000-4000-8000-000000000001'::uuid) $sql$,
  '55000',
  'tenant_terminal',
  'mark-ready cannot resurrect a canceled tenant'
);
SELECT results_eq(
  $sql$ SELECT status, state
         FROM esig_organizations o
         JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
         WHERE o.id = '00000000-0000-4000-8000-000000000001'::uuid $sql$,
  $sql$ VALUES ('disabled'::text, 'disabled'::text) $sql$,
  'failed mark-ready leaves canceled organization and provisioning state disabled'
);
SELECT throws_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000099'::uuid, 'canceled', NULL) $sql$,
  'P0002',
  'tenant_not_found',
  'disable fails closed for an unknown tenant'
);

CREATE TEMP TABLE past_due_initial_result AS
  SELECT * FROM provision_esig_tenant(
    '00000000-0000-4000-8000-000000000003'::uuid,
    'sub_test_past_due', 'cus_test_past_due', 'past-due@example.com',
    'Past Due Organization', 'past-due-org', 'cloud_starter', 'shared',
    NULL
  );

SELECT ok(
  (SELECT created AND credential_plaintext IS NOT NULL
   FROM past_due_initial_result),
  'past-due lifecycle fixture starts active with a one-time credential'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000003'::uuid, 'past_due', NULL) $sql$,
  'active to past-due suspension succeeds'
);
SELECT results_eq(
  $sql$ SELECT o.status, e.subscription_status, p.state
         FROM esig_organizations o
         JOIN esig_entitlements e ON e.tenant_id = o.id
         JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
         WHERE o.id = '00000000-0000-4000-8000-000000000003'::uuid $sql$,
  $sql$ VALUES ('suspended'::text, 'past_due'::text, 'suspended'::text) $sql$,
  'past-due immediately puts organization and provisioning into non-signing suspended state'
);
SELECT results_eq(
  $sql$ SELECT count(*)::bigint FROM esig_api_keys
         WHERE tenant_id = '00000000-0000-4000-8000-000000000003'::uuid
           AND status = 'active' $sql$,
  ARRAY[0::bigint],
  'suspension revokes every active credential'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000003'::uuid, 'past_due', NULL) $sql$,
  'duplicate past-due suspension is idempotent'
);
SELECT results_eq(
  $sql$ SELECT o.status, e.subscription_status, p.state
         FROM esig_organizations o
         JOIN esig_entitlements e ON e.tenant_id = o.id
         JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
         WHERE o.id = '00000000-0000-4000-8000-000000000003'::uuid $sql$,
  $sql$ VALUES ('suspended'::text, 'past_due'::text, 'suspended'::text) $sql$,
  'suspension retry remains suspended without state drift'
);
SELECT throws_ok(
  $sql$ SELECT * FROM reissue_esig_tenant_credential(
           '00000000-0000-4000-8000-000000000003'::uuid,
           'sub_test_past_due'
         ) $sql$,
  '55000',
  'tenant_suspended',
  'generic credential reissue cannot restore signing while suspended'
);
SELECT throws_ok(
  $sql$ SELECT mark_esig_tenant_ready('00000000-0000-4000-8000-000000000003'::uuid) $sql$,
  '55000',
  'tenant_terminal',
  'mark-ready cannot resurrect a past-due tenant'
);

CREATE TEMP TABLE resumed_tenant_result AS
  SELECT * FROM resume_esig_tenant(
    '00000000-0000-4000-8000-000000000003'::uuid,
    'sub_test_past_due'
  );

SELECT ok(
  (SELECT resumed
          AND tenant_id = '00000000-0000-4000-8000-000000000003'::uuid
          AND organization_status = 'provisioning'
          AND provisioning_state = 'provisioning'
          AND storage_namespace = '00000000-0000-4000-8000-000000000003/'
          AND credential_id <> (SELECT credential_id FROM past_due_initial_result)
          AND credential_plaintext ~ '^esig_live_[a-f0-9]{64}$'
   FROM resumed_tenant_result),
  'first active event resumes the same tenant and returns one freshly rotated credential'
);
SELECT results_eq(
  $sql$ SELECT o.status, e.subscription_status, p.state
         FROM esig_organizations o
         JOIN esig_entitlements e ON e.tenant_id = o.id
         JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
         WHERE o.id = '00000000-0000-4000-8000-000000000003'::uuid $sql$,
  $sql$ VALUES ('provisioning'::text, 'active'::text, 'provisioning'::text) $sql$,
  'resume requires a new mark-ready pass before signing'
);
SELECT results_eq(
  $sql$ SELECT status, count(*)::bigint
         FROM esig_api_keys
         WHERE tenant_id = '00000000-0000-4000-8000-000000000003'::uuid
         GROUP BY status ORDER BY status $sql$,
  $sql$ VALUES ('active'::text, 1::bigint), ('revoked'::text, 1::bigint) $sql$,
  'resume leaves one new active credential and the suspended credential revoked'
);
SELECT results_eq(
  $sql$ SELECT key_hash FROM esig_api_keys
         WHERE id = (SELECT credential_id FROM resumed_tenant_result) $sql$,
  $sql$ SELECT encode(sha256(convert_to(credential_plaintext, 'UTF8')), 'hex')
         FROM resumed_tenant_result $sql$,
  'resume persists only the new credential SHA-256'
);

CREATE TEMP TABLE resumed_tenant_retry AS
  SELECT * FROM resume_esig_tenant(
    '00000000-0000-4000-8000-000000000003'::uuid,
    'sub_test_past_due'
  );

SELECT results_eq(
  $sql$ SELECT credential_id, credential_plaintext, resumed
         FROM resumed_tenant_retry $sql$,
  $sql$ SELECT credential_id, NULL::text, false FROM resumed_tenant_result $sql$,
  'duplicate active event returns credential identity without replaying plaintext or rotating again'
);
SELECT lives_ok(
  $sql$ SELECT mark_esig_tenant_ready('00000000-0000-4000-8000-000000000003'::uuid) $sql$,
  'resumed tenant can be marked ready after credential handoff'
);
SELECT results_eq(
  $sql$ SELECT o.status, p.state
         FROM esig_organizations o
         JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
         WHERE o.id = '00000000-0000-4000-8000-000000000003'::uuid $sql$,
  $sql$ VALUES ('ready'::text, 'ready'::text) $sql$,
  'mark-ready completes the resumed tenant activation'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000003'::uuid, 'past_due', NULL) $sql$,
  'active resumed tenant can be suspended again'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000003'::uuid, 'canceled', NULL) $sql$,
  'terminal cancellation from suspended succeeds'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000003'::uuid, 'past_due', NULL) $sql$,
  'late past-due delivery after cancellation is harmless'
);
SELECT lives_ok(
  $sql$ SELECT disable_esig_tenant('00000000-0000-4000-8000-000000000003'::uuid, 'refunded', NULL) $sql$,
  'late refund delivery after cancellation remains terminal'
);
SELECT results_eq(
  $sql$ SELECT o.status, e.subscription_status, p.state
         FROM esig_organizations o
         JOIN esig_entitlements e ON e.tenant_id = o.id
         JOIN esig_tenant_provisioning p ON p.tenant_id = o.id
         WHERE o.id = '00000000-0000-4000-8000-000000000003'::uuid $sql$,
  $sql$ VALUES ('disabled'::text, 'canceled'::text, 'disabled'::text) $sql$,
  'terminal disable is irreversible and delayed events cannot downgrade it'
);
SELECT results_eq(
  $sql$ SELECT status, count(*)::bigint
         FROM esig_api_keys
         WHERE tenant_id = '00000000-0000-4000-8000-000000000003'::uuid
         GROUP BY status $sql$,
  $sql$ VALUES ('revoked'::text, 2::bigint) $sql$,
  'terminal disable leaves every old and resumed credential revoked'
);
SELECT throws_ok(
  $sql$ SELECT * FROM resume_esig_tenant(
           '00000000-0000-4000-8000-000000000003'::uuid,
           'sub_test_past_due'
         ) $sql$,
  '55000',
  'tenant_disabled',
  'resume cannot resurrect a canceled or refunded tenant'
);
SELECT results_eq(
  $sql$ SELECT count(*)::bigint FROM esig_api_keys
         WHERE tenant_id = '00000000-0000-4000-8000-000000000003'::uuid $sql$,
  ARRAY[2::bigint],
  'failed terminal resume creates no replacement credential'
);

INSERT INTO auth.users (id, email) VALUES
  ('10000000-0000-4000-8000-000000000001'::uuid, 'member-a@example.com'),
  ('10000000-0000-4000-8000-000000000002'::uuid, 'member-b@example.com');

UPDATE esig_memberships
SET user_id = '10000000-0000-4000-8000-000000000001'::uuid,
    status = 'active'
WHERE tenant_id = '00000000-0000-4000-8000-000000000001'::uuid;

SELECT lives_ok($sql$
  SELECT * FROM provision_esig_tenant(
    '00000000-0000-4000-8000-000000000002'::uuid,
    'sub_test_002',
    'cus_test_002',
    'member-b@example.com',
    'Second Organization',
    'second-org',
    'cloud_starter',
    'shared',
    NULL
  );
$sql$, 'second isolated tenant provisions successfully');

UPDATE esig_memberships
SET user_id = '10000000-0000-4000-8000-000000000002'::uuid,
    status = 'active'
WHERE tenant_id = '00000000-0000-4000-8000-000000000002'::uuid;

INSERT INTO esig_audit_log (tenant_id, action) VALUES
  ('00000000-0000-4000-8000-000000000001'::uuid, 'pdf.signed'),
  ('00000000-0000-4000-8000-000000000002'::uuid, 'pdf.signed');

SELECT set_config(
  'request.jwt.claim.sub',
  '10000000-0000-4000-8000-000000000001',
  true
);
SET LOCAL ROLE authenticated;

SELECT results_eq(
  $sql$ SELECT id FROM esig_organizations ORDER BY id $sql$,
  ARRAY['00000000-0000-4000-8000-000000000001'::uuid],
  'member A can read only organization A'
);
SELECT results_eq(
  $sql$ SELECT tenant_id FROM esig_memberships ORDER BY tenant_id $sql$,
  ARRAY['00000000-0000-4000-8000-000000000001'::uuid],
  'member A can read only membership A'
);
SELECT results_eq(
  $sql$ SELECT tenant_id FROM esig_entitlements ORDER BY tenant_id $sql$,
  ARRAY['00000000-0000-4000-8000-000000000001'::uuid],
  'member A can read only entitlement A'
);
SELECT results_eq(
  $sql$ SELECT tenant_id FROM esig_audit_log ORDER BY tenant_id $sql$,
  ARRAY['00000000-0000-4000-8000-000000000001'::uuid],
  'member A can read only audit evidence A'
);
SELECT throws_ok(
  $sql$ SELECT key_hash FROM esig_api_keys $sql$,
  '42501',
  'permission denied for table esig_api_keys',
  'authenticated members cannot read API-key hashes'
);

RESET ROLE;
SELECT set_config(
  'request.jwt.claim.sub',
  '10000000-0000-4000-8000-000000000002',
  true
);
SET LOCAL ROLE authenticated;
SELECT results_eq(
  $sql$ SELECT id FROM esig_organizations ORDER BY id $sql$,
  ARRAY['00000000-0000-4000-8000-000000000002'::uuid],
  'member B can read only organization B'
);
RESET ROLE;

SELECT col_is_pk('public', 'esig_organizations', 'id', 'organization ID is the primary key');
SELECT col_not_null('public', 'esig_api_keys', 'key_hash', 'API-key hash cannot be null');
SELECT hasnt_column(
  'public',
  'esig_api_keys',
  'credential_plaintext',
  'credential plaintext has no persistence column'
);

CREATE TEMP TABLE esig_pgtap_finish AS SELECT * FROM finish();
TABLE esig_pgtap_finish;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM esig_pgtap_finish
    WHERE finish LIKE '# Looks like you failed%'
  ) THEN
    RAISE EXCEPTION 'pgTAP assertions failed';
  END IF;
END;
$$;
ROLLBACK;
