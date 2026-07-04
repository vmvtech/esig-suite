-- 0002_esig_audit_hashchain.sql
--
-- Tamper-evident hash chain for esig_audit_log, layered on 0001. RLS already
-- limits writes to service_role INSERT — but service_role BYPASSES RLS, so a
-- leaked service key (or a careless dashboard session) could silently rewrite
-- history. Triggers fire for every role, so this migration adds:
--
--   1. action_known relaxed        — keep 0001's known list, additionally
--                                    allow 'envelope.%' / 'verify.%' actions
--   2. chain columns               — seq, prev_hash, row_hash, payload_canonical
--   3. backfill                    — existing rows chained in (created_at, id) order
--   4. hash-chain INSERT trigger   — per-tenant seq + SHA-256 linkage
--   5. append-only triggers        — UPDATE / DELETE / TRUNCATE always RAISE
--
-- Verify from JS with verifyAuditChain() (@e-sig/supabase): it re-derives the
-- SHA-256 linkage from payload_canonical and cross-checks each row's scalar
-- columns against the canonical string. Honest threat model: a superuser can
-- still DISABLE TRIGGER and rewrite rows — but cannot do so without breaking
-- the chain for any verifier holding an earlier row_hash. For hard guarantees,
-- anchor the latest row_hash externally (e.g. publish it periodically).

-- ==================================================================
-- CANONICAL PAYLOAD SPEC v1 — single source of truth
-- ==================================================================
-- Implemented twice, byte-for-byte: here (trigger + backfill) and in
-- packages/esig-supabase/src/audit-chain.ts. Change one → change both, and
-- bump the leading version tag.
--
--   payload_canonical =
--        'v1'
--     || '|' || tenant_id::text                       (lowercase uuid text)
--     || '|' || action
--     || '|' || coalesce(actor_user_id::text, '')     ('' when NULL)
--     || '|' || coalesce(target_table, '')            ('' when NULL)
--     || '|' || coalesce(target_id::text, '')         ('' when NULL)
--     || '|' || (extract(epoch from created_at) * 1000000)::bigint::text
--                                                     (epoch MICROseconds)
--     || '|' || md5(metadata::text)                   (32 lowercase hex)
--
--   row_hash  = encode(sha256(convert_to(
--                 coalesce(prev_hash, '') || '|' || payload_canonical,
--                 'UTF8')), 'hex')
--   seq       = 0-origin, contiguous per tenant
--   prev_hash = row_hash of the tenant's previous row (NULL at seq 0)
--
-- Notes:
--   * jsonb normalization (key order, spacing, numeric rendering) is PG-side:
--     the md5 is taken over Postgres's canonical `metadata::text` rendering,
--     which JS cannot reproduce reliably. The md5 therefore travels inside
--     payload_canonical and is integrity-protected by the chain itself; JS
--     verifiers cross-check only the SCALAR fields column-by-column.
--   * convert_to(…, 'UTF8') — NOT a text::bytea cast, which would reinterpret
--     backslashes as bytea escape sequences. The JS side hashes UTF-8 bytes.
--   * (extract(epoch …) * 1000000)::bigint is exact on PG 14+ (extract returns
--     numeric); timestamptz precision is exactly 1 µs, so nothing rounds.
--   * seq is deliberately NOT part of the canonical: deleting a row and
--     renumbering still breaks prev_hash linkage, which the verifier checks.

-- ==================================================================
-- 0. action_known — relax for forward compatibility
-- ==================================================================
-- 0001 rejected unknown actions outright, so every new SDK feature would need
-- a migration per action. Keep the known list (its intent: no free-form junk
-- in the audit log) and additionally accept namespaced 'envelope.%' and
-- 'verify.%' actions. Existing rows all use the old list — a subset — so the
-- re-ADD validates cleanly.
ALTER TABLE esig_audit_log DROP CONSTRAINT IF EXISTS action_known;
ALTER TABLE esig_audit_log ADD CONSTRAINT action_known CHECK (
  action IN (
    'cert.created', 'cert.rotated', 'cert.deactivated',
    'pdf.rendered', 'pdf.signed', 'pdf.verified',
    'consent.recorded'
  )
  OR action LIKE 'envelope.%'
  OR action LIKE 'verify.%'
);

-- ==================================================================
-- 1. Chain columns
-- ==================================================================
-- Nullable during backfill; seq / row_hash / payload_canonical become
-- NOT NULL in section 3. prev_hash stays nullable (NULL at seq 0).
ALTER TABLE esig_audit_log
  ADD COLUMN IF NOT EXISTS seq               bigint,
  ADD COLUMN IF NOT EXISTS prev_hash         text,
  ADD COLUMN IF NOT EXISTS row_hash          text,
  ADD COLUMN IF NOT EXISTS payload_canonical text;

-- ==================================================================
-- 2. Canonicalization + hashing helpers (spec v1 above)
-- ==================================================================
CREATE OR REPLACE FUNCTION esig_audit_canonical(
  p_tenant_id    uuid,
  p_action       text,
  p_actor_user_id uuid,
  p_target_table text,
  p_target_id    uuid,
  p_created_at   timestamptz,
  p_metadata     jsonb
)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = public, pg_catalog
AS $$
  SELECT 'v1'
    || '|' || p_tenant_id::text
    || '|' || p_action
    || '|' || coalesce(p_actor_user_id::text, '')
    || '|' || coalesce(p_target_table, '')
    || '|' || coalesce(p_target_id::text, '')
    || '|' || ((extract(epoch FROM p_created_at) * 1000000)::bigint)::text
    || '|' || md5(coalesce(p_metadata, '{}'::jsonb)::text)
$$;

CREATE OR REPLACE FUNCTION esig_audit_row_hash(p_prev_hash text, p_canonical text)
RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = public, pg_catalog
AS $$
  SELECT encode(sha256(convert_to(
    coalesce(p_prev_hash, '') || '|' || p_canonical, 'UTF8')), 'hex')
$$;

-- ==================================================================
-- 3. Backfill — chain existing rows in (created_at, id) order
-- ==================================================================
-- Re-run safety: only rows with row_hash IS NULL are touched (re-running on a
-- fully chained table is a no-op), and the append-only gate from section 5 is
-- lifted first so a partial re-run can complete.
DROP TRIGGER IF EXISTS esig_audit_log_block_update   ON esig_audit_log;
DROP TRIGGER IF EXISTS esig_audit_log_block_delete   ON esig_audit_log;
DROP TRIGGER IF EXISTS esig_audit_log_block_truncate ON esig_audit_log;

DO $$
DECLARE
  r          record;
  cur_tenant uuid;
  next_seq   bigint;
  prev       text;
  canon      text;
  hash       text;
BEGIN
  FOR r IN
    SELECT id, tenant_id, action, actor_user_id, target_table, target_id,
           created_at, metadata
    FROM esig_audit_log
    WHERE row_hash IS NULL
    ORDER BY tenant_id, created_at, id
  LOOP
    IF cur_tenant IS DISTINCT FROM r.tenant_id THEN
      cur_tenant := r.tenant_id;
      -- Continue after any already-chained rows for this tenant.
      SELECT seq + 1, row_hash INTO next_seq, prev
      FROM esig_audit_log
      WHERE tenant_id = r.tenant_id AND seq IS NOT NULL
      ORDER BY seq DESC NULLS LAST
      LIMIT 1;
      IF next_seq IS NULL THEN
        next_seq := 0;
        prev := NULL;
      END IF;
    END IF;

    canon := esig_audit_canonical(r.tenant_id, r.action, r.actor_user_id,
                                  r.target_table, r.target_id,
                                  r.created_at, r.metadata);
    hash  := esig_audit_row_hash(prev, canon);

    UPDATE esig_audit_log
    SET seq = next_seq, prev_hash = prev,
        payload_canonical = canon, row_hash = hash
    WHERE id = r.id;

    prev     := hash;
    next_seq := next_seq + 1;
  END LOOP;
END;
$$;

ALTER TABLE esig_audit_log
  ALTER COLUMN seq               SET NOT NULL,
  ALTER COLUMN row_hash          SET NOT NULL,
  ALTER COLUMN payload_canonical SET NOT NULL;

-- Belt and braces: even with triggers disabled, duplicate (tenant, seq) pairs
-- are impossible, and the INSERT trigger's max-seq lookup stays index-only.
CREATE UNIQUE INDEX IF NOT EXISTS esig_audit_log_tenant_seq_key
  ON esig_audit_log(tenant_id, seq);

-- ==================================================================
-- 4. Hash-chain INSERT trigger
-- ==================================================================
-- Computed values always win: any client-supplied seq/prev_hash/row_hash/
-- payload_canonical is overwritten, so a writer cannot forge chain state.
-- The per-tenant advisory xact lock serializes concurrent inserts for one
-- tenant until commit (hashtext() collisions across tenants only cost a
-- moment of extra serialization, never correctness).
CREATE OR REPLACE FUNCTION esig_audit_log_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_catalog
AS $$
DECLARE
  last_seq  bigint;
  last_hash text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext(NEW.tenant_id::text));

  NEW.created_at := coalesce(NEW.created_at, now());

  SELECT seq, row_hash INTO last_seq, last_hash
  FROM esig_audit_log
  WHERE tenant_id = NEW.tenant_id
  ORDER BY seq DESC NULLS LAST
  LIMIT 1;

  NEW.seq               := coalesce(last_seq + 1, 0);
  NEW.prev_hash         := last_hash;               -- NULL at genesis (seq 0)
  NEW.payload_canonical := esig_audit_canonical(
    NEW.tenant_id, NEW.action, NEW.actor_user_id,
    NEW.target_table, NEW.target_id, NEW.created_at, NEW.metadata);
  NEW.row_hash          := esig_audit_row_hash(NEW.prev_hash, NEW.payload_canonical);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS esig_audit_log_chain ON esig_audit_log;
CREATE TRIGGER esig_audit_log_chain
  BEFORE INSERT ON esig_audit_log
  FOR EACH ROW EXECUTE FUNCTION esig_audit_log_chain();

-- ==================================================================
-- 5. Append-only enforcement — UPDATE / DELETE / TRUNCATE always RAISE
-- ==================================================================
-- RLS already denies UPDATE/DELETE to ordinary roles, but service_role
-- bypasses RLS entirely; triggers fire regardless of role.
CREATE OR REPLACE FUNCTION esig_audit_log_block_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'esig_audit_log is append-only: % is not allowed (hash-chained audit trail)', TG_OP;
END;
$$;

CREATE TRIGGER esig_audit_log_block_update
  BEFORE UPDATE ON esig_audit_log
  FOR EACH ROW EXECUTE FUNCTION esig_audit_log_block_mutation();

CREATE TRIGGER esig_audit_log_block_delete
  BEFORE DELETE ON esig_audit_log
  FOR EACH ROW EXECUTE FUNCTION esig_audit_log_block_mutation();

CREATE TRIGGER esig_audit_log_block_truncate
  BEFORE TRUNCATE ON esig_audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION esig_audit_log_block_mutation();
