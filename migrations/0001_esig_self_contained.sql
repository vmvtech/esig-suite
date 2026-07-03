-- 0001_esig_self_contained.sql
--
-- Persistence backbone for the @e-sig/* self-contained PDF signing
-- pipeline, paired with @e-sig/supabase. Generic, tenant_id-keyed.
--
--   1. esig_tenant_member(uuid)   — RLS predicate STUB (you MUST replace it)
--   2. org_signing_certs          — one RSA cert+key per tenant (key encrypted)
--   3. esig_audit_log             — append-only attribution log (ESIGN R3 / UETA §13)
--   4. signed-documents bucket    — private, tenant-folder-scoped (Supabase Storage)
--
-- This bundle does NOT include any document/domain table — the consumer keeps
-- its own (DUA, contract, consent, …) and stores the returned signed_pdf_url +
-- esig_audit_log id on its row. `@e-sig/supabase` defaults to the table
-- names + `tenant_id` column below; pass options to map onto an existing schema.

-- ==================================================================
-- 0. Tenant-access predicate — REPLACE THIS STUB.
-- ==================================================================
-- All read policies below call esig_tenant_member(tenant_id). The shipped stub
-- returns FALSE (deny-by-default — safe). Replace its body with your real
-- tenant-membership check so members can read their own certs/audit/PDFs, e.g.:
--   Opendelphi: RETURN is_org_member(t);
--   generic:    RETURN EXISTS (SELECT 1 FROM memberships m
--                              WHERE m.tenant_id = t AND m.user_id = auth.uid());
CREATE OR REPLACE FUNCTION esig_tenant_member(t uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
  -- TODO: replace with your tenant-membership predicate.
  RETURN false;
END;
$$;

-- ==================================================================
-- 1. org_signing_certs
-- ==================================================================
-- One signing cert per tenant, created lazily by ensureActiveCert() on first
-- sign. cert_pem is PUBLIC (embedded in every signature). key_pem_encrypted is
-- the AES-GCM-encrypted PEM (encrypted app-side with your passphrase; pgsodium
-- not assumed — app-side encryption is portable across DB tiers).
CREATE TABLE IF NOT EXISTS org_signing_certs (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL,                 -- your tenant/org key (add a FK to your tenants table)
  cert_pem            text NOT NULL,
  key_pem_encrypted   bytea NOT NULL,
  cert_fingerprint    text NOT NULL,                 -- SHA-256 hex; used by the audit log
  not_before          timestamptz NOT NULL,
  not_after           timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  rotated_from        uuid REFERENCES org_signing_certs(id),
  active              boolean NOT NULL DEFAULT true,
  CONSTRAINT cert_pem_starts_with_pem CHECK (cert_pem LIKE '-----BEGIN CERTIFICATE-----%'),
  CONSTRAINT key_encrypted_nonempty   CHECK (length(key_pem_encrypted) > 0)
);

-- One active cert per tenant (rotation flips active=false then inserts a new row).
CREATE UNIQUE INDEX IF NOT EXISTS one_active_cert_per_tenant
  ON org_signing_certs(tenant_id) WHERE active;
CREATE INDEX IF NOT EXISTS org_signing_certs_tenant_idx ON org_signing_certs(tenant_id);

ALTER TABLE org_signing_certs ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_signing_certs_read ON org_signing_certs
  FOR SELECT TO authenticated
  USING (esig_tenant_member(tenant_id));

CREATE POLICY org_signing_certs_write_service ON org_signing_certs
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- ==================================================================
-- 2. esig_audit_log (append-only)
-- ==================================================================
CREATE TABLE IF NOT EXISTS esig_audit_log (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL,
  actor_user_id       uuid,                          -- your users table / Supabase auth.users(id); null = system
  action              text NOT NULL,
  target_table        text,
  target_id           uuid,
  cert_id             uuid REFERENCES org_signing_certs(id),
  cert_fingerprint    text,
  ip                  inet,
  user_agent          text,
  session_id          text,
  signed_pdf_url      text,
  metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT action_known CHECK (action IN (
    'cert.created', 'cert.rotated', 'cert.deactivated',
    'pdf.rendered', 'pdf.signed', 'pdf.verified',
    'consent.recorded'
  ))
);

CREATE INDEX IF NOT EXISTS esig_audit_log_tenant_idx  ON esig_audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS esig_audit_log_actor_idx   ON esig_audit_log(actor_user_id);
CREATE INDEX IF NOT EXISTS esig_audit_log_target_idx  ON esig_audit_log(target_table, target_id);
CREATE INDEX IF NOT EXISTS esig_audit_log_created_idx ON esig_audit_log(created_at DESC);

ALTER TABLE esig_audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY esig_audit_log_read ON esig_audit_log
  FOR SELECT TO authenticated
  USING (esig_tenant_member(tenant_id));

-- Append-only: only service-role INSERT; no UPDATE/DELETE policies.
CREATE POLICY esig_audit_log_insert_service ON esig_audit_log
  FOR INSERT TO service_role
  WITH CHECK (true);

-- ==================================================================
-- 3. signed-documents storage bucket (Supabase Storage)
-- ==================================================================
-- Private bucket; objects are stored under {tenant_id}/{document_id}/{ts}.pdf so
-- the path-prefix RLS scopes reads to tenant members. Omit this section if you
-- store signed PDFs elsewhere (implement your own PdfStorageStore).
INSERT INTO storage.buckets (id, name, public)
VALUES ('signed-documents', 'signed-documents', false)
ON CONFLICT (id) DO NOTHING;

CREATE POLICY signed_documents_read_tenant_member ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'signed-documents'
    AND esig_tenant_member((storage.foldername(name))[1]::uuid)
  );

CREATE POLICY signed_documents_write_service ON storage.objects
  FOR ALL TO service_role
  USING (bucket_id = 'signed-documents')
  WITH CHECK (bucket_id = 'signed-documents');
