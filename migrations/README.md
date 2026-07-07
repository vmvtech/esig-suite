# Migrations — `esig-suite`

`0001_esig_self_contained.sql` creates the persistence backbone for the
self-contained signing pipeline: `org_signing_certs`, the append-only
`esig_audit_log`, and a private `signed-documents` Supabase Storage bucket.

`0002_esig_audit_hashchain.sql` makes the audit log tamper-evident: per-tenant
`seq` + SHA-256 hash chain computed by a `BEFORE INSERT` trigger, hard
UPDATE/DELETE/TRUNCATE guards (they fire even for `service_role`, which
bypasses RLS), a backfill of existing rows in `(created_at, id)` order, and a
relaxed action CHECK admitting `envelope.*` / `verify.*` actions. Verify a
tenant's chain from JS with `verifyAuditChain()` from `@e-sig/supabase`.

`0003_esig_pq_keys.sql` adds `org_pq_keys` — managed persistence for the
post-quantum hybrid key bundles (Ed25519 + ML-DSA-65, FIPS 204). One active
bundle per tenant, RLS mirroring `org_signing_certs` (tenant-member read,
`service_role` write). Driven by `ensureActivePqKeys` / `rotatePqKeys`
(`@e-sig/core`) through `SupabasePqKeyStore` (`@e-sig/supabase`). Independent of
0002 — apply any time after 0001.

## Apply it

- **Supabase:** copy each file into
  `supabase/migrations/<timestamp>_<name>.sql` (0001 before 0002) and
  `supabase db push` (or `supabase db reset` locally). The Storage section of
  0001 uses `storage.buckets` / `storage.objects`, which exist on Supabase.
- **Plain Postgres:** `psql -1 "$DATABASE_URL" -f 0001_esig_self_contained.sql`
  then `psql -1 "$DATABASE_URL" -f 0002_esig_audit_hashchain.sql` (`-1` wraps
  the run in one transaction — apply 0002 in a low-write window so the backfill
  and `SET NOT NULL` see a quiet table). Drop the storage section of 0001 and
  implement your own `PdfStorageStore` if you aren't on Supabase Storage.

## You MUST do two things

1. **Replace `esig_tenant_member(uuid)`.** It ships as a deny-by-default stub
   (returns `false`). Set its body to your tenant-membership predicate so members
   can read their certs / audit rows / signed PDFs. Example:
   ```sql
   CREATE OR REPLACE FUNCTION esig_tenant_member(t uuid) RETURNS boolean
   LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
     SELECT EXISTS (SELECT 1 FROM memberships m
                    WHERE m.tenant_id = t AND m.user_id = auth.uid());
   $$;
   ```
2. **Wire `tenant_id`** to your org/tenant key. The tables key on `tenant_id`;
   `@e-sig/supabase` defaults to that column. If your column is different
   (e.g. an existing `org_id`), pass `{ tenantColumn: 'org_id' }` to the store
   constructors instead of renaming.

## Notes

- `actor_user_id` has no FK in the bundle — add one to your users table (Supabase:
  `REFERENCES auth.users(id)`).
- The audit log is append-only (only a service-role INSERT policy; no
  UPDATE/DELETE). Keep it that way for ESIGN R3 / UETA §13 evidence integrity.
- Storage objects are laid out `{tenant_id}/{document_id}/{timestamp}.pdf` — the
  path-prefix RLS reads the first folder segment as the tenant id.
- This bundle deliberately ships **no document table**. Keep your own (DUA,
  contract, consent form, …) and persist `signedPdfUrl` + the `esig_audit_log`
  id returned by `signDocument()` onto your row.
