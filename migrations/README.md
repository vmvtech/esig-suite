# Migrations — `esig-suite`

`0001_esig_self_contained.sql` creates the persistence backbone for the
self-contained signing pipeline: `org_signing_certs`, the append-only
`esig_audit_log`, and a private `signed-documents` Supabase Storage bucket.

## Apply it

- **Supabase:** copy into `supabase/migrations/<timestamp>_esig_self_contained.sql`
  and `supabase db push` (or `supabase db reset` locally). The Storage section
  uses `storage.buckets` / `storage.objects`, which exist on Supabase.
- **Plain Postgres:** `psql "$DATABASE_URL" -f 0001_esig_self_contained.sql`.
  Drop the storage section and implement your own `PdfStorageStore` if you
  aren't on Supabase Storage.

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
   `@vmvtech/esig-supabase` defaults to that column. If your column is different
   (Opendelphi uses `org_id`), pass `{ tenantColumn: 'org_id' }` to the store
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
