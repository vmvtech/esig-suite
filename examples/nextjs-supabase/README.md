# Starter: Next.js + Supabase + self-contained e-sign

Reference wiring of the suite end-to-end. These files are illustrative — drop
them into a Next.js (App Router) project that already has a Supabase SSR client
(`@/lib/supabase/server`) and a service-role client (`@/lib/supabase/service-role`)
— see Opendelphi `src/lib/supabase/{server,service-role}.ts` for a reference impl.

## What's here
- `app/api/esign/sign/route.ts` — auth → load your `documents` row → compose HTML
  with the drawn signature → `signDocument()` over the Supabase stores → persist
  `signed_pdf_url` + audit id on the row.
- `app/api/esign/download/[...path]/route.ts` — RLS-gated proxy for the private
  `signed-documents` bucket (session client, so Storage RLS enforces tenancy).
- `app/sign/page.tsx` + `app/sign/sign-client.tsx` — load the doc, render
  `<SelfSignFlow>` (or `<SelfSignedReceipt>` once signed).

## Setup
1. Install:
   ```bash
   npm i @e-sig/core @e-sig/supabase @e-sig/react
   ```
2. Apply `../../migrations/0001_esig_self_contained.sql` to your Supabase DB, then
   **replace the `esig_tenant_member()` stub** with your tenant-membership check.
3. Create a demo `documents` table:
   ```sql
   create table documents (
     id uuid primary key default gen_random_uuid(),
     tenant_id uuid not null,
     tenant_name text not null,
     signer_name text not null,
     signer_email text not null,
     body_html text not null,
     status text default 'draft',
     signed_pdf_url text,
     signature_image_url text,
     esig_audit_log_id uuid references esig_audit_log(id),
     signed_at timestamptz,
     signatory text
   );
   -- add RLS so a member can read their tenant's documents.
   ```
4. Set env: `ESIG_CERT_PASSPHRASE` (key-at-rest passphrase),
   `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`,
   `SUPABASE_SERVICE_ROLE_KEY`. See `.env.example`.
5. `npm run dev`, open `/sign?document=<id>`, draw a signature, submit. A signed
   PDF lands in the `signed-documents` bucket; an `esig_audit_log` row is written;
   the page re-renders to the receipt with a download link.

## Optional: RFC-3161 trusted timestamps (CAdES-T)
Pass a `tsa` transport to `signDocument()` to embed a trusted timestamp. The
transport is just `{ required, fetch(derBytes) → derBytes }` — wrap your egress
client (or plain `fetch`) to POST `application/timestamp-query` to a TSA like
`http://timestamp.digicert.com`. The TSA only sees a SHA-256 hash, never the PDF.
