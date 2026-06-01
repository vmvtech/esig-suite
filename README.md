# esig-suite — self-contained PDF e-signature SDK

A portable, **self-hosted** PDF e-signature stack: render an HTML document to
PDF, sign it with a self-issued per-tenant certificate (PKCS#7 / ETSI CAdES,
optional RFC-3161 trusted timestamp → CAdES-T), store it, and keep an
append-only attribution log. **No SaaS, no metering, no per-document fees** — you
own the certs, the PDFs, and the audit trail.

Extracted from the Opendelphi production pipeline (live since 2026-05).

## Packages

| Package | What | Stack |
|---|---|---|
| **`@vmvtech/esig-core`** | The engine: `renderHtmlToPdf` → `signPdf` (+TSA) → `verifyPdfStructure`, self-signed cert issuance, the `CertStore`/`AuditLogStore`/`PdfStorageStore` interfaces, `ensureActiveCert`, and the end-to-end `signDocument()` orchestrator. | Node, stack-agnostic |
| **`@vmvtech/esig-supabase`** | Reference adapters: `SupabaseCertStore`, `SupabaseAuditLogStore`, `SupabasePdfStorageStore`. | Supabase (Postgres + Storage) |
| **`@vmvtech/esig-react`** | UI: `SignaturePadCanvas` (draw-to-sign), `SelfSignFlow`, `SelfSignedReceipt`. | React 18/19 |

Plus **`migrations/`** (a `tenant_id`-keyed schema bundle) and a **Next.js +
Supabase starter** under `examples/nextjs-supabase`.

## Quickstart (Next.js + Supabase)

```bash
npm i @vmvtech/esig-core @vmvtech/esig-supabase @vmvtech/esig-react
```
(Add `@vmvtech:registry=https://npm.pkg.github.com` to a project-local `.npmrc`
+ a GitHub token with `read:packages`.)

1. **Migrate** — apply `migrations/0001_esig_self_contained.sql` and replace the
   `esig_tenant_member()` stub with your tenant-membership check. (See
   `migrations/README.md`.)
2. **Wire the sign route** — load your document, compose the signature-embedded
   HTML, call `signDocument()` over the three Supabase stores, persist the result:
   ```ts
   import { signDocument } from "@vmvtech/esig-core";
   import { SupabaseCertStore, SupabaseAuditLogStore, SupabasePdfStorageStore } from "@vmvtech/esig-supabase";

   const result = await signDocument({
     html, signatureImage: { bytes, contentType: "image/png" },
     tenantId, subjectName: tenantName, passphrase: process.env.ESIG_CERT_PASSPHRASE!,
     signer: { name, email }, actorUserId,
     certStore: new SupabaseCertStore(service),
     auditStore: new SupabaseAuditLogStore(service),
     storage: new SupabasePdfStorageStore(service),
     pathPrefix: `${tenantId}/${documentId}`,
     targetTable: "documents", targetId: documentId,
   });
   // → { signedPdfUrl, auditLogId, certFingerprint, timestamped }
   ```
3. **Mount the UI** — `<SelfSignFlow documentId signer preview signEndpoint onSigned />`,
   then `<SelfSignedReceipt … />` once signed.

The full wiring is in `examples/nextjs-supabase/`.

## Bring your own stack

`signDocument()` depends only on the three interfaces in
`@vmvtech/esig-core/adapters` — implement them against any DB/storage (the
Supabase package is just the reference). The React components take a `signEndpoint`
+ callbacks and have no Next/Supabase coupling. The migration is `tenant_id`-keyed
with a single tenant-access predicate to replace.

## Legal posture

The signing path targets ESIGN/UETA: intent (consent checkbox), attribution
(`esig_audit_log` — actor, IP, UA, cert fingerprint), and integrity (PKCS#7
detached signature, optional RFC-3161 timestamp). You remain responsible for
your own compliance review.

## Build (workspace)

```bash
npm install
npm run build     # builds core → supabase → react in dep order
npm run smoke     # Chrome-free runtime smoke against the built core
```

License: MIT.
