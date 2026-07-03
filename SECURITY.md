# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/vmvtech/esig-suite/security/advisories/new)
(preferred) or by email to **security@e-sig.org** (replace with your real
contact before publishing). Do not open a public issue for a security report.

We aim to acknowledge within 3 business days and to ship a fix or mitigation
plan within 30 days for confirmed issues. Please give us a reasonable
disclosure window before publishing details.

## Scope

These packages produce and verify PDF digital signatures. The most security-
relevant surfaces are:

- **Signing / verification** (`@e-sig/core`: `pem-signer`, `sign-pdf`,
  `verify-pdf`, `timestamp`, `cert-issuer`).
- **HTML→PDF rendering** — untrusted HTML is rendered in headless Chromium.
  Scripting is disabled by default (`javascriptEnabled: false`); enable it only
  for trusted templates.
- **Persistence adapters** (`@e-sig/supabase`) and the RLS in
  `migrations/` — note the reference migration ships an `esig_tenant_member()`
  stub that denies by default; you must replace it.

## What the signature does and does not establish

- `verifyPdfSignature()` verifies the signature **math and document integrity**
  (the ByteRange digest matches and the RSA signature verifies against the
  embedded certificate). A single altered byte under the signature fails
  verification.
- It does **not** establish third-party **trust** in the signer certificate.
  Certificates issued by `cert-issuer` are self-signed, so stock Adobe Reader
  shows "validity unknown" until the certificate is trusted out-of-band (org
  trust-store import) or you plug in an AATL/CA signer. Chain building, AATL /
  EUTL membership, and revocation (CRL/OCSP) are out of scope for the built-in
  self-issued path.

## Deployment guidance

- Do not enable in-page JavaScript when rendering untrusted document HTML.
- Keep the cert key-wrapping passphrase (`ESIG_CERT_PASSPHRASE`) high-entropy
  and out of source control; prefer per-tenant isolation for higher assurance.
- Treat the append-only audit log as tamper-*evident* only if you write it with
  a role that cannot `UPDATE`/`DELETE` (the Supabase `service_role` bypasses
  RLS); consider hash-chaining rows for stronger evidence.

## Supported versions

The latest published minor of each package is supported. Security fixes are not
backported to older minors pre-1.0.
