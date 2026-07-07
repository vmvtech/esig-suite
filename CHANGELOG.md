# Changelog

All notable changes to the `@e-sig/*` packages. This project follows
[Semantic Versioning](https://semver.org/). Dates are ISO-8601.

## 0.6.0 — 2026-07-06

### `@e-sig/core` 0.6.0 — post-quantum hybrid seal + ML-DSA-65 X.509

**Post-quantum signing (FIPS 204).** New optional hybrid **Ed25519 + ML-DSA-65**
seal, embedded *under* the classical PKCS#7/PAdES RSA signature so signed PDFs
stay valid in every reader (Adobe Acrobat included) while gaining quantum
resistance — the NIST / CNSA 2.0 migration path. `signPdf` / `signDocument`
accept a `pqSeal` / `pq` option; `verifyDocument` returns both the classical and
post-quantum verdicts, with optional in-band fingerprint pinning
(`expectedMldsa65Fpr`) and `requirePq` (no silent downgrade). The seal covers
SHA-256 of the pre-seal PDF and is embedded append-only so the classical
`/ByteRange` protects it — tampering the document breaks **both** layers. Managed
keys via `ensureActivePqKeys` / `rotatePqKeys` over a bring-your-own `PqKeyStore`.

**ML-DSA-65 X.509 identity (RFC 9881).** `issueMlDsaCertificate` mints a
self-signed ML-DSA-65 certificate (SubjectPublicKeyInfo *and* signature both
`id-ml-dsa-65`, OID `2.16.840.1.101.3.4.3.18`) — parses and verifies in
OpenSSL 3.5+. `verifyDocument({ signerCert })` binds a certificate to a seal by
public-key fingerprint; `verifyMlDsaCertificate` / `certMatchesPqSeal` are also
exported. Fully backward compatible — the seal is opt-in and unsealed documents
verify exactly as before.

### `@e-sig/supabase` 0.3.0 — managed post-quantum keys

`SupabasePqKeyStore` implements the core `PqKeyStore` over a new `org_pq_keys`
table (migration `0003_esig_pq_keys.sql`): one active hybrid bundle per tenant,
AES-256-GCM-wrapped at rest, RLS mirroring `org_signing_certs`. Peer dependency
widened to allow `@e-sig/core` `^0.6.0`.

### `@e-sig/react` 0.2.1

Version bump for the coordinated 0.6.0 release; no code changes.

## 0.5.0 — 2026-07-03

### `@e-sig/core` 0.5.0 — envelopes, fs adapters, verifier fix

**Multi-signer envelopes + tokenized signing links.** New storage-agnostic
envelope model (`createEnvelope`, `resolveSigningToken`, `recordSignature`,
`declineEnvelope`, `voidEnvelope`, `composeEnvelopeHtml`, `EnvelopeStore`
interface): N ordered signers over one document, each addressed by an opaque
single-use 32-byte token returned exactly once — only SHA-256 hashes are
persisted. Equal order signs in parallel; lower orders gate higher ones; a
decline voids the envelope; expiry applies lazily. Completion composes all
signature blocks for the single cryptographic seal via `signDocument()`.
Sequential *PDF* re-signing remains deliberately out of scope (single
/ByteRange signer+verifier) and is documented as such. Audit vocabulary gains
`envelope.*` actions.

**Filesystem adapters (`@e-sig/core/fs`).** `FsCertStore`, `FsAuditLogStore`
(append-only NDJSON), `FsPdfStorageStore` (traversal-guarded), and
`FsEnvelopeStore` run the entire pipeline on a bare directory — no Supabase,
no database. Single-process semantics, atomic-replace JSON state.

**Verifier fix (false rejection).** `/Contents` placeholder padding is now
stripped by slicing at the DER's TLV-declared length instead of trimming
trailing `00` hex pairs, which truncated any PKCS#7 blob whose final byte was
legitimately `0x00` (~1/256 of RSA signatures) and rejected valid documents.
Could never false-accept — a truncated DER never parses.

**Signature block.** The audit footer no longer hardcodes an origin-project
name, and the caller-supplied `platformLabel` is HTML-escaped like every other
interpolation.

### `@e-sig/supabase` 0.2.0 — tamper-evident audit chain

Migration `0002_esig_audit_hashchain.sql` chains `esig_audit_log` per tenant
(SHA-256 linkage computed by a `BEFORE INSERT` trigger under an advisory lock)
and blocks UPDATE/DELETE/TRUNCATE even for `service_role`; existing rows are
backfilled. New `verifyAuditChain()` re-derives the chain client-side,
cross-checks each row's columns against its canonical payload, and fails loudly
when a server row cap truncates pages. The audit action CHECK now admits
`envelope.*` / `verify.*`. Vitest suite added and wired into root `npm test`.
Peer range widened to `@e-sig/core ^0.4.0 || ^0.5.0`.

### `@e-sig/react` 0.2.0 — VerifyPanel + honest consent evidence

New `VerifyPanel` component: verdict badge, structure/digest/signature rows,
signer and RFC-3161 timestamp details, failure list, and a fixed scope caveat
(embedded-cert validation, first signature only, no chain/revocation). Zero
dependency on core (structural `VerifyResult` mirror).

`SelfSignFlow` now POSTs `consent_given` plus the exact consent text it
rendered (`consent_text_shown`), so servers can record what the signer actually
saw instead of a hardcoded string. Servers should require these fields — the
example app's sign route now does.

## 0.4.0 — 2026-07-03

### `@e-sig/core` 0.4.0 — cryptographic hardening

Security- and correctness-focused release. Signature output changed (an extra
signed attribute is added and the signature is recomputed), so it is a minor
bump; previously-signed PDFs are unaffected and still verify.

**Verification is now cryptographic.** `verifyPdfStructure()` (aliased as the
clearer `verifyPdfSignature()`) no longer only checks byte-range structure — it
recomputes SHA-256 over the ByteRange-covered bytes and compares it to the
`messageDigest` signed attribute, then RSA-verifies the signature over the
signed attributes against the embedded signer certificate. `ok === true` now
means the signature is valid over the exact document; a single flipped byte
under the signature yields `ok:false` / `digestValid:false`. New result fields:
`digestValid`, `signatureValid`.

**PAdES / CAdES cert binding.** Every signature now carries the ESS
`signing-certificate-v2` signed attribute (RFC 5035), binding the signer
certificate into the signed data. New `padesStrict` option on `signPdf` /
`PemSigner` additionally drops the PAdES-forbidden `signing-time` attribute for
strict ETSI EN 319 142-1 **PAdES-B-B** conformance. Default mode is additive and
backward-compatible (keeps `signing-time`).

**Certificate hygiene.** Serial numbers are now 128 bits of CSPRNG entropy
(RFC 5280 §4.1.2.2) instead of `Date.now()`. The extended-key-usage no longer
claims `clientAuth` (TLS client, semantically wrong for document signing) — it
is `emailProtection` only, plus a Subject Key Identifier.

**Rendering.** `renderHtmlToPdf` now disables in-page JavaScript by default
(`javascriptEnabled` to opt back in) and waits for the `load` event (not
`domcontentloaded`) so embedded signature images and logos are present in the
PDF rather than occasionally blank. Added a `timeoutMs` option.

**Injection guard.** `renderSignatureBlocksHtml` (and the new exported
`assertImageDataUrl`) reject anything that is not a base64 image data URL before
interpolating it into the signed document, closing an attribute-breakout /
script-injection surface.

**Tests + CI.** Added a real Vitest suite (cert issuance, AES-GCM key wrapping,
sign→verify, tamper rejection, ESS attribute presence, strict-PAdES, data-URL
guard) run against the built package, plus a GitHub Actions workflow on Node
20/22. The Chrome-free smoke test now asserts the signature is valid and that a
tampered PDF is rejected.

### `@e-sig/supabase`

- Peer/dev dependency on `@e-sig/core` bumped to `^0.4.0`.
