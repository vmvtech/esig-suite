# Changelog

All notable changes to the `@e-sig/*` packages. This project follows
[Semantic Versioning](https://semver.org/). Dates are ISO-8601.

## 0.7.0 wave — published 2026-08-27

Ships everything in this section **and** the "0.7.0 — 2026-07-07" section
below in one publish: `@e-sig/core@0.7.0`, `@e-sig/supabase@0.3.1`,
`@e-sig/uuaid@0.1.1`, `@e-sig/uaid-exch@0.1.0-preview.1` (tag `preview`),
`@e-sig/worm@0.1.0`, `@e-sig/hsm-pkcs11@0.1.0`, and the new
`@e-sig/mcp@0.1.0`. `@e-sig/react@0.2.1` was already current.

### `@e-sig/mcp` 0.1.0: new package — agent-driven signing with human approval

An MCP server over `@e-sig/core` that lets an untrusted-by-default AI agent
ingest documents, create multi-signer envelopes, poll status, and verify
signed PDFs, while signing stays with humans via single-use tokenized links
in a built-in approval page. Signing tokens never cross MCP; link delivery
is an explicit operator channel (`ESIG_MCP_DELIVERY`: file outbox, opt-in
console, https webhook). Design and threat model:
`docs/architecture/esig-mcp.md`. RedTeam-reviewed before publish.

### `@e-sig/core`: fix signature-dictionary injection via `signPdf` options (security)

Reported by the UUAID lane on 2026-08-11, found while adversarially testing an
independent verifier against `@e-sig/core@0.6.0`. A caller of `signPdf` could
splice arbitrary keys into the PDF signature dictionary through its options —
including viewer-actionable ones such as `/OpenAction`. The resulting document
is *validly signed*: the signature genuinely covers the injected content, which
is what makes it dangerous. It matters wherever `signPdf` options are fed from
user or tenant input; a hardcoded call site was never exposed.

Root cause is `PDFObject.convert` in `@signpdf/utils` (inherited from pdfkit),
on two paths:

- **`subFilter`** was passed through as a JS string, which that converter emits
  as a raw unescaped PDF name (`/${value}`) — so whitespace or a delimiter in
  the value ends the `/SubFilter` token early and everything after it becomes
  sibling keys in the signature dictionary.
- **`reason` / `name` / `location` / `contactInfo`** (found while reproducing
  the above, and the more exposed of the two — these commonly come straight
  from a web form). The converter's dictionary branch emits *any* value whose
  string form contains `<<` completely raw — not converted, not escaped, not
  even wrapped in the PDF string parens.

Fixed in two layers:

- **`subFilter` is now validated against a closed set** — `ETSI.CAdES.detached`
  and `adbe.pkcs7.detached`, the only two this signer can actually produce.
  Exported as `SUPPORTED_SUBFILTERS` / the `SubFilter` type. The check is at
  runtime, not only in the types, because the attack surface is JS callers.
  Narrowing `subFilter?: string` to `subFilter?: SubFilter` is a compile-time
  breaking change for TS callers that pass a plain `string`.
- **The vendored serializer is hardened** (new
  `src/vendor/placeholder-plain/pdfObject.ts`, replacing `@signpdf/utils`'
  `PDFObject` at the one call site): the raw-splice branch is removed outright,
  and PDF names are escaped per ISO 32000-1 §7.3.5. This closes the class, not
  just the two reported paths. It is the only deliberate divergence from
  upstream in that vendored directory.

Output is **byte-identical to upstream for every legitimate input** — verified
on the real path by running `plainAddPlaceholder` through both converters over
the same PDF across 8 cases (both subfilters, unicode and paren-bearing string
fields, `appName`, `widgetRect`, large budget) and diffing bytes. Regression
coverage in `test/sig-dict-injection.test.ts`, which asserts the byte-identity
claim rather than assuming it.

### `@e-sig/core`: optional signer-asserted UUAID in the post-quantum seal

Enables IAASO-0004 (Media Provenance & Attribution) identity attribution for
e-sig-signed PDFs, at the request of the UUAID registry lane.

- **`buildPqSeal({ …, uuaid })` / `signPdf({ pqSeal: { …, uuaid } })`** embed an
  optional `uuaid` field in the seal's *signed* payload, so the assertion is
  bound under both Ed25519 and ML-DSA-65 and cannot be added to, removed from,
  or swapped on an existing seal. `signPdf` returns it as `pqUuaid`.
- **`verifyPqSeal` / `verifyDocument`** surface `verdict.uuaid` and accept
  `expectedUuaid` to pin it (mirroring `expectedMldsa65Fpr`). Pinning against a
  seal that asserts no UUAID fails — no silent downgrade.
- **Fail-closed on malformed claims.** `buildPqSeal` refuses to sign a
  structurally invalid identifier, and `verifyPqSealSignatures` rejects a seal
  carrying one (new `uuaidOk`, folded into `ok`) even when its signatures are
  intact. Validation is structural only — which subject classes and object types
  exist is UUAID's registry to evolve, not this package's to adjudicate.
  `isWellFormedUuaidAssertion` is exported as the wire contract.
- **Not a version bump of the seal.** `PQ_SEAL_VERSION` stays `1`: the field is
  omitted entirely unless supplied, so unattributed seals are byte-identical to
  pre-`uuaid` output, and verifiers that predate the field still verify
  uuaid-bearing seals (the signed payload is reconstructed generically as "the
  seal minus `sig`"). Bumping the version would have been the breaking change.
  Verified twice: 7/7 checks against **`@e-sig/core@0.6.0` installed from npm**
  (the current `latest`, and the version downstream verifiers pin) — it accepts
  attributed seals and PDFs, round-trips the field verbatim, and simply ignores
  it; plus 13/13 cross-version checks, both directions, against a local snapshot
  of the pre-`uuaid` 0.7.0 build (unpublished — 0.7.0 has never been released to
  npm).
- **Semantics — read before relying on it.** A valid `uuaid` proves the seal key
  *claims* that identity (key → uuaid). It does **not** prove the identity's
  owner authorised the document; the uuaid → key direction lives in the UUAID
  registry and is out of scope here. Unmatched, the assertion is worth no more
  than the TOFU fingerprint beside it.
- One additive break for consumers doing exact-shape assertions:
  `PqSealVerification` gained `uuaidOk`.

## 0.7.0 — 2026-07-07 (published 2026-08-27 as part of the wave above)

The "tech behind the add-ons" release: every self-serve vertical add-on now
ships real, tested capability — not a label and a price.

### Pre-publish hardening (2026-07-12)

Folded into 0.7.0 before its first npm publish:

- **`@e-sig/core`: zero-vulnerability consumer installs.** The
  `@signpdf/placeholder-plain` dependency (whose `placeholder-pdfkit010`
  transitive declares a `pdfkit@~0.10.0` peer that npm auto-installs, dragging
  in `crypto-js@3.3.0` with 6 critical advisories) is replaced by a vendored
  TypeScript port (`src/vendor/placeholder-plain/`, MIT, provenance headers +
  `LICENSE-signpdf.md`). Output proven byte-identical to upstream across 12
  input×option combinations, including the already-signed incremental path.
  `npm install @e-sig/core` now audits clean: 0 vulnerabilities.
- **`@e-sig/core`: portable Chrome discovery.** `renderHtmlToPdf` honors
  `ESIG_CHROME_PATH` / `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH`, scans
  common Chrome/Chromium/Edge/Brave locations on macOS/Linux/Windows, fails
  loud when an env var points at a non-executable, and the not-found error
  lists every path tried plus the override options.
- **`@e-sig/core`: deterministic PQ key provisioning.**
  `generatePqKeyBundle({ mldsa65Seed, ed25519Pkcs8 })` derives the hybrid
  bundle from caller-supplied key material (same seed → same identity);
  omitted fields stay random. Input validation on seed length and key type.
- **`@e-sig/uaid-exch`: ships its LICENSE.** The package directory was missing
  the LICENSE file that `files` referenced, so the tarball published without
  license text.
- Repo hygiene: workspace devDependencies on `@e-sig/core` pinned to `^0.7.0`
  (stale `^0.6.0` pins nested old registry copies of core — and their pdfkit
  chain — under `packages/*/node_modules`); `esig-uuaid` moved to vitest 4;
  the root `crypto-js` override is gone (nothing pulls crypto-js anymore).
  Root `npm audit`: 0 vulnerabilities.

### `@e-sig/core` 0.7.0 — ExternalSigner (HSM seam)

**`ExternalSigner`.** `signPdf` / `PemSigner` accept `{ externalSigner }` as an
alternative to `keyPem`: `{ keyType, certificatePem, signRsaSha256(data) }`.
The RSA private key never has to enter process memory — signatures are
delegated to hardware (HSM, PKCS#11 token, KMS). Sync or async signers both
work; output is byte-identical to the in-memory path (proven by test). Existing
callers are unaffected — `keyPem` behaves exactly as before (87 pre-existing
tests unchanged, 7 new).

### `@e-sig/hsm-pkcs11` 0.1.0 — NEW (HSM Signer add-on)

`Pkcs11Signer` implements `ExternalSigner` over an injected PKCS#11 session
(CKM_SHA256_RSA_PKCS), fail-closed on login failure / missing key / wrong-size
signatures; fresh session per signature. `pkcs11js` is an optional peer — wire
AWS CloudHSM / YubiHSM / SoftHSM per the README.

### `@e-sig/worm` 0.1.0 — NEW (WORM Archival add-on)

`WormPdfStorageStore` (a core `PdfStorageStore`) writes every object with S3
Object Lock retention set atomically (default COMPLIANCE / 7 years) and a
conditional create (`IfNoneMatch: "*"`) so overwrite is rejected by the store
AND by S3; there is no delete surface. `exportAuditRowsToWorm` snapshots the
tenant audit chain as deterministic NDJSON into the same locked bucket.
Includes a provisioning script and SEC 17a-4 / FINRA framing docs.

### `@e-sig/uaid-exch` 0.1.0-preview.1 — revocation lists

UAP-EXCH-1 § 9 (draft): `createRevocationList` / `revokeCredential`
(append-only, JCS-canonical sha256 digest, idempotent) /
`verifyRevocationListIntegrity` / `assertCredentialUsable`. Fail-closed
everywhere: tampered lists throw on lookup, unparseable validity dates reject,
expiry + revocation both gate use. 14 new tests (26 total in the package).

### `@e-sig/uuaid` 0.1.1 · `@e-sig/supabase` 0.3.1

Peer ranges widened to allow `@e-sig/core` `^0.7.0`; no code changes.

### Compliance packs (repo `docs/compliance/`, ship with paid add-ons)

HIPAA: BAA template (45 CFR 164.504(e)) + healthcare operations runbook.
21 CFR Part 11: clause-by-clause requirements mapping (§ 11.10–11.300 → real
product controls, with an honest customer-responsibility column) + IQ/OQ/PQ
validation protocol templates. All marked DRAFT pending counsel review.

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
