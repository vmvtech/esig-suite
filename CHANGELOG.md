# Changelog

All notable changes to the `@e-sig/*` packages. This project follows
[Semantic Versioning](https://semver.org/). Dates are ISO-8601.

## [Unreleased]

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
