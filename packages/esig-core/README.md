# `@e-sig/core` — Portable In-Platform E-Signature

> Self-contained PKCS#7 PDF signing — no SaaS, no metering, no per-doc fees.
> Battle-tested in production at [opendelphi.org](https://opendelphi.org).

```sh
npm i @e-sig/core
```

Crypto + rendering primitives for real, cryptographic PDF signing: no key-custody service, no per-signature metering, no third-party processor in the middle. You bring persistence, UI, and auth; this library gives you the actual signing math.

## Requirements

- **Node.js >= 20**, ESM (`"type": "module"`).
- **Chrome/Chromium is needed ONLY for `renderHtmlToPdf`** (HTML → PDF rendering). If you already have PDFs to sign — from a form library, an existing document, wherever — you never need Chrome at all; see the quickstart below. When you do render HTML, point at a binary with `ESIG_CHROME_PATH`, `PUPPETEER_EXECUTABLE_PATH`, or `CHROME_PATH` (checked in that order — [`src/render-pdf.ts`](https://github.com/vmvtech/esig-suite/blob/main/packages/esig-core/src/render-pdf.ts)), or let it auto-detect a system install. On AWS Lambda or Vercel it uses the optional peer dependency `@sparticuz/chromium` instead.
- Everything else — cert issuance, PKCS#7/PAdES signing, verification, the post-quantum seal, envelopes — is pure Node/crypto with no browser dependency.

## What it does

Given a PDF (or HTML you render to one) and a person who wants to sign it, this library: (1) generates or reuses a self-signed RSA-2048 X.509 cert for the signing tenant; (2) embeds a PKCS#7 detached signature under the **ETSI.CAdES.detached** subfilter, with the ESS **signing-certificate-v2** attribute binding the signer cert into the signed data (`padesStrict: true` for strict **PAdES B-B**); (3) produces a PDF that opens cleanly in Preview / Adobe Reader with a valid signature panel — any post-signing edit invalidates the signature, and `verifyPdfSignature()` checks that cryptographically (recomputes the digest over the signed ByteRange and RSA-verifies the signature); (4) *optionally* renders HTML to that starting PDF for you (headless Chromium via `puppeteer-core`, scripting disabled by default — see [Requirements](#requirements)); (5) *optionally* adds a **post-quantum hybrid seal** — **Ed25519 + ML-DSA-65 (FIPS 204)** — embedded under the classical signature so the PDF stays Acrobat-valid while gaining quantum resistance (see [Post-quantum seal](#post-quantum-seal--ml-dsa-65-fips-204)).

> **Trust vs. validity.** The signature is cryptographically *valid*, but the cert is *self-issued* — stock Adobe Reader shows "validity unknown" until the cert is trusted (org trust-store import, or plug in an AATL/CA signer). This verifies the signature math and integrity, not third-party trust. See the compliance notes below.

~600 lines of TypeScript, zero runtime dependency on Supabase, Next.js, or any SaaS.

## What it does NOT do

By design — these are wrapper concerns:

- **Storage of the signed PDF.** You decide where (S3, local disk, Supabase Storage, …).
- **Auth / authorization.** You decide who's allowed to sign.
- **UI.** You build the signature-capture surface (or use [`@e-sig/mcp`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-mcp), which ships one for agent-driven workflows).
- **Persistence of the cert pool.** Implement the `CertStore` adapter interface (or use `@e-sig/core/fs` for a zero-dependency filesystem-backed one).
- **Audit logging.** Implement the `AuditLogStore` adapter interface.

## Quickstart — sign, verify, tamper-check (no Chrome needed)

The whole pipeline over an existing PDF, adapted from [`examples/quickstart/index.mjs`](https://github.com/vmvtech/esig-suite/blob/main/examples/quickstart/index.mjs) (runnable as-is: `npm install && npm start` in that directory):

```ts
import { readFile, writeFile } from "node:fs/promises";
import { generateSelfSignedCert, signPdf, verifyPdfSignature } from "@e-sig/core";

// 1. Issue a certificate. Self-issued certs are their own trust root — fine for
//    org-internal signing; swap in a CA-issued PEM pair for public trust.
const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });

// 2. Sign. signPdf injects the signature placeholder itself — any well-formed
//    PDF works as input, however you got it (no rendering step, no Chrome).
const unsigned = await readFile("./contract.pdf");
const { signedPdf } = await signPdf({
  pdf: unsigned, keyPem: cert.keyPem, certPem: cert.certPem,
  reason: "Agreed to terms", location: "", contactInfo: "",
  name: "Ada Lovelace", signingTime: new Date(),
});
await writeFile("./signed.pdf", signedPdf);

// 3. Verify. ok:true means the signature is cryptographically valid over these
//    exact bytes: ByteRange structure + SHA-256 digest + RSA signature.
const v = verifyPdfSignature(signedPdf);
console.log(v.ok, v.digestValid, v.signatureValid, v.signerCommonName);
// → true true true "E-sig (Acme Inc)"

// 4. Tamper: flip a single byte inside the signed region → must be rejected.
const tampered = Buffer.from(signedPdf);
tampered[v.byteRange[0] + 64] ^= 0xff;
console.log(verifyPdfSignature(tampered).ok); // → false
```

Open `signed.pdf` in Preview — signature panel shows valid (self-signed).

### Rendering HTML into a PDF (needs Chrome)

If you're starting from HTML rather than an existing PDF, render it first — the one step that needs a real Chrome/Chromium (see [Requirements](#requirements)):

```ts
import { generateSelfSignedCert, renderHtmlToPdf, signPdf } from "@e-sig/core";

const cert = generateSelfSignedCert({ subjectName: "Acme Corp" });
const unsigned = await renderHtmlToPdf({ html: "<h1>Service Agreement</h1><p>Signed by Jane Doe.</p>" });
const { signedPdf } = await signPdf({
  pdf: unsigned, keyPem: cert.keyPem, certPem: cert.certPem,
  reason: "Service Agreement acceptance", location: "https://acme.example",
  contactInfo: "jane@example.com", name: "Jane Doe",
});
```

Everything downstream (verify, post-quantum seal, envelopes) is identical either way — `signPdf` doesn't care whether the input PDF came from `renderHtmlToPdf`, a form library, or a file someone uploaded.

## RFC 3161 trusted timestamps (CAdES-T)

Pass a `tsa` transport to `signPdf` to embed an RFC 3161 TimeStampToken, upgrading the signature from CAdES-B to CAdES-T. The token is added as the `id-aa-timeStampToken` unsigned attribute (OID `1.2.840.113549.1.9.16.2.14`) computed over the SignerInfo signatureValue (RFC 3161 §2.4.1). The package performs **no network egress** — you inject the POST so the package stays dependency-free — and the TSA only ever receives a **SHA-256 hash**, never the document or any PHI:

```ts
import type { TsaTransport } from "@e-sig/core";

const tsa: TsaTransport = {
  required: false, // false = degrade to CAdES-B on TSA failure; true = throw
  fetch: async (reqDerBytes) => {
    const res = await fetch("http://timestamp.digicert.com", {
      method: "POST", headers: { "Content-Type": "application/timestamp-query" }, body: reqDerBytes,
    });
    return new Uint8Array(await res.arrayBuffer());
  },
};

const { signedPdf, timestamped, tsaError } = await signPdf({
  pdf, keyPem, certPem, reason: "DUA acceptance", location: "opendelphi.org",
  contactInfo: "legal@acme.org", name: "Acme Research Institute", tsa,
});

const v = verifyPdfStructure(signedPdf);
// v.timestamped, v.timestampTime (ISO), v.tsaCommonName; v.ok is false if the
// §2.4.2 binding check fails (imprint != sha256(sigValue))
```

Notes: when `tsa` is supplied and `signatureLength` is omitted, the `/Contents` placeholder budget defaults to **30720** (vs `8192` without a TSA) to fit the TimeStampToken plus its certificate chain — an overflow is rejected, never silently truncated. With `required: false` (default), a TSA error produces a valid CAdES-B signature and sets `tsaError`; with `required: true` the error is rethrown. Verification enforces the RFC 3161 §2.4.2 binding: the token's `messageImprint` must equal `sha256(SignerInfo.signature)`, else `ok:false`.

See [`CONSUMING.md`](https://github.com/vmvtech/esig-suite/blob/main/packages/esig-core/CONSUMING.md) for the full consumer guide.

## Post-quantum seal — ML-DSA-65 (FIPS 204)

Harvest-now-decrypt-later is a real threat to long-lived signed documents: a signature that is only RSA/ECDSA today is forgeable the day a cryptographically relevant quantum computer exists. `@e-sig/core` can add a **hybrid post-quantum seal** — **Ed25519 + ML-DSA-65** (the FIPS 204 module-lattice signature, née Dilithium) — to any signed PDF, without giving up compatibility.

**How it stays compatible:** the seal does **not** replace the PKCS#7/PAdES RSA signature (no mainstream PDF reader validates ML-DSA in PAdES yet). It's embedded *first*, as an append-only incremental update, and the classical RSA signature is applied on top — so it **cryptographically covers the seal**. Adobe Acrobat still shows a valid signature; your verifier additionally confirms the quantum-resistant layer. This is the hybrid migration path NIST/CNSA 2.0 recommend over a hard cutover.

```ts
import { generateSelfSignedCert, generatePqKeyBundle, loadPqSigningKeys, signPdf, verifyDocument } from "@e-sig/core";

const cert = generateSelfSignedCert({ subjectName: "Acme Corp" });
// One hybrid key bundle per signer/tenant (persist wrapPqKeyBundle(...) at
// rest; or use ensureActivePqKeys with a PqKeyStore — see below).
const pqKeys = loadPqSigningKeys(generatePqKeyBundle().bundle);

const { signedPdf } = await signPdf({
  pdf: unsigned, keyPem: cert.keyPem, certPem: cert.certPem,
  reason: "Service Agreement acceptance", location: "", contactInfo: "jane@example.com",
  name: "Jane Doe", pqSeal: { keys: pqKeys },   // ← adds the post-quantum seal
});

// One call, two verdicts:
const v = verifyDocument(signedPdf);
console.log("classical (PAdES/RSA):", v.classical.ok);      // → true (Acrobat-grade)
console.log("post-quantum (ML-DSA-65):", v.postQuantum.ok); // → true
// v.ok === true only when BOTH layers verify AND the seal lies inside the
// RSA-signed region. Tampering with one byte of the document fails BOTH.
```

**Managed keys.** `ensureActivePqKeys({ store, tenantId, passphrase })` mints + wraps a bundle on first use and reuses it thereafter (implement the small `PqKeyStore` interface against your DB, same pattern as `CertStore`); `rotatePqKeys(...)` rolls to a fresh key while old documents keep verifying against the public key embedded in each seal. `signDocument({ pq: { keys } })` threads it through the end-to-end orchestrator and records the PQ key id + fingerprint in the audit row.

**Trust model (v1).** The seal carries the raw ML-DSA-65 public key + its SHA-256 fingerprint; a relying party pins/publishes the expected fingerprint (TOFU). Assert it in-band with `verifyDocument(signedPdf, { expectedMldsa65Fpr: "<published fingerprint>", requirePq: true })` — `requirePq` rejects a document with no seal at all (no silent downgrade).

**X.509 identity (RFC 9881).** For an enterprise-shaped identity, `issueMlDsaCertificate({ keys, subjectName })` issues a self-signed **ML-DSA-65 X.509 certificate** (OID `2.16.840.1.101.3.4.3.18`, SubjectPublicKeyInfo *and* signature both ML-DSA-65 — parses/verifies in OpenSSL 3.5+). Bind it at verify time with `verifyDocument(signedPdf, { signerCert: cert.certPem })` — fails unless the cert is valid AND owns the seal's key. `verifyMlDsaCertificate()` checks the self-signature/algorithm/validity window standalone; `certMatchesPqSeal()` ties a cert to a seal by fingerprint. Both seal signatures are required — either Ed25519 or ML-DSA-65 failing (or a fingerprint/keyId mismatch) fails the whole seal.

## Multi-signer envelopes + tokenized signing links

For a multi-party flow — draft once, N people sign in order, one final seal — `createEnvelope`/`resolveSigningToken`/`recordSignature`/`composeEnvelopeHtml` give you the storage-agnostic state machine `@e-sig/mcp` is built on:

```ts
import { createEnvelope, resolveSigningToken, recordSignature, composeEnvelopeHtml } from "@e-sig/core";

// Mints one 32-byte CSPRNG token per signer, returned ONCE — only its
// SHA-256 hash is persisted, so a leaked store can't forge a signing link.
const { envelope, signingTokens } = await createEnvelope({
  store, // your EnvelopeStore implementation (or @e-sig/core/fs's FsEnvelopeStore)
  tenantId: "acme-corp", title: "Consulting Agreement", html: "<p>Terms…</p>",
  signers: [
    { name: "Alice", email: "alice@example.com", order: 1 },
    { name: "Bob", email: "bob@example.com", order: 2 }, // gated until Alice signs
  ],
});
// Deliver signingTokens[i].token to each signer out-of-band — it can't be recovered.

// On the signing surface, per token:
const resolution = await resolveSigningToken({ store, token }); // ok | not_your_turn | already_signed | completed | voided | expired | invalid
const signed = await recordSignature({ store, token, signatureImageDataUrl }); // auto-completes on the last signer

// Once `signed.status === "completed"`: compose the final HTML (base + every
// signer's block) and seal it however you seal a single PDF — renderHtmlToPdf
// → signPdf → your PdfStorageStore.
const composed = composeEnvelopeHtml(signed, { platformLabel: "Your App" });
```

`declineEnvelope`/`voidEnvelope` cover the two ways an envelope ends without completing. Implement `EnvelopeStore` against your DB, or use `@e-sig/core/fs`'s `FsEnvelopeStore` (single-process only — see its own header comment).

## Persisting certs + audit logs across requests

For real usage you need to cache certs per tenant (don't regenerate on every sign), encrypt private keys at rest (a DB leak shouldn't compromise signing authority), and log every sign (ESIGN / UETA / 21 CFR §11 compliance evidence). The library provides adapter **interfaces** — `CertStore`, `AuditLogStore`, `PdfStorageStore`, `EnvelopeStore`, `PqKeyStore` (exported from `@e-sig/core`, defined in [`src/adapters.ts`](https://github.com/vmvtech/esig-suite/blob/main/packages/esig-core/src/adapters.ts) and [`src/envelope.ts`](https://github.com/vmvtech/esig-suite/blob/main/packages/esig-core/src/envelope.ts)) — implement them against your DB, or import the zero-dependency filesystem-backed ones from `@e-sig/core/fs`.

A reference Supabase implementation ships as [`@e-sig/supabase`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-supabase) — cert store, audit store (hash-chained, tamper-evident), and PQ key store, against the schema in [`migrations/0001_esig_self_contained.sql`](https://github.com/vmvtech/esig-suite/blob/main/migrations/0001_esig_self_contained.sql).

```ts
interface CertStore {
  findActive(tenantId: string): Promise<StoredCert | null>;
  insert(input: { tenantId; generated; keyPemEncrypted; rotatedFromId? }): Promise<StoredCert>;
  deactivate(id: string): Promise<void>;
  findExpiring(withinDays: number): Promise<StoredCert[]>;
}
interface AuditLogStore {
  insert(entry: AuditLogEntry): Promise<AuditLogRow>;
}
```

`ensureActiveCert` is the get-or-create wrapper around your `CertStore` — mints on first use, reuses thereafter:

```ts
const result = await ensureActiveCert({
  store: new YourCertStore(...), tenantId: "acme-corp",
  subjectName: "Acme Corp", passphrase: process.env.ESIG_CERT_PASSPHRASE!,
});
// result.certPem + result.keyPem ready to feed into signPdf()
```

## Compliance posture

The production pipeline this library was extracted from uses it for HIPAA-bound Data Use Agreements and is mapped against **ESIGN Act § 7001 (R1–R5)** — Intent, Consent to electronic, Attribution, Integrity, Retention (R4 Integrity is fully covered by the crypto core; R1/R2/R3/R5 are wrapper concerns) — **UETA § 9 + § 13** (Attribution + system attribution log), and **21 CFR § 11.50 / § 11.70** (FDA-grade requirements where applicable).

**Not legal advice.** Talk to your lawyer about whether this satisfies the regulatory framework for your specific use case.

## Background — why this exists

**Why not DocuSign / DocuSeal / Documenso?** Per-document metering (~$0.20/sig) made the unit economics painful at scale, and every signed PDF flowed through a third-party processor — making HIPAA + GDPR compliance harder than it had to be. This library is what you reach for when "no SaaS, no metering, no fees" is a hard requirement.

**Why not `pdf-lib`?** It hasn't shipped a release since 2021. This core drives `puppeteer-core` for rendering and `@signpdf` + `node-forge` for signing instead, both actively maintained.

**Why not PKCS#12?** `node-forge.pkcs12.toPkcs12Asn1` produces P12 bundles whose MAC neither node-forge nor openssl can verify (a long-standing BMPString-password-derivation bug) — bypassed entirely; the `PemSigner` takes raw PEM and drives `forge.pkcs7` directly.

**Bugs we hit so you don't have to:** ASCII-only cert subject names (`forge.pki.certificateFromPem` mis-counts bytes for non-ASCII, breaking PEM round-trip); `@signpdf/signpdf` v3's ESM default import is opaque — use the named export (`import { SignPdf } from "@signpdf/signpdf"`); store key + cert as separate PEM files/DB columns, not one multi-block file (`certificateFromPem` doesn't round-trip a re-encoded block from one).

## Performance

End-to-end on Vercel Lambda cold start, in production: render HTML → PDF ~2.5 s (cold) / ~0.5 s (warm), first-sign cert generation ~0.8 s (RSA-2048 keygen dominates), PKCS#7 sign ~0.1 s, upload + audit + DB row flip ~0.3 s — **~4.5 s total cold-start round-trip**, ~1–1.5 s warm with a cached cert. Skipping `renderHtmlToPdf` (signing an already-existing PDF, the quickstart above) skips the render line item entirely.

## License

License: MIT. Copyright (c) 2026 VMVTech, Ltd.

## Acknowledgments

[@signpdf](https://github.com/vbuch/node-signpdf) for the PKCS#7 placeholder + signing infrastructure; [node-forge](https://github.com/digitalbazaar/forge) for the X.509 + PKCS#7 + crypto primitives; [Documenso](https://github.com/documenso/documenso) + [DocuSeal CE](https://github.com/docusealco/docuseal) as reference implementations (read-only — no code copied).
