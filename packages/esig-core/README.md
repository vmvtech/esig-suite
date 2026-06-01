# `@opendelphi/esig-core` — Portable In-Platform E-Signature

> Self-contained PKCS#7 PDF signing — no SaaS, no metering, no per-doc fees.
> Battle-tested in production at [opendelphi.org](https://opendelphi.org).

This directory is the **portable core** of the Opendelphi e-signature pipeline. Drop it (plus a tiny adapter you write) into any TypeScript / Node.js project to add real cryptographic signing of PDFs.

---

## What it does

Given an HTML document and a person who wants to sign it, this library:

1. Renders the HTML to a PDF (headless Chromium via `puppeteer-core`).
2. Generates or reuses a self-signed RSA-2048 X.509 cert for the signing tenant.
3. Embeds a PKCS#7 detached signature into the PDF using the modern **ETSI.CAdES.detached** subfilter (PAdES B-B baseline).
4. Produces a PDF that opens cleanly in Preview / Adobe Reader with a valid signature panel — any post-signing edit invalidates the signature.

That's the **whole thing**. It's ~600 lines of TypeScript with zero runtime dependencies on Supabase, Next.js, or any SaaS.

---

## What it does NOT do

By design — these are wrapper concerns:

- **Storage of the signed PDF.** You decide where (S3, local disk, Supabase Storage, …).
- **Auth / authorization.** You decide who's allowed to sign.
- **UI.** You build the signature-capture surface.
- **Persistence of the cert pool.** Implement the `CertStore` adapter interface.
- **Audit logging.** Implement the `AuditLogStore` adapter interface.

The library gives you **crypto + rendering**. You bring **persistence + UI + auth**.

---

## Files

| File | Purpose | Project-agnostic? |
|---|---|---|
| `pem-signer.ts` | Custom `@signpdf` `Signer` driven by raw PEM key+cert (bypasses node-forge's broken P12 round-trip — see Background below) | ✅ |
| `cert-issuer.ts` | Generate self-signed RSA-2048 X.509; AES-256-GCM-wrap private keys for at-rest storage | ✅ |
| `render-pdf.ts` | HTML → PDF via puppeteer-core; auto-detects Lambda vs local Chrome | ✅ |
| `sign-pdf.ts` | Combine placeholder injection + PKCS#7 sign (ETSI.CAdES) | ✅ |
| `verify-pdf.ts` | Structural verifier (parses /ByteRange + PKCS#7 blob, returns diagnostics) | ✅ |
| `signature-block.ts` | HTML helper to render N signature blocks for multi-party flows | ✅ |
| `types.ts` | Shared TS types (`Signer`, `SigningCertPem`, …) | ✅ |
| `index.ts` | Public re-export barrel | ✅ |

---

## Install

```sh
npm install \
  @signpdf/signpdf \
  @signpdf/utils \
  @signpdf/placeholder-plain \
  node-forge \
  puppeteer-core \
  @sparticuz/chromium  # only on Lambda; skip for local-only
```

Plus `@types/node-forge` if you're using TypeScript.

If you're on Next.js, you MUST externalize the binary-adjacent packages in `next.config.ts`:

```ts
const nextConfig = {
  serverExternalPackages: [
    "@sparticuz/chromium",
    "puppeteer-core",
    "node-forge",
    "@signpdf/signpdf",
    "@signpdf/utils",
    "@signpdf/placeholder-plain",
  ],
  // The chromium binary tarball is a static asset; tell file-tracing to
  // include it in your e-sig route's bundle.
  outputFileTracingIncludes: {
    "/api/your-esig-route": [
      "./node_modules/@sparticuz/chromium/bin/**",
    ],
  },
};
```

---

## 30-second example

```ts
import {
  generateSelfSignedCert,
  renderHtmlToPdf,
  signPdf,
  verifyPdfStructure,
} from "./core";

// 1. Issue a one-off cert (in real life, persist + reuse).
const cert = generateSelfSignedCert({ subjectName: "Acme Corp" });

// 2. Render HTML → unsigned PDF.
const unsigned = await renderHtmlToPdf({
  html: `<h1>Service Agreement</h1><p>Signed by Jane Doe at ${new Date().toISOString()}.</p>`,
});

// 3. Sign it.
const { signedPdf } = await signPdf({
  pdf: unsigned,
  keyPem: cert.keyPem,
  certPem: cert.certPem,
  reason: "Service Agreement acceptance",
  location: "https://acme.example",
  contactInfo: "jane@example.com",
  name: "Jane Doe",
});

// 4. Verify the result (optional — sanity-check before persistence).
const verify = verifyPdfStructure(signedPdf);
console.log(verify.ok, verify.signerCommonName);
// → true, "E-sig (Acme Corp)"

// 5. Persist + serve. Up to you.
require("fs").writeFileSync("./signed.pdf", signedPdf);
```

That's it. Open `signed.pdf` in Preview — signature panel shows valid (self-signed).

---

## RFC 3161 trusted timestamps (CAdES-T)

Pass a `tsa` transport to `signPdf` to embed an RFC 3161 TimeStampToken,
upgrading the signature from CAdES-B to CAdES-T. The token is added as the
`id-aa-timeStampToken` unsigned attribute (OID `1.2.840.113549.1.9.16.2.14`)
computed over the SignerInfo signatureValue (RFC 3161 §2.4.1).

The package performs **no network egress** — you inject the POST so the package
stays dependency-free. The TSA only ever receives a **SHA-256 hash**, never the
document or any PHI:

```ts
import type { TsaTransport } from "@vmvtech/esig-core";

const tsa: TsaTransport = {
  required: false, // false = degrade to CAdES-B on TSA failure; true = throw
  fetch: async (reqDerBytes) => {
    const res = await fetch("http://timestamp.digicert.com", {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: reqDerBytes,
    });
    return new Uint8Array(await res.arrayBuffer());
  },
};

const { signedPdf, timestamped, tsaError } = await signPdf({
  pdf, keyPem, certPem,
  reason: "DUA acceptance", location: "opendelphi.org",
  contactInfo: "legal@acme.org", name: "Acme Research Institute",
  tsa,
});

const v = verifyPdfStructure(signedPdf);
// v.timestamped, v.timestampTime (ISO), v.tsaCommonName
// v.ok is false if the §2.4.2 binding check fails (imprint != sha256(sigValue))
```

Notes:

- **Budget**: when `tsa` is supplied and `signatureLength` is omitted, the
  `/Contents` placeholder budget defaults to **30720** (vs `8192` without a TSA)
  to fit the TimeStampToken plus the TSA certificate chain. An overflow is
  rejected, never silently truncated.
- **Degradation**: with `required: false` (default), a TSA error produces a
  valid CAdES-B signature and sets `tsaError`; with `required: true` the error
  is rethrown.
- **Verification** enforces the RFC 3161 §2.4.2 binding: the token's
  `messageImprint` must equal `sha256(SignerInfo.signature)`, else `ok:false`.

See `CONSUMING.md` for the full consumer guide.

---

## Persisting certs + audit logs across requests

For real usage you need to:
- **Cache certs per tenant** so you don't regenerate on every sign.
- **Encrypt private keys at rest** so a DB leak doesn't compromise signing authority.
- **Log every sign** for ESIGN / UETA / 21 CFR §11 compliance evidence.

The library provides adapter **interfaces** (`CertStore`, `AuditLogStore` — see `../adapters/types.ts`). Implement them against your DB.

A reference Supabase implementation lives at `../adapters/supabase.ts` (~150 lines). It works against any schema with these two tables — copy the migration from `supabase/migrations/00106_esig_self_contained.sql` for the canonical shape, or write your own.

### CertStore interface

```ts
interface CertStore {
  findActive(tenantId: string): Promise<StoredCert | null>;
  insert(input: { tenantId; generated; keyPemEncrypted; rotatedFromId? }): Promise<StoredCert>;
  deactivate(id: string): Promise<void>;
  findExpiring(withinDays: number): Promise<StoredCert[]>;
}
```

### AuditLogStore interface

```ts
interface AuditLogStore {
  insert(entry: AuditLogEntry): Promise<AuditLogRow>;
}
```

Then use the convenience helper `ensureActiveCert` from `../adapters/supabase.ts` as a template:

```ts
const result = await ensureActiveCert({
  store: new YourCertStore(...),
  tenantId: "acme-corp",
  subjectName: "Acme Corp",
  passphrase: process.env.ESIG_CERT_PASSPHRASE!,
});
// result.certPem + result.keyPem ready to feed into signPdf()
```

---

## Compliance posture

The Opendelphi production wire-up uses this library for HIPAA-bound Data Use Agreements and is mapped against:

- **ESIGN Act § 7001 (R1–R5)** — Intent, Consent to electronic, Attribution, Integrity, Retention. R4 Integrity is fully covered by the crypto core; R1/R2/R3/R5 are wrapper concerns.
- **UETA § 9 + § 13** — Attribution + system attribution log.
- **21 CFR § 11.50 / § 11.70** — FDA-grade requirements where applicable.

See `.planning/phases/19-esig-primitives-spike/19-04-ESIGN-GAPS.md` for the full mapping.

**Not legal advice.** Talk to your lawyer about whether this satisfies the regulatory framework for your specific use case.

---

## Background — why this exists

### Why not DocuSign / DocuSeal / Documenso?

Per-document metering (~$0.20/sig) made the unit economics painful at scale. And every signed PDF flowed through a third-party processor — making HIPAA + GDPR compliance harder than it had to be.

This library is what you reach for when "no SaaS, no metering, no fees" is a hard requirement.

### Why not `pdf-lib`?

[`pdf-lib`](https://github.com/Hopding/pdf-lib) is the most popular Node PDF library, but it hasn't shipped a release since 2021. Documenso uses [`@libpdf/core`](https://github.com/libpdf/libpdf) instead — same conclusion here. (Neither is actually used by this core — we drive `puppeteer` for rendering and `@signpdf` + `node-forge` for signing, both actively maintained.)

### Why not PKCS#12?

We tried. `node-forge.pkcs12.toPkcs12Asn1` produces P12 bundles whose MAC neither node-forge **nor openssl** can verify. Looks like a long-standing BMPString-password-derivation bug. We bypass it entirely — the PemSigner takes raw PEM and drives `forge.pkcs7` directly.

### Bugs to avoid (we hit these so you don't have to)

1. **Don't use `node-forge.pkcs12.toPkcs12Asn1`** — see above.
2. **ASCII-only cert subject names** — `forge.pki.certificateFromPem` mis-counts bytes for non-ASCII (em-dash in OU breaks PEM round-trip with "Too few bytes to parse DER").
3. **`@signpdf/signpdf` v3 ESM default import is opaque** — use the named export: `import { SignPdf } from "@signpdf/signpdf"` and `new SignPdf().sign(...)`.
4. **`@sparticuz/chromium` is Lambda-only** — locally, use system Chrome via the `executablePath` override.
5. **Storing key + cert in one PEM file is fragile** — `forge.pem.decode` extracts blocks correctly, but re-encoding the cert block from a multi-block buffer doesn't survive `certificateFromPem` round-trip. Store them as separate files / DB columns.

---

## Performance

End-to-end on Vercel Lambda (cold start), tested against [opendelphi.org](https://opendelphi.org/api/esig/dua-self-sign) in production:

- Render HTML → unsigned PDF: ~2.5 s (cold) / ~0.5 s (warm)
- Generate cert (first sign per tenant): ~0.8 s (RSA-2048 keygen dominates)
- PKCS#7 sign: ~0.1 s
- Upload + audit + DB row flip: ~0.3 s
- **Total cold-start round-trip: ~4.5 s**

Subsequent signs reuse the cached cert → ~1–1.5 s warm.

---

## License

Same as the parent project. The `core/` directory is intentionally self-contained so it can be vendored under your own license.

---

## Acknowledgments

- **[@signpdf](https://github.com/vbuch/node-signpdf)** for the PKCS#7 placeholder + signing infrastructure.
- **[node-forge](https://github.com/digitalbazaar/forge)** for the X.509 + PKCS#7 + crypto primitives.
- **[Documenso](https://github.com/documenso/documenso)** + **[DocuSeal CE](https://github.com/docusealco/docuseal)** as reference implementations (read-only — no code copied — see `.planning/phases/19-esig-primitives-spike/19-02-PATTERNS-OBSERVED.md` for the lessons borrowed).
