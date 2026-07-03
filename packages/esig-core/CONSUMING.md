# Consuming `@e-sig/core`

How to install and use this package in another project. It is a self-contained,
dependency-light PKCS#7 PDF signing core — no SaaS, no metering, no per-document
fees — extracted from the Opendelphi production e-signature pipeline.

## Install

Published to the public npm registry — no auth or registry config needed:

```sh
npm install @e-sig/core
```

Runtime requirements: Node ≥ 20, ESM. The only crypto dependencies are
`node-forge` and the `@signpdf/*` packages (declared as dependencies).
`@sparticuz/chromium` is an optional peer (only needed for `renderHtmlToPdf` on
Lambda/Vercel).

## Minimal sign + verify

```ts
import { generateSelfSignedCert, signPdf, verifyPdfStructure } from "@e-sig/core";

const { keyPem, certPem } = generateSelfSignedCert({ subjectName: "Acme" });
const { signedPdf } = await signPdf({
  pdf, keyPem, certPem,
  reason: "Agreement", location: "example.org",
  contactInfo: "legal@acme.org", name: "Acme",
});
const v = verifyPdfStructure(signedPdf); // { ok, signerCommonName, ... }
```

## RFC 3161 trusted timestamps (CAdES-T)

Pass a `tsa` transport to upgrade the signature from CAdES-B to CAdES-T by
embedding an RFC 3161 TimeStampToken (`id-aa-timeStampToken`,
OID `1.2.840.113549.1.9.16.2.14`) over the SignerInfo signatureValue.

**The consumer injects the network POST.** The package never performs egress
itself, which keeps it dependency-free and keeps egress under your control. The
TSA only ever receives a **SHA-256 hash** — never the document, never any PHI.

```ts
import type { TsaTransport } from "@e-sig/core";

const tsa: TsaTransport = {
  required: false, // false → degrade to CAdES-B on failure; true → throw
  fetch: async (reqDerBytes) => {
    const res = await fetch("http://timestamp.digicert.com", {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: reqDerBytes,
    });
    if (!res.ok) throw new Error(`TSA HTTP ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  },
};

const { signedPdf, timestamped, tsaError } = await signPdf({
  pdf, keyPem, certPem,
  reason: "Agreement", location: "example.org",
  contactInfo: "legal@acme.org", name: "Acme",
  tsa,
});

const v = verifyPdfStructure(signedPdf);
// v.timestamped, v.timestampTime (ISO 8601), v.tsaCommonName
```

### What you need to know

- **Placeholder budget.** When `tsa` is provided and you do not set
  `signatureLength`, the `/Contents` budget defaults to **30720** bytes (vs
  `8192` without a TSA) to fit the TimeStampToken plus the TSA certificate
  chain. If the signed PKCS#7 would overflow the placeholder, `signPdf` throws
  rather than producing a silently-truncated signature. Override
  `signatureLength` only if your TSA's chain is unusually large.
- **Privacy.** The request sent to the TSA is an RFC 3161 `TimeStampReq` whose
  `messageImprint` is `sha256(SignerInfo.signature)`. No document bytes, no
  identifiers, no PHI leave your process beyond that single hash.
- **Failure modes.** With `required: false` (default) a TSA error yields a valid
  CAdES-B signature and populates `tsaError`; `timestamped` is `false`. With
  `required: true` the error is rethrown and no signature is returned.
- **Verification.** `verifyPdfStructure` enforces the RFC 3161 §2.4.2 binding:
  the token's `messageImprint` must equal `sha256(SignerInfo.signature)`. A
  mismatch sets `ok:false` with `"timestamp messageImprint does not match
  signature value"`. A PDF with no timestamp verifies normally with
  `timestamped:false` (backward compatible).

### Choosing a TSA

Any RFC 3161 TSA works. Free public TSAs include
`http://timestamp.digicert.com` and `http://timestamp.sectigo.com`. For
HIPAA/regulated contexts, prefer a TSA you have a relationship with; remember
the TSA only sees a hash, so a BAA is generally not required for the hash
itself — confirm with your compliance owner.
