// @e-sig/core quickstart — the whole pipeline in four steps, no services needed:
//   1. issue a self-signed signing certificate (your org's own trust root)
//   2. cryptographically sign a PDF (PAdES ETSI.CAdES.detached)
//   3. verify the signature — structure, document digest, RSA signature
//   4. flip one byte and watch verification reject the tampered document
//
// Run: npm install && npm start   (writes signed.pdf next to this file)

import { readFile, writeFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { generateSelfSignedCert, signPdf, verifyPdfSignature } from "@e-sig/core";

// 1. Issue a certificate. Self-issued certs are their own trust root — fine for
//    org-internal signing; swap in a CA-issued PEM pair for public trust.
const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
console.log(`1. issued cert  sha256:${cert.fingerprint.slice(0, 16)}…  valid until ${cert.notAfter.toISOString().slice(0, 10)}`);

// 2. Sign. signPdf injects the signature placeholder itself — any well-formed
//    PDF works as input.
const unsigned = await readFile(new URL("./sample.pdf", import.meta.url));
const { signedPdf } = await signPdf({
  pdf: unsigned,
  keyPem: cert.keyPem,
  certPem: cert.certPem,
  reason: "Agreed to terms",
  location: "",
  contactInfo: "",
  name: "Ada Lovelace",
  signingTime: new Date(),
});
await writeFile(new URL("./signed.pdf", import.meta.url), signedPdf);
console.log(`2. signed       ${unsigned.length} → ${signedPdf.length} bytes (signed.pdf written)`);

// 3. Verify. ok:true means the signature is cryptographically valid over these
//    exact bytes: ByteRange structure + SHA-256 digest + RSA signature.
const v = verifyPdfSignature(signedPdf);
assert.equal(v.ok, true, `expected valid signature, got failures: ${v.failures}`);
console.log(`3. verified     ok=${v.ok} digestValid=${v.digestValid} signatureValid=${v.signatureValid} signer="${v.signerCommonName}"`);

// 4. Tamper: flip a single byte inside the signed region → must be rejected.
const tampered = Buffer.from(signedPdf);
tampered[v.byteRange[0] + 64] ^= 0xff;
const tv = verifyPdfSignature(tampered);
assert.equal(tv.ok, false, "tampered PDF must not verify");
assert.equal(tv.digestValid, false, "tampering must be caught by the digest check");
console.log(`4. tamper check ok=${tv.ok} → rejected: "${tv.failures[0]}"`);

console.log("\nquickstart passed ✓");
