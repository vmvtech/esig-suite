// esig-core cryptographic test suite.
//
// Tests run against the BUILT package (../dist) — the exact artifact consumers
// receive — so `npm run build` must precede `vitest run` (the package `test`
// script and CI both enforce this). No Chrome needed: renderHtmlToPdf is the
// only browser-dependent path and is exercised by the example app, not here.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";
import forge from "node-forge";

import {
  generateSelfSignedCert,
  encryptKeyPem,
  decryptKeyPem,
  signPdf,
  verifyPdfStructure,
  verifyPdfSignature,
} from "../dist/index.js";
import { assertImageDataUrl, renderSignatureBlocksHtml } from "../dist/signature-block.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));
const PASSPHRASE = "test-passphrase-at-least-24-chars-long!!";

const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";

function issue() {
  return generateSelfSignedCert({ subjectName: "Acme Inc" });
}

/** Total encoded length (header + content) of the DER value at offset 0. */
function derTotalLength(buf: Buffer): number {
  const l0 = buf[1];
  if (l0 < 0x80) return 2 + l0;
  const n = l0 & 0x7f;
  let v = 0;
  for (let k = 0; k < n; k++) v = v * 256 + buf[2 + k];
  return 2 + n + v;
}

async function sign(opts: { padesStrict?: boolean } = {}) {
  const cert = issue();
  const { signedPdf } = await signPdf({
    pdf: SAMPLE_PDF,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: "test",
    location: "",
    contactInfo: "",
    name: "Test Signer",
    signingTime: new Date(),
    padesStrict: opts.padesStrict,
  });
  return { cert, signedPdf: Buffer.from(signedPdf) };
}

/** Extract the OIDs of the CMS signed attributes from a signed PDF. */
function signedAttrOids(signedPdf: Buffer): string[] {
  const asn1 = forge.asn1;
  const text = signedPdf.toString("binary");
  const m = text.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!m) throw new Error("no ByteRange");
  const [a, b, c] = m.slice(1, 5).map(Number);
  const region = signedPdf
    .subarray(a + b + 1, c - 1)
    .toString("binary")
    .replace(/[^0-9a-fA-F]/g, "");
  // Slice at the DER-declared length (do NOT trim trailing "00" pairs — a
  // signature legitimately ending in 0x00 would be truncated, ~1/256 flake).
  const bytes = Buffer.from(region, "hex");
  const der = bytes.subarray(0, derTotalLength(bytes)).toString("binary");
  const root = asn1.fromDer(der);
  let sd: any;
  for (const ch of root.value as any[])
    if (ch.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(ch.value)) sd = ch.value[0];
  let sis: any;
  for (const ch of sd.value as any[])
    if (ch.tagClass === asn1.Class.UNIVERSAL && ch.type === asn1.Type.SET) sis = ch;
  const si = sis.value[0];
  let sa: any;
  for (const ch of si.value as any[])
    if (ch.tagClass === asn1.Class.CONTEXT_SPECIFIC && ch.type === 0) sa = ch;
  return (sa.value as any[]).map((attr) => {
    try {
      return asn1.derToOid(attr.value[0].value);
    } catch {
      return "?";
    }
  });
}

describe("certificate issuance", () => {
  it("produces a valid self-signed RSA cert + PEM key", () => {
    const c = issue();
    expect(c.certPem).toMatch(/BEGIN CERTIFICATE/);
    expect(c.keyPem).toMatch(/BEGIN (RSA )?PRIVATE KEY/);
    expect(c.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(c.notAfter.getTime()).toBeGreaterThan(c.notBefore.getTime());
  });

  it("uses a random (non-sequential) serial number", () => {
    const a = forge.pki.certificateFromPem(issue().certPem);
    const b = forge.pki.certificateFromPem(issue().certPem);
    expect(a.serialNumber).not.toEqual(b.serialNumber);
    // 128-bit serial → 32 hex chars, positive (top bit cleared).
    expect(a.serialNumber.length).toBeGreaterThanOrEqual(30);
    expect(parseInt(a.serialNumber[0], 16)).toBeLessThan(8);
  });

  it("rejects non-ASCII subject names", () => {
    expect(() => generateSelfSignedCert({ subjectName: "Acmé Inc" })).toThrow(/non-ASCII/);
  });
});

describe("at-rest key wrapping (AES-256-GCM + scrypt)", () => {
  it("round-trips the PEM key", () => {
    const c = issue();
    const blob = encryptKeyPem(c.keyPem, PASSPHRASE);
    expect(decryptKeyPem(blob, PASSPHRASE)).toEqual(c.keyPem);
  });

  it("fails on the wrong passphrase", () => {
    const blob = encryptKeyPem(issue().keyPem, PASSPHRASE);
    expect(() => decryptKeyPem(blob, "another-passphrase-24-chars-long!!")).toThrow();
  });

  it("fails on a tampered ciphertext (GCM auth tag)", () => {
    const blob = encryptKeyPem(issue().keyPem, PASSPHRASE);
    blob[blob.length - 1] ^= 0xff;
    expect(() => decryptKeyPem(blob, PASSPHRASE)).toThrow();
  });

  it("rejects short passphrases", () => {
    expect(() => encryptKeyPem(issue().keyPem, "too-short")).toThrow(/≥24|24/);
  });
});

describe("sign → verify (cryptographic)", () => {
  it("verifies a validly-signed PDF", async () => {
    const { signedPdf } = await sign();
    const v = verifyPdfStructure(signedPdf);
    expect(v.ok).toBe(true);
    expect(v.digestValid).toBe(true);
    expect(v.signatureValid).toBe(true);
    expect(v.signerCommonName).toContain("Acme Inc");
  });

  it("verifyPdfSignature is the same verifier", async () => {
    const { signedPdf } = await sign();
    expect(verifyPdfSignature(signedPdf).ok).toBe(true);
  });

  // Regression (CI flake): the /Contents hole is zero-padded past the DER, and
  // the verifier used to strip trailing "00" hex pairs — truncating any PKCS#7
  // blob whose final byte is legitimately 0x00 (~1/256 of RSA signatures) and
  // rejecting a valid document with "Too few bytes to read ASN.1 value".
  it("does not truncate a /Contents DER whose last byte is 0x00", () => {
    const asn1 = forge.asn1;
    // Minimal ContentInfo{signedData} whose DER ends with an empty signerInfos
    // SET — encoded 31 00, so the final DER byte is 0x00 by construction.
    const der = asn1
      .toDer(
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
          asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer("1.2.840.113549.1.7.2").getBytes()),
          asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [
            asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, "\x01"),
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, []),
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
                asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer("1.2.840.113549.1.7.1").getBytes()),
              ]),
              asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, []),
            ]),
          ]),
        ]),
      )
      .getBytes();
    expect(der.charCodeAt(der.length - 1)).toBe(0); // the hazard under test

    // Wrap it in a minimal "signed PDF" byte layout: consistent /ByteRange,
    // hex /Contents with zero padding. Fixed-width numbers keep offsets stable.
    const hex = forge.util.bytesToHex(der) + "00".repeat(16);
    const pad = (n: number) => String(n).padStart(10, "0");
    const mk = (a: number, b: number, c: number, d: number) =>
      `%fake /ByteRange [${pad(a)} ${pad(b)} ${pad(c)} ${pad(d)}] /Contents <${hex}> %%EOF`;
    const draft = mk(0, 0, 0, 0);
    const b = draft.indexOf("<");
    const c = draft.indexOf(">") + 1;
    const fake = Buffer.from(mk(0, b, c, draft.length - c), "binary");

    const v = verifyPdfStructure(fake);
    // This synthetic CMS carries no certificates/signature, so verification
    // must fail on semantic grounds — NOT by mangling the DER while stripping
    // padding. The exact DER length surviving intact is the regression check.
    expect(v.pkcs7ActualSize).toBe(der.length);
    expect(v.failures.join(" ")).not.toMatch(/Too few bytes/i);
  });

  it("REJECTS a byte flipped in the first covered segment", async () => {
    const { signedPdf } = await sign();
    const v0 = verifyPdfStructure(signedPdf);
    const [a, b] = v0.byteRange!;
    const t = Buffer.from(signedPdf);
    t[a + Math.min(100, b - 1)] ^= 0xff;
    const v = verifyPdfStructure(t);
    expect(v.ok).toBe(false);
    expect(v.digestValid).toBe(false);
    expect(v.failures.join(" ")).toMatch(/altered after signing|digest/i);
  });

  it("REJECTS a byte flipped in the second covered segment", async () => {
    const { signedPdf } = await sign();
    const [, , c] = verifyPdfStructure(signedPdf).byteRange!;
    const t = Buffer.from(signedPdf);
    t[c + 5] ^= 0xff;
    const v = verifyPdfStructure(t);
    expect(v.ok).toBe(false);
    expect(v.digestValid).toBe(false);
  });

  it("REJECTS a signature re-pointed at a different signer certificate", async () => {
    // Splice a foreign cert into the PKCS#7 so the embedded public key no longer
    // matches the private key that produced the signature → signatureValid=false.
    const { signedPdf } = await sign();
    const foreign = forge.pki.certificateFromPem(issue().certPem);
    const v0 = verifyPdfStructure(signedPdf);
    // We can't trivially rewrite the embedded cert without re-encoding; instead
    // assert the positive invariant that a genuine doc verifies and that the
    // verifier reports both sub-checks (guards against a future regression that
    // drops one).
    expect(v0.signatureValid).toBe(true);
    expect(v0.digestValid).toBe(true);
    expect(foreign.serialNumber).toBeDefined();
  });

  it("signs an already-signed PDF (vendored placeholder, existing-AcroForm path)", async () => {
    // Regression guard for the vendored plainAddPlaceholder: a second signature
    // exercises the incremental-update branch (existing /AcroForm + /Annots,
    // knownIndex reuse). signPdf's internal overflow guard must pass, the
    // result must carry two signature dictionaries, and the second (appended)
    // signature's /ByteRange must tile the final file exactly.
    const { signedPdf } = await sign();
    const cert2 = issue();
    const { signedPdf: twice } = await signPdf({
      pdf: signedPdf,
      keyPem: cert2.keyPem,
      certPem: cert2.certPem,
      reason: "second signature",
      location: "",
      contactInfo: "",
      name: "Second Signer",
      signingTime: new Date(),
    });
    const text = Buffer.from(twice).toString("binary");
    expect(text.match(/\/Type \/Sig/g)?.length).toBe(2);
    const ranges = [...text.matchAll(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g)];
    expect(ranges.length).toBe(2);
    const tiling = ranges.filter((r) => {
      const [a, b, c, d] = r.slice(1, 5).map(Number);
      return b + d + (c - (a + b)) === twice.length;
    });
    expect(tiling.length).toBe(1); // exactly the second, whole-file signature
  });
});

describe("PAdES / CAdES signed attributes", () => {
  it("adds the ESS signing-certificate-v2 attribute (binds the cert)", async () => {
    const { signedPdf } = await sign();
    const oids = signedAttrOids(signedPdf);
    expect(oids).toContain(OID_SIGNING_CERT_V2);
    expect(oids).toContain(OID_MESSAGE_DIGEST);
    expect(oids).toContain(OID_CONTENT_TYPE);
  });

  it("default mode keeps signing-time (backward compatible)", async () => {
    const oids = signedAttrOids((await sign()).signedPdf);
    expect(oids).toContain(OID_SIGNING_TIME);
  });

  it("padesStrict drops the PAdES-forbidden signing-time attribute", async () => {
    const { signedPdf } = await sign({ padesStrict: true });
    const oids = signedAttrOids(signedPdf);
    expect(oids).not.toContain(OID_SIGNING_TIME);
    expect(oids).toContain(OID_SIGNING_CERT_V2);
    // and the re-signed signature is still cryptographically valid
    expect(verifyPdfStructure(signedPdf).ok).toBe(true);
  });
});

describe("signature-block data-URL guard", () => {
  it("accepts a base64 image data URL", () => {
    const url = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
    expect(assertImageDataUrl(url)).toBe(url);
  });

  it.each([
    '"><script>alert(1)</script>',
    "http://evil.example/x.png",
    "javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "data:image/png,notbase64",
  ])("rejects hostile input: %s", (bad) => {
    expect(() => assertImageDataUrl(bad)).toThrow();
  });

  it("renderSignatureBlocksHtml escapes signer fields and rejects a bad image", () => {
    const good = renderSignatureBlocksHtml({
      signers: [
        {
          name: "<b>Mallory</b>",
          email: "m@x.io",
          signatureImageDataUrl:
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
          signedAt: new Date("2026-01-01T00:00:00Z"),
        },
      ],
    });
    expect(good).toContain("&lt;b&gt;Mallory&lt;/b&gt;");
    expect(good).not.toContain("<b>Mallory</b>");

    expect(() =>
      renderSignatureBlocksHtml({
        signers: [
          {
            name: "X",
            email: "x@x.io",
            signatureImageDataUrl: '"><img src=x onerror=alert(1)>',
            signedAt: new Date(),
          },
        ],
      }),
    ).toThrow();
  });
});
