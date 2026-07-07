// ExternalSigner seam tests.
//
// Proves the HSM signing seam: an ExternalSigner whose signRsaSha256 runs
// RSASSA-PKCS1-v1_5/SHA-256 via node:crypto produces a PKCS#7 that is
// byte-identical to the in-memory keyPem path for the same key, verifies
// cryptographically (verifyPdfStructure ok:true), and fails closed on tamper,
// key-type mismatch, and malformed signer output. Like the rest of the suite,
// tests run against the BUILT package (../dist).

import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";

import {
  generateSelfSignedCert,
  signPdf,
  verifyPdfStructure,
  PemSigner,
  type ExternalSigner,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

function issue() {
  return generateSelfSignedCert({ subjectName: "Acme Inc" });
}

/**
 * ExternalSigner backed by node:crypto — an independent RSASSA-PKCS1-v1_5
 * implementation (not node-forge), so agreement proves the seam's contract.
 */
function nodeCryptoSigner(keyPem: string, certPem: string): ExternalSigner {
  const key = crypto.createPrivateKey(keyPem);
  return {
    keyType: "rsa-2048",
    certificatePem: certPem,
    signRsaSha256: (data) => new Uint8Array(crypto.sign("sha256", data, key)),
  };
}

describe("ExternalSigner seam", () => {
  it("signPdf with an ExternalSigner (no keyPem/certPem) verifies cryptographically", async () => {
    const cert = issue();
    const { signedPdf } = await signPdf({
      pdf: SAMPLE_PDF,
      externalSigner: nodeCryptoSigner(cert.keyPem, cert.certPem),
      reason: "hsm seam test",
      location: "",
      contactInfo: "",
      name: "External Signer",
      signingTime: new Date(),
    });
    const v = verifyPdfStructure(Buffer.from(signedPdf));
    expect(v.ok).toBe(true);
    expect(v.digestValid).toBe(true);
    expect(v.signatureValid).toBe(true);
  });

  it("supports an async signRsaSha256 (network HSM shape)", async () => {
    const cert = issue();
    const key = crypto.createPrivateKey(cert.keyPem);
    const external: ExternalSigner = {
      keyType: "rsa-2048",
      certificatePem: cert.certPem,
      signRsaSha256: async (data) => {
        await new Promise((r) => setTimeout(r, 5)); // simulate HSM round-trip
        return new Uint8Array(crypto.sign("sha256", data, key));
      },
    };
    const { signedPdf } = await signPdf({
      pdf: SAMPLE_PDF,
      externalSigner: external,
      reason: "async hsm",
      location: "",
      contactInfo: "",
      name: "Async External",
    });
    expect(verifyPdfStructure(Buffer.from(signedPdf)).ok).toBe(true);
  });

  it("produces a PKCS#7 byte-identical to the in-memory keyPem path", async () => {
    // PKCS1-v1_5 is deterministic: same key + same signed attributes (fixed
    // signingTime) must yield the exact same CMS. PemSigner.sign() returns the
    // raw detached CMS DER, so compare the two paths byte-for-byte.
    const cert = issue();
    const t = new Date("2026-01-02T03:04:05Z");
    const viaKeyPem = await new PemSigner({
      keyPem: cert.keyPem,
      certPem: cert.certPem,
    }).sign(SAMPLE_PDF, t);
    const viaExternal = await new PemSigner({
      externalSigner: nodeCryptoSigner(cert.keyPem, cert.certPem),
    }).sign(SAMPLE_PDF, t);
    expect(viaExternal.equals(viaKeyPem)).toBe(true);
  });

  it("detects tamper under an externally-produced signature", async () => {
    const cert = issue();
    const { signedPdf } = await signPdf({
      pdf: SAMPLE_PDF,
      externalSigner: nodeCryptoSigner(cert.keyPem, cert.certPem),
      reason: "tamper test",
      location: "",
      contactInfo: "",
      name: "External Signer",
    });
    const signed = Buffer.from(signedPdf);
    expect(verifyPdfStructure(signed).ok).toBe(true);

    const tampered = Buffer.from(signed);
    tampered[100] ^= 0xff; // inside the first ByteRange-covered region
    const v = verifyPdfStructure(tampered);
    expect(v.ok).toBe(false);
    expect(v.digestValid).toBe(false);
  });

  it("rejects a keyType that does not match the certificate's modulus", async () => {
    const cert = issue(); // RSA-2048
    const bad: ExternalSigner = {
      ...nodeCryptoSigner(cert.keyPem, cert.certPem),
      keyType: "rsa-3072",
    };
    await expect(
      signPdf({
        pdf: SAMPLE_PDF,
        externalSigner: bad,
        reason: "mismatch",
        location: "",
        contactInfo: "",
        name: "X",
      }),
    ).rejects.toThrow(/does not match the certificate's RSA modulus/);
  });

  it("rejects both keyPem and externalSigner, and neither", async () => {
    const cert = issue();
    const base = {
      pdf: SAMPLE_PDF,
      reason: "x",
      location: "",
      contactInfo: "",
      name: "X",
    };
    await expect(
      signPdf({
        ...base,
        keyPem: cert.keyPem,
        certPem: cert.certPem,
        externalSigner: nodeCryptoSigner(cert.keyPem, cert.certPem),
      }),
    ).rejects.toThrow(/either keyPem or externalSigner, not both/);
    await expect(signPdf({ ...base })).rejects.toThrow(/keyPem or externalSigner is required/);
  });

  it("fails closed when the signer returns a wrong-sized signature", async () => {
    const cert = issue();
    const truncating: ExternalSigner = {
      keyType: "rsa-2048",
      certificatePem: cert.certPem,
      signRsaSha256: (data) => {
        const key = crypto.createPrivateKey(cert.keyPem);
        return new Uint8Array(crypto.sign("sha256", data, key)).subarray(0, 16);
      },
    };
    await expect(
      signPdf({
        pdf: SAMPLE_PDF,
        externalSigner: truncating,
        reason: "short",
        location: "",
        contactInfo: "",
        name: "X",
      }),
    ).rejects.toThrow(/expected exactly 256/);
  });
});
