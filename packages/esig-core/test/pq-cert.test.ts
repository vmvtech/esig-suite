// Self-signed ML-DSA-65 X.509 (RFC 9881) test suite. Runs against ../dist.
// Covers issuance, byte-exact parse, self-signature verification, validity
// window, tamper-evidence, binding a cert to a seal, and the verifyDocument
// signerCert path.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import crypto from "node:crypto";
import { describe, it, expect } from "vitest";

import {
  generateSelfSignedCert,
  signPdf,
  verifyDocument,
  generatePqKeyBundle,
  loadPqSigningKeys,
  buildPqSeal,
  issueMlDsaCertificate,
  parseMlDsaCertificate,
  verifyMlDsaCertificate,
  certMatchesPqSeal,
  ID_ML_DSA_65,
  type PqSigningKeys,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

function keys(): PqSigningKeys {
  return loadPqSigningKeys(generatePqKeyBundle().bundle);
}

describe("pq-cert: issuance + structure", () => {
  it("issues a self-signed ML-DSA-65 certificate", () => {
    const k = keys();
    const cert = issueMlDsaCertificate({ keys: k, subjectName: "Acme Inc" });
    expect(cert.certPem).toMatch(/-----BEGIN CERTIFICATE-----/);
    expect(cert.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    // The cert's public-key fingerprint equals SHA-256 of the raw ML-DSA key.
    expect(cert.publicKeyFingerprint).toBe(
      crypto.createHash("sha256").update(k.mldsa65PublicKey).digest("hex"),
    );
    expect(cert.notAfter.getTime()).toBeGreaterThan(cert.notBefore.getTime());
  });

  it("parses back byte-exact fields", () => {
    const k = keys();
    const cert = issueMlDsaCertificate({ keys: k, subjectName: "Acme Inc" });
    const p = parseMlDsaCertificate(cert.certPem);
    expect(p.signatureAlgOid).toBe(ID_ML_DSA_65);
    expect(p.publicKey.length).toBe(1952);
    expect(p.signature.length).toBe(3309);
    expect(Buffer.from(p.publicKey)).toEqual(Buffer.from(k.mldsa65PublicKey));
    expect(p.subjectCommonName).toContain("Acme Inc");
  });

  it("rejects a non-ASCII subject", () => {
    expect(() => issueMlDsaCertificate({ keys: keys(), subjectName: "Acmé Inc" })).toThrow();
  });
});

describe("pq-cert: verification", () => {
  it("verifies a freshly issued certificate", () => {
    const cert = issueMlDsaCertificate({ keys: keys(), subjectName: "Acme Inc" });
    const v = verifyMlDsaCertificate(cert.certDer);
    expect(v).toMatchObject({ ok: true, algOk: true, selfSignatureOk: true, timeValid: true });
    expect(v.failures).toHaveLength(0);
  });

  it("fails when the signature is tampered", () => {
    const cert = issueMlDsaCertificate({ keys: keys(), subjectName: "Acme Inc" });
    const der = Buffer.from(cert.certDer);
    der[der.length - 100] ^= 0xff; // inside the trailing signature BIT STRING
    const v = verifyMlDsaCertificate(der);
    expect(v.selfSignatureOk).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("fails when the TBS is tampered", () => {
    const cert = issueMlDsaCertificate({ keys: keys(), subjectName: "Acme Inc" });
    const der = Buffer.from(cert.certDer);
    der[Math.floor(der.length * 0.25)] ^= 0xff; // inside the SPKI / TBS region
    expect(verifyMlDsaCertificate(der).ok).toBe(false);
  });

  it("fails an expired certificate", () => {
    const past = new Date(Date.now() - 400 * 86_400_000);
    const cert = issueMlDsaCertificate({ keys: keys(), subjectName: "Acme Inc", notBefore: past, validityDays: 1 });
    const v = verifyMlDsaCertificate(cert.certDer);
    expect(v.selfSignatureOk).toBe(true); // signature is fine…
    expect(v.timeValid).toBe(false); // …but the window has passed
    expect(v.ok).toBe(false);
  });

  it("fails a not-yet-valid certificate", () => {
    const future = new Date(Date.now() + 30 * 86_400_000);
    const cert = issueMlDsaCertificate({ keys: keys(), subjectName: "Acme Inc", notBefore: future });
    expect(verifyMlDsaCertificate(cert.certDer).timeValid).toBe(false);
  });

  it("fails closed on garbage input", () => {
    expect(verifyMlDsaCertificate(Buffer.from("not a certificate")).ok).toBe(false);
    expect(() => verifyMlDsaCertificate(Buffer.from("not a certificate"))).not.toThrow();
  });
});

describe("pq-cert: binding a certificate to a seal", () => {
  it("matches a seal produced by the same key", () => {
    const k = keys();
    const cert = issueMlDsaCertificate({ keys: k, subjectName: "Acme Inc" });
    const seal = buildPqSeal({ digestHex: crypto.createHash("sha256").update("doc").digest("hex"), coveredBytes: 3, keys: k });
    expect(certMatchesPqSeal(cert.certDer, seal)).toBe(true);
  });

  it("does NOT match a seal produced by a different key", () => {
    const cert = issueMlDsaCertificate({ keys: keys(), subjectName: "Acme Inc" });
    const otherSeal = buildPqSeal({ digestHex: crypto.createHash("sha256").update("doc").digest("hex"), coveredBytes: 3, keys: keys() });
    expect(certMatchesPqSeal(cert.certDer, otherSeal)).toBe(false);
  });
});

describe("pq-cert: verifyDocument signerCert path", () => {
  function signSealedWith(k: PqSigningKeys) {
    const rsa = generateSelfSignedCert({ subjectName: "Acme Inc" });
    return signPdf({
      pdf: SAMPLE_PDF,
      keyPem: rsa.keyPem,
      certPem: rsa.certPem,
      reason: "cert path",
      location: "",
      contactInfo: "",
      name: "Acme Inc",
      pqSeal: { keys: k },
    });
  }

  it("accepts a matching signer certificate and reports certIdentityOk", async () => {
    const k = keys();
    const r = await signSealedWith(k);
    const cert = issueMlDsaCertificate({ keys: k, subjectName: "Acme Inc" });
    const v = verifyDocument(r.signedPdf, { signerCert: cert.certPem });
    expect(v.ok).toBe(true);
    expect(v.postQuantum.certIdentityOk).toBe(true);
  });

  it("rejects a certificate for a different key", async () => {
    const r = await signSealedWith(keys());
    const wrongCert = issueMlDsaCertificate({ keys: keys(), subjectName: "Impostor" });
    const v = verifyDocument(r.signedPdf, { signerCert: wrongCert.certPem });
    expect(v.postQuantum.certIdentityOk).toBe(false);
    expect(v.ok).toBe(false);
  });
});
