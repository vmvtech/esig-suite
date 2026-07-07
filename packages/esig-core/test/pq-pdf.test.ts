// End-to-end post-quantum PDF tests: embed a hybrid seal, apply the classical
// RSA PAdES signature on top, and verify BOTH layers — including that tampering
// with the document breaks the classical signature AND the post-quantum digest.
//
// Runs against ../dist. Uses the sample unsigned PDF fixture (no Chrome needed).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";

import crypto from "node:crypto";
import {
  generateSelfSignedCert,
  signPdf,
  verifyPdfSignature,
  generatePqKeyBundle,
  loadPqSigningKeys,
  buildPqSeal,
  verifyDocument,
  verifyPqSeal,
  extractPqSeal,
  hasPqSeal,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

function signSealed() {
  const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
  const keys = loadPqSigningKeys(generatePqKeyBundle().bundle);
  return signPdf({
    pdf: SAMPLE_PDF,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: "PQ e2e",
    location: "",
    contactInfo: "a@b.co",
    name: "Acme Inc",
    pqSeal: { keys },
  });
}

describe("pq-pdf: sealed signing", () => {
  it("reports the seal in the signPdf result", async () => {
    const r = await signSealed();
    expect(r.pqSealed).toBe(true);
    expect(r.pqKeyId).toMatch(/^[0-9a-f]{32}$/);
    expect(r.pqMldsa65Fpr).toMatch(/^[0-9a-f]{64}$/);
    expect(hasPqSeal(r.signedPdf)).toBe(true);
  });

  it("verifies both classical and post-quantum layers", async () => {
    const r = await signSealed();
    const v = verifyDocument(r.signedPdf);
    expect(v.classical.ok).toBe(true); // Acrobat-grade RSA PAdES
    expect(v.postQuantum.present).toBe(true);
    expect(v.postQuantum.ed25519).toBe(true);
    expect(v.postQuantum.mldsa65).toBe(true);
    expect(v.postQuantum.digestBinds).toBe(true);
    expect(v.postQuantum.ok).toBe(true);
    expect(v.ok).toBe(true);
  });

  it("the seal identity fields round-trip", async () => {
    const r = await signSealed();
    const seal = extractPqSeal(r.signedPdf)!;
    expect(seal.alg).toBe("hybrid-ed25519-ml-dsa-65");
    expect(seal.keyId).toBe(r.pqKeyId);
    expect(seal.keys.mldsa65Fpr).toBe(r.pqMldsa65Fpr);
  });
});

describe("pq-pdf: tamper breaks BOTH layers", () => {
  it("flipping a document byte fails classical AND post-quantum", async () => {
    const r = await signSealed();
    const seal = extractPqSeal(r.signedPdf)!;
    const tampered = Buffer.from(r.signedPdf);
    const at = Math.floor(seal.coveredBytes / 2); // mid-document, inside the covered region
    tampered[at] ^= 0xff;

    const v = verifyDocument(tampered);
    expect(v.classical.ok).toBe(false); // RSA /ByteRange digest changed
    expect(v.postQuantum.digestBinds).toBe(false); // seal digest no longer matches
    expect(v.postQuantum.ok).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("tampering with the seal bytes fails the RSA signature (seal is covered)", async () => {
    const r = await signSealed();
    const idx = r.signedPdf.indexOf(Buffer.from("/Type/ESigPQSeal", "latin1"));
    expect(idx).toBeGreaterThan(0);
    const tampered = Buffer.from(r.signedPdf);
    // Flip a byte inside the seal's base64 payload (a bit after the marker).
    tampered[idx + 40] ^= 0x01;
    const v = verifyDocument(tampered);
    expect(v.classical.ok).toBe(false); // the seal lives inside the RSA-signed region
    expect(v.ok).toBe(false);
  });
});

describe("pq-pdf: identity pinning + requirePq", () => {
  it("pins the post-quantum signer fingerprint (match passes, mismatch fails)", async () => {
    const r = await signSealed();
    const good = verifyDocument(r.signedPdf, { expectedMldsa65Fpr: r.pqMldsa65Fpr });
    expect(good.ok).toBe(true);
    expect(good.postQuantum.ok).toBe(true);

    const bad = verifyDocument(r.signedPdf, { expectedMldsa65Fpr: "deadbeef".repeat(8) });
    expect(bad.postQuantum.ok).toBe(false);
    expect(bad.ok).toBe(false);
    expect(bad.postQuantum.failures.join(" ")).toMatch(/pinned/i);
  });

  it("requirePq rejects an unsealed document", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const r = await signPdf({
      pdf: SAMPLE_PDF,
      keyPem: cert.keyPem,
      certPem: cert.certPem,
      reason: "no PQ",
      location: "",
      contactInfo: "",
      name: "Acme Inc",
    });
    expect(verifyDocument(r.signedPdf).ok).toBe(true); // classical-only is fine by default
    expect(verifyDocument(r.signedPdf, { requirePq: true }).ok).toBe(false); // but not when PQ is required
  });
});

describe("pq-pdf: seal-append substitution is defeated", () => {
  it("an attacker seal appended after signing is ignored; classical check fails", async () => {
    const r = await signSealed();
    const original = extractPqSeal(r.signedPdf)!;

    // Attacker mints their OWN seal over the same document digest and appends it
    // after the RSA signature (outside the /ByteRange).
    const attackerKeys = loadPqSigningKeys(generatePqKeyBundle().bundle);
    const attackerSeal = buildPqSeal({
      digestHex: original.digest,
      coveredBytes: original.coveredBytes,
      keys: attackerKeys,
    });
    const attackerB64 = Buffer.from(JSON.stringify(attackerSeal), "utf8").toString("base64");
    const appended = Buffer.concat([
      r.signedPdf,
      Buffer.from(`\n999 0 obj\n<</Type/ESigPQSeal/V 1/Seal(${attackerB64})>>\nendobj\n`, "latin1"),
    ]);

    // First-match extraction returns the AUTHENTIC seal, not the attacker's.
    const seen = extractPqSeal(appended)!;
    expect(seen.keyId).toBe(original.keyId);
    expect(seen.keyId).not.toBe(attackerSeal.keyId);

    // And appending bytes after signing breaks the classical file-length check.
    const v = verifyDocument(appended);
    expect(v.classical.ok).toBe(false);
    expect(v.ok).toBe(false);
  });
});

describe("pq-pdf: backward compatibility (no seal)", () => {
  it("an unsealed signature still verifies; PQ reported absent", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const r = await signPdf({
      pdf: SAMPLE_PDF,
      keyPem: cert.keyPem,
      certPem: cert.certPem,
      reason: "no PQ",
      location: "",
      contactInfo: "",
      name: "Acme Inc",
    });
    expect(r.pqSealed).toBe(false);
    expect(hasPqSeal(r.signedPdf)).toBe(false);

    const v = verifyDocument(r.signedPdf);
    expect(v.classical.ok).toBe(true);
    expect(v.postQuantum.present).toBe(false);
    expect(v.ok).toBe(true); // judged on the classical signature alone

    expect(verifyPqSeal(r.signedPdf).present).toBe(false);
  });
});
