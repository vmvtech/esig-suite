// pq-seal cryptographic test suite — hybrid Ed25519 + ML-DSA-65 (FIPS 204).
//
// Runs against the BUILT package (../dist), like crypto.test.ts. Covers the S1
// gate: sign/verify, tamper-evidence, hybrid AND-semantics (a single broken
// scheme fails the whole seal), fingerprint binding, at-rest wrap/unwrap,
// deterministic key derivation, and fail-closed behaviour on malformed input.

import crypto from "node:crypto";
import { describe, it, expect } from "vitest";

import {
  generatePqKeyBundle,
  loadPqSigningKeys,
  publicMaterialForKeys,
  wrapPqKeyBundle,
  unwrapPqKeyBundle,
  buildPqSeal,
  verifyPqSealSignatures,
  canonicalJson,
  PQ_SEAL_ALG,
  PQ_SEAL_VERSION,
  type PqSeal,
} from "../dist/index.js";

const PASSPHRASE = "test-passphrase-at-least-24-chars-long!!";

function sha256Hex(bytes: Uint8Array | string): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/** A fresh signer + a seal over a random document digest. */
function seal(digestHex = sha256Hex(crypto.randomBytes(64)), coveredBytes = 4096) {
  const { bundle } = generatePqKeyBundle();
  const keys = loadPqSigningKeys(bundle);
  return { bundle, keys, seal: buildPqSeal({ digestHex, coveredBytes, keys }) };
}

/** Deep-clone a seal so tests can tamper without cross-contaminating. */
function clone(s: PqSeal): PqSeal {
  return JSON.parse(JSON.stringify(s));
}

describe("pq-seal: shape", () => {
  it("produces a well-formed hybrid seal", () => {
    const { seal: s } = seal();
    expect(s.v).toBe(PQ_SEAL_VERSION);
    expect(s.alg).toBe(PQ_SEAL_ALG);
    expect(s.over).toBe("sha256");
    expect(s.digest).toMatch(/^[0-9a-f]{64}$/);
    // Raw sizes: Ed25519 pub 32B, ML-DSA-65 pub 1952B / sig 3309B, Ed25519 sig 64B.
    expect(Buffer.from(s.keys.ed25519, "base64").length).toBe(32);
    expect(Buffer.from(s.keys.mldsa65, "base64").length).toBe(1952);
    expect(Buffer.from(s.sig.ed25519, "base64").length).toBe(64);
    expect(Buffer.from(s.sig.mldsa65, "base64").length).toBe(3309);
    expect(s.keys.mldsa65Fpr).toBe(sha256Hex(Buffer.from(s.keys.mldsa65, "base64")));
  });

  it("rejects a malformed digest or non-positive coveredBytes", () => {
    const { keys } = seal();
    expect(() => buildPqSeal({ digestHex: "not-hex", coveredBytes: 10, keys })).toThrow();
    expect(() => buildPqSeal({ digestHex: sha256Hex("x"), coveredBytes: 0, keys })).toThrow();
  });
});

describe("pq-seal: verification (happy path)", () => {
  it("verifies both signatures and the fingerprint", () => {
    const { seal: s } = seal();
    const v = verifyPqSealSignatures(s);
    expect(v).toEqual({ ed25519: true, mldsa65: true, fingerprintOk: true, keyIdOk: true, ok: true });
  });

  it("survives a JSON round-trip (transport-safe)", () => {
    const { seal: s } = seal();
    const v = verifyPqSealSignatures(JSON.parse(JSON.stringify(s)) as PqSeal);
    expect(v.ok).toBe(true);
  });
});

describe("pq-seal: tamper-evidence", () => {
  it("fails when the covered digest is changed", () => {
    const { seal: s } = seal();
    const t = clone(s);
    t.digest = sha256Hex(crypto.randomBytes(64));
    const v = verifyPqSealSignatures(t);
    // digest is inside the signed payload → BOTH schemes fail.
    expect(v.ed25519).toBe(false);
    expect(v.mldsa65).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("fails when coveredBytes is changed", () => {
    const { seal: s } = seal(undefined, 4096);
    const t = clone(s);
    t.coveredBytes = 9999;
    expect(verifyPqSealSignatures(t).ok).toBe(false);
  });

  it("fails when a public key is swapped for another valid key", () => {
    const { seal: s } = seal();
    const other = seal();
    const t = clone(s);
    t.keys.ed25519 = other.seal.keys.ed25519; // valid key, wrong payload binding
    expect(verifyPqSealSignatures(t).ok).toBe(false);
  });
});

describe("pq-seal: hybrid AND-semantics (a single broken scheme fails the whole seal)", () => {
  it("classical broken → mldsa still valid, but seal fails", () => {
    const { seal: s } = seal();
    const t = clone(s);
    // Corrupt only the Ed25519 signature (keep length valid: flip one byte).
    const edSig = Buffer.from(t.sig.ed25519, "base64");
    edSig[0] ^= 0xff;
    t.sig.ed25519 = edSig.toString("base64");
    const v = verifyPqSealSignatures(t);
    expect(v.ed25519).toBe(false);
    expect(v.mldsa65).toBe(true);
    expect(v.ok).toBe(false);
  });

  it("post-quantum broken → classical still valid, but seal fails", () => {
    const { seal: s } = seal();
    const t = clone(s);
    const mlSig = Buffer.from(t.sig.mldsa65, "base64");
    mlSig[0] ^= 0xff;
    t.sig.mldsa65 = mlSig.toString("base64");
    const v = verifyPqSealSignatures(t);
    expect(v.ed25519).toBe(true);
    expect(v.mldsa65).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("fails when the ML-DSA fingerprint is inconsistent with its public key", () => {
    const { seal: s } = seal();
    const t = clone(s);
    t.keys.mldsa65Fpr = sha256Hex(crypto.randomBytes(32));
    const v = verifyPqSealSignatures(t);
    expect(v.fingerprintOk).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("fails when keyId is inconsistent with the public keys", () => {
    const { seal: s } = seal();
    const t = clone(s);
    t.keyId = "0".repeat(32);
    const v = verifyPqSealSignatures(t);
    expect(v.keyIdOk).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("a legitimate seal has keyIdOk true", () => {
    const { seal: s } = seal();
    expect(verifyPqSealSignatures(s).keyIdOk).toBe(true);
  });
});

describe("pq-seal: fail-closed on malformed input", () => {
  it("returns ok:false (no throw) on truncated keys/signatures", () => {
    const { seal: s } = seal();
    for (const mutate of [
      (t: PqSeal) => (t.keys.mldsa65 = "AAAA"),
      (t: PqSeal) => (t.keys.ed25519 = ""),
      (t: PqSeal) => (t.sig.mldsa65 = "AAAA"),
      (t: PqSeal) => (t.sig.ed25519 = "%%not-base64%%"),
      (t: PqSeal) => ((t as unknown as { v: number }).v = 99),
      (t: PqSeal) => ((t as unknown as { alg: string }).alg = "rsa"),
    ]) {
      const t = clone(s);
      mutate(t);
      expect(() => verifyPqSealSignatures(t)).not.toThrow();
      expect(verifyPqSealSignatures(t).ok).toBe(false);
    }
  });
});

describe("pq-seal: at-rest key wrapping", () => {
  it("wrap → unwrap → load round-trips and still verifies", () => {
    const { bundle } = generatePqKeyBundle();
    const blob = wrapPqKeyBundle(bundle, PASSPHRASE);
    const back = unwrapPqKeyBundle(blob, PASSPHRASE);
    const keys = loadPqSigningKeys(back);
    const s = buildPqSeal({ digestHex: sha256Hex("doc"), coveredBytes: 3, keys });
    expect(verifyPqSealSignatures(s).ok).toBe(true);
  });

  it("wrong passphrase throws (AES-GCM auth-tag mismatch)", () => {
    const { bundle } = generatePqKeyBundle();
    const blob = wrapPqKeyBundle(bundle, PASSPHRASE);
    expect(() => unwrapPqKeyBundle(blob, "wrong-passphrase-also-24-chars-xx!!")).toThrow();
  });
});

describe("pq-seal: deterministic key derivation", () => {
  it("re-deriving keys from the same bundle yields the same identity", () => {
    const { bundle } = generatePqKeyBundle();
    const a = publicMaterialForKeys(loadPqSigningKeys(bundle));
    const b = publicMaterialForKeys(loadPqSigningKeys(bundle));
    expect(a).toEqual(b);
    expect(a.keyId).toHaveLength(32);
  });

  it("two seals from the same keys over the same digest both verify", () => {
    const { keys } = seal();
    const d = sha256Hex("same-doc");
    const s1 = buildPqSeal({ digestHex: d, coveredBytes: 8, keys });
    const s2 = buildPqSeal({ digestHex: d, coveredBytes: 8, keys });
    expect(verifyPqSealSignatures(s1).ok).toBe(true);
    expect(verifyPqSealSignatures(s2).ok).toBe(true);
  });

  it("generatePqKeyBundle({ mldsa65Seed, ed25519Pkcs8 }) is fully deterministic", () => {
    const seed = new Uint8Array(32).fill(7);
    const { bundle: seedBundle } = generatePqKeyBundle();
    const ed25519Pkcs8 = Buffer.from(seedBundle.ed25519Pkcs8, "base64");

    const a = generatePqKeyBundle({ mldsa65Seed: seed, ed25519Pkcs8 });
    const b = generatePqKeyBundle({ mldsa65Seed: seed, ed25519Pkcs8 });
    expect(a.bundle).toEqual(b.bundle);
    expect(a.public).toEqual(b.public);
    expect(a.public.mldsa65Fpr).toBe(b.public.mldsa65Fpr);

    // and the derived keys match what loadPqSigningKeys re-derives
    expect(publicMaterialForKeys(loadPqSigningKeys(a.bundle))).toEqual(a.public);
  });

  it("generatePqKeyBundle({ mldsa65Seed }) pins the ML-DSA identity only", () => {
    const seed = new Uint8Array(32).fill(9);
    const a = generatePqKeyBundle({ mldsa65Seed: seed });
    const b = generatePqKeyBundle({ mldsa65Seed: seed });
    expect(a.public.mldsa65Fpr).toBe(b.public.mldsa65Fpr);
    expect(a.public.mldsa65).toBe(b.public.mldsa65);
    // ed25519 halves were independently random
    expect(a.public.ed25519).not.toBe(b.public.ed25519);
  });

  it("generatePqKeyBundle rejects a wrong-length seed and a non-Ed25519 key", () => {
    expect(() => generatePqKeyBundle({ mldsa65Seed: new Uint8Array(31) })).toThrow(/32 bytes/);
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const rsaPkcs8 = rsa.privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
    expect(() => generatePqKeyBundle({ ed25519Pkcs8: rsaPkcs8 })).toThrow(/must be an Ed25519 key/);
  });
});

describe("pq-seal: canonicalJson", () => {
  it("is independent of key insertion order", () => {
    expect(canonicalJson({ b: 1, a: 2, c: { z: 1, a: 2 } })).toBe(
      canonicalJson({ c: { a: 2, z: 1 }, a: 2, b: 1 }),
    );
  });
  it("serializes deterministically", () => {
    expect(canonicalJson({ a: [3, 2, 1], b: "x" })).toBe('{"a":[3,2,1],"b":"x"}');
  });
});
