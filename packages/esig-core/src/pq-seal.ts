// pq-seal.ts
//
// Hybrid post-quantum document seal — Ed25519 (classical) + ML-DSA-65 (FIPS 204,
// module-lattice, quantum-resistant). This is the cryptographic core of e-sig's
// post-quantum wedge: every sealed document carries TWO independent signatures
// over the same payload, and a verifier requires BOTH to pass. If either scheme
// is ever broken (a CRQC breaks Ed25519, or an unforeseen lattice attack dents
// ML-DSA), the seal still stands on the other — the belt-and-suspenders
// migration path NIST/CNSA 2.0 recommends over a hard cutover.
//
// The seal is a small canonical-JSON object signed over a SHA-256 digest of the
// document bytes it covers. It does NOT replace the PDF's PKCS#7/PAdES RSA
// signature (which stays valid in every PDF reader, including Adobe Acrobat —
// no mainstream reader validates ML-DSA in PAdES yet, 2026). Instead the seal is
// embedded in the PDF and the RSA /ByteRange signature is applied on top, so the
// classical signature cryptographically covers the seal (see sign-pdf.ts).
//
// Identity model (v1): raw ML-DSA-65 public key + its SHA-256 fingerprint carried
// in the seal (the `keyId` / `mldsa65Fpr`), verified TOFU / against-published-key.
// A self-signed ML-DSA-65 X.509 certificate (RFC 9881 OID 2.16.840.1.101.3.4.3.18)
// is a deliberate fast-follow, not required to ship the seal.
//
// Algorithm binding: both signatures are computed over the SAME canonical bytes —
// the seal object minus its `sig` field — so digest, covered length, public keys,
// timestamp and keyId are all bound together and cannot be swapped independently.

import crypto from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { encryptKeyPem, decryptKeyPem } from "./cert-issuer.js";

// ---------- Constants ----------

/** Seal schema version. Bump on any breaking change to the signed payload shape. */
export const PQ_SEAL_VERSION = 1 as const;
/** Hybrid algorithm identifier embedded in (and bound by) every seal. */
export const PQ_SEAL_ALG = "hybrid-ed25519-ml-dsa-65" as const;
/** Bundle schema version for the wrapped at-rest key material. */
const PQ_BUNDLE_VERSION = 1 as const;

/**
 * DER SubjectPublicKeyInfo prefix for an Ed25519 key (RFC 8410 §4). A raw 32-byte
 * Ed25519 public key is exactly this 12-byte prefix followed by the key, so we
 * can round-trip raw keys ↔ node KeyObjects without a heavier ASN.1 dependency.
 */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// FIPS 204 ML-DSA-65 sizes (raw, unencoded) — asserted defensively at load time.
const MLDSA65_PUBLIC_LEN = 1952;
const MLDSA65_SIGNATURE_LEN = 3309;
const MLDSA65_SEED_LEN = 32;
const ED25519_RAW_PUBLIC_LEN = 32;
const ED25519_SIGNATURE_LEN = 64;

// ---------- Public types ----------

/**
 * The wrappable at-rest key bundle. Persist `wrapPqKeyBundle(bundle, passphrase)`;
 * never store the raw bundle. Compact by design: an Ed25519 PKCS#8 key plus a
 * 32-byte ML-DSA seed (the full 4032-byte ML-DSA secret key is re-derived
 * deterministically via `ml_dsa65.keygen(seed)`).
 */
export interface PqKeyBundle {
  v: typeof PQ_BUNDLE_VERSION;
  /** base64 PKCS#8 DER of the Ed25519 private key. */
  ed25519Pkcs8: string;
  /** base64 32-byte ML-DSA-65 seed. */
  mldsa65Seed: string;
}

/** Public key material derived from a bundle — safe to publish/pin as the signer identity. */
export interface PqPublicMaterial {
  /** base64 raw 32-byte Ed25519 public key. */
  ed25519: string;
  /** base64 raw 1952-byte ML-DSA-65 public key. */
  mldsa65: string;
  /** SHA-256 hex of the raw ML-DSA-65 public key — the post-quantum identity fingerprint. */
  mldsa65Fpr: string;
  /** Stable 128-bit hex id over both public keys (bound into every seal). */
  keyId: string;
}

/** In-memory signing keys, ready to produce seals. Never persisted directly. */
export interface PqSigningKeys {
  ed25519PrivateKey: crypto.KeyObject;
  ed25519PublicRaw: Uint8Array;
  mldsa65SecretKey: Uint8Array;
  mldsa65PublicKey: Uint8Array;
}

/**
 * A hybrid post-quantum seal. The signed payload is every field EXCEPT `sig`,
 * serialized canonically (see `canonicalJson`). `digest` is the SHA-256 (hex) of
 * the first `coveredBytes` bytes of the final document — the PDF-verify layer
 * checks that binding; `verifyPqSealSignatures` only checks the two signatures.
 */
export interface PqSeal {
  v: typeof PQ_SEAL_VERSION;
  alg: typeof PQ_SEAL_ALG;
  /** Digest algorithm over the covered document bytes. */
  over: "sha256";
  /** SHA-256 hex of the covered document bytes (the first `coveredBytes` bytes). */
  digest: string;
  /** Byte length of the document prefix the digest covers (P0 = rendered PDF pre-seal). */
  coveredBytes: number;
  /** ISO 8601 seal creation time. */
  signedAt: string;
  /** 128-bit hex id over both public keys. */
  keyId: string;
  keys: {
    ed25519: string;
    mldsa65: string;
    mldsa65Fpr: string;
  };
  sig: {
    /** base64 Ed25519 signature over canonicalJson(payload). */
    ed25519: string;
    /** base64 ML-DSA-65 signature over canonicalJson(payload). */
    mldsa65: string;
  };
}

/** Result of verifying a seal's two signatures (does NOT check document binding). */
export interface PqSealVerification {
  /** Classical Ed25519 signature valid. */
  ed25519: boolean;
  /** Post-quantum ML-DSA-65 signature valid. */
  mldsa65: boolean;
  /** The embedded `mldsa65Fpr` matches SHA-256(mldsa65 public key). */
  fingerprintOk: boolean;
  /** The embedded `keyId` matches the digest of the two public keys it claims. */
  keyIdOk: boolean;
  /** Hybrid verdict: every check passed (both signatures + fingerprint + keyId). */
  ok: boolean;
}

// ---------- Key generation / loading ----------

export interface GeneratePqKeyBundleOptions {
  /**
   * 32-byte ML-DSA-65 keygen seed. The same seed always derives the same
   * keypair — supply one for deterministic key provisioning (e.g. from a KMS
   * or sealed secret). Omit for a fresh random seed.
   */
  mldsa65Seed?: Uint8Array;
  /**
   * PKCS#8 DER Ed25519 private key to use instead of generating a fresh one.
   * Together with `mldsa65Seed` this makes the whole bundle deterministic.
   */
  ed25519Pkcs8?: Uint8Array;
}

/**
 * Generate a fresh hybrid key bundle plus its derived public material. The bundle
 * is what you wrap + persist; the public material is what you publish/pin as the
 * signer's post-quantum identity. Pass `opts` to provision deterministically
 * from existing key material instead of random generation.
 */
export function generatePqKeyBundle(
  opts: GeneratePqKeyBundleOptions = {}
): { bundle: PqKeyBundle; public: PqPublicMaterial } {
  let ed25519Pkcs8: Buffer;
  let ed25519PublicRaw: Uint8Array;
  if (opts.ed25519Pkcs8) {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.from(opts.ed25519Pkcs8),
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error(
        `generatePqKeyBundle: ed25519Pkcs8 must be an Ed25519 key, got ${privateKey.asymmetricKeyType}`
      );
    }
    ed25519Pkcs8 = Buffer.from(opts.ed25519Pkcs8);
    ed25519PublicRaw = rawEd25519FromKeyObject(crypto.createPublicKey(privateKey));
  } else {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    ed25519Pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
    ed25519PublicRaw = rawEd25519FromKeyObject(publicKey);
  }

  if (opts.mldsa65Seed && opts.mldsa65Seed.length !== MLDSA65_SEED_LEN) {
    throw new Error(
      `generatePqKeyBundle: mldsa65Seed must be ${MLDSA65_SEED_LEN} bytes, got ${opts.mldsa65Seed.length}`
    );
  }
  const seed = opts.mldsa65Seed ? Buffer.from(opts.mldsa65Seed) : crypto.randomBytes(MLDSA65_SEED_LEN);
  const { publicKey: mldsa65PublicKey } = ml_dsa65.keygen(seed);

  const bundle: PqKeyBundle = {
    v: PQ_BUNDLE_VERSION,
    ed25519Pkcs8: b64(ed25519Pkcs8),
    mldsa65Seed: b64(seed),
  };
  return { bundle, public: publicMaterial(ed25519PublicRaw, mldsa65PublicKey) };
}

/** Rehydrate in-memory signing keys from a bundle (deterministically re-derives the ML-DSA keypair). */
export function loadPqSigningKeys(bundle: PqKeyBundle): PqSigningKeys {
  if (bundle.v !== PQ_BUNDLE_VERSION) {
    throw new Error(`loadPqSigningKeys: unknown bundle version ${bundle.v}`);
  }
  const ed25519PrivateKey = crypto.createPrivateKey({
    key: Buffer.from(bundle.ed25519Pkcs8, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const ed25519PublicRaw = rawEd25519FromKeyObject(crypto.createPublicKey(ed25519PrivateKey));

  const seed = Buffer.from(bundle.mldsa65Seed, "base64");
  if (seed.length !== MLDSA65_SEED_LEN) {
    throw new Error(`loadPqSigningKeys: ML-DSA seed must be ${MLDSA65_SEED_LEN} bytes, got ${seed.length}`);
  }
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  return {
    ed25519PrivateKey,
    ed25519PublicRaw,
    mldsa65SecretKey: secretKey,
    mldsa65PublicKey: publicKey,
  };
}

/** Derive the publishable public material for a set of signing keys. */
export function publicMaterialForKeys(keys: PqSigningKeys): PqPublicMaterial {
  return publicMaterial(keys.ed25519PublicRaw, keys.mldsa65PublicKey);
}

// ---------- At-rest wrapping (reuses cert-issuer AES-256-GCM) ----------

/** AES-256-GCM-wrap a key bundle for persistence. `passphrase` ≥ 24 chars. */
export function wrapPqKeyBundle(bundle: PqKeyBundle, passphrase: string): Uint8Array {
  return encryptKeyPem(JSON.stringify(bundle), passphrase);
}

/** Inverse of `wrapPqKeyBundle`. Throws on wrong passphrase / tampering (auth-tag mismatch). */
export function unwrapPqKeyBundle(blob: Uint8Array, passphrase: string): PqKeyBundle {
  const bundle = JSON.parse(decryptKeyPem(blob, passphrase)) as PqKeyBundle;
  if (bundle.v !== PQ_BUNDLE_VERSION) {
    throw new Error(`unwrapPqKeyBundle: unknown bundle version ${bundle.v}`);
  }
  return bundle;
}

// ---------- Sealing ----------

export interface BuildPqSealInput {
  /** SHA-256 hex of the covered document bytes. */
  digestHex: string;
  /** Byte length the digest covers (the document prefix protected by the seal). */
  coveredBytes: number;
  keys: PqSigningKeys;
  /** Seal timestamp. Defaults to now. */
  signedAt?: Date;
}

/**
 * Produce a hybrid seal over `digestHex`. Both signatures are computed over the
 * exact same canonical bytes (the seal minus `sig`), binding digest, covered
 * length, public keys, timestamp and keyId under BOTH schemes.
 */
export function buildPqSeal(input: BuildPqSealInput): PqSeal {
  if (!/^[0-9a-f]{64}$/.test(input.digestHex)) {
    throw new Error("buildPqSeal: digestHex must be 64 lowercase hex chars (SHA-256)");
  }
  if (!Number.isInteger(input.coveredBytes) || input.coveredBytes <= 0) {
    throw new Error("buildPqSeal: coveredBytes must be a positive integer");
  }
  const pub = publicMaterialForKeys(input.keys);
  const payload = {
    v: PQ_SEAL_VERSION,
    alg: PQ_SEAL_ALG,
    over: "sha256" as const,
    digest: input.digestHex,
    coveredBytes: input.coveredBytes,
    signedAt: (input.signedAt ?? new Date()).toISOString(),
    keyId: pub.keyId,
    keys: { ed25519: pub.ed25519, mldsa65: pub.mldsa65, mldsa65Fpr: pub.mldsa65Fpr },
  };

  const signingInput = Buffer.from(canonicalJson(payload), "utf8");
  const ed25519Sig = crypto.sign(null, signingInput, input.keys.ed25519PrivateKey);
  const mldsa65Sig = ml_dsa65.sign(signingInput, input.keys.mldsa65SecretKey);

  return { ...payload, sig: { ed25519: b64(ed25519Sig), mldsa65: b64(mldsa65Sig) } };
}

/**
 * Verify a seal's two signatures over its own payload (does NOT bind the seal to a
 * document — the PDF-verify layer checks `digest` against the covered bytes).
 *
 * Fails CLOSED: any malformed field, wrong-length key/signature, or thrown error
 * yields `ok:false` rather than propagating. The hybrid verdict requires BOTH
 * signatures valid AND the ML-DSA fingerprint self-consistent.
 */
export function verifyPqSealSignatures(seal: PqSeal): PqSealVerification {
  const fail: PqSealVerification = {
    ed25519: false,
    mldsa65: false,
    fingerprintOk: false,
    keyIdOk: false,
    ok: false,
  };
  try {
    if (seal.v !== PQ_SEAL_VERSION || seal.alg !== PQ_SEAL_ALG || seal.over !== "sha256") return fail;

    const ed25519Pub = Buffer.from(seal.keys.ed25519, "base64");
    const mldsa65Pub = Buffer.from(seal.keys.mldsa65, "base64");
    const ed25519Sig = Buffer.from(seal.sig.ed25519, "base64");
    const mldsa65Sig = Buffer.from(seal.sig.mldsa65, "base64");
    if (ed25519Pub.length !== ED25519_RAW_PUBLIC_LEN) return fail;
    if (mldsa65Pub.length !== MLDSA65_PUBLIC_LEN) return fail;
    if (ed25519Sig.length !== ED25519_SIGNATURE_LEN) return fail;
    if (mldsa65Sig.length !== MLDSA65_SIGNATURE_LEN) return fail;

    // Reconstruct the exact signed payload: the seal minus `sig`.
    const { sig: _sig, ...payload } = seal;
    void _sig;
    const signingInput = Buffer.from(canonicalJson(payload), "utf8");

    // Self-consistency of the identity fields carried in the (signed) payload:
    // fingerprint over the ML-DSA key, and keyId over BOTH public keys. These
    // don't add trust (the keys are the seal's own), but they make the identity
    // fields the signature commits to actually correspond to the keys present.
    const fingerprintOk = sha256Hex(mldsa65Pub) === seal.keys.mldsa65Fpr;
    const expectedKeyId = crypto
      .createHash("sha256")
      .update(ed25519Pub)
      .update(mldsa65Pub)
      .digest("hex")
      .slice(0, 32);
    const keyIdOk = seal.keyId === expectedKeyId;

    let ed25519 = false;
    try {
      ed25519 = crypto.verify(null, signingInput, ed25519RawToPublicKey(ed25519Pub), ed25519Sig);
    } catch {
      ed25519 = false;
    }

    let mldsa65 = false;
    try {
      mldsa65 = ml_dsa65.verify(mldsa65Sig, signingInput, mldsa65Pub);
    } catch {
      mldsa65 = false;
    }

    return {
      ed25519,
      mldsa65,
      fingerprintOk,
      keyIdOk,
      ok: ed25519 && mldsa65 && fingerprintOk && keyIdOk,
    };
  } catch {
    return fail;
  }
}

// ---------- Internals ----------

function publicMaterial(ed25519PublicRaw: Uint8Array, mldsa65PublicKey: Uint8Array): PqPublicMaterial {
  const ed25519 = b64(ed25519PublicRaw);
  const mldsa65 = b64(mldsa65PublicKey);
  const mldsa65Fpr = sha256Hex(mldsa65PublicKey);
  const keyId = crypto
    .createHash("sha256")
    .update(ed25519PublicRaw)
    .update(mldsa65PublicKey)
    .digest("hex")
    .slice(0, 32);
  return { ed25519, mldsa65, mldsa65Fpr, keyId };
}

/** Extract the raw 32-byte Ed25519 public key from a node KeyObject (SPKI tail). */
function rawEd25519FromKeyObject(pub: crypto.KeyObject): Uint8Array {
  const spki = pub.export({ type: "spki", format: "der" }) as Buffer;
  return Uint8Array.prototype.slice.call(spki, spki.length - ED25519_RAW_PUBLIC_LEN);
}

/** Rebuild a node public KeyObject from a raw 32-byte Ed25519 key. */
function ed25519RawToPublicKey(raw: Uint8Array): crypto.KeyObject {
  if (raw.length !== ED25519_RAW_PUBLIC_LEN) {
    throw new Error(`ed25519 raw public key must be ${ED25519_RAW_PUBLIC_LEN} bytes`);
  }
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
}

function sha256Hex(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * Deterministic JSON serialization (recursively key-sorted, no insignificant
 * whitespace) used as the signing input. The seal payload contains only strings
 * and safe integers, so this is unambiguous without full RFC 8785 number
 * canonicalization. Both signing and verification serialize the identical field
 * set (payload = seal minus `sig`), so the two sides always agree.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
