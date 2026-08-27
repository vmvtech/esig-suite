/**
 * @e-sig/uaid-exch — local proof verification.
 *
 * Verifies the two `DataIntegrityProof` entries `createExchange()` produces
 * (./index.ts:197-254) without any network round-trip, plus a generic
 * `verifyDataIntegrityProof`/`verifyChallengeProof` pair usable for any
 * JCS-canonicalizable document carrying an `eddsa-jcs-2022` proof — this is
 * the local (L1) leg of the UUAID/IAASO signer-identity ladder described in
 * docs/architecture/esig-mcp.md § 12 ("L1 proven"): a sole-control challenge
 * signed by the presenter, verified here with no registry call.
 *
 * SIGNED-BYTES CONSTRUCTION — divergence from W3C eddsa-jcs-2022 (documented,
 * intentional; ADR note per docs/architecture/esig-mcp.md § 12 "Bindings"):
 * the W3C Data Integrity `eddsa-jcs-2022` cryptosuite signs
 * `sha256(JCS(proofConfig)) || sha256(JCS(document))` — a hash of the proof
 * options (everything in the proof object except `proofValue`) concatenated
 * with a hash of the document. `createExchange()` (./index.ts:229-234) does
 * NOT do this: it JCS-canonicalizes ONLY the exchange body with the `proof`
 * property omitted (`const canonicalBytes = jcsBytes(body)`, ./index.ts:229)
 * and signs those bytes directly — the proof's own `created`,
 * `verificationMethod`, and `proofPurpose` fields are never part of the
 * signed input, and there is no proof-config hash at all. Every function
 * below mirrors `createExchange` exactly (interop with our own artifacts
 * wins per the build ticket), NOT the W3C double-hash construction. See the
 * "signs jcsBytes(document) directly (createExchange's construction), not
 * the W3C eddsa-jcs-2022 proofConfig-hash construction" test in
 * tests/verify.test.ts for a pinned, human-checkable example of the
 * divergence.
 *
 * Key resolution supports two `verificationMethod` shapes (docs/architecture
 * /esig-mcp.md § 12 T10): a `did:key:z...` URI (multibase + multicodec
 * Ed25519) and a raw JWK (`{kty:"OKP", crv:"Ed25519", x}` — EXACTLY those
 * three fields, no more; RedTeam G6, rt-verdict-ESIGMCP-V02-IDENTITY-20260827:
 * a JWK carrying any other property, notably `d` (the RFC 8037 §2 PRIVATE
 * half of an OKP/Ed25519 keypair), is rejected outright rather than having
 * its extra fields silently ignored). This is also the encoding
 * `UaidSigningCredential.credentialSubject.key.publicKey` uses when it
 * carries a JWK rather than a `did:key:` string (./index.ts, schema.json:
 * 80-89 — the real tae/v1 field; the previous doc reference here,
 * `credentialSubject.authenticator.public_key_jwk`, named a field that does
 * not exist in the schema and has been corrected). A bare `"ed25519:<hex64>"` form was considered per the
 * build ticket and rejected: neither `createExchange` (./index.ts:141-151,
 * `AgentSigner.verificationMethod` is documented as
 * `uuaid:foundation:agent:<uuid>#sk-...`) nor any test in tests/ uses that
 * shape, so it is not implemented — inventing an unused key format would be
 * unverifiable surface area.
 */

import { createHash, createPublicKey, verify as ed25519Verify } from "node:crypto";
import {
  jcsBytes,
  type DataIntegrityProof,
  type UaidExchange,
} from "./index.js";

// ============================================================================
// Multibase (only the two prefixes UAP-EXCH-1 / did:key use)
// ============================================================================

/** The multibase prefixes this module understands: `z` = base58btc, `u` = base64url (unpadded). */
export type MultibasePrefix = "z" | "u";

const BASE58BTC_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58BTC_INDEX = new Map<string, number>(
  Array.from(BASE58BTC_ALPHABET).map((c, i) => [c, i])
);

/**
 * Decode a multibase string: `z` prefix → base58btc, `u` prefix →
 * base64url (unpadded, per the multibase spec). Any other (or missing)
 * prefix throws.
 */
export function decodeMultibase(value: string): Uint8Array {
  if (typeof value !== "string" || value.length < 1) {
    throw new Error("decodeMultibase: expected a non-empty multibase string");
  }
  const prefix = value[0];
  const rest = value.slice(1);
  if (prefix === "z") return base58btcDecode(rest);
  if (prefix === "u") return base64UrlDecode(rest);
  throw new Error(
    `decodeMultibase: unsupported multibase prefix ${JSON.stringify(prefix)}`
  );
}

/** Encode bytes as multibase under the given prefix. Counterpart to {@link decodeMultibase}, used by tests and by callers building their own did:key values. */
export function encodeMultibase(
  bytes: Uint8Array,
  prefix: MultibasePrefix
): string {
  if (prefix === "z") return "z" + base58btcEncode(bytes);
  if (prefix === "u") return "u" + base64UrlEncode(bytes);
  throw new Error(
    `encodeMultibase: unsupported multibase prefix ${JSON.stringify(prefix)}`
  );
}

/** Inline base58btc decoder (Bitcoin alphabet) — no dependency. */
function base58btcDecode(s: string): Uint8Array {
  let num = 0n;
  for (const ch of s) {
    const digit = BASE58BTC_INDEX.get(ch);
    if (digit === undefined) {
      throw new Error(`decodeMultibase: invalid base58btc character ${JSON.stringify(ch)}`);
    }
    num = num * 58n + BigInt(digit);
  }
  let hex = num.toString(16);
  if (hex.length % 2 === 1) hex = "0" + hex;
  const body =
    hex.length === 0
      ? new Uint8Array(0)
      : new Uint8Array(hex.match(/.{2}/g)!.map((byte) => parseInt(byte, 16)));
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  const out = new Uint8Array(leadingZeros + body.length);
  out.set(body, leadingZeros);
  return out;
}

/** Inline base58btc encoder — no dependency. */
function base58btcEncode(bytes: Uint8Array): string {
  let num = 0n;
  for (const b of bytes) num = (num << 8n) | BigInt(b);
  let out = "";
  while (num > 0n) {
    const rem = Number(num % 58n);
    out = BASE58BTC_ALPHABET[rem] + out;
    num /= 58n;
  }
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b === 0) leadingZeros++;
    else break;
  }
  return BASE58BTC_ALPHABET[0].repeat(leadingZeros) + out;
}

function base64UrlDecode(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error("decodeMultibase: invalid base64url characters");
  }
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// ============================================================================
// Key resolution — did:key (Ed25519 multicodec) or raw Ed25519 JWK
// ============================================================================

export class UnsupportedVerificationMethodError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedVerificationMethodError";
  }
}

// multicodec varint for "ed25519-pub" (table code 0xed) is the two bytes
// [0xed, 0x01] — 0xed >= 0x80 so the varint continues: byte0 = (0xed & 0x7f)
// | 0x80 = 0xed, byte1 = 0xed >> 7 = 0x01. Verified against did:key spec
// examples (all begin `z6Mk`, decoding to this exact 2-byte prefix).
const ED25519_MULTICODEC_PREFIX = [0xed, 0x01] as const;

/**
 * Resolve the raw 32-byte Ed25519 public key from a `verificationMethod`.
 * Accepts a `did:key:z...` URI (optionally with a `#fragment`, which is
 * ignored — did:key's method-specific-id already IS the key) or a raw
 * `{kty:"OKP", crv:"Ed25519", x}` JWK — EXACTLY those three fields.
 * Anything else throws {@link UnsupportedVerificationMethodError}.
 *
 * G6 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, LOW): a JWK carrying
 * ANY property beyond `{kty, crv, x}` is rejected outright, before the
 * shape check below even runs — most notably `d` (RFC 8037 §2's PRIVATE
 * half of an OKP/Ed25519 keypair). A counterparty handing over `d`
 * alongside `x` is either malformed or testing whether this verifier
 * silently drops unrecognized fields on a key it is about to trust for
 * authentication; either way, "pass the public half, ignore the rest" is
 * the wrong response — reject the whole JWK instead.
 */
const ALLOWED_JWK_FIELDS = new Set(["kty", "crv", "x"]);

export function publicKeyFromVerificationMethod(
  vm: string | JsonWebKey
): Uint8Array {
  if (typeof vm === "string") return publicKeyFromDidKey(vm);
  if (vm && typeof vm === "object") {
    const extra = Object.keys(vm).filter((k) => !ALLOWED_JWK_FIELDS.has(k));
    if (extra.length > 0) {
      throw new UnsupportedVerificationMethodError(
        `unsupported Ed25519 JWK: unexpected extra field(s) ${JSON.stringify(extra)} — only ` +
          `{kty, crv, x} is accepted (G6: no extra key material, e.g. a private "d")`
      );
    }
  }
  if (
    vm &&
    typeof vm === "object" &&
    vm.kty === "OKP" &&
    vm.crv === "Ed25519" &&
    typeof vm.x === "string"
  ) {
    let raw: Uint8Array;
    try {
      raw = base64UrlDecode(vm.x);
    } catch (err) {
      throw new UnsupportedVerificationMethodError(
        `unsupported Ed25519 JWK: invalid base64url "x" (${err instanceof Error ? err.message : String(err)})`
      );
    }
    if (raw.length !== 32) {
      throw new UnsupportedVerificationMethodError(
        `unsupported Ed25519 JWK: expected 32-byte "x", got ${raw.length}`
      );
    }
    return raw;
  }
  throw new UnsupportedVerificationMethodError(
    `unsupported verificationMethod: ${JSON.stringify(vm)}`
  );
}

function publicKeyFromDidKey(vm: string): Uint8Array {
  const match = /^did:key:([^#]+)(?:#.*)?$/.exec(vm);
  if (!match) {
    throw new UnsupportedVerificationMethodError(
      `unsupported verificationMethod: ${JSON.stringify(vm)}`
    );
  }
  let decoded: Uint8Array;
  try {
    decoded = decodeMultibase(match[1]);
  } catch (err) {
    throw new UnsupportedVerificationMethodError(
      `unsupported did:key verificationMethod ${JSON.stringify(vm)}: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    throw new UnsupportedVerificationMethodError(
      `unsupported did:key verificationMethod ${JSON.stringify(vm)}: expected Ed25519 multicodec prefix ` +
        `0xed 0x01 + 32 key bytes (34 bytes total), got ${decoded.length} bytes with prefix ` +
        `0x${(decoded[0] ?? 0).toString(16).padStart(2, "0")} 0x${(decoded[1] ?? 0).toString(16).padStart(2, "0")}`
    );
  }
  return decoded.slice(2);
}

// ============================================================================
// DataIntegrityProof verification
// ============================================================================

// DER SubjectPublicKeyInfo prefix for a raw Ed25519 public key (RFC 8410):
// SEQUENCE { SEQUENCE { OID 1.3.101.112 (Ed25519) } BIT STRING (32 bytes) }.
// Verified live against node:crypto's own SPKI export for a generated
// Ed25519 key (identical 12-byte prefix) before use here.
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export interface DataIntegrityProofOpts {
  /** Override key resolution — skip deriving from `proof.verificationMethod`. */
  publicKey?: Uint8Array;
  /** Reject the proof unless `proof.proofPurpose` equals this. */
  expectedProofPurpose?: "authentication" | "assertionMethod";
}

export interface DataIntegrityVerifyResult {
  ok: boolean;
  reason?: string;
  /** sha256 hex digest of the 32 raw Ed25519 public key bytes, when a key was resolved. */
  keyFingerprint?: string;
  verificationMethod: string;
}

/**
 * Verify an `eddsa-jcs-2022` `DataIntegrityProof` over `document`. `document`
 * must NOT include the `proof` property — pass the same shape
 * `createExchange` signed (everything except `proof`; see the module doc
 * comment on the signed-bytes construction). Never throws: any failure
 * (unknown type/cryptosuite, purpose mismatch, unresolvable or wrong-length
 * key, bad multibase `proofValue`, bad signature) comes back as `ok: false`
 * with a `reason`, fail-closed like the rest of this package
 * (revocation.ts's `verifyRevocationListIntegrity`).
 */
export function verifyDataIntegrityProof(
  document: unknown,
  proof: DataIntegrityProof,
  opts: DataIntegrityProofOpts = {}
): DataIntegrityVerifyResult {
  const verificationMethod = proof?.verificationMethod ?? "";
  try {
    if (proof?.type !== "DataIntegrityProof") {
      return {
        ok: false,
        reason: `unsupported proof type: ${JSON.stringify(proof?.type)}`,
        verificationMethod,
      };
    }
    if (proof.cryptosuite !== "eddsa-jcs-2022") {
      return {
        ok: false,
        reason: `unsupported cryptosuite: ${JSON.stringify(proof.cryptosuite)}`,
        verificationMethod,
      };
    }
    if (
      opts.expectedProofPurpose !== undefined &&
      proof.proofPurpose !== opts.expectedProofPurpose
    ) {
      return {
        ok: false,
        reason: `proofPurpose mismatch: expected "${opts.expectedProofPurpose}", got "${proof.proofPurpose}"`,
        verificationMethod,
      };
    }

    let publicKey: Uint8Array;
    try {
      publicKey = opts.publicKey ?? publicKeyFromVerificationMethod(proof.verificationMethod);
    } catch (err) {
      return {
        ok: false,
        reason: err instanceof Error ? err.message : String(err),
        verificationMethod,
      };
    }
    if (publicKey.length !== 32) {
      return {
        ok: false,
        reason: `invalid public key length: expected 32 bytes, got ${publicKey.length}`,
        verificationMethod,
      };
    }
    const keyFingerprint = sha256Hex(publicKey);

    let signature: Uint8Array;
    try {
      signature = decodeMultibase(proof.proofValue);
    } catch (err) {
      return {
        ok: false,
        reason: `bad multibase proofValue: ${err instanceof Error ? err.message : String(err)}`,
        keyFingerprint,
        verificationMethod,
      };
    }

    const keyObject = createPublicKey({
      key: Buffer.concat([Buffer.from(ED25519_SPKI_PREFIX), Buffer.from(publicKey)]),
      format: "der",
      type: "spki",
    });
    // The exact bytes createExchange signed: jcsBytes(body-without-proof),
    // NOT a W3C proofConfig-hash construction — see module doc comment.
    const signedBytes = jcsBytes(document);
    const sigOk = ed25519Verify(null, signedBytes, keyObject, signature);
    if (!sigOk) {
      return { ok: false, reason: "signature verification failed", keyFingerprint, verificationMethod };
    }
    return { ok: true, keyFingerprint, verificationMethod };
  } catch (err) {
    return {
      ok: false,
      reason: `verification error: ${err instanceof Error ? err.message : String(err)}`,
      verificationMethod,
    };
  }
}

/**
 * Thin alias of {@link verifyDataIntegrityProof} for an arbitrary
 * JCS-canonicalizable document that carries no embedded `proof` field of its
 * own — e.g. the MCP sole-control challenge
 * (docs/architecture/esig-mcp.md § 12: `{type, envelopeId, signerId,
 * htmlSha256, nonce, issuedAt, expiresAt}`, proof presented alongside it,
 * never inside it).
 */
export function verifyChallengeProof(
  challenge: object,
  proof: DataIntegrityProof,
  opts: DataIntegrityProofOpts = {}
): DataIntegrityVerifyResult {
  return verifyDataIntegrityProof(challenge, proof, opts);
}

// ============================================================================
// UaidExchange verification (two proofs: agent = authentication, issuer = assertionMethod)
// ============================================================================

export interface VerifyExchangeOpts {
  agentPublicKey?: Uint8Array;
  issuerPublicKey?: Uint8Array;
}

export interface VerifyExchangeResult {
  ok: boolean;
  agent: DataIntegrityVerifyResult;
  issuer: DataIntegrityVerifyResult;
  failures: string[];
}

/**
 * Verify both proofs on a `UaidExchange` produced by `createExchange`
 * (./index.ts:197-254): `proof[0]` is always the agent's (`authentication`),
 * `proof[1]` is always the issuer's (`assertionMethod`) — createExchange
 * constructs the array in exactly that fixed order (./index.ts:253). Both
 * proofs sign the same canonical bytes: the exchange with its `proof` array
 * removed. Never throws.
 */
export function verifyExchange(
  exchange: UaidExchange,
  opts: VerifyExchangeOpts = {}
): VerifyExchangeResult {
  const proofCount = Array.isArray(exchange?.proof) ? exchange.proof.length : -1;
  if (proofCount !== 2) {
    const reason = `expected exactly 2 proofs (agent, issuer), got ${proofCount < 0 ? "none" : proofCount}`;
    const unresolved: DataIntegrityVerifyResult = { ok: false, reason, verificationMethod: "" };
    return { ok: false, agent: unresolved, issuer: unresolved, failures: [reason] };
  }

  const { proof, ...documentBody } = exchange;
  const [agentProof, issuerProof] = proof;

  const agent = verifyDataIntegrityProof(documentBody, agentProof, {
    publicKey: opts.agentPublicKey,
    expectedProofPurpose: "authentication",
  });
  const issuer = verifyDataIntegrityProof(documentBody, issuerProof, {
    publicKey: opts.issuerPublicKey,
    expectedProofPurpose: "assertionMethod",
  });

  const failures: string[] = [];
  if (!agent.ok) failures.push(`agent: ${agent.reason}`);
  if (!issuer.ok) failures.push(`issuer: ${issuer.reason}`);

  return { ok: agent.ok && issuer.ok, agent, issuer, failures };
}
