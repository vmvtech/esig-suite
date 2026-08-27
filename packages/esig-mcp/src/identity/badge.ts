// identity/badge.ts
//
// UUAID registry Verifiable Badge (IAASO-0003) verification for identity
// level L2 (docs/architecture/esig-mcp.md §12). The badge is the registry's
// SIGNED identity snapshot and the ONLY public registry surface that carries
// an agent's presentation key — `GET /resolve/{uuaid}` carries NO signer key
// material for ANY agent (Uuaid-Lead, evidence
// /Volumes/X/uuaid/docs/evidence/2026-08-27-resolve-shape-for-esig-mcp-l2.md),
// so an earlier design that looked for the key on /resolve was a guaranteed
// false negative. The badge is also registry-signed, so L2 can verify it
// against a PINNED key instead of trusting TLS alone.
//
// Wire format (uuaid repo packages/uuaid-core/src/{badge,envelope,canonical,
// signing}.ts @ d5e677c — the deployed api.uuaid.org implementation):
//   SignatureEnvelope { payload,
//                       payloadHash: "0x" + sha256hex(JCS(payload)),
//                       signatures: [{alg, keyId, publicKey: hex,
//                                     signature: hex, created}] }
//   Ed25519 signatures cover UTF8(JCS(payload)) bytes.
//
// This package deliberately does NOT depend on @uuaid/core (same 2026-08-26
// decision that keeps @uuaid/sdk out — see identity/registry.ts). The
// verifier below re-implements exactly the checks L2 needs, fail-closed:
// hash binding, a signature from the PINNED registry key (a badge carries
// its signer's own public key, so without a pin every other check passes
// for a badge anyone minted — uuaid-core's own verifyBadge fails closed the
// same way), and freshness. ML-DSA-65 signatures are present on hybrid
// badges but NOT verified here (no PQ implementation in this package's
// dependency tree) — the pinned classical key is the trust anchor; a hybrid
// badge verifies by its Ed25519 half.

import crypto from "node:crypto";

import { jcsBytes } from "@e-sig/uaid-exch";

export class BadgeError extends Error {
  constructor(
    message: string,
    /** Short machine-checkable reason; identity/verify.ts surfaces it as `L2_<reason>`. */
    public readonly reason: string,
  ) {
    super(message);
    this.name = "BadgeError";
  }
}

/** `payload.subject.presentationKey` — `publicKey` is 64 hex chars (32 raw Ed25519 bytes), lowercase on the live registry (it lowercases on write). */
export interface BadgePresentationKey {
  alg: string;
  publicKey: string;
  keyId: string;
}

/** Only the fields L2 reads; the real payload carries more (credentials, issuer, issuedAt, resolve, …) which passes through untouched. */
export interface BadgePayload {
  subject: {
    uuaid: string;
    presentationKey: BadgePresentationKey | null;
  };
  status: string;
  statusReasonCode?: string;
  freshUntil: string;
}

interface BadgeSignature {
  alg?: unknown;
  keyId?: unknown;
  publicKey?: unknown;
  signature?: unknown;
  created?: unknown;
}

/** hex → bytes; throws {@link BadgeError} unless exactly `bytes` long and all-hex. */
export function hexToBytes(hex: string, bytes: number, what: string): Uint8Array {
  if (hex.length !== bytes * 2 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new BadgeError(`${what} is not ${bytes * 2} hex characters (got ${hex.length})`, "BADGE_MALFORMED");
  }
  return Buffer.from(hex, "hex");
}

// RFC 8410: an Ed25519 SPKI DER is a fixed 12-byte prefix + the 32 raw key bytes.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519Verify(msg: Uint8Array, publicKey: Uint8Array, signature: Uint8Array): boolean {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, msg, key, signature);
  } catch {
    return false;
  }
}

export interface VerifyBadgeOptions {
  /**
   * The PINNED registry Ed25519 public key (64 hex chars) — the trust anchor,
   * `keys[].publicKey` (`uuaid-registry-1`) from
   * `GET /.well-known/uuaid-registry.json`. Pinned at config time
   * (`ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY`); never fetched per-request.
   */
  pinnedRegistryKey: string;
  now?: Date;
}

/**
 * Verify a fetched badge envelope (fail-closed) and return its payload.
 * Checks, in order:
 *   1. structure — a SignatureEnvelope whose payload has subject.uuaid and
 *      freshUntil, plus ≥1 signature;
 *   2. hash binding — `payloadHash` equals sha256(JCS(payload))
 *      ("0x"-prefixed on the wire); a mismatch means the payload was
 *      tampered with;
 *   3. issuer pin — at least one Ed25519 signature whose publicKey EQUALS
 *      the pinned registry key AND verifies over the payload. Every OTHER
 *      Ed25519 signature present must also verify (mirrors uuaid-core's
 *      verifyEnvelope, which requires all signatures to verify). Non-Ed25519
 *      (ML-DSA) signatures are ignored, not verified — see the module header;
 *   4. freshness — `payload.freshUntil` is in the future.
 *
 * Does NOT interpret `status` or the presentation key — that policy lives in
 * identity/verify.ts. JCS is `@e-sig/uaid-exch`'s `jcsBytes`; badge payloads
 * are string/bool/array/object-only by design (uuaid-core avoids floats so
 * any RFC 8785 implementation reproduces the bytes), so it is
 * byte-identical to the signer's canonicalization.
 */
export function verifyRegistryBadge(raw: unknown, opts: VerifyBadgeOptions): BadgePayload {
  const now = opts.now ?? new Date();
  if (!raw || typeof raw !== "object") {
    throw new BadgeError("badge response is not an object", "BADGE_MALFORMED");
  }
  const env = raw as { payload?: unknown; payloadHash?: unknown; signatures?: unknown };
  const payload = env.payload as BadgePayload | undefined;
  if (
    !payload ||
    typeof payload !== "object" ||
    !payload.subject ||
    typeof payload.subject !== "object" ||
    typeof payload.subject.uuaid !== "string" ||
    typeof payload.freshUntil !== "string" ||
    typeof env.payloadHash !== "string" ||
    !Array.isArray(env.signatures) ||
    env.signatures.length === 0
  ) {
    throw new BadgeError("badge response is missing required envelope/payload fields", "BADGE_MALFORMED");
  }

  // 2. hash binding (tamper-evidence).
  const computedHash = "0x" + crypto.createHash("sha256").update(jcsBytes(payload)).digest("hex");
  if (computedHash !== env.payloadHash.toLowerCase()) {
    throw new BadgeError("badge payloadHash does not match sha256(JCS(payload)) — payload tampered", "BADGE_HASH_MISMATCH");
  }

  // 3. issuer pin + signature verification.
  const pinned = opts.pinnedRegistryKey.toLowerCase();
  let pinnedKeyVerified = false;
  for (const sig of env.signatures as BadgeSignature[]) {
    if (!sig || typeof sig !== "object") {
      throw new BadgeError("badge carries a malformed signature entry", "BADGE_MALFORMED");
    }
    if (sig.alg !== "ed25519") continue; // ML-DSA half: present on hybrid badges, not verifiable here
    if (typeof sig.publicKey !== "string" || typeof sig.signature !== "string") {
      throw new BadgeError("badge Ed25519 signature entry is missing publicKey/signature", "BADGE_MALFORMED");
    }
    const ok = ed25519Verify(
      jcsBytes(payload),
      hexToBytes(sig.publicKey, 32, "signature publicKey"),
      hexToBytes(sig.signature, 64, "signature value"),
    );
    if (sig.publicKey.toLowerCase() === pinned) {
      if (!ok) {
        throw new BadgeError("badge signature from the pinned registry key is INVALID", "BADGE_SIGNATURE_INVALID");
      }
      pinnedKeyVerified = true;
    } else if (!ok) {
      // Mirrors uuaid-core verifyEnvelope: every signature present must verify.
      throw new BadgeError("badge carries an invalid non-pinned Ed25519 signature", "BADGE_SIGNATURE_INVALID");
    }
  }
  if (!pinnedKeyVerified) {
    throw new BadgeError(
      "no valid signature from the pinned registry key — the badge signed itself (a badge carries its " +
        "signer's own public key, so only a pin makes it trustworthy)",
      "BADGE_ISSUER_UNTRUSTED",
    );
  }

  // 4. freshness.
  const freshUntilMs = Date.parse(payload.freshUntil);
  if (!Number.isFinite(freshUntilMs) || freshUntilMs < now.getTime()) {
    throw new BadgeError(`badge snapshot is stale (freshUntil ${payload.freshUntil})`, "BADGE_STALE");
  }

  return payload;
}
