// identity/types.ts
//
// Shared shapes for signer identity via UUAID + IAASO
// (docs/architecture/esig-mcp.md §12). Levels map 1:1 onto the IAASO
// assurance ladder — this package defines no levels of its own.

import type { Envelope } from "@e-sig/core";
import type { DataIntegrityProof, UaidExchange, UaidSigningCredential } from "@e-sig/uaid-exch";

export type IdentityLevel = "none" | "L0" | "L1" | "L2";

export const IDENTITY_LEVEL_ORDER: Record<IdentityLevel, number> = { none: 0, L0: 1, L1: 2, L2: 3 };

/** The stronger of two levels — the ONLY direction `esig_create_envelope`'s requested level may move config's floor (design doc §12 "Policy": "may only raise"). */
export function maxIdentityLevel(a: IdentityLevel, b: IdentityLevel): IdentityLevel {
  return IDENTITY_LEVEL_ORDER[a] >= IDENTITY_LEVEL_ORDER[b] ? a : b;
}

/** `esig_create_envelope`'s `identity` input, resolved and persisted on the envelope (envelopes.ts `create()`). */
export interface EnvelopeIdentityPolicy {
  minLevel: IdentityLevel;
  /** Per-signer expected uuaid pin, keyed by signerId (T12: identity substitution). */
  signers: Record<string, { expectedUuaid?: string }>;
  /**
   * G3 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, MED): the
   * `ESIG_MCP_UUAID_REGISTRY_URL` this envelope committed to at CREATION
   * time, set only when `minLevel === "L2"` (the only level that ever
   * consults a registry). `identity/verify.ts` refuses (`L2_REGISTRY_URL_CHANGED`)
   * if the server's CURRENTLY configured registry URL differs from this
   * pinned value at verify time — closing the window where an operator
   * (or an attacker with config access) could repoint the registry between
   * an envelope's creation and a signer's proof, silently changing which
   * registry attests the key<->uuaid binding for an already-issued envelope.
   */
  registryUrl?: string;
}

/** The single-use sole-control challenge state persisted on a signer (§12 "Challenge"). */
export interface SignerChallengeState {
  nonce: string;
  /**
   * ISO-8601. Recorded alongside the nonce (beyond the ticket's illustrative
   * `{nonce, expiresAt, consumed:false}`) because `identity/verify.ts` must
   * recompute the EXACT JCS document the presenter signed
   * (`{type, envelopeId, signerId, htmlSha256, nonce, issuedAt, expiresAt}`,
   * §12 "Challenge") to verify the proof — `issuedAt` is part of that
   * document and is wall-clock-at-issue, so it cannot be recomputed; it must
   * be stored to be reproduced.
   */
  issuedAt: string;
  /** ISO-8601. */
  expiresAt: string;
  consumed: boolean;
}

export interface SignerIdentityRegistryRecord {
  resolvedAt: string;
  credentialId?: string;
  credentialValid?: boolean;
  receiptId?: string;
  anchor?: unknown;
  /**
   * R1: sha256 digest of the raw `GET /resolve/{uuaid}` response body
   * persisted to `blobs/identity/<digest>.json` (via the same
   * `PdfStorageStore` seam `pdfStorage` already gives `EnvelopeService`) —
   * the full snapshot lives in the blob, never in audit metadata.
   */
  registrySnapshotDigest?: string;
}

/** What gets recorded per signer once identity is verified (§12 "What gets recorded"). */
export interface SignerIdentityRecord {
  level: IdentityLevel;
  uuaid: string;
  /** sha256 hex of the raw 32-byte Ed25519 public key. Absent at L0 — no cryptographic proof is required at that level. */
  keyFingerprint?: string;
  /**
   * sha256 hex of `jcs(proof)`. Absent at L0. R1: this is now also the
   * content-addressed digest of the blob the raw proof JSON was persisted
   * under (`blobs/identity/<proofDigest>.json`) whenever a blob store is
   * wired — the SAME digest, by construction (one hash, one write path),
   * never a separately-computed value that could drift from the file name.
   */
  proofDigest?: string;
  /** R1: sha256 digest of the presented credential JSON, persisted the same way as `proofDigest`. Present only when `identityProof.credential` was supplied. */
  credentialDigest?: string;
  verifiedAt: string;
  registry?: SignerIdentityRegistryRecord;
}

export interface SignerIdentityState {
  challenge?: SignerChallengeState;
  verified?: SignerIdentityRecord;
}

export interface EnvelopeIdentityMetadata {
  policy?: EnvelopeIdentityPolicy;
  /** Keyed by signerId. */
  signers?: Record<string, SignerIdentityState>;
}

/**
 * `POST /sign/<token>`'s optional `identityProof` (§12 "Presenting a
 * proof") / `esig_create_envelope`'s per-signer uuaid pin echoed back at
 * sign time. `proof` is required from L1 up; a bare `{uuaid}` is enough for
 * L0 (asserted-only, no cryptographic proof involved).
 */
export interface IdentityProofInput {
  uuaid: string;
  proof?: DataIntegrityProof;
  credential?: UaidSigningCredential;
  exchange?: UaidExchange;
}

/** Thrown by `identity/verify.ts` on any identity failure. `POST /sign` maps this to 403 `{error, reason}` (http.ts); `EnvelopeService.sign()` audits `signer.identity_rejected` from it before rethrowing. */
export class IdentityError extends Error {
  constructor(
    message: string,
    /** A short machine-checkable code, e.g. `"L1_PROOF_INVALID"` — audited alongside the human message. */
    public readonly reason: string,
    public readonly uuaid?: string,
    public readonly level?: IdentityLevel,
  ) {
    super(message);
    this.name = "IdentityError";
  }
}

// ============================================================================
// envelope.metadata.mcp.identity accessors
// ============================================================================
//
// `Envelope.metadata` (core, envelope.ts) is a bare `Record<string, unknown>`.
// This package's own `mcp` bucket within it (`McpEnvelopeMetadata`,
// envelopes.ts) is not exported — these accessors reach into
// `metadata.mcp.identity` at the same untyped-at-the-edges level core itself
// uses, and are the ONLY place in this package that does so directly;
// everything else (challenge.ts, verify.ts, envelopes.ts, http.ts) goes
// through them. Every setter replaces the `identity`/`signers` object with a
// FRESH one (never mutates in place beyond that) so `envelopes.ts`'s own
// `envelope.metadata = {...envelope.metadata, mcp: {...mcpMeta(envelope), ...}}`
// spread pattern (seal()/create()) always carries the latest identity data
// forward untouched.

interface McpMetadataBucket {
  identity?: EnvelopeIdentityMetadata;
  [key: string]: unknown;
}

function mcpBucket(envelope: Envelope): McpMetadataBucket {
  const metadata = (envelope.metadata ?? {}) as Record<string, unknown>;
  const mcp = (metadata.mcp ?? {}) as McpMetadataBucket;
  metadata.mcp = mcp;
  envelope.metadata = metadata;
  return mcp;
}

export function getEnvelopeIdentityPolicy(envelope: Envelope): EnvelopeIdentityPolicy | undefined {
  return mcpBucket(envelope).identity?.policy;
}

/**
 * G2 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, MED): the IMMUTABLE
 * base-html sha256 pinned at creation (`envelopes.ts` `create()`'s
 * `metadata: { mcp: { htmlSha256, ... } }` — set unconditionally for every
 * envelope, never only when identity is required). Read-only accessor,
 * deliberately separate from `mcpBucket()`'s mutating helpers above: this
 * value must never be RECOMPUTED from `envelope.html` at challenge/verify
 * time (that would silently track whatever `envelope.html` happens to hold,
 * defeating the point of pinning it) — every caller that needs "the html
 * this envelope committed to" reads it from here.
 */
export function getPinnedHtmlSha256(envelope: Envelope): string | undefined {
  const metadata = (envelope.metadata ?? {}) as Record<string, unknown>;
  const mcp = (metadata.mcp ?? {}) as Record<string, unknown>;
  return typeof mcp.htmlSha256 === "string" ? mcp.htmlSha256 : undefined;
}

export function setEnvelopeIdentityPolicy(envelope: Envelope, policy: EnvelopeIdentityPolicy): void {
  const mcp = mcpBucket(envelope);
  mcp.identity = { ...mcp.identity, policy };
}

export function getSignerIdentityState(envelope: Envelope, signerId: string): SignerIdentityState | undefined {
  return mcpBucket(envelope).identity?.signers?.[signerId];
}

export function setSignerIdentityState(envelope: Envelope, signerId: string, state: SignerIdentityState): void {
  const mcp = mcpBucket(envelope);
  const identity = mcp.identity ?? {};
  mcp.identity = { ...identity, signers: { ...identity.signers, [signerId]: state } };
}
