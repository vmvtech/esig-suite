// types.ts
//
// Small, LOCAL structural interfaces this package is built against. These
// are documented as "the contract @e-sig/mcp adopts in Stage B"
// (docs/architecture/esig-mcp.md §17 seams 2-4) — deliberately NOT imported
// from `@e-sig/mcp` (its dist is mid-edit under a concurrent lock, see
// .maestro/WALK-esig-mcp-v04.LOCK.md) and deliberately NOT identical to the
// current `packages/esig-mcp/src/delivery.ts` shapes (e.g. today's `Receipt`
// carries a `channel` field this package's `Receipt` does not — Stage B
// reconciles that when it adopts this contract). Treat this file as the
// wire-level target, not a copy of prior art.

/** One signer's delivery target. */
export interface DeliveryLink {
  signerId: string;
  name: string;
  email: string;
  /** `${baseUrl}/sign/<raw token>` — treat as a secret; deliver out-of-band. */
  url: string;
  /** Present when the signer should be reached over Pillar instead of (or in addition to) email. */
  pillar?: {
    /** The signer's `uuaid:foundation:agent:<localId>`. */
    uuaid: string;
    /** The signer's Ed25519 public key, 64 lowercase hex chars (raw 32 bytes). */
    publicKey: string;
  };
}

/** Envelope-level metadata a delivery channel may need. */
export interface DeliveryEnvelopeMeta {
  id: string;
  title: string;
  /** ISO-8601 envelope expiry, if any. */
  expiresAt?: string;
  /** Optional sender note. */
  message?: string;
}

/** Per-signer delivery outcome. */
export interface Receipt {
  signerId: string;
  /**
   * This bridge only ever produces `"pillar"` receipts — `@e-sig/mcp`'s own
   * `Receipt.channel` is `string` (packages/esig-mcp/src/delivery.ts), so
   * this literal is directly assignable to it when Stage B adopts this
   * contract (RT-2026-08-28-01 F6).
   */
  channel: "pillar";
  ok: boolean;
  detail?: string;
  /** The transport's own message id (Pillar envelope id, SMTP Message-ID, etc.) — never the signing URL. */
  messageId?: string;
}

/** A pluggable channel that hands signing links to signers. */
export interface DeliveryChannel {
  deliver(meta: DeliveryEnvelopeMeta, links: DeliveryLink[]): Promise<Receipt[]>;
}

/** One signer, as carried on a lifecycle event. */
export interface EsigEventSigner {
  signerId: string;
  name: string;
  email: string;
  status: string;
}

/**
 * A lifecycle event (docs/architecture/esig-mcp.md §16). `type` and `phase`
 * are typed as `string` here (not the real `EsigEventType`/`EnvelopePhase`
 * union types) to avoid a compile-time dependency on `@e-sig/mcp` — Stage B
 * narrows them back to the real unions when it adopts this contract
 * (RT-2026-08-28-01 F6: this stays `string`, deliberately, on THIS side of
 * the seam; only `@e-sig/mcp`'s own copy carries the real string-literal
 * unions).
 */
export interface EsigEvent {
  id: string;
  type: string;
  /** ISO-8601. */
  createdAt: string;
  envelopeId: string;
  phase: string;
  signer?: EsigEventSigner;
  data: Record<string, unknown>;
}

/** A pluggable sink that publishes lifecycle events. */
export interface EventSink {
  publish(event: EsigEvent): Promise<void>;
}

/**
 * A local structural mirror of `@e-sig/uaid-exch`'s `DataIntegrityProof`
 * (packages/esig-uaid-exch/src/index.ts) — the shape this package passes
 * through untouched. `IdentityProofSource` never verifies a proof itself;
 * it only relays what the recipient sealed, so the caller (Stage B's own
 * `verifyDataIntegrityProof`/`verifyExchange`) does the verification.
 */
export interface DataIntegrityProofLike {
  type: "DataIntegrityProof";
  cryptosuite: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
}

/** What `IdentityProofSource`'s callback receives for one accepted proof. */
export interface IdentityProofEvent {
  envelopeId: string;
  signerId: string;
  uuaid: string;
  proof: DataIntegrityProofLike;
  credential?: unknown;
  /** The Pillar uuaid that sealed the proof envelope (the signer's own identity). */
  senderUuaid: string;
  /** The Pillar envelope id the proof arrived in — replay-guard key. */
  pillarEnvelopeId: string;
}

/** A pluggable source of out-of-band identity proofs (docs/architecture/esig-mcp.md §17 seam 3). */
export interface IdentityProofSource {
  start(onProof: (event: IdentityProofEvent) => void): void;
  stop(): void;
}

/**
 * A structured audit event this package can emit for the operator's own
 * audit store (RT-2026-08-28-01 F2/F4/G1/G4) — `esig-mcp` wires `onAudit`
 * callbacks up to whatever it uses for audit logging. Fields beyond
 * `action` vary by event; never contains a passphrase, private key, or
 * signing material — only identifiers (uuaid, fingerprint, file paths,
 * version strings) safe to persist in a log.
 */
export interface PillarAuditEvent {
  action: string;
  [key: string]: unknown;
}

export type PillarAuditCallback = (event: PillarAuditEvent) => void;
