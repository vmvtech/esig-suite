// envelope.ts
//
// Multi-signer envelopes + tokenized signing links, storage-agnostic.
//
// An Envelope tracks N signers over one HTML document. Each signer gets an
// opaque single-use signing token (32-byte CSPRNG, base64url) minted at
// creation and returned to the caller EXACTLY ONCE — only its SHA-256 hash is
// persisted, so a leaked store cannot forge signing links. Signing order is a
// 1-based integer; equal order signs in parallel, lower orders gate higher ones.
//
// Cryptographic model (deliberate, documented): signatures are collected as
// drawn images per signer; when the LAST signer completes, the caller composes
// the final document (`composeEnvelopeHtml`) — the base HTML plus every
// signer's block — and applies ONE cryptographic seal over the whole thing
// (e.g. via `signDocument()`). Sequential *PDF* re-signing is intentionally out
// of scope: the current signer/verifier pair handles a single /ByteRange, so a
// second incremental signature would be invisible to `verifyPdfSignature`.
//
// Persistence is bring-your-own via `EnvelopeStore` (same pattern as
// CertStore). Stores that expect concurrent signers should apply optimistic
// concurrency in `update()` (e.g. a version column) — core performs
// read-modify-write.

import crypto from "node:crypto";

import { assertImageDataUrl, renderSignatureBlocksHtml } from "./signature-block.js";

// ---------- Model ----------

export type EnvelopeStatus =
  | "sent"
  | "partially_signed"
  | "completed"
  | "voided"
  | "expired";

export type EnvelopeSignerStatus = "pending" | "signed" | "declined";

export interface EnvelopeSigner {
  id: string;
  name: string;
  email: string;
  /** Optional role shown above the signature block ("Witness", "CEO", ...). */
  roleLabel?: string;
  /** 1-based signing order; equal values sign in parallel. Default 1. */
  order: number;
  status: EnvelopeSignerStatus;
  /** SHA-256 (hex) of the signing token. The raw token is never persisted. */
  tokenHash: string;
  signedAt?: Date;
  /** Drawn signature (data:image/... URL), set when the signer signs. */
  signatureImageDataUrl?: string;
  declinedAt?: Date;
  declineReason?: string;
}

export interface Envelope {
  id: string;
  tenantId: string;
  title: string;
  /** Base document HTML; signature blocks are appended at completion. */
  html: string;
  status: EnvelopeStatus;
  signers: EnvelopeSigner[];
  createdAt: Date;
  expiresAt?: Date;
  completedAt?: Date;
  voidedAt?: Date;
  metadata?: Record<string, unknown>;
}

// ---------- EnvelopeStore (bring-your-own persistence) ----------

export interface EnvelopeStore {
  insert(envelope: Envelope): Promise<Envelope>;
  /** Full-envelope replace by id. Apply optimistic concurrency here if needed. */
  update(envelope: Envelope): Promise<Envelope>;
  findById(tenantId: string, id: string): Promise<Envelope | null>;
  /** Look up the envelope containing a signer with this token hash (unique). */
  findByTokenHash(tokenHash: string): Promise<Envelope | null>;
}

// ---------- Errors ----------

export class EnvelopeError extends Error {
  constructor(
    public code:
      | "invalid_input"
      | "invalid_token"
      | "not_your_turn"
      | "already_signed"
      | "not_signable"
      | "not_complete",
    message: string,
  ) {
    super(message);
    this.name = "EnvelopeError";
  }
}

// ---------- Creation ----------

export interface CreateEnvelopeInput {
  store: EnvelopeStore;
  tenantId: string;
  title: string;
  html: string;
  signers: Array<{ name: string; email: string; roleLabel?: string; order?: number }>;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

export interface CreateEnvelopeResult {
  envelope: Envelope;
  /**
   * The raw signing tokens, ONE PER SIGNER, returned only here. Deliver each
   * to its signer out-of-band (email link etc.) — they cannot be recovered.
   */
  signingTokens: Array<{ signerId: string; email: string; token: string }>;
}

export async function createEnvelope(input: CreateEnvelopeInput): Promise<CreateEnvelopeResult> {
  if (!input.tenantId) throw new EnvelopeError("invalid_input", "tenantId is required");
  if (!input.html?.trim()) throw new EnvelopeError("invalid_input", "html must be non-empty");
  if (!input.signers?.length) throw new EnvelopeError("invalid_input", "at least one signer is required");
  if (input.expiresAt && input.expiresAt.getTime() <= Date.now()) {
    throw new EnvelopeError("invalid_input", "expiresAt must be in the future");
  }

  const signingTokens: CreateEnvelopeResult["signingTokens"] = [];
  const signers: EnvelopeSigner[] = input.signers.map((s) => {
    if (!s.name?.trim()) throw new EnvelopeError("invalid_input", "signer name must be non-empty");
    if (!s.email?.includes("@")) throw new EnvelopeError("invalid_input", `signer email looks invalid: ${s.email}`);
    const order = s.order ?? 1;
    if (!Number.isInteger(order) || order < 1) {
      throw new EnvelopeError("invalid_input", "signer order must be a positive integer");
    }
    const token = crypto.randomBytes(32).toString("base64url");
    const signer: EnvelopeSigner = {
      id: crypto.randomUUID(),
      name: s.name,
      email: s.email,
      roleLabel: s.roleLabel,
      order,
      status: "pending",
      tokenHash: hashToken(token),
    };
    signingTokens.push({ signerId: signer.id, email: signer.email, token });
    return signer;
  });

  const envelope: Envelope = {
    id: crypto.randomUUID(),
    tenantId: input.tenantId,
    title: input.title,
    html: input.html,
    status: "sent",
    signers,
    createdAt: new Date(),
    expiresAt: input.expiresAt,
    metadata: input.metadata,
  };

  return { envelope: await input.store.insert(envelope), signingTokens };
}

// ---------- Token resolution ----------

export type TokenResolution =
  | { status: "ok"; envelope: Envelope; signer: EnvelopeSigner }
  | { status: "not_your_turn"; envelope: Envelope; signer: EnvelopeSigner; waitingOn: EnvelopeSigner[] }
  | { status: "already_signed"; envelope: Envelope; signer: EnvelopeSigner }
  | { status: "completed" | "voided" | "expired"; envelope: Envelope; signer: EnvelopeSigner }
  | { status: "invalid" };

/**
 * Resolve a raw signing token to its envelope + signer, applying every gate a
 * signing surface needs: token validity, envelope liveness (expiry is applied
 * lazily and persisted), single-use, and signing order.
 */
export async function resolveSigningToken(input: {
  store: EnvelopeStore;
  token: string;
}): Promise<TokenResolution> {
  const envelope = await input.store.findByTokenHash(hashToken(input.token));
  if (!envelope) return { status: "invalid" };
  const signer = envelope.signers.find((s) => s.tokenHash === hashToken(input.token));
  if (!signer) return { status: "invalid" };

  if (envelope.status === "sent" || envelope.status === "partially_signed") {
    if (envelope.expiresAt && envelope.expiresAt.getTime() <= Date.now()) {
      envelope.status = "expired";
      await input.store.update(envelope);
      return { status: "expired", envelope, signer };
    }
  }
  if (envelope.status === "completed") return { status: "completed", envelope, signer };
  if (envelope.status === "voided") return { status: "voided", envelope, signer };
  if (envelope.status === "expired") return { status: "expired", envelope, signer };

  if (signer.status === "signed") return { status: "already_signed", envelope, signer };

  const waitingOn = envelope.signers.filter(
    (s) => s.order < signer.order && s.status !== "signed",
  );
  if (waitingOn.length > 0) return { status: "not_your_turn", envelope, signer, waitingOn };

  return { status: "ok", envelope, signer };
}

// ---------- Signing / declining / voiding ----------

/**
 * Record a signer's drawn signature. Enforces the same gates as
 * `resolveSigningToken`; on the last signature the envelope flips to
 * `completed` (compose + seal with `composeEnvelopeHtml` + `signDocument`).
 */
export async function recordSignature(input: {
  store: EnvelopeStore;
  token: string;
  signatureImageDataUrl: string;
  signedAt?: Date;
}): Promise<Envelope> {
  const res = await resolveSigningToken({ store: input.store, token: input.token });
  if (res.status === "invalid") throw new EnvelopeError("invalid_token", "unknown signing token");
  if (res.status === "not_your_turn") {
    throw new EnvelopeError(
      "not_your_turn",
      `waiting on ${res.waitingOn.length} earlier signer(s)`,
    );
  }
  if (res.status === "already_signed") throw new EnvelopeError("already_signed", "token already used");
  if (res.status !== "ok") throw new EnvelopeError("not_signable", `envelope is ${res.status}`);

  // Same guard the block renderer applies at seal time, applied early so a bad
  // image is rejected at signing time. Throws on anything but a base64 image
  // data URL; returns the whitespace-compacted form we persist.
  let imageDataUrl: string;
  try {
    imageDataUrl = assertImageDataUrl(input.signatureImageDataUrl);
  } catch {
    throw new EnvelopeError(
      "invalid_input",
      "signatureImageDataUrl must be a base64 image data URL (data:image/png;base64,…)",
    );
  }

  const { envelope, signer } = res;
  signer.status = "signed";
  signer.signedAt = input.signedAt ?? new Date();
  signer.signatureImageDataUrl = imageDataUrl;

  const allSigned = envelope.signers.every((s) => s.status === "signed");
  envelope.status = allSigned ? "completed" : "partially_signed";
  if (allSigned) envelope.completedAt = new Date();

  return input.store.update(envelope);
}

/** Decline on behalf of the token's signer; the whole envelope becomes voided. */
export async function declineEnvelope(input: {
  store: EnvelopeStore;
  token: string;
  reason?: string;
}): Promise<Envelope> {
  const res = await resolveSigningToken({ store: input.store, token: input.token });
  if (res.status === "invalid") throw new EnvelopeError("invalid_token", "unknown signing token");
  if (res.status === "already_signed" || res.status === "completed") {
    throw new EnvelopeError("not_signable", "cannot decline after signing");
  }
  if (res.status === "voided" || res.status === "expired") {
    throw new EnvelopeError("not_signable", `envelope is ${res.status}`);
  }

  const { envelope, signer } = res;
  signer.status = "declined";
  signer.declinedAt = new Date();
  signer.declineReason = input.reason;
  envelope.status = "voided";
  envelope.voidedAt = new Date();
  return input.store.update(envelope);
}

/** Sender-side cancellation (no token — tenant + id addressed). */
export async function voidEnvelope(input: {
  store: EnvelopeStore;
  tenantId: string;
  envelopeId: string;
}): Promise<Envelope> {
  const envelope = await input.store.findById(input.tenantId, input.envelopeId);
  if (!envelope) throw new EnvelopeError("invalid_input", "envelope not found");
  if (envelope.status === "completed") {
    throw new EnvelopeError("not_signable", "cannot void a completed envelope");
  }
  envelope.status = "voided";
  envelope.voidedAt = new Date();
  return input.store.update(envelope);
}

// ---------- Completion ----------

/**
 * Compose the final signature-embedded HTML for a COMPLETED envelope: the base
 * document plus one rendered block per signer (name, role, image, timestamp).
 * Feed the result to `signDocument()` (or `renderHtmlToPdf` + `signPdf`) to
 * apply the single cryptographic seal.
 */
export function composeEnvelopeHtml(
  envelope: Envelope,
  opts: { platformLabel?: string; platformUrl?: string } = {},
): string {
  if (envelope.status !== "completed") {
    throw new EnvelopeError("not_complete", `envelope is ${envelope.status}, not completed`);
  }
  const blocks = renderSignatureBlocksHtml({
    signers: envelope.signers.map((s) => ({
      name: s.name,
      email: s.email,
      roleLabel: s.roleLabel,
      signatureImageDataUrl: s.signatureImageDataUrl!,
      signedAt: s.signedAt!,
    })),
    platformLabel: opts.platformLabel,
    platformUrl: opts.platformUrl,
  });
  return `${envelope.html}\n${blocks}`;
}

// ---------- Internals ----------

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token, "utf8").digest("hex");
}
