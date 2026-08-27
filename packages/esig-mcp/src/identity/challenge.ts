// identity/challenge.ts
//
// The sole-control challenge (docs/architecture/esig-mcp.md §12
// "Challenge"): issued per signer, single-use, 15-minute default TTL,
// JCS-canonical. Two entry points share `issueChallenge` —
// `GET /sign/<token>/challenge` (http.ts) and the MCP tool
// `esig_identity_challenge` (tools/identity-challenge.ts) — both via
// `EnvelopeService.issueIdentityChallenge` (envelopes.ts), which also
// applies the hourly rate limit and audits `signer.challenge_issued`.

import crypto from "node:crypto";

import type { EnvelopeStore } from "@e-sig/core";

import { getPinnedHtmlSha256, getSignerIdentityState, setSignerIdentityState, type SignerIdentityRecord } from "./types.js";

export const CHALLENGE_TYPE = "esig-signer-challenge/v1";

export interface IdentityChallengePayload {
  type: typeof CHALLENGE_TYPE;
  envelopeId: string;
  signerId: string;
  htmlSha256: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export class ChallengeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChallengeError";
  }
}

export interface IssueChallengeInput {
  store: EnvelopeStore;
  tenantId: string;
  envelopeId: string;
  signerId: string;
  /** Seconds. `ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC` (config.ts), default 900. */
  ttlSec: number;
  now?: () => Date;
}

/**
 * Issue a challenge for one signer. G5 (RedTeam
 * rt-verdict-ESIGMCP-V02-IDENTITY-20260827, LOW): IDEMPOTENT within TTL — a
 * live, unconsumed, unexpired challenge already on this signer is returned
 * AS-IS (same nonce) rather than being rotated out. Rotating on every call
 * used to mean a signer who reloaded the approval page, or a sender agent
 * relaying via `esig_identity_challenge` while the signer's own page had
 * already issued one, could silently invalidate a challenge someone was in
 * the middle of signing. A fresh nonce is only ever minted when the prior
 * one is MISSING, CONSUMED, or EXPIRED — once consumed it stays consumed
 * (finalizeChallenge's own re-validation still applies; this function never
 * un-consumes anything).
 */
export async function issueChallenge(input: IssueChallengeInput): Promise<IdentityChallengePayload> {
  const now = (input.now ?? (() => new Date()))();
  const envelope = await input.store.findById(input.tenantId, input.envelopeId);
  if (!envelope) throw new ChallengeError(`envelope not found: ${input.envelopeId}`);
  // G5: validate the signerId belongs to THIS envelope (never a signerId
  // that happens to exist on a different envelope) — a 400 at the HTTP
  // layer (`GET /sign/<token>/challenge`'s try/catch around this call), an
  // isError tool result at the MCP layer.
  const signer = envelope.signers.find((s) => s.id === input.signerId);
  if (!signer) throw new ChallengeError(`signer not found: ${input.signerId} on envelope ${input.envelopeId}`);

  // G2: the challenge's htmlSha256 is ALWAYS the immutable base html pinned
  // at creation (metadata.mcp.htmlSha256) — never recomputed from
  // `envelope.html` (which would silently track drift if some other code
  // path ever mutated it) and never the composed/render html (which only
  // ever exists as a local variable at seal time, never written back onto
  // the envelope — see envelopes.ts `seal()`'s own I4 content-binding check).
  const htmlSha256 = getPinnedHtmlSha256(envelope);
  if (!htmlSha256) {
    throw new ChallengeError(
      `envelope ${envelope.id} has no pinned base-html digest (metadata.mcp.htmlSha256) — cannot issue an identity challenge`,
    );
  }

  const prior = getSignerIdentityState(envelope, signer.id);
  const existing = prior?.challenge;
  if (existing && !existing.consumed && Date.parse(existing.expiresAt) > now.getTime()) {
    return {
      type: CHALLENGE_TYPE,
      envelopeId: envelope.id,
      signerId: signer.id,
      htmlSha256,
      nonce: existing.nonce,
      issuedAt: existing.issuedAt,
      expiresAt: existing.expiresAt,
    };
  }

  const nonce = crypto.randomBytes(32).toString("base64url");
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + input.ttlSec * 1000).toISOString();

  const payload: IdentityChallengePayload = {
    type: CHALLENGE_TYPE,
    envelopeId: envelope.id,
    signerId: signer.id,
    htmlSha256,
    nonce,
    issuedAt,
    expiresAt,
  };

  setSignerIdentityState(envelope, signer.id, { ...prior, challenge: { nonce, issuedAt, expiresAt, consumed: false } });
  await input.store.update(envelope);

  return payload;
}

export interface FinalizeChallengeInput {
  store: EnvelopeStore;
  tenantId: string;
  envelopeId: string;
  signerId: string;
  /** The nonce a proof was already verified over — re-checked fresh at write time (defense against a re-issue racing this call). */
  nonce: string;
  record: SignerIdentityRecord;
  now?: () => Date;
}

export type FinalizeChallengeResult = { ok: true } | { ok: false; reason: string };

const MAX_FINALIZE_ATTEMPTS = 5;

/**
 * Atomically mark the given nonce consumed AND persist `record` as the
 * signer's verified identity, in ONE read-CAS-write (I3 class — the same
 * mechanism `ConcurrencySafeEnvelopeStore.update()` gives
 * `EnvelopeService.sign()`'s own signature race, see stores.ts). Called only
 * AFTER every required verification step (crypto proof, and — for L2 — the
 * registry checks) has already passed (see identity/verify.ts's header
 * comment for why finalize is the LAST step, not interleaved with them).
 *
 * Re-validates the challenge (exists / not consumed / matches nonce / not
 * expired) against a FRESH read on every attempt: a concurrent
 * finalize/re-issue that wins the race is a real rejection (T11 replay
 * defense), not a transient conflict to retry past — only an
 * `EnvelopeStore.update()` throw (the store's own optimistic-concurrency
 * conflict, e.g. `EnvelopeConflictError`) is retried, bounded.
 */
export async function finalizeChallenge(input: FinalizeChallengeInput): Promise<FinalizeChallengeResult> {
  const now = (input.now ?? (() => new Date()))();
  for (let attempt = 0; attempt < MAX_FINALIZE_ATTEMPTS; attempt++) {
    const envelope = await input.store.findById(input.tenantId, input.envelopeId);
    if (!envelope) return { ok: false, reason: `envelope not found: ${input.envelopeId}` };
    const state = getSignerIdentityState(envelope, input.signerId);
    const challenge = state?.challenge;
    if (!challenge) return { ok: false, reason: "no challenge has been issued for this signer" };
    if (challenge.consumed) return { ok: false, reason: "challenge nonce already consumed" };
    if (challenge.nonce !== input.nonce) return { ok: false, reason: "nonce does not match the currently issued challenge" };
    if (Date.parse(challenge.expiresAt) <= now.getTime()) return { ok: false, reason: "challenge has expired" };

    setSignerIdentityState(envelope, input.signerId, {
      ...state,
      challenge: { ...challenge, consumed: true },
      verified: input.record,
    });
    try {
      await input.store.update(envelope);
      return { ok: true };
    } catch (e) {
      if (attempt === MAX_FINALIZE_ATTEMPTS - 1) throw e;
      // A concurrent writer won the CAS — retry from a fresh read (I3 class).
    }
  }
  return { ok: false, reason: "could not finalize identity verification (concurrent update contention)" };
}
