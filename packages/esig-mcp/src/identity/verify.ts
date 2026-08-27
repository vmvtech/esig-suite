// identity/verify.ts
//
// Signer-identity verification orchestrator (docs/architecture/esig-mcp.md
// §12): L0 (asserted) / L1 (proven, local) / L2 (registry-bound). Called
// from `EnvelopeService.sign()` BEFORE core `recordSignature` — a rejected
// identity throws {@link IdentityError} and the signature is never recorded
// (T10-T14).
//
// ORDERING, AND WHY: this function runs every required check — uuaid
// well-formedness/pin (L0), the local crypto proof (L1), and (L2) the two
// registry calls — WITHOUT touching the store at all, and only consumes the
// challenge nonce + persists the final identity record in ONE atomic write
// (`finalizeChallenge`, challenge.ts), once every required check has
// already passed. This matches the ticket's "success -> persist signer
// identity record ...; only then recordSignature" (verification reads as
// all-or-nothing for a given `minLevel`) and means a transient registry
// outage at L2 does not burn the signer's nonce for a proof that was
// otherwise valid — they can retry the SAME proof once the registry answers,
// rather than needing a whole new challenge round-trip. The proof itself
// (an Ed25519 signature over a fixed nonce) is still only ever consumable
// once the nonce IS consumed, so this ordering does not weaken T11 (replay):
// nothing is accepted as "signed" until finalize succeeds.

import crypto from "node:crypto";
import type { JsonWebKey } from "node:crypto";

import { isWellFormedUuaidAssertion, type EnvelopeStore, type PdfStorageStore } from "@e-sig/core";
import { jcsBytes, publicKeyFromVerificationMethod, verifyChallengeProof } from "@e-sig/uaid-exch";

import { CHALLENGE_TYPE, finalizeChallenge } from "./challenge.js";
import { BadgeError, hexToBytes, verifyRegistryBadge, type BadgePayload } from "./badge.js";
import { bytesEqual, RegistryNotFoundError, type RegistryClient } from "./registry.js";
import {
  getPinnedHtmlSha256,
  getSignerIdentityState,
  setSignerIdentityState,
  IdentityError,
  type IdentityLevel,
  type IdentityProofInput,
  type SignerIdentityRecord,
} from "./types.js";

export interface VerifySignerIdentityInput {
  store: EnvelopeStore;
  tenantId: string;
  envelopeId: string;
  signerId: string;
  minLevel: IdentityLevel;
  expectedUuaid?: string;
  proof?: IdentityProofInput;
  registry?: RegistryClient;
  /**
   * G3: the registry URL this envelope's identity policy pinned at creation
   * (`getEnvelopeIdentityPolicy(envelope)?.registryUrl`, set only when
   * `minLevel === "L2"`). Compared against `configuredRegistryUrl` before
   * any registry call is ever made.
   */
  pinnedRegistryUrl?: string;
  /** G3: the server's CURRENT `ESIG_MCP_UUAID_REGISTRY_URL`, read fresh by the caller at verify time (never cached from creation time). */
  configuredRegistryUrl?: string;
  /**
   * The server's CURRENT `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` — the PINNED
   * registry Ed25519 public key (64 hex) badges are verified against. Unlike
   * the registry URL this is NOT pinned per envelope: the URL pin (G3)
   * already fixes WHICH registry attests, and that registry legitimately
   * rotating its signing key must not strand already-created envelopes — a
   * rotated key simply fails verification (fail closed) until the operator
   * updates config. Required for L2 (fail-closed `L2_NO_REGISTRY_KEY`
   * otherwise, before any network call).
   */
  registrySigningKey?: string;
  /**
   * R1: content-addressed store for identity artifacts (proof JSON,
   * credential JSON if any, resolve-response snapshot). When provided, the
   * raw artifacts are persisted to `blobs/identity/<sha256>.json` (via the
   * same `PdfStorageStore` seam `EnvelopeService` already holds) and the
   * digests this function computes are the SAME digests the blobs are
   * named by. When omitted (e.g. a direct unit-test call), digests are
   * still computed and returned — nothing is persisted to disk.
   */
  blobStore?: PdfStorageStore;
  now?: () => Date;
}

function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function sha256Hex(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * R1: compute the sha256 digest of `bytes` and, when `store` is given,
 * persist them to `blobs/identity/<digest>.json` — the digest returned is
 * ALWAYS the same value whether or not persistence happens, so a caller
 * without a blob store still gets a correct, addressable-if-persisted-later
 * digest (matching `proofDigest`'s pre-existing "always computed" contract).
 */
async function persistIdentityBlob(store: PdfStorageStore | undefined, bytes: Uint8Array): Promise<string> {
  const digest = sha256Hex(bytes);
  if (store) {
    await store.upload({ path: `identity/${digest}.json`, bytes, contentType: "application/json" });
  }
  return digest;
}

const MAX_UNTRUSTED_IDENTITY_STRING_LEN = 256;

/**
 * G7 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, LOW): every
 * registry-sourced or attacker-supplied string this module reads off a
 * presented credential or a registry response (credentialId, the
 * credential's `key.keyId`, the registry's `verifyCredential` reason text)
 * is length-bounded and control-character-free before it is ever used in an
 * `IdentityError` message, an audit row, or (were a future change to add
 * them) the composed HTML identity line — the same defense-in-depth class
 * `envelopes.ts`'s `identityAttestationsHtml` already applies via
 * `escapeHtml` to uuaid/level/keyFingerprint/verifiedAt. `uuaid` itself is
 * NOT re-validated here — it is already length-capped (255) and
 * charset-restricted to `[A-Za-z0-9_-]` by core's own
 * `isWellFormedUuaidAssertion` (pq-seal.ts), enforced earlier in this
 * function for every code path that reaches this point.
 */
function assertSafeIdentityString(
  value: string,
  field: string,
  uuaid: string | undefined,
  level: IdentityLevel,
): string {
  if (value.length > MAX_UNTRUSTED_IDENTITY_STRING_LEN) {
    throw new IdentityError(
      `${field} exceeds ${MAX_UNTRUSTED_IDENTITY_STRING_LEN} characters`,
      "L1_UNSAFE_IDENTITY_STRING",
      uuaid,
      level,
    );
  }
  if (/[\x00-\x1f\x7f]/.test(value)) {
    throw new IdentityError(`${field} contains control characters`, "L1_UNSAFE_IDENTITY_STRING", uuaid, level);
  }
  return value;
}

/**
 * Decode `credentialSubject.key.publicKey` (schema.json:80-89 — a bare
 * `string`, no encoding mandated by the schema) into raw Ed25519 key bytes.
 * Two forms are accepted, both already whitelisted by
 * `publicKeyFromVerificationMethod` (G1c: did:key Ed25519 or a
 * `{kty:"OKP",crv:"Ed25519",x}` JWK — never a network-dereferenced form
 * like did:web or an http(s) URL): a `did:key:` URI passed straight
 * through, or a JSON-encoded JWK object (detected by a leading `{`),
 * parsed and passed through as an object.
 */
function publicKeyFromCredentialKey(publicKey: string): Uint8Array {
  const trimmed = publicKey.trim();
  if (trimmed.startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      throw new Error(`credentialSubject.key.publicKey looks like JSON but does not parse: ${messageOf(e)}`);
    }
    return publicKeyFromVerificationMethod(parsed as JsonWebKey);
  }
  return publicKeyFromVerificationMethod(trimmed);
}

/**
 * Verify a signer's presented identity proof against `minLevel` (the
 * envelope's effective identity policy for this signer). Returns
 * `undefined` when `minLevel` is `"none"` (nothing to verify — the v0.1
 * behavior). Throws {@link IdentityError} on any failure; never downgrades
 * silently (T13 — a down/unreachable registry at L2 is a hard failure, not
 * a fall-back to L1).
 */
export async function verifySignerIdentity(
  input: VerifySignerIdentityInput,
): Promise<SignerIdentityRecord | undefined> {
  if (input.minLevel === "none") return undefined;

  const now = input.now ?? (() => new Date());
  const proof = input.proof;

  // ---- L0: uuaid well-formed, and equal to the pin if one was set ----
  if (!proof || typeof proof.uuaid !== "string") {
    throw new IdentityError(
      "identityProof (with a uuaid) is required for this envelope",
      "IDENTITY_PROOF_REQUIRED",
      proof?.uuaid,
      input.minLevel,
    );
  }
  if (!isWellFormedUuaidAssertion(proof.uuaid)) {
    throw new IdentityError(
      `identityProof.uuaid is not a well-formed uuaid: "${proof.uuaid}"`,
      "L0_MALFORMED_UUAID",
      proof.uuaid,
      input.minLevel,
    );
  }
  if (input.expectedUuaid !== undefined && proof.uuaid !== input.expectedUuaid) {
    throw new IdentityError(
      `identityProof.uuaid "${proof.uuaid}" does not match the uuaid pinned for this signer at ` +
        `envelope creation ("${input.expectedUuaid}")`,
      "L0_UUAID_MISMATCH",
      proof.uuaid,
      input.minLevel,
    );
  }

  if (input.minLevel === "L0") {
    // L0 has no nonce to consume (no cryptographic proof is involved at
    // all) — persist the record with a bounded, retried plain
    // read-modify-write rather than `finalizeChallenge` (which exists to
    // atomically consume a nonce alongside the record; L0 has none).
    const record: SignerIdentityRecord = { level: "L0", uuaid: proof.uuaid, verifiedAt: now().toISOString() };
    await persistL0Record(input.store, input.tenantId, input.envelopeId, input.signerId, record);
    return record;
  }

  // ---- L1: local DataIntegrityProof over the sole-control challenge ----
  if (!proof.proof) {
    throw new IdentityError(
      "identityProof.proof (a DataIntegrityProof) is required for identity level L1",
      "L1_PROOF_REQUIRED",
      proof.uuaid,
      input.minLevel,
    );
  }

  const envelope = await input.store.findById(input.tenantId, input.envelopeId);
  if (!envelope) {
    throw new IdentityError(`envelope not found: ${input.envelopeId}`, "ENVELOPE_NOT_FOUND", proof.uuaid, input.minLevel);
  }
  const challenge = getSignerIdentityState(envelope, input.signerId)?.challenge;
  if (!challenge) {
    throw new IdentityError(
      "no identity challenge has been issued for this signer — call esig_identity_challenge or " +
        "GET /sign/<token>/challenge first",
      "L1_NO_CHALLENGE",
      proof.uuaid,
      input.minLevel,
    );
  }
  if (challenge.consumed) {
    throw new IdentityError("identity challenge has already been used", "L1_NONCE_CONSUMED", proof.uuaid, input.minLevel);
  }
  if (Date.parse(challenge.expiresAt) <= now().getTime()) {
    throw new IdentityError("identity challenge has expired", "L1_CHALLENGE_EXPIRED", proof.uuaid, input.minLevel);
  }

  // G2 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, MED): the
  // IMMUTABLE base-html digest pinned at creation, never recomputed from
  // `envelope.html` — see identity/types.ts's `getPinnedHtmlSha256` header
  // comment for why. Reconstructed ENTIRELY from server-authoritative
  // fields (the pinned digest + the stored challenge) — never trusts a
  // client-supplied document (T10, T11): a forged
  // envelopeId/signerId/htmlSha256/nonce simply fails to reproduce the
  // bytes the presenter actually signed, so the signature check below
  // fails closed.
  const htmlSha256 = getPinnedHtmlSha256(envelope);
  if (!htmlSha256) {
    throw new IdentityError(
      `envelope ${envelope.id} has no pinned base-html digest (metadata.mcp.htmlSha256) — cannot verify a sole-control challenge`,
      "ENVELOPE_MISSING_HTML_DIGEST",
      proof.uuaid,
      input.minLevel,
    );
  }
  const document = {
    type: CHALLENGE_TYPE,
    envelopeId: envelope.id,
    signerId: input.signerId,
    htmlSha256,
    nonce: challenge.nonce,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  };

  const verification = verifyChallengeProof(document, proof.proof, { expectedProofPurpose: "authentication" });
  if (!verification.ok) {
    throw new IdentityError(
      `identity proof verification failed: ${verification.reason}`,
      "L1_PROOF_INVALID",
      proof.uuaid,
      input.minLevel,
    );
  }

  // G1(b)/G6/G7 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, HIGH):
  // resolve the proof's own key ONCE — needed both for the credential-key
  // match right below (checked at ANY level a credential is presented at,
  // not only L2) and for the L2 registry-key-listing check further down.
  // Cannot fail here: `verification` above already succeeded, and
  // `verifyChallengeProof` internally resolves this EXACT
  // `proof.proof.verificationMethod` via this EXACT function before it will
  // ever return `ok: true`.
  const proofRawKey = publicKeyFromVerificationMethod(proof.proof.verificationMethod);

  let credentialId: string | undefined;
  let credentialDigest: string | undefined;
  if (proof.credential) {
    credentialId = assertSafeIdentityString(
      proof.credential.id,
      "identityProof.credential.id",
      proof.uuaid,
      input.minLevel,
    );
    // The real tae/v1 field is credentialSubject.key.publicKey
    // (schema.json:80-89) — G1's original bug named a field that does not
    // exist in the schema at all, so no check against it could ever fire.
    const credentialKey = proof.credential.credentialSubject?.key;
    if (!credentialKey || typeof credentialKey.publicKey !== "string" || credentialKey.publicKey.length === 0) {
      throw new IdentityError(
        "identityProof.credential.credentialSubject.key.publicKey is required when a credential is presented",
        "L1_CREDENTIAL_KEY_MISSING",
        proof.uuaid,
        input.minLevel,
      );
    }
    if (typeof credentialKey.keyId === "string") {
      assertSafeIdentityString(
        credentialKey.keyId,
        "identityProof.credential.credentialSubject.key.keyId",
        proof.uuaid,
        input.minLevel,
      );
    }
    let credentialRawKey: Uint8Array;
    try {
      credentialRawKey = publicKeyFromCredentialKey(credentialKey.publicKey);
    } catch (e) {
      throw new IdentityError(
        `identityProof.credential.credentialSubject.key.publicKey could not be resolved to a key: ${messageOf(e)}`,
        "L1_CREDENTIAL_KEY_UNSUPPORTED",
        proof.uuaid,
        input.minLevel,
      );
    }
    if (!bytesEqual(proofRawKey, credentialRawKey)) {
      throw new IdentityError(
        "identityProof.proof's key does not match identityProof.credential.credentialSubject.key.publicKey",
        "L1_CREDENTIAL_KEY_MISMATCH",
        proof.uuaid,
        input.minLevel,
      );
    }
    // R1: persist the full credential JSON to blobs/identity/<digest>.json —
    // never the raw artifact in audit metadata, only this digest.
    credentialDigest = await persistIdentityBlob(
      input.blobStore,
      Buffer.from(JSON.stringify(proof.credential), "utf8"),
    );
  }

  const record: SignerIdentityRecord = {
    level: "L1",
    uuaid: proof.uuaid,
    keyFingerprint: verification.keyFingerprint,
    // R1: persists the raw proof JSON to blobs/identity/<proofDigest>.json
    // when a blob store is wired — the digest returned here IS the blob's
    // file name, by construction (one hash, one write path).
    proofDigest: await persistIdentityBlob(input.blobStore, jcsBytes(proof.proof)),
    ...(credentialDigest ? { credentialDigest } : {}),
    verifiedAt: now().toISOString(),
  };

  // ---- L2: L1 + registry-bound key + (optionally) credential status ----
  if (input.minLevel === "L2") {
    if (!input.registry) {
      throw new IdentityError(
        "ESIG_MCP_UUAID_REGISTRY_URL is required for identity level L2",
        "L2_NO_REGISTRY",
        proof.uuaid,
        input.minLevel,
      );
    }

    // G3: this envelope's identity policy pinned the registry URL at
    // creation time (envelopes.ts `create()`); refuse BEFORE any network
    // call if the server's CURRENTLY configured registry differs — closes
    // the window where repointing ESIG_MCP_UUAID_REGISTRY_URL between an
    // envelope's creation and a signer's proof would silently change which
    // registry attests the key<->uuaid binding for an already-issued
    // envelope.
    if (input.pinnedRegistryUrl !== undefined && input.pinnedRegistryUrl !== input.configuredRegistryUrl) {
      throw new IdentityError(
        `this envelope's identity policy pinned registry URL "${input.pinnedRegistryUrl}" at creation, but ` +
          `the server is currently configured with "${input.configuredRegistryUrl ?? "(none)"}" — refusing ` +
          "rather than verifying against a different registry than the one this envelope committed to.",
        "L2_REGISTRY_URL_CHANGED",
        proof.uuaid,
        input.minLevel,
      );
    }

    // The pinned registry key is the trust anchor the badge is verified
    // against (identity/badge.ts) — required BEFORE any network call so a
    // misconfigured server fails fast and identically every time.
    if (!input.registrySigningKey) {
      throw new IdentityError(
        "ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY (the pinned registry Ed25519 public key, 64 hex chars from " +
          "the registry's /.well-known/uuaid-registry.json) is required for identity level L2",
        "L2_NO_REGISTRY_KEY",
        proof.uuaid,
        input.minLevel,
      );
    }

    // The badge is the ONLY registry surface carrying an agent's presentation
    // key — and it is registry-signed, so it is verified below against the
    // PINNED key instead of trusting TLS alone. (`/resolve/{uuaid}` carries no
    // signer key material at all — Uuaid-Lead, evidence 2026-08-27.)
    let badgeRaw: unknown;
    try {
      badgeRaw = await input.registry.badge(proof.uuaid);
    } catch (e) {
      if (e instanceof RegistryNotFoundError) {
        // A badge 404 is authoritative (absent, or tombstoned where /resolve
        // would still return 200 — Uuaid-Lead, evidence §4.5).
        throw new IdentityError(
          `registry has no badge for uuaid "${proof.uuaid}": ${messageOf(e)}`,
          "L2_UUAID_NOT_FOUND",
          proof.uuaid,
          input.minLevel,
        );
      }
      // T13: registry down/non-2xx/timeout ⇒ FAIL, never silently drop to L1.
      throw new IdentityError(`registry badge fetch failed: ${messageOf(e)}`, "L2_REGISTRY_UNAVAILABLE", proof.uuaid, input.minLevel);
    }

    let badgePayload: BadgePayload;
    try {
      badgePayload = verifyRegistryBadge(badgeRaw, { pinnedRegistryKey: input.registrySigningKey, now: now() });
    } catch (e) {
      if (e instanceof BadgeError) {
        throw new IdentityError(`registry badge rejected: ${e.message}`, `L2_${e.reason}`, proof.uuaid, input.minLevel);
      }
      throw new IdentityError(`registry badge verification failed: ${messageOf(e)}`, "L2_BADGE_MALFORMED", proof.uuaid, input.minLevel);
    }

    // Blind-verifier finding 2026-08-27: a badge carries its OWN subject —
    // the pinned-key check above proves the registry signed it, not that it
    // is a badge FOR the uuaid being proven. Without this, a registry-signed
    // badge for a different subject B that happens to share (or bear) the
    // proof's key would satisfy every check below. Also catches a
    // missing/empty subject.uuaid (falls through the same `!==`, since
    // `proof.uuaid` is already confirmed non-empty by the L0 well-formed
    // check above).
    if (badgePayload.subject.uuaid !== proof.uuaid) {
      throw new IdentityError(
        `registry badge is for uuaid "${badgePayload.subject.uuaid || "(missing)"}", not the uuaid being proven "${proof.uuaid}"`,
        "L2_BADGE_SUBJECT_MISMATCH",
        proof.uuaid,
        input.minLevel,
      );
    }

    // A SUPERSEDED (or otherwise non-active) agent still yields a perfectly
    // valid badge — `status` is what retires it (Uuaid-Lead, evidence §4.4).
    if (badgePayload.status !== "active") {
      throw new IdentityError(
        `registry status for uuaid "${proof.uuaid}" is "${badgePayload.status}"` +
          `${badgePayload.statusReasonCode ? ` (${badgePayload.statusReasonCode})` : ""} — only an "active" uuaid satisfies L2`,
        "L2_UUAID_NOT_ACTIVE",
        proof.uuaid,
        input.minLevel,
      );
    }

    // The presentation key is the registry's ATTESTATION of the key<->uuaid
    // binding — NOT a proof of key possession (registering a key proves
    // ownership of the AGENT, never possession of the KEY; L1's sole-control
    // challenge above is what supplies possession). Keep the two claims apart
    // in any user-facing copy.
    const presentationKey = badgePayload.subject.presentationKey;
    if (!presentationKey) {
      throw new IdentityError(
        `the registry has NO presentation key bound to uuaid "${proof.uuaid}" (badge subject.presentationKey is null) — ` +
          "the agent must bind its signing key with the registry first; L2 attests only what the registry attests",
        "L2_KEY_NOT_BOUND",
        proof.uuaid,
        input.minLevel,
      );
    }
    let badgeKeyBytes: Uint8Array;
    try {
      if (presentationKey.alg !== "ed25519") {
        throw new BadgeError(`presentationKey.alg is "${presentationKey.alg}", expected "ed25519"`, "BADGE_MALFORMED");
      }
      badgeKeyBytes = hexToBytes(presentationKey.publicKey, 32, "presentationKey.publicKey");
    } catch (e) {
      throw new IdentityError(
        `registry badge presentationKey is unusable: ${messageOf(e)}`,
        "L2_BADGE_MALFORMED",
        proof.uuaid,
        input.minLevel,
      );
    }
    if (!bytesEqual(proofRawKey, badgeKeyBytes)) {
      throw new IdentityError(
        `the registry's attested presentation key does not match this proof's key for uuaid "${proof.uuaid}". ` +
          "Note: when an agent has several active keys the badge reports ONE, chosen arbitrarily by the registry " +
          "(no ordering guarantee) — a mismatch may mean the signer used a different registered key, not that " +
          "the key is unregistered.",
        "L2_KEY_MISMATCH",
        proof.uuaid,
        input.minLevel,
      );
    }

    record.level = "L2";
    record.registry = {
      resolvedAt: now().toISOString(),
      // R1: persist the raw badge envelope (the signed snapshot this decision
      // rests on) so the digest names exactly the bytes that were verified.
      registrySnapshotDigest: await persistIdentityBlob(input.blobStore, Buffer.from(JSON.stringify(badgeRaw), "utf8")),
    };

    if (proof.credential) {
      let verified;
      try {
        verified = await input.registry.verifyCredential(credentialId!);
      } catch (e) {
        throw new IdentityError(
          `registry credential verification failed: ${messageOf(e)}`,
          "L2_CREDENTIAL_UNAVAILABLE",
          proof.uuaid,
          input.minLevel,
        );
      }
      if (verified.reason) {
        assertSafeIdentityString(verified.reason, "registry verifyCredential reason", proof.uuaid, input.minLevel);
      }
      if (!(verified.valid && verified.active && verified.notExpired)) {
        throw new IdentityError(
          `credential ${credentialId} is not usable (valid=${verified.valid}, active=${verified.active}, ` +
            `notExpired=${verified.notExpired}${verified.reason ? `, reason=${verified.reason}` : ""})`,
          "L2_CREDENTIAL_INVALID",
          proof.uuaid,
          input.minLevel,
        );
      }
      // The credential's OWNED subject must equal the proving uuaid: AIAU's
      // exam flow never checks that the caller owns the handle, so a valid
      // credential can exist for a uuaid that never presented anything
      // (Uuaid-Lead, evidence §5 — auditCredentialOrigin, routes.ts:461-500).
      // Asserting the binding here closes that gap on this side for free.
      if (verified.agentUuaid !== proof.uuaid) {
        throw new IdentityError(
          `credential ${credentialId} is bound to ${verified.agentUuaid ? `uuaid "${verified.agentUuaid}"` : "no uuaid (registry returned no agent_uuaid)"}, ` +
            `not the proving uuaid "${proof.uuaid}"`,
          "L2_CREDENTIAL_UUAID_MISMATCH",
          proof.uuaid,
          input.minLevel,
        );
      }
      record.registry.credentialId = credentialId;
      record.registry.credentialValid = true;
    }
  }

  // Every required check for the requested level passed — atomically consume
  // the nonce and persist the final record in ONE write (I3 class; T11).
  const finalized = await finalizeChallenge({
    store: input.store,
    tenantId: input.tenantId,
    envelopeId: input.envelopeId,
    signerId: input.signerId,
    nonce: challenge.nonce,
    record,
    now,
  });
  if (!finalized.ok) {
    throw new IdentityError(
      `could not finalize identity verification: ${finalized.reason}`,
      "L1_FINALIZE_FAILED",
      proof.uuaid,
      input.minLevel,
    );
  }

  return record;
}

const MAX_L0_PERSIST_ATTEMPTS = 5;

/**
 * L0 has no nonce to consume — a plain read-modify-write, but still bounded
 * and retried against the store's own optimistic-concurrency conflict (e.g.
 * `EnvelopeConflictError` from `ConcurrencySafeEnvelopeStore`), the same
 * shape as `finalizeChallenge` minus the nonce re-validation L1/L2 need.
 */
async function persistL0Record(
  store: EnvelopeStore,
  tenantId: string,
  envelopeId: string,
  signerId: string,
  record: SignerIdentityRecord,
): Promise<void> {
  for (let attempt = 0; attempt < MAX_L0_PERSIST_ATTEMPTS; attempt++) {
    const envelope = await store.findById(tenantId, envelopeId);
    if (!envelope) throw new IdentityError(`envelope not found: ${envelopeId}`, "ENVELOPE_NOT_FOUND", record.uuaid, record.level);
    const state = getSignerIdentityState(envelope, signerId);
    setSignerIdentityState(envelope, signerId, { ...state, verified: record });
    try {
      await store.update(envelope);
      return;
    } catch (e) {
      if (attempt === MAX_L0_PERSIST_ATTEMPTS - 1) throw e;
    }
  }
}
