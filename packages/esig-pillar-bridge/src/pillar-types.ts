// pillar-types.ts
//
// Hand-written structural types for the five `@uuaid/pillar` modules this
// bridge dynamic-imports via `file://` (shim.ts). Pillar ships no `.d.ts`
// files (plain `.mjs`, no TypeScript in the published package) and a
// dynamic `import()` of a runtime-constructed path is untyped by
// TypeScript regardless — these interfaces exist purely so the REST of
// this package (identity.ts, carrier.ts, delivery.ts, events.ts,
// proofs.ts) gets compile-time checking after the one `as unknown as X`
// cast at the shim boundary (shim.ts's `doLoadPillar`). Field shapes are
// transcribed from the real source read out of the published tarballs
// (`net/envelope.mjs`, `identity/keychain.mjs`, `identity/jcs.mjs`,
// `net/carrier-client.mjs`, `identity/tier.mjs` @ 0.2.0-alpha.12), not
// guessed.

export interface PillarIdentityRecord {
  uuaid: string;
  publicKey: unknown; // node:crypto KeyObject
  privateKey: unknown; // node:crypto KeyObject
  publicKeyHex: string;
  createdAt: string;
}

export interface PillarKeychainInstance {
  readonly path: string;
  _identity: PillarIdentityRecord | null;
  exists(): boolean;
  load(opts?: { passphrase?: string }): PillarIdentityRecord;
  save(identity: PillarIdentityRecord, opts?: { passphrase?: string }): void;
  publicView(): { uuaid: string; publicKeyHex: string; createdAt: string } | null;
  /** Synchronous; returns the raw Ed25519 signature bytes. */
  sign(data: Uint8Array | string): Buffer;
}

export interface PillarKeychainCtor {
  new (path: string): PillarKeychainInstance;
  generate(opts?: {
    uuaidNamespace?: string;
    objectType?: string;
    localId?: string | null;
  }): PillarIdentityRecord;
  /** `sha256(rawPub)[0..16]`, formatted `8-4-4-4-12`. Hashes RAW key bytes, never hex text. */
  _localIdFromKey(rawPub: Uint8Array | Buffer): string;
  verifyDetached(publicKeyHex: string, data: Uint8Array | string, signatureBytes: Uint8Array | Buffer): boolean;
}

export interface PillarEnvelopeEnc {
  alg: string;
  epk: string;
  iv: string;
  ct: string;
}

export interface PillarTransportSignature {
  alg: string;
  keyId: string;
  publicKey: string;
  signature: string;
  created: string;
}

export interface PillarEnvelope {
  version: string;
  id: string;
  sender: string;
  recipient: string;
  kind: string;
  enc: PillarEnvelopeEnc;
  createdAt: string;
  transportSignature: PillarTransportSignature;
}

export interface PillarSealBody {
  recipient: string;
  /** Ed25519 pubkey hex (64 lowercase chars) — REQUIRED, encryption is not optional. */
  recipientPublicKey: string;
  kind?: string;
  payload?: unknown;
  id?: string;
  createdAt?: string;
  sender?: string;
}

export interface PillarOpenVerdict {
  ok: boolean;
  reason?: string;
}

export interface PillarEnvelopeModule {
  ENVELOPE_VERSION: string;
  seal(keychain: PillarKeychainInstance, body: PillarSealBody): PillarEnvelope;
  open(envelope: PillarEnvelope, opts?: { cryptoInventory?: Record<string, string> }): PillarOpenVerdict;
  decrypt(keychain: PillarKeychainInstance, envelope: PillarEnvelope): unknown;
  envelopeSha(envelope: PillarEnvelope): string;
  keychainSeed(keychain: PillarKeychainInstance): Buffer;
  mkEnvelopeId(): string;
}

export interface PillarCarrierAttempt {
  carrier: string;
  ok: boolean;
  seq?: number;
  sha?: string;
  duplicate?: boolean;
  error?: string;
}

export interface PillarCarrierDeliverResult {
  carrier: string;
  seq: number;
  sha: string;
  duplicate: boolean;
  all: PillarCarrierAttempt[];
}

export interface PillarCarrierInboxResult {
  envelopes: Array<{ seq: number; envelope: PillarEnvelope }>;
  now: number;
}

export interface PillarCarrierClientInstance {
  readonly uuaid: string;
  readonly publicKeyHex: string;
  deliver(envelope: PillarEnvelope, opts?: { timeoutMs?: number }): Promise<PillarCarrierDeliverResult>;
  fetchInbox(
    base: string,
    opts?: { since?: number; waitS?: number; timeoutMs?: number }
  ): Promise<PillarCarrierInboxResult>;
  startPolling(opts: {
    onEnvelope: (envelope: PillarEnvelope, ctx: { carrier: string; seq: number }) => Promise<void> | void;
    cursors?: Record<string, number>;
    waitS?: number;
    onError?: (err: Error, ctx: { carrier: string }) => void;
  }): { stop(): void; cursors(): Record<string, number>; done: Promise<unknown> };
}

export interface PillarCarrierClientCtor {
  new (opts: { keychain: PillarKeychainInstance; carriers: string[]; tierGrant?: unknown }): PillarCarrierClientInstance;
}

export interface PillarTierDefault {
  envelopesPerMin: number;
  maxBodyBytes: number;
}

export interface PillarTierGrant {
  v: 1;
  uuaid: string;
  tier: string;
  envelopesPerMin: number;
  maxBodyBytes: number;
  expires: string;
  issuer: string;
  sig: string;
}

export interface PillarTierModule {
  TIER_DEFAULTS: Record<string, PillarTierDefault>;
  ABSOLUTE_MAX_BODY: number;
  ABSOLUTE_MAX_RATE: number;
  makeTierGrant(
    keychain: PillarKeychainInstance,
    opts: { uuaid: string; tier: string; envelopesPerMin?: number; maxBodyBytes?: number; expires: string }
  ): PillarTierGrant;
  verifyTierGrant(
    grant: PillarTierGrant,
    trustedIssuers: string[],
    now?: number
  ): { ok: boolean; reason?: string; grant?: PillarTierGrant };
  grantFingerprint(grant: PillarTierGrant): string;
}

/** Everything {@link import("./shim.js").loadPillar} resolves. */
export interface PillarModules {
  /** Pillar's `src/` directory. */
  root: string;
  /** `@uuaid/pillar`'s `package.json` `version`. */
  version: string;
  envelope: PillarEnvelopeModule;
  Keychain: PillarKeychainCtor;
  jcs: (value: unknown) => string;
  CarrierClient: PillarCarrierClientCtor;
  /** `null` when `identity/tier.mjs` is absent from the resolved Pillar tree. */
  tier: PillarTierModule | null;
}
