// pq-lifecycle.ts
//
// Stack-agnostic "ensure an active post-quantum key bundle for this tenant"
// helper — the ML-DSA-65 / Ed25519 analogue of ensureActiveCert. Depends only on
// the bring-your-own `PqKeyStore` interface plus the crypto in pq-seal; no DB, no
// stack assumptions.
//
// Unlike signing certificates, hybrid key bundles do not expire on a clock —
// rotation is an explicit, deployment-driven decision (e.g. suspected key
// compromise, or a policy roll). `ensureActivePqKeys` therefore generates on
// first use and reuses thereafter; `rotatePqKeys` mints a fresh bundle and links
// the predecessor. Consumers that don't want a managed store can skip this module
// entirely and use generatePqKeyBundle / wrapPqKeyBundle / loadPqSigningKeys
// directly, persisting the wrapped blob wherever they like.

import {
  generatePqKeyBundle,
  loadPqSigningKeys,
  wrapPqKeyBundle,
  unwrapPqKeyBundle,
  type PqSigningKeys,
  type PqPublicMaterial,
} from "./pq-seal.js";

/** A persisted, wrapped post-quantum key bundle + its public identity material. */
export interface StoredPqKeys {
  id: string;
  tenantId: string;
  /** `wrapPqKeyBundle` output (AES-256-GCM). Never store the unwrapped bundle. */
  keyBundleEncrypted: Uint8Array;
  /** base64 raw Ed25519 public key. */
  ed25519Public: string;
  /** base64 raw ML-DSA-65 public key. */
  mldsa65Public: string;
  /** SHA-256 hex of the ML-DSA-65 public key — the identity to publish/pin. */
  mldsa65Fpr: string;
  /** 128-bit hex id over both public keys. */
  keyId: string;
  active: boolean;
  rotatedFromId?: string | null;
  createdAt: Date;
}

/** Bring-your-own persistence for post-quantum key bundles (mirrors CertStore). */
export interface PqKeyStore {
  /** The active bundle for a tenant, or null if none exists yet. */
  findActive(tenantId: string): Promise<StoredPqKeys | null>;
  /** Persist a new bundle. Ensure at most one `active=true` per tenant. */
  insert(input: {
    tenantId: string;
    keyBundleEncrypted: Uint8Array;
    public: PqPublicMaterial;
    rotatedFromId?: string | null;
  }): Promise<StoredPqKeys>;
  /** Mark a bundle inactive (used during rotation). */
  deactivate(id: string): Promise<void>;
}

export interface EnsurePqKeysResult {
  record: StoredPqKeys;
  /** In-memory signing keys ready for `signPdf({ pqSeal: { keys } })`. */
  keys: PqSigningKeys;
  public: PqPublicMaterial;
}

/**
 * Ensure an active post-quantum key bundle for the tenant, generating + wrapping
 * one on first use. `passphrase` (≥24 chars) wraps the bundle at rest.
 */
export async function ensureActivePqKeys(opts: {
  store: PqKeyStore;
  tenantId: string;
  passphrase: string;
}): Promise<EnsurePqKeysResult> {
  const existing = await opts.store.findActive(opts.tenantId);
  if (existing) {
    const bundle = unwrapPqKeyBundle(existing.keyBundleEncrypted, opts.passphrase);
    const keys = loadPqSigningKeys(bundle);
    return {
      record: existing,
      keys,
      public: {
        ed25519: existing.ed25519Public,
        mldsa65: existing.mldsa65Public,
        mldsa65Fpr: existing.mldsa65Fpr,
        keyId: existing.keyId,
      },
    };
  }
  return mint(opts.store, opts.tenantId, opts.passphrase, null);
}

/**
 * Force a rotation: deactivate the current bundle (if any) and mint a fresh one
 * with `rotatedFromId` set. Documents already sealed with the old key keep
 * verifying — verification uses the public key embedded in each seal.
 */
export async function rotatePqKeys(opts: {
  store: PqKeyStore;
  tenantId: string;
  passphrase: string;
}): Promise<EnsurePqKeysResult> {
  const existing = await opts.store.findActive(opts.tenantId);
  if (existing) await opts.store.deactivate(existing.id);
  return mint(opts.store, opts.tenantId, opts.passphrase, existing?.id ?? null);
}

async function mint(
  store: PqKeyStore,
  tenantId: string,
  passphrase: string,
  rotatedFromId: string | null,
): Promise<EnsurePqKeysResult> {
  const { bundle, public: pub } = generatePqKeyBundle();
  const keyBundleEncrypted = wrapPqKeyBundle(bundle, passphrase);
  const record = await store.insert({ tenantId, keyBundleEncrypted, public: pub, rotatedFromId });
  return { record, keys: loadPqSigningKeys(bundle), public: pub };
}
