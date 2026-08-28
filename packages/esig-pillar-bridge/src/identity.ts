// identity.ts
//
// A loaded/generated Pillar identity for THIS process (the esig-mcp
// operator's own agent identity, or the reference recipient's identity in
// examples/pillar-agent) — a thin wrapper over the real `Keychain` class
// (shim.ts) plus two dependency-free pure functions any caller can use to
// derive a UUAID from a raw Ed25519 key without loading Pillar at all.

import path from "node:path";
import { createHash } from "node:crypto";
import { existsSync, statSync } from "node:fs";

import { loadPillar } from "./shim.js";
import type { PillarKeychainInstance, PillarModules } from "./pillar-types.js";
import type { PillarAuditCallback } from "./types.js";

/**
 * `hex(sha256(raw32))[0..16]`, formatted `8-4-4-4-12` — Pillar's
 * `Keychain._localIdFromKey` (identity/keychain.mjs), reimplemented
 * dependency-free so callers can derive/validate a local id without
 * loading Pillar. Hashes the RAW 32 key bytes, never the hex string.
 * Cross-checked against the real `Keychain._localIdFromKey` on 50 random
 * keys in test/identity.test.ts.
 */
export function localIdFromEd25519Key(raw32: Uint8Array): string {
  if (raw32.length !== 32) {
    throw new Error(`localIdFromEd25519Key: expected 32 raw bytes, got ${raw32.length}`);
  }
  const digestHex = createHash("sha256").update(raw32).digest("hex");
  const first16BytesHex = digestHex.slice(0, 32); // first 16 bytes = 32 hex chars
  return [
    first16BytesHex.slice(0, 8),
    first16BytesHex.slice(8, 12),
    first16BytesHex.slice(12, 16),
    first16BytesHex.slice(16, 20),
    first16BytesHex.slice(20, 32),
  ].join("-");
}

/** `uuaid:foundation:agent:<localIdFromEd25519Key(raw32)>`. */
export function uuaidFromEd25519Key(raw32: Uint8Array): string {
  return `uuaid:foundation:agent:${localIdFromEd25519Key(raw32)}`;
}

export interface PillarIdentityLoadOptions {
  /** Directory holding `keychain.json`. */
  home: string;
  /** Falls back to `ESIG_PILLAR_PASSPHRASE`, then `PILLAR_PASSPHRASE`, then `""` (which then fails the minimum-length check below). */
  passphrase?: string;
  /** Fires `{action:"pillar.identity_loaded"|"pillar.identity_generated", uuaid, fingerprint}` on success — never the passphrase or key material (RT-2026-08-28-01 F4/G4). */
  onAudit?: PillarAuditCallback;
}

export interface PillarIdentityGenerateOptions extends PillarIdentityLoadOptions {
  uuaidNamespace?: string;
  objectType?: string;
}

/** RT-2026-08-28-01 G4: same floor as `ESIG_MCP_PASSPHRASE` — the fleet precedent (PILLAR-P1) is 144 identities burned on an empty default passphrase. */
const MIN_PASSPHRASE_LENGTH = 24;

function resolvePassphrase(explicit?: string): string {
  return explicit ?? process.env.ESIG_PILLAR_PASSPHRASE ?? process.env.PILLAR_PASSPHRASE ?? "";
}

function assertPassphraseStrength(passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(
      `PillarIdentity: passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters (set ESIG_PILLAR_PASSPHRASE, or PILLAR_PASSPHRASE, or pass { passphrase } explicitly) — got ${passphrase.length}`
    );
  }
}

/** RT-2026-08-28-01 F4/G4: refuse to load a keychain file readable/writable by group or other — it should be 0600, owner-only. */
function assertKeychainModeSafe(keychainPath: string): void {
  const mode = statSync(keychainPath).mode & 0o777;
  if (mode & 0o077) {
    throw new Error(
      `PillarIdentity: refusing to load ${keychainPath} — file mode ${mode.toString(8).padStart(3, "0")} is readable/writable by group or other (expected 0600); chmod 600 it before loading`
    );
  }
}

/** A short, non-secret correlation id for audit events — sha256 of the raw public key, truncated. Never derived from the passphrase or private key. */
function fingerprintOf(publicKeyHex: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 16);
}

/** A loaded or freshly generated Pillar identity. */
export class PillarIdentity {
  private constructor(private readonly keychain: PillarKeychainInstance) {}

  get uuaid(): string {
    return this.identityRecord().uuaid;
  }

  get publicKeyHex(): string {
    return this.identityRecord().publicKeyHex;
  }

  /** Raw Ed25519 signature bytes over `bytes`. */
  sign(bytes: Uint8Array | string): Buffer {
    return this.keychain.sign(bytes);
  }

  private identityRecord() {
    if (!this.keychain._identity) throw new Error("PillarIdentity: keychain not loaded");
    return this.keychain._identity;
  }

  /**
   * The real Pillar `Keychain` instance backing this identity — for
   * internal use by `carrier.ts`/`delivery.ts`/`events.ts`/`proofs.ts`
   * only (they need it to call `envelope.seal`/`decrypt` and to construct
   * a `CarrierClient`). Not part of the package's public surface contract.
   */
  _keychain(): PillarKeychainInstance {
    return this.keychain;
  }

  /** Load an existing identity from `<home>/keychain.json`. */
  static async load(opts: PillarIdentityLoadOptions): Promise<PillarIdentity> {
    const passphrase = resolvePassphrase(opts.passphrase);
    assertPassphraseStrength(passphrase);
    const keychainPath = path.join(opts.home, "keychain.json");
    if (existsSync(keychainPath)) {
      assertKeychainModeSafe(keychainPath);
    }
    const pillar: PillarModules = await loadPillar();
    const keychain = new pillar.Keychain(keychainPath);
    keychain.load({ passphrase });
    const identity = new PillarIdentity(keychain);
    opts.onAudit?.({ action: "pillar.identity_loaded", uuaid: identity.uuaid, fingerprint: fingerprintOf(identity.publicKeyHex) });
    return identity;
  }

  /**
   * Generate a fresh identity and persist it (0600) to `<home>/keychain.json`.
   * Never overwrites. The passphrase itself — whether caller-supplied or
   * read from `ESIG_PILLAR_PASSPHRASE`/`PILLAR_PASSPHRASE` — is used only to
   * encrypt the keychain in place (Pillar's own `Keychain.save`); this
   * package never writes it, generated or otherwise, to a file beside
   * `keychain.json` or anywhere else (RT-2026-08-28-01 F4/G4) — the only
   * copies that exist afterward are the caller's own `opts.passphrase`
   * value and whatever 0600 env-var path the caller/CLI owns.
   */
  static async generate(opts: PillarIdentityGenerateOptions): Promise<PillarIdentity> {
    const passphrase = resolvePassphrase(opts.passphrase);
    assertPassphraseStrength(passphrase);
    const pillar: PillarModules = await loadPillar();
    const keychainPath = path.join(opts.home, "keychain.json");
    const keychain = new pillar.Keychain(keychainPath);
    if (keychain.exists()) {
      throw new Error(`PillarIdentity.generate: ${keychainPath} already exists — use load() instead`);
    }
    const identityRecord = pillar.Keychain.generate({
      uuaidNamespace: opts.uuaidNamespace,
      objectType: opts.objectType,
    });
    keychain.save(identityRecord, { passphrase });
    const identity = new PillarIdentity(keychain);
    opts.onAudit?.({ action: "pillar.identity_generated", uuaid: identity.uuaid, fingerprint: fingerprintOf(identity.publicKeyHex) });
    return identity;
  }
}
