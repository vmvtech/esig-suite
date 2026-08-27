// stores.ts
//
// Filesystem-backed persistence for @e-sig/mcp v0.1, rooted at
// `config.dataDir`: @e-sig/core/fs already ships CertStore / AuditLogStore /
// PdfStorageStore / EnvelopeStore adapters (fs-adapters.ts) — this file adds
// the two things core does not ship:
//
//   1. FsPqKeyStore — core has no filesystem PqKeyStore (pq-lifecycle.ts is
//      interface-only). This mirrors packages/esig-gateway/src/stores.ts's
//      FsPqKeyStore exactly (same gap, same fix, same on-disk shape), which
//      itself mirrors FsCertStore's shape (fs-adapters.ts:59-126) — see that
//      file's own header comment for why the gap exists.
//   2. ConcurrencySafeEnvelopeStore — see the FINDING below (I3).

import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

import { FsAuditLogStore, FsCertStore, FsEnvelopeStore, FsPdfStorageStore } from "@e-sig/core/fs";
import type {
  AuditLogStore,
  CertStore,
  Envelope,
  EnvelopeStore,
  PdfStorageStore,
  PqKeyStore,
  PqPublicMaterial,
  StoredPqKeys,
} from "@e-sig/core";

import type { Config } from "./config.js";

async function writeJsonAtomic(file: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(value, null, 2), "utf8");
  await fs.rename(tmp, file);
}

async function readJson<T>(file: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as T;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw e;
  }
}

// ---------- FsPqKeyStore ----------

type PqKeysJson = Omit<StoredPqKeys, "keyBundleEncrypted" | "createdAt"> & {
  keyBundleEncrypted: string; // base64
  createdAt: string;
};

/**
 * Filesystem-backed {@link PqKeyStore}. The wrapped bundle
 * (`keyBundleEncrypted`) is AES-256-GCM ciphertext produced by core's
 * `wrapPqKeyBundle` (pq-seal.ts:303-305, itself `encryptKeyPem` under the
 * same passphrase discipline as `FsCertStore`) — this store never sees or
 * persists the unwrapped bundle.
 */
export class FsPqKeyStore implements PqKeyStore {
  private file: string;

  constructor(rootDir: string) {
    this.file = path.join(rootDir, "pq-keys.json");
  }

  private async rows(): Promise<PqKeysJson[]> {
    return readJson<PqKeysJson[]>(this.file, []);
  }

  private static revive(r: PqKeysJson): StoredPqKeys {
    return {
      ...r,
      keyBundleEncrypted: new Uint8Array(Buffer.from(r.keyBundleEncrypted, "base64")),
      createdAt: new Date(r.createdAt),
    };
  }

  async findActive(tenantId: string): Promise<StoredPqKeys | null> {
    const row = (await this.rows()).find((r) => r.tenantId === tenantId && r.active);
    return row ? FsPqKeyStore.revive(row) : null;
  }

  async insert(input: {
    tenantId: string;
    keyBundleEncrypted: Uint8Array;
    public: PqPublicMaterial;
    rotatedFromId?: string | null;
  }): Promise<StoredPqKeys> {
    const rows = await this.rows();
    // At most one active bundle per tenant (PqKeyStore contract, pq-lifecycle.ts:48).
    for (const r of rows) if (r.tenantId === input.tenantId) r.active = false;
    const row: PqKeysJson = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      keyBundleEncrypted: Buffer.from(input.keyBundleEncrypted).toString("base64"),
      ed25519Public: input.public.ed25519,
      mldsa65Public: input.public.mldsa65,
      mldsa65Fpr: input.public.mldsa65Fpr,
      keyId: input.public.keyId,
      active: true,
      rotatedFromId: input.rotatedFromId ?? null,
      createdAt: new Date().toISOString(),
    };
    rows.push(row);
    await writeJsonAtomic(this.file, rows);
    return FsPqKeyStore.revive(row);
  }

  async deactivate(id: string): Promise<void> {
    const rows = await this.rows();
    const row = rows.find((r) => r.id === id);
    if (row) {
      row.active = false;
      await writeJsonAtomic(this.file, rows);
    }
  }
}

// ---------- ConcurrencySafeEnvelopeStore ----------
//
// FINDING (per the ticket's "read the constructors" instruction):
// `FsEnvelopeStore.update` (packages/esig-core/src/fs-adapters.ts:247-254) is
//
//   const rows = await this.rows();
//   const i = rows.findIndex((r) => r.id === envelope.id);
//   rows[i] = FsEnvelopeStore.toJson(envelope);
//   await writeJsonAtomic(this.file, rows);
//
// — a plain read-modify-write with NO version/precondition check. It is not
// conditional or atomic across two racing callers. `EnvelopeStore.update`'s
// own contract flags exactly this gap ("Full-envelope replace by id. Apply
// optimistic concurrency here if needed.", envelope.ts:76), and invariant I3
// requires it: two concurrent `recordSignature` calls on the SAME token must
// yield exactly one success. Left as-is, both concurrent calls would read
// the same "pending" signer state, both pass every core-side gate, and both
// successfully overwrite the row — a real double-sign, silently. Verified
// live (throwaway repro, not kept in the suite): both calls report
// `fulfilled` against the bare `FsEnvelopeStore`.
//
// FIRST DESIGN TRIED, AND WHY IT WAS WRONG (kept as a record — a live bug
// this ticket's own tests caught before landing): an earlier version of this
// class kept the "version" in an in-memory `Map<envelopeId, number>` and
// tagged each `find*()`-returned object (via a `WeakMap`) with "the current
// version at the moment the read's promise resolved". That is measurably
// NOT the same instant as "the version the disk content actually reflects":
// a debug trace of the real race (both calls' `find` issued together, then
// racing to `update`) showed
//
//   find#1 START +3.40ms      find#2 START +3.53ms
//   find#1 END   +3.80ms
//   update#3(A) START +3.96ms   <- A's synchronous version bump happens HERE
//   find#2 END   +4.02ms         <- B's find resolves AFTER A already bumped
//
// — B's disk read completed BEFORE A's write ever reached disk (both reads
// saw the same pre-signature row), but B's wrapper-side tag() ran AFTER A's
// purely-synchronous version bump (a JS-tick race, not a disk race), so B
// was tagged with the ALREADY-BUMPED version and its later `update()` check
// wrongly passed. Both calls ended up "fulfilled" — the exact bug I3 exists
// to catch, reproduced by this package's own concurrency test before this
// fix. Root cause: the "expected version" must come from the ACTUAL DATA
// READ, not from a side-channel counter whose timing is decoupled from disk
// I/O completion order.
//
// D1 FIX (verifier-reproduced, on top of the above): `insert()` below was
// NOT run through the mutex at all — only `update()` was. `FsEnvelopeStore.
// insert` (fs-adapters.ts:240-245) is the same unserialized whole-file
// read-modify-write as `update`: 3 concurrent `insert()` calls each read the
// same on-disk rows array, each push their own row onto their own in-memory
// copy, and whichever `writeJsonAtomic` wins the rename last-write-wins over
// the other two — verified live (throwaway repro): 3 concurrent creates
// persisted only 1 envelope row. And because `insert` and `update` share the
// exact same underlying file, an `insert` racing an `update` (for a
// different envelope) has the identical failure mode even though neither
// call's CAS check (which only compares `__mcpRev` on the SAME row) would
// ever catch it.
//
// Fix: route BOTH `insert` and `update` through the SAME single mutex key —
// this store backs exactly one file, so every call that touches it must
// serialize against every other call that touches it, not just calls
// touching the same envelope id (per-id keying, which `update` used before,
// does not help here: `FsEnvelopeStore` always rewrites the WHOLE file on
// every op regardless of which row changed, so two different envelope ids
// already contend on the same file — per-id mutex keys bought no real
// parallelism, only a false sense of one).
const STORE_KEY = "__store__";

// ACTUAL FIX: a real, persisted revision number, embedded in the envelope
// row itself. `FsEnvelopeStore.toJson`/`revive` (fs-adapters.ts:210-238) both
// naively object-spread (`{...e, ...}` / `{...r, ...}`) with no allowlist, so
// ANY extra property placed directly on the `Envelope` object (not part of
// its TS-declared shape, but present at runtime) round-trips through
// disk-serialize-deserialize untouched. `insert()` stamps a hidden `rev: 0`
// this way; every subsequent `find*()` call returns it as part of the SAME
// atomic disk read that returns everything else, so "the version this
// object was read at" is now tied to real bytes on disk, not JS scheduling.
// `update()` then does a genuine compare-and-swap: under a per-envelope-id
// mutex (`KeyedMutex`, same primitive and rationale as
// packages/esig-gateway/src/stores.ts:112-135's own "per-key async mutex ...
// removes that window without serialising unrelated tenants"), it re-reads
// the CURRENT persisted row fresh, compares its rev to the rev the caller's
// object was stamped with, and only on a match writes rev+1. Because the
// comparison value is re-fetched from the authoritative store immediately
// before the write, under mutual exclusion, it cannot go stale the way the
// in-memory counter did — there is no window where "current" can mean two
// different things depending on which continuation happens to run first.
//
// This is single-process only, matching `FsEnvelopeStore`'s own documented
// scope (fs-adapters.ts:7-10: "NOT multi-process safe").
//
// Limitation (inherent to piggy-backing the rev on the object, not fixable
// without changing `EnvelopeStore`'s shape): this only works when the
// WRAPPED store round-trips arbitrary extra properties the way `FsEnvelopeStore`
// does. A store backed by, say, typed SQL columns that only serializes its
// own known fields would silently drop the rev and defeat this mechanism —
// out of scope for v0.1 (Fs-backed only), flagged for whoever adds a second
// backing store.
//
// Known limitation (not required by I3, noted for the next worker): this is
// an envelope-level version check, so two concurrent `sign()` calls for TWO
// DIFFERENT signers on the same multi-signer envelope will also conflict —
// the loser's write is correctly rejected as stale (it would otherwise
// silently drop the winner's mutation), but nothing here retries it
// automatically. A caller that wants both to eventually succeed must retry
// on `EnvelopeConflictError`.

export class EnvelopeConflictError extends Error {
  constructor(
    public readonly envelopeId: string,
    message: string,
  ) {
    super(message);
    this.name = "EnvelopeConflictError";
  }
}

/** The hidden field name used to piggy-back a revision number on `Envelope` objects — see the class comment above. */
const REV_FIELD = "__mcpRev";

function getRev(e: Envelope): number {
  return ((e as unknown as Record<string, unknown>)[REV_FIELD] as number | undefined) ?? 0;
}

function setRev(e: Envelope, rev: number): void {
  (e as unknown as Record<string, unknown>)[REV_FIELD] = rev;
}

/**
 * Per-key async mutex — same primitive and purpose as
 * packages/esig-gateway/src/stores.ts:112-135's `KeyedMutex` (a read-then-write
 * race removed by serializing per partition key, without serializing
 * unrelated keys). Reimplemented here rather than imported: the gateway
 * package does not export it as a shared dependency of this one.
 */
class KeyedMutex {
  private tails = new Map<string, Promise<void>>();

  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => {
      release = r;
    });
    const tail = prev.then(() => mine);
    this.tails.set(key, tail);

    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
  }
}

export class ConcurrencySafeEnvelopeStore implements EnvelopeStore {
  private readonly mutex = new KeyedMutex();

  constructor(private readonly inner: EnvelopeStore) {}

  async insert(envelope: Envelope): Promise<Envelope> {
    setRev(envelope, 0);
    // D1: serialize against every other insert/update on this store — see
    // the STORE_KEY comment above for why a single shared key is required
    // (this store backs exactly one file; per-envelope-id keying would let
    // two concurrent inserts race the same whole-file read-modify-write).
    return this.mutex.run(STORE_KEY, () => this.inner.insert(envelope));
  }

  async update(envelope: Envelope): Promise<Envelope> {
    const expected = getRev(envelope);
    return this.mutex.run(STORE_KEY, async () => {
      // Re-read the CURRENT persisted state fresh, under the lock, so the
      // comparison is against real bytes on disk at commit time — never a
      // side-channel counter (see the class comment for why that failed).
      const fresh = await this.inner.findById(envelope.tenantId, envelope.id);
      if (!fresh) {
        throw new EnvelopeConflictError(envelope.id, "envelope not found during concurrency check");
      }
      const current = getRev(fresh);
      if (current !== expected) {
        throw new EnvelopeConflictError(
          envelope.id,
          `stale write: envelope was read at rev ${expected}, current rev is ${current} ` +
            "(a concurrent update already won).",
        );
      }
      setRev(envelope, current + 1);
      return this.inner.update(envelope);
    });
  }

  async findById(tenantId: string, id: string): Promise<Envelope | null> {
    return this.inner.findById(tenantId, id);
  }

  async findByTokenHash(tokenHash: string): Promise<Envelope | null> {
    return this.inner.findByTokenHash(tokenHash);
  }
}

// ---------- List convenience (NOT part of the core EnvelopeStore contract) ----------
//
// `EnvelopeStore` (envelope.ts:74-81) has no "list all" method — by design,
// core stays storage-agnostic and a generic list/query API is exactly the
// kind of stack assumption it avoids. `esig_list_envelopes` (design doc §4)
// still needs *something* to enumerate over in v0.1's default filesystem
// deployment, so this reads @e-sig/core/fs's own DOCUMENTED on-disk layout
// directly (fs-adapters.ts:12-16: "envelopes.json — Envelope rows") — the
// same non-contractual-convenience precedent as `FsAuditLogStore.readAll()`
// (fs-adapters.ts:144-146: "not part of the core interface — a convenience
// for local inspection and tests").
//
// Limitation: this only works for the default Fs-backed deployment `buildStores`
// wires up. A deployment that injects a non-filesystem EnvelopeStore (e.g. a
// future @e-sig/supabase-backed one) will need its own list() path — out of
// scope for v0.1.

interface RawEnvelopeJson {
  id: string;
  tenantId: string;
  title: string;
  html: string;
  status: Envelope["status"];
  signers: Array<Omit<Envelope["signers"][number], "signedAt" | "declinedAt"> & {
    signedAt?: string;
    declinedAt?: string;
  }>;
  createdAt: string;
  expiresAt?: string;
  completedAt?: string;
  voidedAt?: string;
  metadata?: Record<string, unknown>;
}

function reviveEnvelope(r: RawEnvelopeJson): Envelope {
  return {
    ...r,
    createdAt: new Date(r.createdAt),
    expiresAt: r.expiresAt ? new Date(r.expiresAt) : undefined,
    completedAt: r.completedAt ? new Date(r.completedAt) : undefined,
    voidedAt: r.voidedAt ? new Date(r.voidedAt) : undefined,
    signers: r.signers.map((s) => ({
      ...s,
      signedAt: s.signedAt ? new Date(s.signedAt) : undefined,
      declinedAt: s.declinedAt ? new Date(s.declinedAt) : undefined,
    })),
  };
}

/** List every envelope for a tenant, newest-insertion-order-preserved. See the header note above. */
export async function listEnvelopes(dataDir: string, tenantId: string): Promise<Envelope[]> {
  const rows = await readJson<RawEnvelopeJson[]>(path.join(dataDir, "envelopes.json"), []);
  return rows.filter((r) => r.tenantId === tenantId).map(reviveEnvelope);
}

// ---------- buildStores ----------

export interface McpStores {
  certStore: CertStore;
  auditStore: AuditLogStore;
  pdfStorage: PdfStorageStore;
  pqKeyStore: PqKeyStore;
  envelopeStore: EnvelopeStore;
}

/** Build the default filesystem-backed store set rooted at `config.dataDir` (§5 "Stores"). */
export function buildStores(config: Config): McpStores {
  return buildStoresFromDataDir(config.dataDir);
}

/** Same as {@link buildStores}, taking a bare directory — used by tests that don't need a full Config. */
export function buildStoresFromDataDir(dataDir: string): McpStores {
  return {
    certStore: new FsCertStore(dataDir),
    auditStore: new FsAuditLogStore(dataDir),
    pdfStorage: new FsPdfStorageStore(dataDir),
    pqKeyStore: new FsPqKeyStore(dataDir),
    envelopeStore: new ConcurrencySafeEnvelopeStore(new FsEnvelopeStore(dataDir)),
  };
}
