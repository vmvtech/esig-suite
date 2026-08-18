// stores.ts
//
// Persistence for the pilot: @e-sig/core ships filesystem CertStore /
// AuditLogStore / PdfStorageStore implementations (`@e-sig/core/fs`), but no
// filesystem PqKeyStore — the hybrid Ed25519 + ML-DSA-65 bundle store is
// interface-only in core. `FsPqKeyStore` below fills that gap, mirroring
// FsCertStore's shape exactly.
//
// SCOPE WARNING (read before scaling the deployment): these stores are
// single-process. Core documents FsCertStore as read-modify-write with atomic
// replace, which serialises within ONE process only. Two gateway replicas
// sharing a volume can both mint a "first" cert for the same tenant and one
// will silently lose the single-active-per-tenant race. The pilot therefore
// runs at replica count 1; the upgrade path is a real CertStore (@e-sig/supabase,
// or a small DynamoDB conditional-write store) behind the same interfaces,
// which is a constructor swap in `createGateway`.

import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

import type { PqKeyStore, StoredPqKeys, PqPublicMaterial } from "@e-sig/core";

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

type PqKeysJson = Omit<StoredPqKeys, "keyBundleEncrypted" | "createdAt"> & {
  keyBundleEncrypted: string; // base64
  createdAt: string;
};

/** Filesystem-backed {@link PqKeyStore} — the fs-adapters analogue for PQ bundles. */
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
    // At most one active bundle per tenant (PqKeyStore contract).
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

/**
 * Per-key async mutex. `ensureActiveCert` / `ensureActivePqKeys` are
 * read-then-write: two concurrent first-signs for the same (tenant, alias) both
 * see "no active cert" and both mint one. Serialising per partition key removes
 * that window without serialising unrelated tenants.
 */
export class KeyedMutex {
  /** Per-key tail of the wait chain. Never rejects, so one failure cannot
   *  poison every subsequent waiter on the same key. */
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
      // Drop the entry only if nobody queued behind us, so the map stays bounded.
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
  }
}
