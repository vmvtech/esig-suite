// fs-adapters.ts
//
// Filesystem-backed reference implementations of every persistence interface
// (CertStore, AuditLogStore, PdfStorageStore, EnvelopeStore) — the full
// pipeline with zero external services: `import ... from "@e-sig/core/fs"`.
//
// Intended for development, demos, CLIs, and small single-node deployments.
// NOT multi-process safe: JSON state is read-modify-write with atomic replace
// (write temp + rename), which serializes within one process only. The audit
// log is a true append-only NDJSON file.
//
// Layout under the root directory:
//   certs.json           — StoredCert rows (keyPemEncrypted as base64)
//   envelopes.json       — Envelope rows
//   audit-log.ndjson     — one JSON audit row per line, append-only
//   blobs/<path>         — uploaded PDFs / signature images

import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

import type {
  AuditLogEntry,
  AuditLogRow,
  AuditLogStore,
  CertStore,
  PdfStorageStore,
  StoredCert,
} from "./adapters.js";
import type { GeneratedCert } from "./cert-issuer.js";
import type { Envelope, EnvelopeStore } from "./envelope.js";

/** Serialize-with-rename so a crash never leaves a half-written JSON file. */
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

// ---------- FsCertStore ----------

type CertJson = Omit<StoredCert, "keyPemEncrypted" | "notBefore" | "notAfter" | "createdAt"> & {
  keyPemEncrypted: string; // base64
  notBefore: string;
  notAfter: string;
  createdAt: string;
};

export class FsCertStore implements CertStore {
  private file: string;

  constructor(rootDir: string) {
    this.file = path.join(rootDir, "certs.json");
  }

  private async rows(): Promise<CertJson[]> {
    return readJson<CertJson[]>(this.file, []);
  }

  private static revive(r: CertJson): StoredCert {
    return {
      ...r,
      keyPemEncrypted: new Uint8Array(Buffer.from(r.keyPemEncrypted, "base64")),
      notBefore: new Date(r.notBefore),
      notAfter: new Date(r.notAfter),
      createdAt: new Date(r.createdAt),
    };
  }

  async findActive(tenantId: string): Promise<StoredCert | null> {
    const row = (await this.rows()).find((r) => r.tenantId === tenantId && r.active);
    return row ? FsCertStore.revive(row) : null;
  }

  async insert(input: {
    tenantId: string;
    generated: GeneratedCert;
    keyPemEncrypted: Uint8Array;
    rotatedFromId?: string | null;
  }): Promise<StoredCert> {
    const rows = await this.rows();
    // Single-active-per-tenant invariant (see CertStore contract).
    for (const r of rows) if (r.tenantId === input.tenantId) r.active = false;
    const row: CertJson = {
      id: crypto.randomUUID(),
      tenantId: input.tenantId,
      certPem: input.generated.certPem,
      keyPemEncrypted: Buffer.from(input.keyPemEncrypted).toString("base64"),
      certFingerprint: input.generated.fingerprint,
      notBefore: input.generated.notBefore.toISOString(),
      notAfter: input.generated.notAfter.toISOString(),
      active: true,
      rotatedFromId: input.rotatedFromId ?? null,
      createdAt: new Date().toISOString(),
    };
    rows.push(row);
    await writeJsonAtomic(this.file, rows);
    return FsCertStore.revive(row);
  }

  async deactivate(id: string): Promise<void> {
    const rows = await this.rows();
    const row = rows.find((r) => r.id === id);
    if (row) {
      row.active = false;
      await writeJsonAtomic(this.file, rows);
    }
  }

  async findExpiring(withinDays: number): Promise<StoredCert[]> {
    const horizon = Date.now() + withinDays * 24 * 60 * 60 * 1000;
    return (await this.rows())
      .filter((r) => r.active && new Date(r.notAfter).getTime() <= horizon)
      .map(FsCertStore.revive);
  }
}

// ---------- FsAuditLogStore ----------

export class FsAuditLogStore implements AuditLogStore {
  private file: string;

  constructor(rootDir: string) {
    this.file = path.join(rootDir, "audit-log.ndjson");
  }

  async insert(entry: AuditLogEntry): Promise<AuditLogRow> {
    const row = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), ...entry };
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    await fs.appendFile(this.file, JSON.stringify(row) + "\n", "utf8");
    return { id: row.id, createdAt: new Date(row.createdAt) };
  }

  /** Read every persisted row (newest last). Not part of the core interface —
   *  a convenience for local inspection and tests. */
  async readAll(): Promise<Array<AuditLogEntry & AuditLogRow>> {
    try {
      const text = await fs.readFile(this.file, "utf8");
      return text
        .split("\n")
        .filter(Boolean)
        .map((l) => {
          const r = JSON.parse(l);
          return { ...r, createdAt: new Date(r.createdAt) };
        });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw e;
    }
  }
}

// ---------- FsPdfStorageStore ----------

export class FsPdfStorageStore implements PdfStorageStore {
  private blobRoot: string;

  constructor(rootDir: string) {
    this.blobRoot = path.join(rootDir, "blobs");
  }

  async upload(input: { path: string; bytes: Uint8Array; contentType: string }): Promise<{ url: string }> {
    // Resolve inside blobRoot and refuse traversal escapes.
    const abs = path.resolve(this.blobRoot, input.path);
    if (abs !== this.blobRoot && !abs.startsWith(this.blobRoot + path.sep)) {
      throw new Error(`FsPdfStorageStore: path escapes storage root: ${input.path}`);
    }
    await fs.mkdir(path.dirname(abs), { recursive: true });
    await fs.writeFile(abs, input.bytes);
    return { url: abs };
  }
}

// ---------- FsEnvelopeStore ----------

type EnvelopeJson = Omit<Envelope, "createdAt" | "expiresAt" | "completedAt" | "voidedAt" | "signers"> & {
  createdAt: string;
  expiresAt?: string;
  completedAt?: string;
  voidedAt?: string;
  signers: Array<
    Omit<Envelope["signers"][number], "signedAt" | "declinedAt"> & {
      signedAt?: string;
      declinedAt?: string;
    }
  >;
};

export class FsEnvelopeStore implements EnvelopeStore {
  private file: string;

  constructor(rootDir: string) {
    this.file = path.join(rootDir, "envelopes.json");
  }

  private async rows(): Promise<EnvelopeJson[]> {
    return readJson<EnvelopeJson[]>(this.file, []);
  }

  private static toJson(e: Envelope): EnvelopeJson {
    return {
      ...e,
      createdAt: e.createdAt.toISOString(),
      expiresAt: e.expiresAt?.toISOString(),
      completedAt: e.completedAt?.toISOString(),
      voidedAt: e.voidedAt?.toISOString(),
      signers: e.signers.map((s) => ({
        ...s,
        signedAt: s.signedAt?.toISOString(),
        declinedAt: s.declinedAt?.toISOString(),
      })),
    };
  }

  private static revive(r: EnvelopeJson): Envelope {
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

  async insert(envelope: Envelope): Promise<Envelope> {
    const rows = await this.rows();
    rows.push(FsEnvelopeStore.toJson(envelope));
    await writeJsonAtomic(this.file, rows);
    return envelope;
  }

  async update(envelope: Envelope): Promise<Envelope> {
    const rows = await this.rows();
    const i = rows.findIndex((r) => r.id === envelope.id);
    if (i === -1) throw new Error(`FsEnvelopeStore: envelope not found: ${envelope.id}`);
    rows[i] = FsEnvelopeStore.toJson(envelope);
    await writeJsonAtomic(this.file, rows);
    return envelope;
  }

  async findById(tenantId: string, id: string): Promise<Envelope | null> {
    const row = (await this.rows()).find((r) => r.tenantId === tenantId && r.id === id);
    return row ? FsEnvelopeStore.revive(row) : null;
  }

  async findByTokenHash(tokenHash: string): Promise<Envelope | null> {
    const row = (await this.rows()).find((r) => r.signers.some((s) => s.tokenHash === tokenHash));
    return row ? FsEnvelopeStore.revive(row) : null;
  }
}
