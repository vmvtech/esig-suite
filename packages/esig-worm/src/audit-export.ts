// @e-sig/worm — exportAuditRowsToWorm
//
// Serializes a tenant's chain-linked audit rows (the esig_audit_log hash
// chain — see `audit-chain.ts` in @e-sig/supabase, migration 0002) to NDJSON,
// one row per line, and writes the payload as a single Object Lock-retained
// WORM object keyed by tenant + time range. Pairing the DB-side hash chain
// with an immutable periodic export gives you a fixed point: even a
// self-consistent rewrite of the live chain now contradicts the locked
// snapshot.
//
// Determinism: the same set of rows always produces byte-identical NDJSON
// (rows sorted by `seq`, JSON keys emitted in a fixed order, nested objects
// deep-sorted) — so the returned sha256 is reproducible and can be recorded
// elsewhere (e.g. stamped into the audit log itself, or anchored via
// @e-sig/uuaid) to later prove the export is the one that was taken.

import { createHash } from "node:crypto";

import {
  WormPdfStorageStore,
  type WormObjectLockClient,
  type WormRetentionMode,
} from "./worm-storage.js";

/**
 * One chain-linked audit row, matching the columns `verifyAuditChain()` in
 * @e-sig/supabase reads from `esig_audit_log`. Extra columns are allowed and
 * exported too (deep-sorted for determinism).
 */
export interface ChainedAuditRow {
  id: string;
  seq: number | string;
  prev_hash: string | null;
  row_hash: string;
  payload_canonical: string;
  action: string;
  actor_user_id?: string | null;
  target_table?: string | null;
  target_id?: string | null;
  created_at: string;
  tenant_id: string;
  [column: string]: unknown;
}

export interface ExportAuditRowsToWormOptions {
  /** Tenant whose rows are being exported; becomes part of the object key.
   * Rows carrying a different `tenant_id` are rejected. */
  tenantId: string;
  /** Required when passing a raw client instead of a WormPdfStorageStore. */
  bucket?: string;
  /** Retention mode for the export object (raw-client form only; a passed
   * store keeps its own configuration). Default `COMPLIANCE`. */
  mode?: WormRetentionMode;
  /** Retention days for the export object (raw-client form only). Default 2555. */
  retentionDays?: number;
  /** Key namespace for exports. Default `audit-exports/`. */
  keyPrefix?: string;
  /** Range start for the key. Default: min `created_at` across rows. */
  from?: Date | string;
  /** Range end for the key. Default: max `created_at` across rows. */
  to?: Date | string;
}

export interface WormAuditExportResult {
  /** Full object key the export was written to. */
  key: string;
  /** Lowercase hex sha256 of the exact NDJSON bytes written. */
  sha256: string;
  /** Number of rows exported. */
  rowCount: number;
}

/** Emission order for the well-known chain columns (extras follow, sorted). */
const ROW_FIELD_ORDER = [
  "id",
  "seq",
  "prev_hash",
  "row_hash",
  "payload_canonical",
  "action",
  "actor_user_id",
  "target_table",
  "target_id",
  "created_at",
  "tenant_id",
] as const;

/** Deep-sort object keys so serialization is order-independent. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "object" && value !== null) {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(src).sort()) {
      if (src[k] !== undefined) out[k] = canonicalize(src[k]);
    }
    return out;
  }
  return value;
}

function serializeRow(row: ChainedAuditRow): string {
  const out: Record<string, unknown> = {};
  for (const key of ROW_FIELD_ORDER) {
    if (row[key] !== undefined) out[key] = canonicalize(row[key]);
  }
  for (const key of Object.keys(row).sort()) {
    if (!(key in out) && row[key] !== undefined) out[key] = canonicalize(row[key]);
  }
  return JSON.stringify(out);
}

/** `2026-07-06T01:02:03.000Z` → `20260706T010203Z` (S3-key friendly). */
function keyTimestamp(d: Date): string {
  if (Number.isNaN(d.getTime())) throw new Error("exportAuditRowsToWorm: invalid from/to date");
  return d.toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:]/g, "");
}

function parseCreatedAt(row: ChainedAuditRow): number {
  const ms = Date.parse(row.created_at);
  if (Number.isNaN(ms)) {
    throw new Error(
      `exportAuditRowsToWorm: unparseable created_at "${row.created_at}" (row ${row.id}) — ` +
        "pass explicit opts.from/opts.to",
    );
  }
  return ms;
}

/**
 * Export chain-linked audit rows to a locked NDJSON object at
 * `<keyPrefix><tenantId>/<from>__<to>.ndjson`, with the same atomic Object
 * Lock retention semantics as `WormPdfStorageStore.upload()` (it IS that
 * upload). Accepts either a configured `WormPdfStorageStore` or a raw
 * S3-like client + `opts.bucket`. Returns the object key and the sha256 of
 * the payload bytes.
 */
export async function exportAuditRowsToWorm(
  rows: ChainedAuditRow[],
  storeOrClient: WormPdfStorageStore | WormObjectLockClient,
  opts: ExportAuditRowsToWormOptions,
): Promise<WormAuditExportResult> {
  if (!opts?.tenantId) throw new Error("exportAuditRowsToWorm: opts.tenantId is required");
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("exportAuditRowsToWorm: rows is empty — nothing to archive");
  }
  for (const row of rows) {
    if (row.tenant_id !== opts.tenantId) {
      throw new Error(
        `exportAuditRowsToWorm: row ${row.id} belongs to tenant "${row.tenant_id}", ` +
          `not "${opts.tenantId}" — refusing to mix tenants in one compliance artifact`,
      );
    }
  }

  const store =
    storeOrClient instanceof WormPdfStorageStore
      ? storeOrClient
      : (() => {
          if (!opts.bucket) {
            throw new Error(
              "exportAuditRowsToWorm: opts.bucket is required when passing a raw client",
            );
          }
          return new WormPdfStorageStore(storeOrClient, {
            bucket: opts.bucket,
            mode: opts.mode,
            retentionDays: opts.retentionDays,
          });
        })();

  // Sort by seq (numeric, id tiebreak) so payload bytes — and therefore the
  // sha256 — do not depend on input order.
  const sorted = [...rows].sort((a, b) => {
    const d = Number(a.seq) - Number(b.seq);
    return d !== 0 ? d : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });

  const from = opts.from
    ? new Date(opts.from)
    : new Date(Math.min(...sorted.map(parseCreatedAt)));
  const to = opts.to ? new Date(opts.to) : new Date(Math.max(...sorted.map(parseCreatedAt)));

  const keyPrefix = opts.keyPrefix ?? "audit-exports/";
  const path = `${keyPrefix}${opts.tenantId}/${keyTimestamp(from)}__${keyTimestamp(to)}.ndjson`;

  const ndjson = sorted.map(serializeRow).join("\n") + "\n";
  const bytes = new Uint8Array(Buffer.from(ndjson, "utf8"));
  const sha256 = createHash("sha256").update(bytes).digest("hex");

  const { url } = await store.upload({
    path,
    bytes,
    contentType: "application/x-ndjson",
  });

  return { key: url, sha256, rowCount: sorted.length };
}
