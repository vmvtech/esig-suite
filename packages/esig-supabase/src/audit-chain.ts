// @e-sig/supabase — verifyAuditChain
//
// Client-side tamper-evidence verifier for the esig_audit_log hash chain
// installed by migrations/0002_esig_audit_hashchain.sql. Fetches one tenant's
// rows in seq order, re-derives the SHA-256 linkage from payload_canonical,
// and cross-checks the canonical's scalar fields against the row's actual
// columns — so edited columns, edited canonicals, deleted/reordered rows and
// re-hashed suffixes all surface as failures.
//
// ==================================================================
// CANONICAL PAYLOAD SPEC v1 — MUST match migrations/0002 byte-for-byte
// ==================================================================
//   payload_canonical =
//        'v1'
//     || '|' || tenant_id::text                    (lowercase uuid text)
//     || '|' || action
//     || '|' || coalesce(actor_user_id::text, '')  ('' when NULL)
//     || '|' || coalesce(target_table, '')         ('' when NULL)
//     || '|' || coalesce(target_id::text, '')      ('' when NULL)
//     || '|' || epoch MICROseconds of created_at, as integer text
//     || '|' || md5(metadata::text)                (32 lowercase hex)
//
//   row_hash  = sha256hex(utf8((prev_hash ?? "") + "|" + payload_canonical))
//   seq       = 0-origin, contiguous per tenant
//   prev_hash = previous row's row_hash (null at seq 0)
//
// jsonb normalization is PG-side: md5(metadata::text) hashes Postgres's
// canonical jsonb rendering (its key ordering / spacing / numeric scale),
// which JS cannot reproduce reliably. The md5 therefore travels inside
// payload_canonical and is integrity-protected by the chain itself; this
// verifier cross-checks the SCALAR fields column-by-column and validates
// only the md5's shape.

import { createHash } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";

export interface VerifyAuditChainOptions {
  /** Tenant whose chain to verify. */
  tenantId: string;
  /** Table name. Default `esig_audit_log`. */
  table?: string;
  /** Tenant key column. Default `tenant_id`. */
  tenantColumn?: string;
  /** Rows fetched per request. Default 1000 (PostgREST's usual max). */
  pageSize?: number;
}

export interface AuditChainFailure {
  /** `seq` of the offending row (falls back to the row's position when seq itself is unusable). */
  seq: number;
  /** Row id. */
  id: string;
  /** Human-readable description of what broke. */
  reason: string;
}

export interface VerifyAuditChainResult {
  /** True iff every row checked out. Vacuously true for an empty chain. */
  ok: boolean;
  /** Number of rows fetched and checked. */
  checkedRows: number;
  /** seq of the first failing row, when any failed. */
  firstBrokenSeq?: number;
  /** One entry per detected problem, in chain order. */
  failures: AuditChainFailure[];
}

interface RawChainRow {
  id: string;
  seq: number | string | null;
  prev_hash: string | null;
  row_hash: string | null;
  payload_canonical: string | null;
  action: string;
  actor_user_id: string | null;
  target_table: string | null;
  target_id: string | null;
  created_at: string;
  [column: string]: unknown;
}

const MD5_HEX = /^[0-9a-f]{32}$/;

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Epoch microseconds of a Postgres/PostgREST timestamptz text value — mirrors
 * `(extract(epoch from created_at) * 1000000)::bigint`. Accepts
 * `2026-07-03T12:34:56.789012+00:00` (PostgREST), the space-separated PG text
 * form, `Z`, and 2-digit offsets; fractional seconds may be 0-6 digits (PG
 * trims trailing zeros). Exact in a float64 until far beyond year 2200.
 */
function timestamptzToEpochMicros(value: string): number {
  const m = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)$/.exec(
    value,
  );
  if (!m) throw new Error(`unparseable timestamptz "${value}"`);
  let offset = m[4];
  if (/^[+-]\d{2}$/.test(offset)) offset += ":00";
  else if (/^[+-]\d{4}$/.test(offset)) offset = `${offset.slice(0, 3)}:${offset.slice(3)}`;
  const baseMs = Date.parse(`${m[1]}T${m[2]}${offset}`);
  if (Number.isNaN(baseMs)) throw new Error(`unparseable timestamptz "${value}"`);
  return baseMs * 1000 + Number((m[3] ?? "0").padEnd(6, "0"));
}

const CANONICAL_FIELDS = [
  "version",
  "tenant_id",
  "action",
  "actor_user_id",
  "target_table",
  "target_id",
  "created_at_epoch_us",
  "metadata_md5",
] as const;

/** Names the disagreeing fields when both strings split into the v1 shape. */
function describeCanonicalMismatch(expected: string, actual: string): string {
  const e = expected.split("|");
  const a = actual.split("|");
  if (e.length === CANONICAL_FIELDS.length && a.length === CANONICAL_FIELDS.length) {
    const diff = CANONICAL_FIELDS.filter((_, i) => e[i] !== a[i]);
    if (diff.length > 0) {
      return `payload_canonical disagrees with row columns on: ${diff.join(", ")}`;
    }
  }
  return "payload_canonical disagrees with row columns";
}

/**
 * Verify a tenant's esig_audit_log hash chain (migration 0002). Per row:
 *   (a) seq is contiguous from 0,
 *   (b) prev_hash equals the previous row's row_hash (linkage),
 *   (c) row_hash = sha256(prev_hash|payload_canonical) (self-consistency),
 *   (d) payload_canonical's scalar fields match the row's actual columns.
 * Read access to the chain columns is required (service key, or a member
 * session if your esig_tenant_member() grants SELECT).
 */
export async function verifyAuditChain(
  client: SupabaseClient,
  opts: VerifyAuditChainOptions,
): Promise<VerifyAuditChainResult> {
  const table = opts.table ?? "esig_audit_log";
  const tenantColumn = opts.tenantColumn ?? "tenant_id";
  const pageSize = opts.pageSize ?? 1000;
  const columns = [
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
    tenantColumn,
  ].join(", ");

  const rows: RawChainRow[] = [];
  let serverTotal: number | null = null;
  for (let from = 0; ; from += pageSize) {
    // count:'exact' on the first page guards against a PostgREST max-rows cap
    // below pageSize: a short page would otherwise read as end-of-chain and
    // silently verify only a prefix.
    const { data, error, count } = await client
      .from(table)
      .select(columns, from === 0 ? { count: "exact" } : undefined)
      .eq(tenantColumn, opts.tenantId)
      .order("seq", { ascending: true })
      .range(from, from + pageSize - 1);
    if (error) throw new Error(`verifyAuditChain: ${error.message}`);
    if (from === 0 && typeof count === "number") serverTotal = count;
    const page = (data ?? []) as unknown as RawChainRow[];
    rows.push(...page);
    if (page.length < pageSize) break;
  }
  if (serverTotal !== null && rows.length !== serverTotal) {
    return {
      ok: false,
      checkedRows: rows.length,
      failures: [
        {
          seq: rows.length,
          id: "",
          reason:
            `fetched ${rows.length} rows but the server reports ${serverTotal} — ` +
            "a row cap (e.g. PostgREST max-rows) is truncating pages; lower pageSize below the cap",
        },
      ],
    };
  }

  const failures: AuditChainFailure[] = [];
  let firstBrokenSeq: number | undefined;
  let expectedPrev: string | null = null;

  rows.forEach((row, i) => {
    const seqNum = row.seq === null ? Number.NaN : Number(row.seq);
    const reportSeq = Number.isFinite(seqNum) ? seqNum : i;
    const fail = (reason: string) => {
      failures.push({ seq: reportSeq, id: row.id, reason });
      if (firstBrokenSeq === undefined) firstBrokenSeq = reportSeq;
    };

    if (row.seq === null || row.row_hash === null || row.payload_canonical === null) {
      fail("chain columns missing (row predates the 0002 backfill, or was nulled out)");
      expectedPrev = row.row_hash;
      return;
    }

    // (a) seq continuity — 0-origin, no gaps, no duplicates.
    if (seqNum !== i) fail(`seq discontinuity: expected ${i}, found ${row.seq}`);

    // (b) linkage — stored prev_hash must equal the previous row's row_hash.
    if ((row.prev_hash ?? null) !== expectedPrev) {
      fail(
        "prev_hash does not match the previous row_hash (chain broken: row deleted, reordered, or suffix re-hashed)",
      );
    }

    // (c) self-consistency — row_hash must re-derive from this row's own fields.
    const recomputed = sha256Hex(`${row.prev_hash ?? ""}|${row.payload_canonical}`);
    if (recomputed !== row.row_hash) {
      fail(`row_hash mismatch: stored ${row.row_hash}, recomputed ${recomputed}`);
    }

    // (d) scalar cross-check — rebuild the canonical from the row's columns
    // (spec v1 above), carrying over only the PG-side metadata md5 tail.
    const md5Start = row.payload_canonical.lastIndexOf("|") + 1;
    const md5Part = md5Start > 0 ? row.payload_canonical.slice(md5Start) : "";
    if (!MD5_HEX.test(md5Part)) {
      fail("malformed payload_canonical: missing metadata md5 tail");
    } else {
      let epochField: string | null = null;
      try {
        epochField = String(timestamptzToEpochMicros(row.created_at));
      } catch {
        fail(`unparseable created_at "${row.created_at}" — cannot cross-check payload_canonical`);
      }
      if (epochField !== null) {
        const expected = [
          "v1",
          String(row[tenantColumn] ?? ""),
          row.action,
          row.actor_user_id ?? "",
          row.target_table ?? "",
          row.target_id ?? "",
          epochField,
          md5Part,
        ].join("|");
        if (expected !== row.payload_canonical) {
          fail(describeCanonicalMismatch(expected, row.payload_canonical));
        }
      }
    }

    expectedPrev = row.row_hash;
  });

  return {
    ok: failures.length === 0,
    checkedRows: rows.length,
    firstBrokenSeq,
    failures,
  };
}
