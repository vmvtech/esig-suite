// esig-supabase audit hash-chain test suite.
//
// Tests run against the BUILT package (../dist) — the exact artifact consumers
// receive — so `npm run build` must precede `vitest run` (the package `test`
// script enforces this via pretest).
//
// Fixtures are produced by an INDEPENDENT JS reference implementation of the
// 0002 trigger algorithm (CANONICAL PAYLOAD SPEC v1 in
// migrations/0002_esig_audit_hashchain.sql). verifyAuditChain() must agree
// with it byte-for-byte: an intact reference chain verifies clean, and every
// tamper class (edited column, edited canonical, deleted row + re-hashed
// suffix) is detected. No live Postgres is involved — the fake supabase
// client below serves the fixture rows through the same
// from/select/eq/order/range surface the verifier uses.

import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

import { verifyAuditChain } from "../dist/index.js";

// ------------------------------------------------------------------
// Reference implementation of the 0002 trigger algorithm (spec v1)
// ------------------------------------------------------------------

const md5Hex = (s: string) => createHash("md5").update(s, "utf8").digest("hex");
const sha256Hex = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

/**
 * Postgres's canonical jsonb text rendering (`metadata::text`) for the simple
 * values used in fixtures: object keys sorted by byte length then bytewise,
 * `", "` between members, `": "` after keys, no padding inside brackets.
 */
function pgJsonbText(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(pgJsonbText).join(", ")}]`;
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort((a, b) => {
    const la = Buffer.byteLength(a);
    const lb = Buffer.byteLength(b);
    if (la !== lb) return la - lb;
    return Buffer.compare(Buffer.from(a), Buffer.from(b));
  });
  return `{${keys.map((k) => `${JSON.stringify(k)}: ${pgJsonbText(obj[k])}`).join(", ")}}`;
}

/** Epoch µs of a fixture timestamptz string — `(extract(epoch)*1e6)::bigint`. */
function epochMicros(ts: string): number {
  const m = /^(.+?)(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(ts);
  if (!m) throw new Error(`bad fixture timestamp ${ts}`);
  return Date.parse(`${m[1]}${m[3]}`) * 1000 + Number((m[2] ?? "0").padEnd(6, "0"));
}

const TENANT = "6b1e2f3a-4c5d-4e6f-8a9b-0c1d2e3f4a5b";
const OTHER_TENANT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

interface FixtureEntry {
  action: string;
  actorUserId?: string | null;
  targetTable?: string | null;
  targetId?: string | null;
  createdAt: string; // timestamptz text, as PostgREST would return it
  metadata?: Record<string, unknown>;
}

interface ChainRow {
  id: string;
  tenant_id: string;
  seq: number;
  prev_hash: string | null;
  row_hash: string;
  payload_canonical: string;
  action: string;
  actor_user_id: string | null;
  target_table: string | null;
  target_id: string | null;
  created_at: string;
}

/** Mirrors the BEFORE INSERT trigger: per-tenant seq + canonical + sha256 link. */
function buildChain(entries: FixtureEntry[], tenantId = TENANT): ChainRow[] {
  let prev: string | null = null;
  return entries.map((e, i) => {
    const canonical = [
      "v1",
      tenantId,
      e.action,
      e.actorUserId ?? "",
      e.targetTable ?? "",
      e.targetId ?? "",
      String(epochMicros(e.createdAt)),
      md5Hex(pgJsonbText(e.metadata ?? {})),
    ].join("|");
    const rowHash = sha256Hex(`${prev ?? ""}|${canonical}`);
    const row: ChainRow = {
      id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
      tenant_id: tenantId,
      seq: i,
      prev_hash: prev,
      row_hash: rowHash,
      payload_canonical: canonical,
      action: e.action,
      actor_user_id: e.actorUserId ?? null,
      target_table: e.targetTable ?? null,
      target_id: e.targetId ?? null,
      created_at: e.createdAt,
    };
    prev = rowHash;
    return row;
  });
}

// ------------------------------------------------------------------
// Fake supabase client — from().select().eq().order().range()
// ------------------------------------------------------------------

function fakeClient(rows: ChainRow[]): SupabaseClient {
  const client = {
    from(_table: string) {
      let filtered = rows.slice();
      const builder = {
        select(_columns: string) {
          return builder;
        },
        eq(column: string, value: unknown) {
          filtered = filtered.filter((r) => (r as Record<string, unknown>)[column] === value);
          return builder;
        },
        order(column: string, opts?: { ascending?: boolean }) {
          const dir = opts?.ascending === false ? -1 : 1;
          filtered = filtered
            .slice()
            .sort((a, b) => {
              const av = (a as Record<string, unknown>)[column] as number;
              const bv = (b as Record<string, unknown>)[column] as number;
              return av < bv ? -dir : av > bv ? dir : 0;
            });
          return builder;
        },
        range(from: number, to: number) {
          return Promise.resolve({ data: filtered.slice(from, to + 1), error: null });
        },
      };
      return builder;
    },
  };
  return client as unknown as SupabaseClient;
}

// ------------------------------------------------------------------
// Fixtures — mixed actions (incl. relaxed 'envelope.%' / 'verify.%'),
// nulls, nested metadata, and varying fractional-second precision.
// ------------------------------------------------------------------

const ENTRIES: FixtureEntry[] = [
  {
    action: "cert.created",
    createdAt: "2026-07-01T09:00:00+00:00",
    metadata: {},
  },
  {
    action: "pdf.rendered",
    actorUserId: "11111111-2222-4333-8444-555555555555",
    targetTable: "documents",
    targetId: "99999999-8888-4777-8666-555555555555",
    createdAt: "2026-07-01T09:00:00.5+00:00",
    metadata: { ip: "10.0.0.1", pages: 3 },
  },
  {
    action: "pdf.signed",
    actorUserId: "11111111-2222-4333-8444-555555555555",
    targetTable: "documents",
    targetId: "99999999-8888-4777-8666-555555555555",
    createdAt: "2026-07-01T09:00:01.123456+00:00",
    metadata: { b: 1, aa: { nested: true }, list: [1, "two", false, null] },
  },
  {
    action: "envelope.completed",
    createdAt: "2026-07-01T09:02:03.000042+00:00",
    metadata: { signers: 2 },
  },
  {
    action: "verify.requested",
    actorUserId: null,
    createdAt: "2026-07-02T00:00:00Z",
    metadata: { source: "api" },
  },
];

function intactRows(): ChainRow[] {
  return buildChain(ENTRIES);
}

// A row from another tenant sitting in the same table must be filtered out
// by the eq(tenantColumn, …) predicate and never disturb the chain.
const FOREIGN_ROWS = buildChain(
  [{ action: "cert.created", createdAt: "2026-07-01T00:00:00+00:00" }],
  OTHER_TENANT,
);

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

describe("verifyAuditChain", () => {
  it("accepts an intact chain (ignoring other tenants' rows)", async () => {
    const result = await verifyAuditChain(fakeClient([...FOREIGN_ROWS, ...intactRows()]), {
      tenantId: TENANT,
    });
    expect(result.failures).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.checkedRows).toBe(ENTRIES.length);
    expect(result.firstBrokenSeq).toBeUndefined();
  });

  it("accepts an intact chain across multiple pages", async () => {
    const result = await verifyAuditChain(fakeClient(intactRows()), {
      tenantId: TENANT,
      pageSize: 2,
    });
    expect(result.ok).toBe(true);
    expect(result.checkedRows).toBe(ENTRIES.length);
  });

  it("detects an edited column (scalar no longer matches payload_canonical)", async () => {
    const rows = intactRows();
    // Attacker rewrites what happened, leaving the chain columns untouched.
    rows[1] = { ...rows[1], action: "pdf.verified" };
    const result = await verifyAuditChain(fakeClient(rows), { tenantId: TENANT });
    expect(result.ok).toBe(false);
    expect(result.firstBrokenSeq).toBe(1);
    expect(result.checkedRows).toBe(ENTRIES.length);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0].seq).toBe(1);
    expect(result.failures[0].reason).toContain("action");
  });

  it("detects an edited payload_canonical (row_hash no longer re-derives)", async () => {
    const rows = intactRows();
    // Attacker rewrites the canonical (backdating the event) without being
    // able to recompute a consistent row_hash.
    const parts = rows[3].payload_canonical.split("|");
    parts[6] = String(Number(parts[6]) - 60_000_000); // shift created_at by -60s
    rows[3] = { ...rows[3], payload_canonical: parts.join("|") };
    const result = await verifyAuditChain(fakeClient(rows), { tenantId: TENANT });
    expect(result.ok).toBe(false);
    expect(result.firstBrokenSeq).toBe(3);
    const reasons = result.failures.map((f) => f.reason).join("; ");
    expect(reasons).toContain("row_hash mismatch");
    expect(reasons).toContain("created_at_epoch_us");
  });

  it("detects a deleted row even when the suffix is renumbered and re-hashed (broken linkage)", async () => {
    const rows = intactRows();
    // Attacker deletes seq 2, renumbers the suffix, and re-hashes each
    // remaining row self-consistently from its STORED prev_hash — every row
    // hashes clean in isolation, but the linkage to the true predecessor is
    // broken where the deleted row used to be.
    const tampered = [...rows.slice(0, 2), ...rows.slice(3)].map((r, i) => ({ ...r, seq: i }));
    for (let i = 2; i < tampered.length; i++) {
      tampered[i] = {
        ...tampered[i],
        row_hash: sha256Hex(`${tampered[i].prev_hash ?? ""}|${tampered[i].payload_canonical}`),
      };
    }
    const result = await verifyAuditChain(fakeClient(tampered), { tenantId: TENANT });
    expect(result.ok).toBe(false);
    expect(result.checkedRows).toBe(ENTRIES.length - 1);
    expect(result.firstBrokenSeq).toBe(2);
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0].reason).toContain("prev_hash");
  });

  it("accepts an empty table", async () => {
    const result = await verifyAuditChain(fakeClient([]), { tenantId: TENANT });
    expect(result).toEqual({
      ok: true,
      checkedRows: 0,
      firstBrokenSeq: undefined,
      failures: [],
    });
  });
});
