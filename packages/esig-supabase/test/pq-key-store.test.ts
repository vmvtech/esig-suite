// SupabasePqKeyStore — validates column/bytea mapping and drives the full
// ensureActivePqKeys / rotatePqKeys lifecycle through an in-memory fake client
// (mirrors the fake-client approach in audit-chain.test.ts). Runs against ../dist.

import crypto from "node:crypto";
import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

import {
  ensureActivePqKeys,
  rotatePqKeys,
  buildPqSeal,
  verifyPqSealSignatures,
} from "@e-sig/core";
import { SupabasePqKeyStore } from "../dist/index.js";

const PASSPHRASE = "pq-store-test-passphrase-32-chars!!";
const TENANT = "6b1e2f3a-4c5d-4e6f-8a9b-0c1d2e3f4a5b";

// Minimal fake of the supabase-js fluent surface used by SupabasePqKeyStore:
// from().select().eq().eq().maybeSingle(); from().insert().select().single();
// from().update().eq() (awaited).
class FakeQuery {
  private mode: "select" | "insert" | "update" = "select";
  private filters: Record<string, unknown> = {};
  private insertObj: Record<string, unknown> | null = null;
  private updateObj: Record<string, unknown> | null = null;
  constructor(private db: { rows: Record<string, unknown>[]; n: number }) {}

  select() {
    return this;
  }
  insert(o: Record<string, unknown>) {
    this.insertObj = o;
    this.mode = "insert";
    return this;
  }
  update(o: Record<string, unknown>) {
    this.updateObj = o;
    this.mode = "update";
    return this;
  }
  eq(col: string, val: unknown) {
    this.filters[col] = val;
    return this;
  }
  async maybeSingle() {
    const rows = this.run();
    return { data: rows[0] ?? null, error: null };
  }
  async single() {
    const rows = this.run();
    return { data: rows[0] ?? null, error: rows[0] ? null : { message: "no row" } };
  }
  // Support `await update(...).eq(...)` (no terminal single()).
  then(resolve: (v: { error: null }) => void) {
    this.run();
    resolve({ error: null });
  }
  private match(r: Record<string, unknown>) {
    return Object.entries(this.filters).every(([k, v]) => r[k] === v);
  }
  private run() {
    if (this.mode === "insert") {
      const row = {
        id: `id-${(this.db.n += 1)}`,
        created_at: new Date().toISOString(),
        active: true,
        rotated_from: null,
        ...this.insertObj,
      };
      this.db.rows.push(row);
      return [row];
    }
    if (this.mode === "update") {
      const matched = this.db.rows.filter((r) => this.match(r));
      matched.forEach((r) => Object.assign(r, this.updateObj));
      return matched;
    }
    return this.db.rows.filter((r) => this.match(r));
  }
}

function fakeClient() {
  const db = { rows: [] as Record<string, unknown>[], n: 0 };
  const client = { from: () => new FakeQuery(db) } as unknown as SupabaseClient;
  return { client, db };
}

describe("SupabasePqKeyStore + lifecycle", () => {
  it("generates on first use, persists public material, and yields usable keys", async () => {
    const { client, db } = fakeClient();
    const store = new SupabasePqKeyStore(client);

    const r = await ensureActivePqKeys({ store, tenantId: TENANT, passphrase: PASSPHRASE });
    expect(db.rows).toHaveLength(1);
    expect(r.record.active).toBe(true);
    expect(r.record.tenantId).toBe(TENANT);
    expect(r.record.keyId).toMatch(/^[0-9a-f]{32}$/);
    expect(r.record.mldsa65Fpr).toMatch(/^[0-9a-f]{64}$/);
    // The at-rest bundle went through the `\x<hex>` bytea encoding + decode.
    expect((db.rows[0].key_bundle_encrypted as string).startsWith("\\x")).toBe(true);

    // Keys actually sign + verify.
    const seal = buildPqSeal({
      digestHex: crypto.createHash("sha256").update("doc").digest("hex"),
      coveredBytes: 3,
      keys: r.keys,
    });
    expect(verifyPqSealSignatures(seal).ok).toBe(true);
    expect(seal.keys.mldsa65Fpr).toBe(r.record.mldsa65Fpr);
  });

  it("reuses the active bundle on subsequent calls (re-derives the same identity)", async () => {
    const { client } = fakeClient();
    const store = new SupabasePqKeyStore(client);
    const a = await ensureActivePqKeys({ store, tenantId: TENANT, passphrase: PASSPHRASE });
    const b = await ensureActivePqKeys({ store, tenantId: TENANT, passphrase: PASSPHRASE });
    expect(b.record.id).toBe(a.record.id);
    expect(b.record.keyId).toBe(a.record.keyId);
    // Round-trips the wrapped bundle out of storage without throwing.
    expect(b.public.mldsa65Fpr).toBe(a.public.mldsa65Fpr);
  });

  it("rotate deactivates the old bundle and links the predecessor", async () => {
    const { client, db } = fakeClient();
    const store = new SupabasePqKeyStore(client);
    const first = await ensureActivePqKeys({ store, tenantId: TENANT, passphrase: PASSPHRASE });
    const second = await rotatePqKeys({ store, tenantId: TENANT, passphrase: PASSPHRASE });

    expect(second.record.id).not.toBe(first.record.id);
    expect(second.record.rotatedFromId).toBe(first.record.id);
    expect(db.rows).toHaveLength(2);
    // Exactly one active row remains, and findActive returns the new one.
    expect(db.rows.filter((r) => r.active === true)).toHaveLength(1);
    const active = await store.findActive(TENANT);
    expect(active?.id).toBe(second.record.id);
  });
});
