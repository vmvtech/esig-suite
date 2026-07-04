// esig-uuaid actor-stamping test suite.
//
// Tests run against the BUILT package (../dist) — the exact artifact
// consumers receive — so `npm run build` must precede `vitest run` (the
// package `test` script enforces this via pretest). The fake store below
// implements the real @e-sig/core AuditLogStore interface, so the decorator
// is exercised against the production contract types.

import { describe, it, expect } from "vitest";
import type { AuditLogStore, AuditLogEntry, AuditLogRow } from "@e-sig/core";

import { withUuaidActor, UUAID_ACTOR_METADATA_KEY } from "../dist/index.js";

const AGENT = "uuaid:agent:0f5b2c9d";

class FakeAuditLogStore implements AuditLogStore {
  entries: AuditLogEntry[] = [];
  async insert(entry: AuditLogEntry): Promise<AuditLogRow> {
    this.entries.push(entry);
    return {
      id: `row-${this.entries.length}`,
      createdAt: new Date("2026-07-03T00:00:00Z"),
    };
  }
}

describe("withUuaidActor", () => {
  it("stamps metadata.uuaidAgent, preserves existing metadata, passes other fields through", async () => {
    const inner = new FakeAuditLogStore();
    const store: AuditLogStore = withUuaidActor(inner, AGENT);
    const row = await store.insert({
      tenantId: "t1",
      action: "pdf.signed",
      actorUserId: "11111111-2222-4333-8444-555555555555",
      targetTable: "documents",
      targetId: "99999999-8888-4777-8666-555555555555",
      metadata: { ip: "10.0.0.1", pages: 3 },
    });
    expect(row).toEqual({ id: "row-1", createdAt: new Date("2026-07-03T00:00:00Z") });
    expect(inner.entries).toHaveLength(1);
    expect(inner.entries[0]).toEqual({
      tenantId: "t1",
      action: "pdf.signed",
      actorUserId: "11111111-2222-4333-8444-555555555555",
      targetTable: "documents",
      targetId: "99999999-8888-4777-8666-555555555555",
      metadata: { ip: "10.0.0.1", pages: 3, [UUAID_ACTOR_METADATA_KEY]: AGENT },
    });
  });

  it("creates the metadata Record when the entry has none", async () => {
    const inner = new FakeAuditLogStore();
    await withUuaidActor(inner, AGENT).insert({ tenantId: "t1", action: "cert.created" });
    expect(inner.entries[0].metadata).toEqual({ [UUAID_ACTOR_METADATA_KEY]: AGENT });
  });

  it("never mutates the caller's entry or metadata objects", async () => {
    const inner = new FakeAuditLogStore();
    const metadata = { ip: "10.0.0.1" };
    const entry: AuditLogEntry = { tenantId: "t1", action: "pdf.rendered", metadata };
    await withUuaidActor(inner, AGENT).insert(entry);
    expect(entry.metadata).toBe(metadata);
    expect(metadata).toEqual({ ip: "10.0.0.1" });
  });

  it("overwrites a caller-supplied uuaidAgent (the decorator is authoritative)", async () => {
    const inner = new FakeAuditLogStore();
    await withUuaidActor(inner, AGENT).insert({
      tenantId: "t1",
      action: "envelope.signed",
      metadata: { [UUAID_ACTOR_METADATA_KEY]: "spoofed" },
    });
    expect(inner.entries[0].metadata).toEqual({ [UUAID_ACTOR_METADATA_KEY]: AGENT });
  });

  it("returns the store unchanged when agentUuaid is blank (stamping cleanly disabled)", async () => {
    const inner = new FakeAuditLogStore();
    const store = withUuaidActor(inner, "");
    expect(store).toBe(inner);
    await store.insert({ tenantId: "t1", action: "pdf.verified" });
    expect(inner.entries[0].metadata).toBeUndefined();
  });
});
