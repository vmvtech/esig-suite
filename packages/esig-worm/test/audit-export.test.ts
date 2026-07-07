// exportAuditRowsToWorm test suite — runs against the BUILT package (../dist),
// with the in-memory FakeS3 standing in for S3 (see fake-s3.ts).

import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";

import {
  WormPdfStorageStore,
  exportAuditRowsToWorm,
  type ChainedAuditRow,
} from "../dist/index.js";
import { FakeS3 } from "./fake-s3.js";

const BUCKET = "esig-worm-test";
const TENANT = "6b1e2f3a-4c5d-4e6f-8a9b-0c1d2e3f4a5b";

/** Two chain-linked rows in the esig_audit_log shape (audit-chain.ts, migration 0002). */
function chainRows(): ChainedAuditRow[] {
  return [
    {
      id: "00000000-0000-4000-8000-000000000001",
      seq: 0,
      prev_hash: null,
      row_hash: "aa11".padEnd(64, "0"),
      payload_canonical: `v1|${TENANT}|pdf.signed||||1782086400000000|${"d".repeat(32)}`,
      action: "pdf.signed",
      actor_user_id: null,
      target_table: "esig_envelopes",
      target_id: "00000000-0000-4000-8000-0000000000aa",
      created_at: "2026-07-01T00:00:00.000000+00:00",
      tenant_id: TENANT,
      metadata: { b: 2, a: 1 },
    },
    {
      id: "00000000-0000-4000-8000-000000000002",
      seq: 1,
      prev_hash: "aa11".padEnd(64, "0"),
      row_hash: "bb22".padEnd(64, "0"),
      payload_canonical: `v1|${TENANT}|envelope.completed||||1782172800000000|${"e".repeat(32)}`,
      action: "envelope.completed",
      actor_user_id: "user-7",
      target_table: "esig_envelopes",
      target_id: "00000000-0000-4000-8000-0000000000aa",
      created_at: "2026-07-02T00:00:00.000000+00:00",
      tenant_id: TENANT,
      metadata: { a: 1, b: 2 }, // same content, different key insertion order
    },
  ];
}

describe("exportAuditRowsToWorm", () => {
  it("writes a locked NDJSON object keyed by tenant + time range and returns key + sha256", async () => {
    const s3 = new FakeS3();
    const result = await exportAuditRowsToWorm(chainRows(), s3, {
      tenantId: TENANT,
      bucket: BUCKET,
      from: "2026-07-01T00:00:00Z",
      to: "2026-07-02T00:00:00Z",
    });

    expect(result.key).toBe(`audit-exports/${TENANT}/20260701T000000Z__20260702T000000Z.ndjson`);
    expect(result.rowCount).toBe(2);
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);

    // Retention semantics identical to PDF archival: mode + retain-until +
    // conditional create, atomically on the single put.
    expect(s3.putCalls).toHaveLength(1);
    const put = s3.putCalls[0];
    expect(put.ObjectLockMode).toBe("COMPLIANCE");
    expect(put.ObjectLockRetainUntilDate.getTime()).toBeGreaterThan(Date.now());
    expect(put.IfNoneMatch).toBe("*");
    expect(put.ContentType).toBe("application/x-ndjson");

    // The returned sha256 is the hash of the exact bytes written, and the
    // payload is one JSON row per line.
    const stored = s3.objects.get(`${BUCKET}/${result.key}`)!;
    expect(createHash("sha256").update(stored.body).digest("hex")).toBe(result.sha256);
    const lines = Buffer.from(stored.body).toString("utf8").trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).seq).toBe(0);
    expect(JSON.parse(lines[1]).seq).toBe(1);
    expect(JSON.parse(lines[1]).row_hash).toBe("bb22".padEnd(64, "0"));
  });

  it("payload hash is stable/deterministic across input order and repeated runs", async () => {
    const opts = { tenantId: TENANT, bucket: BUCKET } as const;
    const a = await exportAuditRowsToWorm(chainRows(), new FakeS3(), opts);
    const b = await exportAuditRowsToWorm([...chainRows()].reverse(), new FakeS3(), opts);
    const c = await exportAuditRowsToWorm(chainRows(), new FakeS3(), opts);

    expect(a.sha256).toBe(b.sha256);
    expect(a.sha256).toBe(c.sha256);
    expect(a.key).toBe(b.key);

    // Nested-object key order must not affect the bytes either: rows 1 and 2
    // carry the same metadata content with different insertion order, and the
    // serializer deep-sorts — swapping the two orderings changes nothing.
    const swapped = chainRows();
    swapped[0].metadata = { a: 1, b: 2 };
    swapped[1].metadata = { b: 2, a: 1 };
    const d = await exportAuditRowsToWorm(swapped, new FakeS3(), opts);
    expect(d.sha256).toBe(a.sha256);
  });

  it("derives the key's time range from row created_at when from/to are omitted", async () => {
    const result = await exportAuditRowsToWorm(chainRows(), new FakeS3(), {
      tenantId: TENANT,
      bucket: BUCKET,
    });
    expect(result.key).toBe(`audit-exports/${TENANT}/20260701T000000Z__20260702T000000Z.ndjson`);
  });

  it("accepts a pre-configured WormPdfStorageStore and uses its retention settings", async () => {
    const s3 = new FakeS3();
    const now = new Date("2026-07-06T00:00:00.000Z");
    const store = new WormPdfStorageStore(s3, {
      bucket: BUCKET,
      mode: "GOVERNANCE",
      retentionDays: 90,
      now: () => now,
    });

    const result = await exportAuditRowsToWorm(chainRows(), store, { tenantId: TENANT });

    expect(s3.putCalls[0].ObjectLockMode).toBe("GOVERNANCE");
    expect(s3.putCalls[0].ObjectLockRetainUntilDate.toISOString()).toBe(
      new Date(now.getTime() + 90 * 86_400_000).toISOString(),
    );
    expect(result.key).toMatch(new RegExp(`^audit-exports/${TENANT}/`));
  });

  it("a repeat export over the same range is rejected (WORM object already locked)", async () => {
    const s3 = new FakeS3();
    const opts = { tenantId: TENANT, bucket: BUCKET } as const;
    await exportAuditRowsToWorm(chainRows(), s3, opts);
    await expect(exportAuditRowsToWorm(chainRows(), s3, opts)).rejects.toThrow(
      /write-once|already exists/,
    );
  });

  it("throws on misconfiguration and bad input", async () => {
    const rows = chainRows();

    // retentionDays < 1 (raw-client form builds a store internally)
    await expect(
      exportAuditRowsToWorm(rows, new FakeS3(), { tenantId: TENANT, bucket: BUCKET, retentionDays: 0 }),
    ).rejects.toThrow(/retentionDays must be an integer >= 1/);

    // raw client without a bucket
    await expect(exportAuditRowsToWorm(rows, new FakeS3(), { tenantId: TENANT })).rejects.toThrow(
      /bucket is required/,
    );

    // empty row set
    await expect(
      exportAuditRowsToWorm([], new FakeS3(), { tenantId: TENANT, bucket: BUCKET }),
    ).rejects.toThrow(/rows is empty/);

    // cross-tenant contamination
    const foreign = chainRows();
    foreign[1].tenant_id = "other-tenant";
    await expect(
      exportAuditRowsToWorm(foreign, new FakeS3(), { tenantId: TENANT, bucket: BUCKET }),
    ).rejects.toThrow(/refusing to mix tenants/);
  });
});
