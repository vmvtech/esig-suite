// WormPdfStorageStore test suite.
//
// Tests run against the BUILT package (../dist) — the exact artifact
// consumers receive — so `npm run build` must precede `vitest run` (the
// package `test` script enforces this via pretest). The S3 side is the
// in-memory FakeS3, which mirrors real S3's conditional-write (412) and
// streaming-body semantics.

import { describe, it, expect } from "vitest";

import { WormPdfStorageStore, DEFAULT_WORM_RETENTION_DAYS } from "../dist/index.js";
import { FakeS3 } from "./fake-s3.js";

const BUCKET = "esig-worm-test";
const NOW = new Date("2026-07-06T00:00:00.000Z");
const DAY_MS = 86_400_000;

function makeStore(s3: FakeS3, opts: Partial<ConstructorParameters<typeof WormPdfStorageStore>[1]> = {}) {
  return new WormPdfStorageStore(s3, { bucket: BUCKET, now: () => NOW, ...opts });
}

describe("WormPdfStorageStore", () => {
  it("sends Object Lock retention params atomically on every put (COMPLIANCE + 2555d default)", async () => {
    const s3 = new FakeS3();
    const store = makeStore(s3);

    await store.upload({ path: "a.pdf", bytes: new Uint8Array([1]), contentType: "application/pdf" });
    await store.upload({ path: "b.pdf", bytes: new Uint8Array([2]), contentType: "application/pdf" });

    expect(s3.putCalls).toHaveLength(2);
    const expectedRetainUntil = new Date(NOW.getTime() + DEFAULT_WORM_RETENTION_DAYS * DAY_MS);
    for (const call of s3.putCalls) {
      expect(call.ObjectLockMode).toBe("COMPLIANCE");
      expect(call.ObjectLockRetainUntilDate.toISOString()).toBe(expectedRetainUntil.toISOString());
      expect(call.IfNoneMatch).toBe("*"); // conditional create on every single put
      expect(call.Bucket).toBe(BUCKET);
    }
  });

  it("honors configured mode and retentionDays", async () => {
    const s3 = new FakeS3();
    const store = makeStore(s3, { mode: "GOVERNANCE", retentionDays: 30 });

    await store.upload({ path: "g.pdf", bytes: new Uint8Array([3]), contentType: "application/pdf" });

    expect(s3.putCalls[0].ObjectLockMode).toBe("GOVERNANCE");
    expect(s3.putCalls[0].ObjectLockRetainUntilDate.toISOString()).toBe(
      new Date(NOW.getTime() + 30 * DAY_MS).toISOString(),
    );
  });

  it("round-trips bytes through upload + download, returning the object key as url", async () => {
    const s3 = new FakeS3();
    const store = makeStore(s3, { keyPrefix: "tenant-1/" });
    const bytes = new Uint8Array([37, 80, 68, 70, 45, 49, 46, 55]); // "%PDF-1.7"

    const { url } = await store.upload({ path: "signed/doc.pdf", bytes, contentType: "application/pdf" });
    expect(url).toBe("tenant-1/signed/doc.pdf");

    const back = await store.download("signed/doc.pdf");
    expect(Array.from(back)).toEqual(Array.from(bytes));
    expect(s3.objects.get(`${BUCKET}/tenant-1/signed/doc.pdf`)?.contentType).toBe("application/pdf");
  });

  it("rejects a second put to the same key (immutability guard)", async () => {
    const s3 = new FakeS3();
    const store = makeStore(s3);
    const input = { path: "once.pdf", bytes: new Uint8Array([1]), contentType: "application/pdf" };

    await store.upload(input);
    await expect(store.upload({ ...input, bytes: new Uint8Array([9, 9, 9]) })).rejects.toThrow(
      /write-once|already exists/,
    );

    // The original object is untouched...
    expect(Array.from(await store.download("once.pdf"))).toEqual([1]);
    // ...and a fresh key still works.
    await expect(
      store.upload({ path: "other.pdf", bytes: new Uint8Array([2]), contentType: "application/pdf" }),
    ).resolves.toEqual({ url: "other.pdf" });
  });

  it("exposes no delete/remove method — overwrite AND delete are structurally impossible", () => {
    const store = makeStore(new FakeS3());
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(store));
    expect(proto).not.toContain("delete");
    expect(proto).not.toContain("remove");
    expect(proto.sort()).toEqual(["constructor", "download", "upload"]);
  });

  it("throws on misconfiguration: retentionDays < 1 or non-integer, bad mode, missing bucket", () => {
    const s3 = new FakeS3();
    expect(() => makeStore(s3, { retentionDays: 0 })).toThrow(/retentionDays must be an integer >= 1/);
    expect(() => makeStore(s3, { retentionDays: -5 })).toThrow(/retentionDays must be an integer >= 1/);
    expect(() => makeStore(s3, { retentionDays: 1.5 })).toThrow(/retentionDays must be an integer >= 1/);
    // @ts-expect-error — bad mode must be rejected at runtime too
    expect(() => makeStore(s3, { mode: "PINKY_PROMISE" })).toThrow(/mode must be/);
    // @ts-expect-error — bucket is required
    expect(() => new WormPdfStorageStore(s3, {})).toThrow(/bucket is required/);
  });

  it("wraps unknown client errors with the failing key", async () => {
    const s3 = new FakeS3();
    s3.putObject = async () => {
      throw new Error("network sadness");
    };
    const store = makeStore(s3);
    await expect(
      store.upload({ path: "x.pdf", bytes: new Uint8Array([1]), contentType: "application/pdf" }),
    ).rejects.toThrow(/upload\(x\.pdf\): network sadness/);
  });
});
