// @e-sig/worm — WormPdfStorageStore
//
// PdfStorageStore (see `adapters.ts` in @e-sig/core) backed by an S3 bucket
// with Object Lock. Every object is written with a retention lock set
// ATOMICALLY in the same PutObject request (`ObjectLockMode` +
// `ObjectLockRetainUntilDate`) — there is no window where the object exists
// unlocked. Default is COMPLIANCE mode with 2555 days (~7 years), the
// conservative retention used for SEC 17a-4(f)-style record keeping.
//
// Write-once by construction:
//  - No `delete`/`remove`/`overwrite` method exists on this class, so
//    application code holding a WormPdfStorageStore cannot delete or replace
//    an archived object — the capability is structurally absent, not merely
//    guarded by a runtime check a refactor could remove.
//  - Every put carries `IfNoneMatch: "*"` (S3 conditional write), so a second
//    put to an existing key fails server-side with 412 PreconditionFailed.
//    This matters because Object Lock requires bucket versioning, and on a
//    versioned bucket a plain re-put would not destroy the locked version but
//    WOULD create a newer version that shadows it on default reads. The
//    conditional write closes that hole atomically, across processes.
//  - The lock itself is enforced by S3: in COMPLIANCE mode no principal —
//    including the account root — can shorten the retention or delete the
//    object version until `ObjectLockRetainUntilDate` passes.
//
// Dependency-light: no hard dependency on @aws-sdk/client-s3. Inject any
// client that structurally satisfies `WormObjectLockClient` below — the
// aggregated `S3` class from @aws-sdk/client-s3 does (see README), and tests
// inject an in-memory fake.

import type { PdfStorageStore } from "@e-sig/core";

/** S3 Object Lock retention mode. COMPLIANCE cannot be shortened or removed
 * by anyone (root included) until the retain-until date passes; GOVERNANCE
 * can be overridden by principals holding `s3:BypassGovernanceRetention`. */
export type WormRetentionMode = "GOVERNANCE" | "COMPLIANCE";

/** PutObject parameters this store sends (a subset of the AWS SDK's
 * `PutObjectCommandInput`, so the real client accepts them as-is). */
export interface WormPutObjectInput {
  Bucket: string;
  Key: string;
  Body: Uint8Array;
  ContentType: string;
  /** Retention mode applied atomically with the write. */
  ObjectLockMode: WormRetentionMode;
  /** Lock expiry applied atomically with the write. */
  ObjectLockRetainUntilDate: Date;
  /** Always `"*"`: reject the write if any current object exists at the key.
   * Required in the type so a caller that drops the conditional-create guard
   * fails to compile rather than silently allowing overwrites. */
  IfNoneMatch: "*";
}

export interface WormGetObjectInput {
  Bucket: string;
  Key: string;
}

export interface WormGetObjectOutput {
  /** Matches the AWS SDK v3 streaming-blob helper surface. */
  Body?: { transformToByteArray(): Promise<Uint8Array> };
}

/**
 * The slice of an S3 client this package needs (mock-friendly). The
 * aggregated `S3` client from `@aws-sdk/client-s3` satisfies it structurally;
 * so does any S3-compatible client exposing the same two calls.
 */
export interface WormObjectLockClient {
  putObject(input: WormPutObjectInput): Promise<{ VersionId?: string; ETag?: string }>;
  getObject(input: WormGetObjectInput): Promise<WormGetObjectOutput>;
}

export interface WormPdfStorageStoreOptions {
  /** Object Lock-enabled bucket (see scripts/provision-worm-bucket.sh). */
  bucket: string;
  /** Retention mode. Default `COMPLIANCE` (17a-4 style: nobody can unlock early). */
  mode?: WormRetentionMode;
  /** Retention period in days from time of write. Integer >= 1. Default 2555 (~7 years). */
  retentionDays?: number;
  /** Prefix prepended to every object key (upload and download). Default "". */
  keyPrefix?: string;
  /** Injectable clock (tests). Default `() => new Date()`. */
  now?: () => Date;
}

const DAY_MS = 86_400_000;

/** Default retention: 2555 days ≈ 7 years (covers the 6-year 17a-4 horizon with margin). */
export const DEFAULT_WORM_RETENTION_DAYS = 2555;

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isPreconditionFailed(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const e = err as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  return e.name === "PreconditionFailed" || e.$metadata?.httpStatusCode === 412;
}

/**
 * Write-once-read-many `PdfStorageStore`. Wire it into `signDocument()` like
 * any other PdfStorageStore; every signed PDF lands with an S3 Object Lock
 * retention applied in the same PutObject. Returns the object KEY as `url`
 * (the bucket is private — serve reads through your own auth-gated route or
 * `download()`).
 *
 * Intentionally has NO delete method — see the header comment for why
 * overwrite/delete of an archived object is structurally impossible here.
 */
export class WormPdfStorageStore implements PdfStorageStore {
  private readonly bucket: string;
  private readonly mode: WormRetentionMode;
  private readonly retentionDays: number;
  private readonly keyPrefix: string;
  private readonly now: () => Date;

  constructor(private s3: WormObjectLockClient, opts: WormPdfStorageStoreOptions) {
    if (!s3) throw new Error("WormPdfStorageStore: an S3-like client is required");
    if (!opts?.bucket) throw new Error("WormPdfStorageStore: options.bucket is required");
    const mode = opts.mode ?? "COMPLIANCE";
    if (mode !== "COMPLIANCE" && mode !== "GOVERNANCE") {
      throw new Error(`WormPdfStorageStore: mode must be "COMPLIANCE" or "GOVERNANCE" (got "${mode}")`);
    }
    const retentionDays = opts.retentionDays ?? DEFAULT_WORM_RETENTION_DAYS;
    if (!Number.isInteger(retentionDays) || retentionDays < 1) {
      throw new Error(
        `WormPdfStorageStore: retentionDays must be an integer >= 1 (got ${retentionDays})`,
      );
    }
    this.bucket = opts.bucket;
    this.mode = mode;
    this.retentionDays = retentionDays;
    this.keyPrefix = opts.keyPrefix ?? "";
    this.now = opts.now ?? (() => new Date());
  }

  /**
   * Upload bytes at `keyPrefix + path` with Object Lock retention set in the
   * same PutObject (atomic — the object is never observable unlocked). The
   * write is conditional (`IfNoneMatch: "*"`): if any object already exists
   * at the key it fails, so an archived object can never be shadowed by a
   * newer version. Returns the full object key as `url`.
   */
  async upload(input: {
    path: string;
    bytes: Uint8Array;
    contentType: string;
  }): Promise<{ url: string }> {
    const key = this.keyPrefix + input.path;
    const retainUntil = new Date(this.now().getTime() + this.retentionDays * DAY_MS);
    try {
      await this.s3.putObject({
        Bucket: this.bucket,
        Key: key,
        Body: input.bytes,
        ContentType: input.contentType,
        ObjectLockMode: this.mode,
        ObjectLockRetainUntilDate: retainUntil,
        IfNoneMatch: "*",
      });
    } catch (err) {
      if (isPreconditionFailed(err)) {
        throw new Error(
          `WormPdfStorageStore.upload(${key}): an object already exists at this key — ` +
            "WORM objects are write-once and cannot be overwritten or shadowed",
        );
      }
      throw new Error(`WormPdfStorageStore.upload(${key}): ${errMessage(err)}`);
    }
    return { url: key };
  }

  /** Read back the bytes previously uploaded at `path` (same `path` you gave
   * `upload()` — the store applies its `keyPrefix` on both sides). */
  async download(path: string): Promise<Uint8Array> {
    const key = this.keyPrefix + path;
    let out: WormGetObjectOutput;
    try {
      out = await this.s3.getObject({ Bucket: this.bucket, Key: key });
    } catch (err) {
      throw new Error(`WormPdfStorageStore.download(${key}): ${errMessage(err)}`);
    }
    if (!out.Body) throw new Error(`WormPdfStorageStore.download(${key}): empty response body`);
    return out.Body.transformToByteArray();
  }
}
