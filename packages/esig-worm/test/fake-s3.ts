// In-memory fake of the WormObjectLockClient slice, with real-S3 semantics
// for the two behaviors the store leans on:
//   * conditional writes: `IfNoneMatch: "*"` fails with a 412
//     PreconditionFailed error when a current object exists at the key
//     (same error shape as @aws-sdk/client-s3 v3),
//   * getObject returns a Body with the SDK's `transformToByteArray()` helper.
// It also records every putObject input so tests can assert the retention
// params sent on the wire.

import type {
  WormGetObjectInput,
  WormGetObjectOutput,
  WormObjectLockClient,
  WormPutObjectInput,
} from "../dist/index.js";

interface StoredObject {
  body: Uint8Array;
  contentType: string;
  objectLockMode: string;
  objectLockRetainUntilDate: Date;
}

export class FakeS3 implements WormObjectLockClient {
  readonly objects = new Map<string, StoredObject>();
  readonly putCalls: WormPutObjectInput[] = [];

  async putObject(input: WormPutObjectInput): Promise<{ VersionId?: string; ETag?: string }> {
    this.putCalls.push(input);
    const mapKey = `${input.Bucket}/${input.Key}`;
    if (input.IfNoneMatch === "*" && this.objects.has(mapKey)) {
      throw Object.assign(new Error("At least one of the pre-conditions you specified did not hold"), {
        name: "PreconditionFailed",
        $metadata: { httpStatusCode: 412 },
      });
    }
    this.objects.set(mapKey, {
      body: input.Body.slice(),
      contentType: input.ContentType,
      objectLockMode: input.ObjectLockMode,
      objectLockRetainUntilDate: input.ObjectLockRetainUntilDate,
    });
    return { VersionId: `v${this.putCalls.length}`, ETag: `"etag-${this.putCalls.length}"` };
  }

  async getObject(input: WormGetObjectInput): Promise<WormGetObjectOutput> {
    const stored = this.objects.get(`${input.Bucket}/${input.Key}`);
    if (!stored) {
      throw Object.assign(new Error("The specified key does not exist."), {
        name: "NoSuchKey",
        $metadata: { httpStatusCode: 404 },
      });
    }
    return { Body: { transformToByteArray: async () => stored.body.slice() } };
  }
}
