# @e-sig/worm

WORM (write-once-read-many) archival adapter for
[`@e-sig/core`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-core) —
a `PdfStorageStore` that writes every signed PDF into an S3 **Object Lock**
bucket with retention applied **atomically in the same PutObject**, plus a
deterministic exporter that snapshots the audit hash chain into the same
locked storage.

```bash
npm i @e-sig/worm @aws-sdk/client-s3
```

`@aws-sdk/client-s3` is *your* dependency, not this package's: `@e-sig/worm`
is dependency-light and accepts any injected client that structurally exposes
`putObject`/`getObject` (the aggregated `S3` class does; so do S3-compatible
stores that support Object Lock semantics).

## Why (SEC 17a-4 / FINRA framing)

SEC Rule 17a-4(f) and FINRA 4511 require broker-dealer records to be kept in
a form that prevents erasure or alteration for the retention period. S3
Object Lock in **COMPLIANCE** mode is the standard technical control for
this: once an object version is locked, **no principal — including the AWS
account root — can shorten the retention or delete the version until the
retain-until date passes**. That is not a limitation; it is the point.

This package supplies the *technical* controls (immutable storage, atomic
retention, tamper-evident export hashing). It is **not legal advice**, and
17a-4 compliance involves more than storage (designated-executive
undertakings / D3P arrangements, audit-system requirements, notification
duties). Have counsel and your compliance officer own the regulatory side.

## What makes it write-once

- **Atomic retention** — `ObjectLockMode` + `ObjectLockRetainUntilDate` ride
  in the same `PutObject` as the bytes. There is no window where the object
  exists unlocked.
- **No delete method** — `WormPdfStorageStore` has `upload()` and
  `download()`, nothing else. Application code holding the store *cannot*
  delete or replace an archived object; the capability is structurally
  absent rather than guarded by a runtime flag a refactor could remove.
- **Conditional writes** — every put carries `IfNoneMatch: "*"`. Object Lock
  requires bucket versioning, and on a versioned bucket a re-put would not
  destroy the locked version but *would* create a newer version shadowing it
  on default reads. The conditional write makes S3 itself reject the second
  put (412), atomically, across processes.
- **COMPLIANCE mode by default**, 2555 days (~7 years). Use `GOVERNANCE`
  only for rehearsal — it can be bypassed by principals holding
  `s3:BypassGovernanceRetention`.

## Provision the bucket

Object Lock can only be enabled at bucket **creation**. The included script
creates a bucket with Object Lock + versioning + a default retention rule +
full public-access block, and **bails if the bucket already exists**:

```bash
./node_modules/@e-sig/worm/scripts/provision-worm-bucket.sh \
  my-esig-worm-archive us-east-1 2555 COMPLIANCE
```

> The script pins the AWS CLI v2 binary path (`/opt/homebrew/bin/aws`).
> Adjust for your machine if your v2 CLI lives elsewhere.

Rehearse with `GOVERNANCE` and a short retention first: a COMPLIANCE-locked
test object stays billable and undeletable for the full period — the only
way out is deleting nothing and waiting.

## Wiring with @aws-sdk/client-s3

Use the **aggregated `S3` client** (method-style API) — it structurally
satisfies the `WormObjectLockClient` interface this package defines:

```ts
import { S3 } from "@aws-sdk/client-s3";
import { WormPdfStorageStore } from "@e-sig/worm";

const s3 = new S3({ region: "us-east-1" });

const wormStore = new WormPdfStorageStore(s3, {
  bucket: "my-esig-worm-archive",
  mode: "COMPLIANCE",   // default
  retentionDays: 2555,  // default (~7 years)
});

// Drop it in wherever a PdfStorageStore goes:
const result = await signDocument({
  // ...certStore, auditStore, pdf inputs...
  pdfStorage: wormStore,
});
// result URL is the object KEY (private bucket — serve via your own
// auth-gated route or wormStore.download(path)).
```

The IAM principal needs `s3:PutObject`, `s3:PutObjectRetention` and
`s3:GetObject` on the bucket — and should **not** have `s3:DeleteObject*`,
`s3:PutBucketObjectLockConfiguration` or `s3:BypassGovernanceRetention`.

## Exporting the audit chain

`@e-sig/supabase`'s hash chain (migration 0002 + `verifyAuditChain()`) is
tamper-evident *inside* the database; a periodic WORM export gives it an
immutable external fixed point. Rewriting the live chain self-consistently
now contradicts the locked snapshot.

```ts
import { exportAuditRowsToWorm } from "@e-sig/worm";

// rows: the tenant's esig_audit_log rows in chain order (id, seq, prev_hash,
// row_hash, payload_canonical, action, ..., created_at, tenant_id).
const { key, sha256, rowCount } = await exportAuditRowsToWorm(rows, s3, {
  tenantId,
  bucket: "my-esig-worm-archive",
});
// key    → audit-exports/<tenantId>/<from>__<to>.ndjson  (locked, COMPLIANCE)
// sha256 → hash of the exact NDJSON bytes written
```

- **NDJSON**: one chain-linked row per line, `seq` ascending.
- **Deterministic**: fixed field order, deep-sorted nested objects — the same
  rows always hash the same. Record the `sha256` somewhere independent (an
  audit row, or anchor it with `@e-sig/uuaid`) to prove the export later.
- Pass a configured `WormPdfStorageStore` instead of a raw client to reuse
  its retention settings; pass explicit `from`/`to` to control the key's
  time range (defaults to the rows' `created_at` span).
- Cross-tenant rows are rejected; re-exporting an existing key fails (the
  object is locked — write a new range instead).

## API

| Export | What it is |
| --- | --- |
| `WormPdfStorageStore` | `PdfStorageStore` with atomic Object Lock retention; `upload()` / `download()` only |
| `exportAuditRowsToWorm(rows, storeOrClient, opts)` | Deterministic NDJSON chain snapshot → locked object; returns `{ key, sha256, rowCount }` |
| `WormObjectLockClient` | The minimal structural S3 slice you inject (`putObject`, `getObject`) |
| `WormRetentionMode` | `"COMPLIANCE" \| "GOVERNANCE"` |
| `DEFAULT_WORM_RETENTION_DAYS` | `2555` |

## License

MIT
