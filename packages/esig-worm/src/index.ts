// @e-sig/worm
//
// WORM (write-once-read-many) archival adapter for @e-sig/core: a
// PdfStorageStore that writes every object into an S3 Object Lock bucket
// with retention set atomically per put (WormPdfStorageStore), plus a
// deterministic NDJSON exporter that snapshots the audit hash chain into the
// same locked storage (exportAuditRowsToWorm). Technical controls in the
// style of SEC 17a-4(f) / FINRA 4511 — dependency-light, bring your own
// S3-compatible client.

export {
  WormPdfStorageStore,
  DEFAULT_WORM_RETENTION_DAYS,
  type WormRetentionMode,
  type WormObjectLockClient,
  type WormPutObjectInput,
  type WormGetObjectInput,
  type WormGetObjectOutput,
  type WormPdfStorageStoreOptions,
} from "./worm-storage.js";
export {
  exportAuditRowsToWorm,
  type ChainedAuditRow,
  type ExportAuditRowsToWormOptions,
  type WormAuditExportResult,
} from "./audit-export.js";
