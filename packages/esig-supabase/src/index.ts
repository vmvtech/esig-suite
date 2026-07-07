// @e-sig/supabase
//
// Supabase reference implementations of the @e-sig/core persistence
// interfaces (CertStore, PqKeyStore, AuditLogStore, PdfStorageStore), plus the
// verifyAuditChain() tamper-evidence checker for the audit hash chain. Pair
// with the bundled migrations (migrations/0001_esig_self_contained.sql +
// 0002_esig_audit_hashchain.sql + 0003_esig_pq_keys.sql). Table/bucket/
// tenant-column names are configurable so you can map onto your existing schema.

export {
  SupabaseCertStore,
  type SupabaseCertStoreOptions,
} from "./cert-store.js";
export {
  SupabasePqKeyStore,
  type SupabasePqKeyStoreOptions,
} from "./pq-key-store.js";
export {
  SupabaseAuditLogStore,
  type SupabaseAuditLogStoreOptions,
} from "./audit-store.js";
export {
  SupabasePdfStorageStore,
  type SupabasePdfStorageStoreOptions,
} from "./storage.js";
export {
  verifyAuditChain,
  type VerifyAuditChainOptions,
  type VerifyAuditChainResult,
  type AuditChainFailure,
} from "./audit-chain.js";
