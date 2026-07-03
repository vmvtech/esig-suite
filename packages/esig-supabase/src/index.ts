// @e-sig/supabase
//
// Supabase reference implementations of the @e-sig/core persistence
// interfaces (CertStore, AuditLogStore, PdfStorageStore). Pair with the bundled
// migration (migrations/0001_esig_self_contained.sql). Table/bucket/tenant-column
// names are configurable so you can map onto your existing schema.

export {
  SupabaseCertStore,
  type SupabaseCertStoreOptions,
} from "./cert-store.js";
export {
  SupabaseAuditLogStore,
  type SupabaseAuditLogStoreOptions,
} from "./audit-store.js";
export {
  SupabasePdfStorageStore,
  type SupabasePdfStorageStoreOptions,
} from "./storage.js";
