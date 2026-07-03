// adapters.ts
//
// Pluggable persistence interfaces. Implement these against your project's
// DB/storage to plug the portable signing engine into any stack. Two stores are
// required (CertStore + AuditLogStore); PdfStorageStore is optional but lets the
// `signDocument()` orchestrator persist the signed PDF for you.
//
// A Supabase reference implementation ships as `@e-sig/supabase`.

import type { GeneratedCert } from "./cert-issuer.js";

// ---------- CertStore ----------

export interface StoredCert {
  id: string;
  tenantId: string;
  certPem: string;
  /** Encrypted PEM key (whatever your at-rest encryption produces). */
  keyPemEncrypted: Uint8Array;
  certFingerprint: string;
  notBefore: Date;
  notAfter: Date;
  active: boolean;
  /** Optional: id of the cert this one replaced on rotation. */
  rotatedFromId?: string | null;
  createdAt: Date;
}

export interface CertStore {
  /**
   * Find the active (non-expired, not rotated) cert for a tenant.
   * Return null if no active cert exists.
   */
  findActive(tenantId: string): Promise<StoredCert | null>;

  /**
   * Insert a new cert. Implementations should ensure only one cert per tenant
   * is `active=true` at any time (handle the "deactivate old + insert new"
   * transaction yourself or in a single SQL statement).
   */
  insert(input: {
    tenantId: string;
    generated: GeneratedCert;
    keyPemEncrypted: Uint8Array;
    rotatedFromId?: string | null;
  }): Promise<StoredCert>;

  /** Mark a cert as inactive (used during rotation). */
  deactivate(id: string): Promise<void>;

  /** Find all active certs whose notAfter is within `withinDays` of now. Used by a rotation cron. */
  findExpiring(withinDays: number): Promise<StoredCert[]>;
}

// ---------- AuditLogStore ----------

/**
 * Standard action vocabulary. Implementations should allow these at minimum
 * but may extend the set (caller passes the action string through).
 */
export type EsigAuditAction =
  | "cert.created"
  | "cert.rotated"
  | "cert.deactivated"
  | "pdf.rendered"
  | "pdf.signed"
  | "pdf.verified"
  | "consent.recorded"
  | "envelope.created"
  | "envelope.signed"
  | "envelope.declined"
  | "envelope.voided"
  | "envelope.completed";

export interface AuditLogEntry {
  tenantId: string;
  action: EsigAuditAction | string;
  actorUserId?: string | null;
  targetTable?: string;
  targetId?: string;
  certId?: string;
  certFingerprint?: string;
  ip?: string;
  userAgent?: string;
  sessionId?: string;
  signedPdfUrl?: string;
  metadata?: Record<string, unknown>;
}

export interface AuditLogRow {
  id: string;
  createdAt: Date;
}

export interface AuditLogStore {
  /** Append one row. Returns the new row id + timestamp for FK references. */
  insert(entry: AuditLogEntry): Promise<AuditLogRow>;
}

// ---------- PdfStorageStore ----------

/**
 * Persists signed PDFs (and optionally signature images). The `signDocument()`
 * orchestrator uses this to store the signed bytes and return a URL/path key.
 */
export interface PdfStorageStore {
  /** Upload bytes at the given path. Returns the canonical URL or path key. */
  upload(input: {
    path: string;
    bytes: Uint8Array;
    contentType: string;
  }): Promise<{ url: string }>;
}
