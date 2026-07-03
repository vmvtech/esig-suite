// @e-sig/supabase — SupabaseAuditLogStore
//
// Append-only AuditLogStore backed by a Postgres table (default `esig_audit_log`)
// via supabase-js. Tenant key column defaults to `tenant_id` (Opendelphi: `org_id`).

import type { SupabaseClient } from "@supabase/supabase-js";
import type { AuditLogStore, AuditLogEntry, AuditLogRow } from "@e-sig/core";

export interface SupabaseAuditLogStoreOptions {
  /** Table name. Default `esig_audit_log`. */
  table?: string;
  /** Tenant key column. Default `tenant_id`. */
  tenantColumn?: string;
}

export class SupabaseAuditLogStore implements AuditLogStore {
  private table: string;
  private tenantColumn: string;
  constructor(private sb: SupabaseClient, opts: SupabaseAuditLogStoreOptions = {}) {
    this.table = opts.table ?? "esig_audit_log";
    this.tenantColumn = opts.tenantColumn ?? "tenant_id";
  }

  async insert(entry: AuditLogEntry): Promise<AuditLogRow> {
    const { data, error } = await this.sb
      .from(this.table)
      .insert({
        [this.tenantColumn]: entry.tenantId,
        actor_user_id: entry.actorUserId ?? null,
        action: entry.action,
        target_table: entry.targetTable ?? null,
        target_id: entry.targetId ?? null,
        cert_id: entry.certId ?? null,
        cert_fingerprint: entry.certFingerprint ?? null,
        ip: entry.ip ?? null,
        user_agent: entry.userAgent ?? null,
        session_id: entry.sessionId ?? null,
        signed_pdf_url: entry.signedPdfUrl ?? null,
        metadata: entry.metadata ?? {},
      })
      .select("id, created_at")
      .single();
    if (error || !data) throw new Error(`SupabaseAuditLogStore.insert: ${error?.message}`);
    return { id: data.id as string, createdAt: new Date(data.created_at as string) };
  }
}
