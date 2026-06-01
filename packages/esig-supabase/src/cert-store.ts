// @vmvtech/esig-supabase — SupabaseCertStore
//
// CertStore backed by a Postgres table (default `org_signing_certs`) via
// supabase-js. Matches the schema in migrations/0001_esig_self_contained.sql.
// The tenant key column is `tenant_id` in the bundled migration; pass
// `tenantColumn` if yours differs (Opendelphi uses `org_id`).

import type { SupabaseClient } from "@supabase/supabase-js";
import type { CertStore, StoredCert, GeneratedCert } from "@vmvtech/esig-core";

interface RawCertRow {
  id: string;
  tenant_id?: string;
  org_id?: string;
  cert_pem: string;
  key_pem_encrypted: Uint8Array | string;
  cert_fingerprint: string;
  not_before: string;
  not_after: string;
  active: boolean;
  rotated_from: string | null;
  created_at: string;
}

export interface SupabaseCertStoreOptions {
  /** Table name. Default `org_signing_certs`. */
  table?: string;
  /** Tenant key column. Default `tenant_id`. */
  tenantColumn?: string;
}

function toStoredCert(r: RawCertRow, tenantColumn: string): StoredCert {
  // Postgres bytea comes back from PostgREST as a `\x<hex>` string. Decode to
  // bytes. Legacy rows may be JSON-Buffer-wrapped (`{"type":"Buffer",...}`) by
  // older supabase-js; detect + unwrap so they're at least diagnosable (they'll
  // still fail GCM decryption — rotate to recover).
  let keyBytes: Uint8Array;
  const raw = r.key_pem_encrypted;
  if (raw instanceof Uint8Array) {
    keyBytes = raw;
  } else if (typeof raw === "string" && raw.startsWith("\\x")) {
    keyBytes = Buffer.from(raw.slice(2), "hex");
    if (keyBytes.length > 0 && keyBytes[0] === 0x7b /* '{' */) {
      try {
        const parsed = JSON.parse(Buffer.from(keyBytes).toString("utf8"));
        if (parsed && parsed.type === "Buffer" && Array.isArray(parsed.data)) {
          keyBytes = Buffer.from(parsed.data);
        }
      } catch {
        /* not JSON — keep original bytes */
      }
    }
  } else if (typeof raw === "string") {
    keyBytes = Buffer.from(raw, "base64");
  } else {
    keyBytes = new Uint8Array();
  }
  const tenantId = (r[tenantColumn as keyof RawCertRow] as string) ?? r.tenant_id ?? r.org_id ?? "";
  return {
    id: r.id,
    tenantId,
    certPem: r.cert_pem,
    keyPemEncrypted: keyBytes,
    certFingerprint: r.cert_fingerprint,
    notBefore: new Date(r.not_before),
    notAfter: new Date(r.not_after),
    active: r.active,
    rotatedFromId: r.rotated_from,
    createdAt: new Date(r.created_at),
  };
}

export class SupabaseCertStore implements CertStore {
  private table: string;
  private tenantColumn: string;
  constructor(private sb: SupabaseClient, opts: SupabaseCertStoreOptions = {}) {
    this.table = opts.table ?? "org_signing_certs";
    this.tenantColumn = opts.tenantColumn ?? "tenant_id";
  }

  async findActive(tenantId: string): Promise<StoredCert | null> {
    const { data, error } = await this.sb
      .from(this.table)
      .select("*")
      .eq(this.tenantColumn, tenantId)
      .eq("active", true)
      .maybeSingle();
    if (error) throw new Error(`SupabaseCertStore.findActive: ${error.message}`);
    return data ? toStoredCert(data as RawCertRow, this.tenantColumn) : null;
  }

  async insert(input: {
    tenantId: string;
    generated: GeneratedCert;
    keyPemEncrypted: Uint8Array;
    rotatedFromId?: string | null;
  }): Promise<StoredCert> {
    // bytea wire encoding: supabase-js JSON-stringifies a Uint8Array, mangling
    // the round-trip. Pre-encode as the Postgres bytea-in hex form `\x<hex>`.
    const bytes = Buffer.isBuffer(input.keyPemEncrypted)
      ? input.keyPemEncrypted
      : Buffer.from(input.keyPemEncrypted);
    const hexEncoded = "\\x" + bytes.toString("hex");
    const { data, error } = await this.sb
      .from(this.table)
      .insert({
        [this.tenantColumn]: input.tenantId,
        cert_pem: input.generated.certPem,
        key_pem_encrypted: hexEncoded,
        cert_fingerprint: input.generated.fingerprint,
        not_before: input.generated.notBefore.toISOString(),
        not_after: input.generated.notAfter.toISOString(),
        rotated_from: input.rotatedFromId ?? null,
      })
      .select()
      .single();
    if (error || !data) throw new Error(`SupabaseCertStore.insert: ${error?.message}`);
    return toStoredCert(data as RawCertRow, this.tenantColumn);
  }

  async deactivate(id: string): Promise<void> {
    const { error } = await this.sb.from(this.table).update({ active: false }).eq("id", id);
    if (error) throw new Error(`SupabaseCertStore.deactivate: ${error.message}`);
  }

  async findExpiring(withinDays: number): Promise<StoredCert[]> {
    const horizon = new Date(Date.now() + withinDays * 86400_000).toISOString();
    const { data, error } = await this.sb
      .from(this.table)
      .select("*")
      .eq("active", true)
      .lte("not_after", horizon);
    if (error) throw new Error(`SupabaseCertStore.findExpiring: ${error.message}`);
    return (data ?? []).map((r) => toStoredCert(r as RawCertRow, this.tenantColumn));
  }
}
