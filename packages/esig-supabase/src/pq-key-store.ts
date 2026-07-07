// @e-sig/supabase — SupabasePqKeyStore
//
// PqKeyStore backed by a Postgres table (default `org_pq_keys`) via supabase-js.
// Matches migrations/0003_esig_pq_keys.sql. Drive it with ensureActivePqKeys /
// rotatePqKeys from @e-sig/core. Mirrors SupabaseCertStore, including the bytea
// `\x<hex>` wire-encoding workaround for the encrypted bundle.

import type { SupabaseClient } from "@supabase/supabase-js";
import type { PqKeyStore, StoredPqKeys, PqPublicMaterial } from "@e-sig/core";

interface RawPqRow {
  id: string;
  tenant_id?: string;
  org_id?: string;
  key_bundle_encrypted: Uint8Array | string;
  ed25519_public: string;
  mldsa65_public: string;
  mldsa65_fpr: string;
  key_id: string;
  active: boolean;
  rotated_from: string | null;
  created_at: string;
}

export interface SupabasePqKeyStoreOptions {
  /** Table name. Default `org_pq_keys`. */
  table?: string;
  /** Tenant key column. Default `tenant_id`. */
  tenantColumn?: string;
}

/** Decode a Postgres bytea (`\x<hex>` from PostgREST, or already-bytes) to a Uint8Array. */
function decodeBytea(raw: Uint8Array | string): Uint8Array {
  if (raw instanceof Uint8Array) return raw;
  if (typeof raw === "string" && raw.startsWith("\\x")) return Buffer.from(raw.slice(2), "hex");
  if (typeof raw === "string") return Buffer.from(raw, "base64");
  return new Uint8Array();
}

function toStoredPqKeys(r: RawPqRow, tenantColumn: string): StoredPqKeys {
  const tenantId = (r[tenantColumn as keyof RawPqRow] as string) ?? r.tenant_id ?? r.org_id ?? "";
  return {
    id: r.id,
    tenantId,
    keyBundleEncrypted: decodeBytea(r.key_bundle_encrypted),
    ed25519Public: r.ed25519_public,
    mldsa65Public: r.mldsa65_public,
    mldsa65Fpr: r.mldsa65_fpr,
    keyId: r.key_id,
    active: r.active,
    rotatedFromId: r.rotated_from,
    createdAt: new Date(r.created_at),
  };
}

export class SupabasePqKeyStore implements PqKeyStore {
  private table: string;
  private tenantColumn: string;
  constructor(private sb: SupabaseClient, opts: SupabasePqKeyStoreOptions = {}) {
    this.table = opts.table ?? "org_pq_keys";
    this.tenantColumn = opts.tenantColumn ?? "tenant_id";
  }

  async findActive(tenantId: string): Promise<StoredPqKeys | null> {
    const { data, error } = await this.sb
      .from(this.table)
      .select("*")
      .eq(this.tenantColumn, tenantId)
      .eq("active", true)
      .maybeSingle();
    if (error) throw new Error(`SupabasePqKeyStore.findActive: ${error.message}`);
    return data ? toStoredPqKeys(data as RawPqRow, this.tenantColumn) : null;
  }

  async insert(input: {
    tenantId: string;
    keyBundleEncrypted: Uint8Array;
    public: PqPublicMaterial;
    rotatedFromId?: string | null;
  }): Promise<StoredPqKeys> {
    // bytea wire encoding: supabase-js JSON-stringifies a Uint8Array, mangling
    // the round-trip. Pre-encode as Postgres bytea-in hex form `\x<hex>`.
    const bytes = Buffer.isBuffer(input.keyBundleEncrypted)
      ? input.keyBundleEncrypted
      : Buffer.from(input.keyBundleEncrypted);
    const hexEncoded = "\\x" + bytes.toString("hex");
    const { data, error } = await this.sb
      .from(this.table)
      .insert({
        [this.tenantColumn]: input.tenantId,
        key_bundle_encrypted: hexEncoded,
        ed25519_public: input.public.ed25519,
        mldsa65_public: input.public.mldsa65,
        mldsa65_fpr: input.public.mldsa65Fpr,
        key_id: input.public.keyId,
        rotated_from: input.rotatedFromId ?? null,
      })
      .select()
      .single();
    if (error || !data) throw new Error(`SupabasePqKeyStore.insert: ${error?.message}`);
    return toStoredPqKeys(data as RawPqRow, this.tenantColumn);
  }

  async deactivate(id: string): Promise<void> {
    const { error } = await this.sb.from(this.table).update({ active: false }).eq("id", id);
    if (error) throw new Error(`SupabasePqKeyStore.deactivate: ${error.message}`);
  }
}
