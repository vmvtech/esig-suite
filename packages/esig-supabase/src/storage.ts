// @e-sig/supabase — SupabasePdfStorageStore
//
// PdfStorageStore backed by a private Supabase Storage bucket (default
// `signed-documents`). Returns the storage PATH as the `url` — private buckets
// have no public URL, so serve signed PDFs through an auth-gated download route
// (RLS on the bucket restricts reads to the owning tenant). Uploads use the
// service-role client (bucket write policy is service-role-only).

import type { SupabaseClient } from "@supabase/supabase-js";
import type { PdfStorageStore } from "@e-sig/core";

export interface SupabasePdfStorageStoreOptions {
  /** Bucket name. Default `signed-documents`. */
  bucket?: string;
  /** Allow overwriting an existing object at the path. Default false. */
  upsert?: boolean;
}

export class SupabasePdfStorageStore implements PdfStorageStore {
  private bucket: string;
  private upsert: boolean;
  constructor(private sb: SupabaseClient, opts: SupabasePdfStorageStoreOptions = {}) {
    this.bucket = opts.bucket ?? "signed-documents";
    this.upsert = opts.upsert ?? false;
  }

  async upload(input: {
    path: string;
    bytes: Uint8Array;
    contentType: string;
  }): Promise<{ url: string }> {
    const body = Buffer.isBuffer(input.bytes) ? input.bytes : Buffer.from(input.bytes);
    const { error } = await this.sb.storage.from(this.bucket).upload(input.path, body, {
      contentType: input.contentType,
      upsert: this.upsert,
    });
    if (error) throw new Error(`SupabasePdfStorageStore.upload(${input.path}): ${error.message}`);
    // Private bucket → return the path key; the app serves it via a download route.
    return { url: input.path };
  }
}
