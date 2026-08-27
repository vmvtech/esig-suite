// verify.ts
//
// Thin wrapper over core's `verifyDocument` (pq-verify.ts:203-234) for
// `esig_verify_document` (design doc §4) — the widest-open tool, deliberately:
// any agent verifying any e-sig document is the intended viral loop, so this
// stays a direct pass-through of core's result plus one human-readable line.

import { verifyDocument, type DocumentVerification, type VerifyDocumentOptions } from "@e-sig/core";

export type VerifyOptions = VerifyDocumentOptions;

export interface VerifyDocumentBytesResult extends DocumentVerification {
  /** One-line human-readable summary, e.g. "OK (classical:valid, post-quantum:valid)". */
  summary: string;
}

export function verifyDocumentBytes(
  bytes: Uint8Array,
  opts: VerifyOptions = {},
): VerifyDocumentBytesResult {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const verification = verifyDocument(buf, opts);
  return { ...verification, summary: summarize(verification) };
}

function summarize(v: DocumentVerification): string {
  const parts = [`classical:${v.classical.ok ? "valid" : "invalid"}`];
  if (v.postQuantum.present) {
    parts.push(`post-quantum:${v.postQuantum.ok ? "valid" : "invalid"}`);
    if (v.postQuantum.uuaid) parts.push(`uuaid:${v.postQuantum.uuaid}`);
  } else {
    parts.push("post-quantum:absent");
  }
  return `${v.ok ? "OK" : "FAILED"} (${parts.join(", ")})`;
}
