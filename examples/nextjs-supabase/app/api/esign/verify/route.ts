// examples/nextjs-supabase — POST /api/esign/verify
//
// Public verification endpoint: accepts a signed PDF (multipart/form-data,
// "file" field) and returns @e-sig/core's VerifyResult as JSON.
//
// Deliberately NO auth and NO persistence: verification is a public-good
// surface — anyone holding a signed document should be able to check it
// without an account, and the request reveals nothing beyond what the caller
// already has (the document itself). Nothing is stored or audit-logged.
//
// Scope matches verifyPdfSignature(): digest + signature vs the certificate
// embedded in the document (first signature only) — no chain building or
// revocation checks. Surface that caveat in your UI (VerifyPanel does).

import { NextRequest, NextResponse } from "next/server";
import { verifyPdfSignature } from "@e-sig/core";

export const runtime = "nodejs"; // node-forge needs the node runtime
export const maxDuration = 30;

/** Refuse anything over 20 MB — signed PDFs from this suite are far smaller. */
const MAX_FILE_BYTES = 20 * 1024 * 1024;

const methodNotAllowed = () =>
  NextResponse.json(
    { ok: false, code: "method_not_allowed" },
    { status: 405, headers: { Allow: "POST" } },
  );

// Next.js already 405s methods a route doesn't export; exporting these keeps
// the contract explicit and the Allow header deterministic.
export const GET = methodNotAllowed;
export const PUT = methodNotAllowed;
export const PATCH = methodNotAllowed;
export const DELETE = methodNotAllowed;

export async function POST(req: NextRequest) {
  // Bound INGEST, not just what gets verified: req.formData() buffers the whole
  // body in memory before file.size is ever seen, and self-hosted app-router
  // handlers have no default body limit. Reject on the declared length up front
  // (multipart framing overhead means a legitimate 20 MB PDF still fits), and
  // refuse length-less (chunked) uploads outright. The hard backstop for a
  // lying Content-Length is your platform/proxy limit (Vercel ~4.5 MB, nginx
  // client_max_body_size) — set one in production.
  const declaredLength = Number(req.headers.get("content-length"));
  if (!Number.isFinite(declaredLength) || declaredLength <= 0) {
    return NextResponse.json(
      { ok: false, code: "length_required", message: "Content-Length is required" },
      { status: 411 },
    );
  }
  if (declaredLength > MAX_FILE_BYTES + 64 * 1024) {
    return NextResponse.json(
      { ok: false, code: "file_too_large", message: "request exceeds the 20 MB limit" },
      { status: 413 },
    );
  }

  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return NextResponse.json(
      { ok: false, code: "bad_request", message: 'expected multipart/form-data with a "file" field' },
      { status: 400 },
    );
  }

  const file = form.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json(
      { ok: false, code: "missing_file", message: 'multipart "file" field is required' },
      { status: 400 },
    );
  }
  if (file.size > MAX_FILE_BYTES) {
    return NextResponse.json(
      { ok: false, code: "file_too_large", message: "file exceeds the 20 MB limit" },
      { status: 413 },
    );
  }

  const bytes = Buffer.from(await file.arrayBuffer());
  if (bytes.length < 5 || !bytes.subarray(0, 5).equals(Buffer.from("%PDF-"))) {
    return NextResponse.json(
      { ok: false, code: "not_a_pdf", message: "file is not a PDF (missing %PDF- header)" },
      { status: 400 },
    );
  }

  return NextResponse.json(verifyPdfSignature(bytes));
}
