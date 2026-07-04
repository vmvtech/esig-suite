// examples/nextjs-supabase — POST /api/esign/sign
//
// Reference wiring of @e-sig/core + @e-sig/supabase. Replace the
// `documents` table + auth/authorize bits with your own domain. The generic
// signDocument() orchestrator does render→cert→sign→store→audit; you only
// supply the HTML, signer, tenant, stores, and persist the result on your row.
//
// `@/lib/supabase/server` (cookie/Bearer SSR client) and `.../service-role`
// (service-role client) are your project's helpers — any standard Supabase
// SSR setup (e.g. the official @supabase/ssr examples) provides both.

import { NextRequest, NextResponse } from "next/server";
import { signDocument } from "@e-sig/core";
import {
  SupabaseCertStore,
  SupabaseAuditLogStore,
  SupabasePdfStorageStore,
} from "@e-sig/supabase";
import { createClient } from "@/lib/supabase/server";
import { getServiceRoleClient } from "@/lib/supabase/service-role";

export const runtime = "nodejs"; // puppeteer-core + node-forge need the node runtime
export const maxDuration = 60;

/** PNG file signature — the only signature-image type this route accepts. */
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export async function POST(req: NextRequest) {
  const { document_id, signature_image_data_url, consent_given, consent_text_shown } =
    await req.json();
  if (!document_id || typeof signature_image_data_url !== "string") {
    return NextResponse.json({ ok: false, code: "bad_request" }, { status: 400 });
  }

  // Bound client inputs before doing any work with them: a drawn signature is
  // tens of KB; 2 MB decoded is already generous. Consent text is a paragraph.
  if (signature_image_data_url.length > 3 * 1024 * 1024) {
    return NextResponse.json({ ok: false, code: "bad_signature_image" }, { status: 413 });
  }
  if (typeof consent_text_shown === "string" && consent_text_shown.length > 8 * 1024) {
    return NextResponse.json({ ok: false, code: "consent_required" }, { status: 413 });
  }

  // Never interpolate the client-supplied string into server-rendered HTML:
  // extract the base64 payload, require it to round-trip as canonical base64
  // decoding to real PNG bytes, then REBUILD the data URL from those bytes.
  const b64 = /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(signature_image_data_url)?.[1];
  const sigBytes = b64 ? Buffer.from(b64, "base64") : Buffer.alloc(0);
  if (
    !b64 ||
    sigBytes.length === 0 ||
    sigBytes.toString("base64") !== b64 ||
    !sigBytes.subarray(0, PNG_MAGIC.length).equals(PNG_MAGIC)
  ) {
    return NextResponse.json({ ok: false, code: "bad_signature_image" }, { status: 400 });
  }
  const signatureImageDataUrl = `data:image/png;base64,${sigBytes.toString("base64")}`;

  // ESIGN/UETA: the audit trail must record the consent text the signer was
  // actually shown — the client sends it; a missing/false consent is a 400.
  if (
    consent_given !== true ||
    typeof consent_text_shown !== "string" ||
    consent_text_shown.trim() === ""
  ) {
    return NextResponse.json({ ok: false, code: "consent_required" }, { status: 400 });
  }

  // 1. Authenticate (your auth).
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ ok: false, code: "unauthenticated" }, { status: 401 });

  // 2. Load YOUR document row (RLS-scoped to the caller) + authorize as you see fit.
  const { data: doc, error } = await supabase
    .from("documents")
    .select("id, tenant_id, tenant_name, signer_name, signer_email, body_html, status")
    .eq("id", document_id)
    .single();
  if (error || !doc) return NextResponse.json({ ok: false, code: "not_found" }, { status: 404 });
  if (doc.status === "signed") return NextResponse.json({ ok: false, code: "already_signed" }, { status: 409 });

  // Only the designated signer may sign — tenant membership is not enough.
  const userEmail = user.email?.trim().toLowerCase();
  const signerEmail =
    typeof doc.signer_email === "string" ? doc.signer_email.trim().toLowerCase() : "";
  if (!userEmail || !signerEmail || userEmail !== signerEmail) {
    return NextResponse.json({ ok: false, code: "not_designated_signer" }, { status: 403 });
  }

  // 3. Compose the signature-embedded HTML (your template + the drawn signature).
  const html = `<!doctype html><html><head><meta charset="utf-8"><style>body{font:14px system-ui;margin:40px}</style></head><body>
    ${doc.body_html}
    <hr/><img src="${signatureImageDataUrl}" alt="signature" style="max-height:120px"/>
    <p>Signed by ${doc.signer_name} &lt;${doc.signer_email}&gt; on ${new Date().toISOString()}</p>
  </body></html>`;

  // 4. Sign via the orchestrator over the Supabase stores.
  const service = getServiceRoleClient();
  const result = await signDocument({
    html,
    signatureImage: { bytes: sigBytes, contentType: "image/png" },
    tenantId: doc.tenant_id,
    subjectName: doc.tenant_name,
    passphrase: process.env.ESIG_CERT_PASSPHRASE!,
    signer: { name: doc.signer_name, email: doc.signer_email },
    actorUserId: user.id,
    certStore: new SupabaseCertStore(service),
    auditStore: new SupabaseAuditLogStore(service),
    storage: new SupabasePdfStorageStore(service),
    pathPrefix: `${doc.tenant_id}/${doc.id}`,
    reason: "Document acceptance",
    targetTable: "documents",
    targetId: doc.id,
    ip: req.headers.get("x-forwarded-for")?.split(",")[0]?.trim(),
    userAgent: req.headers.get("user-agent") ?? undefined,
    metadata: {
      consent_given: true,
      consent_text: consent_text_shown,
      "consent.recorded": true,
    },
  });

  // 5. Persist the result onto YOUR row — conditional on the row still being
  // unsigned (narrows the check-then-sign race) and never swallow the error:
  // the signed PDF + audit row already exist, so a failure here must surface.
  const { data: updated, error: updateError } = await service
    .from("documents")
    .update({
      status: "signed",
      signed_pdf_url: result.signedPdfUrl,
      esig_audit_log_id: result.auditLogId,
    })
    .eq("id", doc.id)
    .neq("status", "signed")
    .select("id");
  if (updateError) {
    // Log the DB detail server-side; the client gets a generic reason plus the
    // audit id so the orphaned signature stays traceable.
    console.error("esign/sign: document update failed after signing", updateError);
    return NextResponse.json(
      {
        ok: false,
        code: "persist_failed",
        reason: `Document row update failed after signing (orphaned signature; audit log ${result.auditLogId})`,
        audit_log_id: result.auditLogId,
      },
      { status: 500 },
    );
  }
  if (!updated || updated.length === 0) {
    return NextResponse.json(
      {
        ok: false,
        code: "already_signed",
        reason: `Document was signed concurrently by another request (this attempt's audit log: ${result.auditLogId})`,
        audit_log_id: result.auditLogId,
      },
      { status: 409 },
    );
  }

  return NextResponse.json({
    ok: true,
    signed_pdf_url: result.signedPdfUrl,
    download_url: `/api/esign/download/${encodeURIComponent(result.signedPdfUrl)}`,
    audit_log_id: result.auditLogId,
  });
}
