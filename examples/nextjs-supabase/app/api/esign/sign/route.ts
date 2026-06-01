// examples/nextjs-supabase — POST /api/esign/sign
//
// Reference wiring of @vmvtech/esig-core + @vmvtech/esig-supabase. Replace the
// `documents` table + auth/authorize bits with your own domain. The generic
// signDocument() orchestrator does render→cert→sign→store→audit; you only
// supply the HTML, signer, tenant, stores, and persist the result on your row.
//
// `@/lib/supabase/server` (cookie/Bearer SSR client) and `.../service-role`
// (service-role client) are your project's helpers — see Opendelphi
// src/lib/supabase/{server,service-role}.ts for a reference.

import { NextRequest, NextResponse } from "next/server";
import { signDocument } from "@vmvtech/esig-core";
import {
  SupabaseCertStore,
  SupabaseAuditLogStore,
  SupabasePdfStorageStore,
} from "@vmvtech/esig-supabase";
import { createClient } from "@/lib/supabase/server";
import { getServiceRoleClient } from "@/lib/supabase/service-role";

export const runtime = "nodejs"; // puppeteer-core + node-forge need the node runtime
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  const { document_id, signature_image_data_url } = await req.json();
  if (!document_id || !/^data:image\/(png|jpeg);base64,/.test(signature_image_data_url ?? "")) {
    return NextResponse.json({ ok: false, code: "bad_request" }, { status: 400 });
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

  // 3. Compose the signature-embedded HTML (your template + the drawn signature).
  const html = `<!doctype html><html><head><meta charset="utf-8"><style>body{font:14px system-ui;margin:40px}</style></head><body>
    ${doc.body_html}
    <hr/><img src="${signature_image_data_url}" alt="signature" style="max-height:120px"/>
    <p>Signed by ${doc.signer_name} &lt;${doc.signer_email}&gt; on ${new Date().toISOString()}</p>
  </body></html>`;

  // 4. Sign via the orchestrator over the Supabase stores.
  const service = getServiceRoleClient();
  const sigBytes = Buffer.from(signature_image_data_url.split(",", 2)[1] ?? "", "base64");
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
      consent_text:
        "I agree to electronically sign this document; my e-signature has the same legal effect as a handwritten one under ESIGN / UETA.",
    },
  });

  // 5. Persist the result onto YOUR row.
  await service
    .from("documents")
    .update({
      status: "signed",
      signed_pdf_url: result.signedPdfUrl,
      esig_audit_log_id: result.auditLogId,
    })
    .eq("id", doc.id);

  return NextResponse.json({
    ok: true,
    signed_pdf_url: result.signedPdfUrl,
    download_url: `/api/esign/download/${encodeURIComponent(result.signedPdfUrl)}`,
    audit_log_id: result.auditLogId,
  });
}
