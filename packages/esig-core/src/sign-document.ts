// sign-document.ts
//
// Generic server-side signing orchestrator — the reusable spine of a
// "self-sign" endpoint, stack-agnostic over the three pluggable stores.
//
//   renderHtmlToPdf → ensureActiveCert → signPdf (+ optional RFC-3161 TSA)
//   → PdfStorageStore.upload → AuditLogStore.insert
//
// Document-specific glue (loading a row, building the HTML/template, RBAC, and
// updating your domain table afterward) stays in the CONSUMER. You pass in the
// fully-rendered `html`, the signer, the stores, and storage layout; you get
// back the stored URL + audit id + cert fingerprint to persist on your row.

import { renderHtmlToPdf } from "./render-pdf.js";
import { signPdf } from "./sign-pdf.js";
import { ensureActiveCert } from "./cert-lifecycle.js";
import type {
  CertStore,
  AuditLogStore,
  PdfStorageStore,
  EsigAuditAction,
} from "./adapters.js";
import type { TsaTransport } from "./types.js";

export interface SignDocumentInput {
  /** Fully-rendered, signature-embedded HTML (the consumer composes this). */
  html: string;
  /** Optional signature image to persist alongside the PDF (e.g. the drawn PNG). */
  signatureImage?: { bytes: Uint8Array; contentType: string };

  /** Tenant whose signing cert is used + audit/storage partition key. */
  tenantId: string;
  /** Cert subject CN — ASCII-clean tenant/org display name. */
  subjectName: string;
  /** Key-at-rest passphrase for the CertStore. */
  passphrase: string;

  signer: { name: string; email?: string };
  actorUserId?: string | null;

  certStore: CertStore;
  auditStore: AuditLogStore;
  storage: PdfStorageStore;

  /** Storage path prefix, e.g. `${tenantId}/${documentId}`. A timestamped filename is appended. */
  pathPrefix: string;

  /** signPdf signature metadata. */
  reason?: string;
  location?: string;
  signingTime?: Date;
  /** Optional RFC-3161 timestamp transport. Provide one to upgrade to CAdES-T. */
  tsa?: TsaTransport;

  /** Audit row fields. */
  action?: EsigAuditAction | string;
  targetTable?: string;
  targetId?: string;
  ip?: string;
  userAgent?: string;
  sessionId?: string;
  /** Extra audit metadata merged into the row (consent text, signer email, etc.). */
  metadata?: Record<string, unknown>;
}

export interface SignDocumentResult {
  signedPdfUrl: string;
  signatureImageUrl?: string;
  auditLogId: string;
  certId: string;
  certFingerprint: string;
  /** True when an RFC-3161 token was embedded (CAdES-T); false = CAdES-B. */
  timestamped: boolean;
  tsaError?: string;
}

export async function signDocument(
  input: SignDocumentInput,
): Promise<SignDocumentResult> {
  const signedAt = input.signingTime ?? new Date();

  // 1. HTML → unsigned PDF.
  const unsignedPdf = await renderHtmlToPdf({ html: input.html });

  // 2. Ensure an active signing cert for the tenant (create/rotate as needed).
  const cert = await ensureActiveCert({
    store: input.certStore,
    tenantId: input.tenantId,
    subjectName: input.subjectName,
    passphrase: input.passphrase,
  });

  // 3. PKCS#7 detached sign (+ optional TSA → CAdES-T).
  const r = await signPdf({
    pdf: unsignedPdf,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: input.reason ?? "Document acceptance",
    location: input.location ?? "",
    contactInfo: input.signer.email ?? "",
    name: input.signer.name,
    signingTime: signedAt,
    tsa: input.tsa,
  });

  // 4. Persist the signed PDF (+ optional signature image).
  const tsKey = signedAt.toISOString().replace(/[:.]/g, "-");
  const pdfPath = `${input.pathPrefix}/${tsKey}.pdf`;
  const pdfUp = await input.storage.upload({
    path: pdfPath,
    bytes: r.signedPdf,
    contentType: "application/pdf",
  });

  let signatureImageUrl: string | undefined;
  if (input.signatureImage) {
    const sigPath = `${input.pathPrefix}/${tsKey}-signature.png`;
    const sigUp = await input.storage.upload({
      path: sigPath,
      bytes: input.signatureImage.bytes,
      contentType: input.signatureImage.contentType,
    });
    signatureImageUrl = sigUp.url;
  }

  // 5. Append the attribution audit row (ESIGN R3 / UETA §13).
  const audit = await input.auditStore.insert({
    tenantId: input.tenantId,
    action: input.action ?? "pdf.signed",
    actorUserId: input.actorUserId ?? null,
    targetTable: input.targetTable,
    targetId: input.targetId,
    certId: cert.cert.id,
    certFingerprint: cert.cert.certFingerprint,
    ip: input.ip,
    userAgent: input.userAgent,
    sessionId: input.sessionId,
    signedPdfUrl: pdfUp.url,
    metadata: {
      ...(input.metadata ?? {}),
      ...(signatureImageUrl ? { signature_image_url: signatureImageUrl } : {}),
      signer_name: input.signer.name,
      ...(input.signer.email ? { signer_email: input.signer.email } : {}),
      timestamp: {
        attempted: !!input.tsa,
        present: r.timestamped,
        degraded: !!input.tsa && !r.timestamped,
        error: r.tsaError ?? null,
      },
    },
  });

  return {
    signedPdfUrl: pdfUp.url,
    signatureImageUrl,
    auditLogId: audit.id,
    certId: cert.cert.id,
    certFingerprint: cert.cert.certFingerprint,
    timestamped: r.timestamped,
    tsaError: r.tsaError,
  };
}
