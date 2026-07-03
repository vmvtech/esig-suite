// @e-sig/core
//
// Portable, self-contained PDF e-signature engine. Zero database / storage /
// auth / framework assumptions: render HTML→PDF, issue a self-signed org cert,
// PKCS#7-detached sign (optional RFC-3161 TSA → CAdES-T), verify.
//
// - Bring-your-own persistence via the CertStore / AuditLogStore / PdfStorageStore
//   interfaces (./adapters). A Supabase reference impl ships as @e-sig/supabase.
// - `signDocument()` is the optional end-to-end orchestrator over those stores.

// ---- Crypto primitives ----
export { PemSigner, type PemSignerInput } from "./pem-signer.js";
export {
  generateSelfSignedCert,
  encryptKeyPem,
  decryptKeyPem,
  type GenerateCertOptions,
  type GeneratedCert,
} from "./cert-issuer.js";
export { renderHtmlToPdf, type RenderHtmlToPdfOptions } from "./render-pdf.js";
export { signPdf, type SignPdfInput, type SignPdfResult } from "./sign-pdf.js";
export { verifyPdfStructure, verifyPdfSignature, type VerifyResult } from "./verify-pdf.js";
export {
  buildTimeStampReq,
  parseTimeStampResp,
  parseTstInfo,
  OID_TIMESTAMP_TOKEN,
} from "./timestamp.js";
export type {
  Signer,
  SigningCertPem,
  SignedPdfMetadata,
  TsaTransport,
} from "./types.js";

// ---- Persistence interfaces (bring-your-own; see @e-sig/supabase) ----
export type {
  StoredCert,
  CertStore,
  AuditLogEntry,
  AuditLogRow,
  AuditLogStore,
  EsigAuditAction,
  PdfStorageStore,
} from "./adapters.js";

// ---- Cert lifecycle (stack-agnostic; interface-only) ----
export { ensureActiveCert, type EnsureCertResult } from "./cert-lifecycle.js";

// ---- End-to-end orchestrator ----
export {
  signDocument,
  type SignDocumentInput,
  type SignDocumentResult,
} from "./sign-document.js";
