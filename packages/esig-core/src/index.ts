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
  ExternalSigner,
  ExternalSignerKeyType,
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

// ---- Multi-signer envelopes + tokenized signing links ----
export {
  createEnvelope,
  resolveSigningToken,
  recordSignature,
  declineEnvelope,
  voidEnvelope,
  composeEnvelopeHtml,
  EnvelopeError,
  type Envelope,
  type EnvelopeSigner,
  type EnvelopeStatus,
  type EnvelopeSignerStatus,
  type EnvelopeStore,
  type CreateEnvelopeInput,
  type CreateEnvelopeResult,
  type TokenResolution,
} from "./envelope.js";

// ---- End-to-end orchestrator ----
export {
  signDocument,
  type SignDocumentInput,
  type SignDocumentResult,
} from "./sign-document.js";

// ---- Post-quantum hybrid seal (Ed25519 + ML-DSA-65, FIPS 204) ----
export {
  generatePqKeyBundle,
  loadPqSigningKeys,
  publicMaterialForKeys,
  wrapPqKeyBundle,
  unwrapPqKeyBundle,
  buildPqSeal,
  verifyPqSealSignatures,
  canonicalJson,
  PQ_SEAL_VERSION,
  PQ_SEAL_ALG,
  type PqKeyBundle,
  type PqPublicMaterial,
  type PqSigningKeys,
  type PqSeal,
  type PqSealVerification,
  type BuildPqSealInput,
} from "./pq-seal.js";
export { embedPqSeal, extractPqSeal, hasPqSeal } from "./pq-embed.js";
export {
  verifyPqSeal,
  verifyDocument,
  type PqSealVerdict,
  type DocumentVerification,
  type VerifyPqSealOptions,
  type VerifyDocumentOptions,
} from "./pq-verify.js";
export {
  ensureActivePqKeys,
  rotatePqKeys,
  type PqKeyStore,
  type StoredPqKeys,
  type EnsurePqKeysResult,
} from "./pq-lifecycle.js";
export {
  issueMlDsaCertificate,
  parseMlDsaCertificate,
  verifyMlDsaCertificate,
  certMatchesPqSeal,
  ID_ML_DSA_65,
  type IssueMlDsaCertOptions,
  type MlDsaCertificate,
  type ParsedMlDsaCertificate,
  type MlDsaCertVerdict,
} from "./pq-cert.js";
