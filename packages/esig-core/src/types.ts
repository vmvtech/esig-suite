// src/lib/integrations/esig/core/types.ts
//
// Phase 21 — public types for the portable e-sig core.
//
// The `core/` module is project-agnostic: pure crypto + rendering + PDF
// structural verification. Database, Storage, and Auth concerns live in
// `adapters/` (the current Supabase implementation) or in whatever you
// supply when porting to another project.

export interface Signer {
  /** Display name shown to humans (PDF visible signature block + cert binding). */
  name: string;
  /** Email — embedded in PKCS#7 contactInfo. ASCII recommended. */
  email: string;
}

export interface SigningCertPem {
  /** PEM-encoded RSA private key. */
  keyPem: string;
  /** PEM-encoded X.509 certificate. */
  certPem: string;
  /** SHA-256 hex digest of the DER-encoded cert (for audit attribution). */
  fingerprint: string;
}

export interface SignedPdfMetadata {
  /** Why the doc was signed — embedded in PDF signature dictionary. */
  reason: string;
  /** Geographic or URL context — embedded in PDF signature dictionary. */
  location: string;
  /** Signer's primary contact — embedded in PDF signature dictionary. */
  contactInfo: string;
  /** Signer's display name — embedded in PDF signature dictionary. */
  name: string;
  /** When the signature was applied. Defaults to now. */
  signingTime?: Date;
}

/**
 * Caller-injected RFC 3161 timestamp transport.
 *
 * The consumer supplies the network POST so this package stays dependency-free
 * and performs no egress itself. `fetch` receives the DER-encoded TimeStampReq
 * bytes and MUST return the raw DER-encoded TimeStampResp bytes. The TSA only
 * ever sees a SHA-256 hash — never PHI.
 */
export interface TsaTransport {
  /** POST the TimeStampReq DER to the TSA and return the TimeStampResp DER. */
  fetch: (reqDerBytes: Uint8Array) => Promise<Uint8Array>;
  /**
   * When true, a TSA failure aborts signing (throws). When false/omitted, a
   * failure degrades gracefully to a plain CAdES-B signature.
   */
  required?: boolean;
}
