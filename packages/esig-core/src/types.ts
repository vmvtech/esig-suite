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

/** RSA key sizes supported by the {@link ExternalSigner} seam. */
export type ExternalSignerKeyType = "rsa-2048" | "rsa-3072" | "rsa-4096";

/**
 * Caller-injected signing seam — lets the RSA private key live OUTSIDE this
 * process (HSM via PKCS#11, KMS, remote signing service…). The key material
 * never touches @e-sig/core; only the certificate (public) and a sign callback
 * are supplied. Pass it to `signPdf({ externalSigner })` or
 * `new PemSigner({ externalSigner })` in place of `keyPem`.
 *
 * Design note (why a single raw-bytes callback is sufficient): the PKCS#7
 * signature that ends up in the PDF is ALWAYS recomputed by `PemSigner` over
 * the final signed-attributes SET (after the ESS signing-certificate-v2 splice)
 * — node-forge's internal sync signing pass is discarded. That recomputation
 * happens in our own async code with the exact to-be-signed bytes in hand, so
 * the external signer is invoked exactly once, may be async (network HSMs),
 * and needs no node-forge shim.
 *
 * A PKCS#11 reference adapter ships as `@e-sig/hsm-pkcs11`.
 */
export interface ExternalSigner {
  /** RSA modulus size of the external key. Validated against `certificatePem`. */
  keyType: ExternalSignerKeyType;
  /**
   * PEM-encoded X.509 certificate whose public key matches the external
   * private key. Embedded in the PKCS#7 and used for structural validation.
   */
  certificatePem: string;
  /**
   * Sign `data` with RSASSA-PKCS1-v1_5 / SHA-256 — the signer hashes the raw
   * bytes itself (PKCS#11 mechanism CKM_SHA256_RSA_PKCS does exactly this).
   * This is byte-identical to what node-forge produces with `key.sign(md)` for
   * the same key. Must return the raw signature, exactly modulus-sized
   * (256/384/512 bytes for rsa-2048/3072/4096). Sync or async.
   */
  signRsaSha256(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
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
