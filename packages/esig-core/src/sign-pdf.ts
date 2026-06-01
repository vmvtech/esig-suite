// src/lib/integrations/esig/core/sign-pdf.ts
//
// Portable PDF signing — placeholder injection + PKCS#7 detached sign.
// Uses ETSI.CAdES.detached subfilter (modern PAdES, not legacy Adobe).
//
// RFC 3161 (CAdES-T): pass `tsa` to embed an RFC 3161 TimeStampToken. When a
// TSA is supplied the default /Contents budget is raised to fit the TST + TSA
// cert chain, and an overflow guard rejects a result whose PKCS#7 exceeded the
// placeholder (which @signpdf would otherwise silently truncate).

import { SignPdf } from "@signpdf/signpdf";
import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { PemSigner } from "./pem-signer.js";
import { verifyPdfStructure } from "./verify-pdf.js";
import type { TsaTransport } from "./types.js";

/** Default /Contents budget (bytes) when no timestamp is embedded. */
const DEFAULT_SIGNATURE_LENGTH = 8192;
/**
 * Default /Contents budget (bytes) when an RFC 3161 timestamp is embedded.
 * A TST plus the TSA cert chain adds several KB; /Contents is hex so 30720
 * bytes ≈ 15 KB of DER headroom.
 */
const TIMESTAMPED_SIGNATURE_LENGTH = 30720;

export interface SignPdfInput {
  pdf: Buffer;
  keyPem: string;
  certPem: string;
  reason: string;
  location: string;
  contactInfo: string;
  name: string;
  signingTime?: Date;
  /**
   * Signature length budget in bytes. 8192 fits RSA-2048 + single cert
   * comfortably (actual PKCS#7 is typically 1.5–2 KB). When `tsa` is provided
   * and this is omitted, the default rises to 30720 to fit the TimeStampToken.
   */
  signatureLength?: number;
  /**
   * Subfilter. Default ETSI.CAdES.detached (PAdES B-B baseline). Override
   * to adbe.pkcs7.detached for legacy Adobe Reader 9+ compatibility.
   */
  subFilter?: string;
  /**
   * Optional RFC 3161 timestamp transport. When provided, the signature is
   * upgraded to CAdES-T and the default `signatureLength` rises to 30720. The
   * caller injects the network POST; the TSA only ever receives a SHA-256 hash,
   * never PHI.
   */
  tsa?: TsaTransport;
}

export interface SignPdfResult {
  signedPdf: Buffer;
  placeholderBudget: number;
  /** True if an RFC 3161 TimeStampToken was embedded (CAdES-T). */
  timestamped: boolean;
  /** Present when a non-required TSA request failed (signature is CAdES-B). */
  tsaError?: string;
}

const signpdfInstance = new SignPdf();

export async function signPdf(input: SignPdfInput): Promise<SignPdfResult> {
  const budget =
    input.signatureLength ??
    (input.tsa ? TIMESTAMPED_SIGNATURE_LENGTH : DEFAULT_SIGNATURE_LENGTH);
  const withPlaceholder = plainAddPlaceholder({
    pdfBuffer: input.pdf,
    reason: input.reason,
    contactInfo: input.contactInfo,
    name: input.name,
    location: input.location,
    signatureLength: budget,
    subFilter: input.subFilter ?? "ETSI.CAdES.detached",
  });
  const signer = new PemSigner({
    keyPem: input.keyPem,
    certPem: input.certPem,
    tsa: input.tsa,
  });
  const signed = await signpdfInstance.sign(withPlaceholder, signer, input.signingTime);

  // Overflow guard: @signpdf silently truncates if the PKCS#7 exceeds the
  // /Contents placeholder. Re-parse and fail loudly if it did not fit (this
  // matters most on the timestamped path, where the TST is large). We compare
  // the actual PKCS#7 size against the structurally-measured /Contents budget.
  const structure = verifyPdfStructure(signed);
  const actual = structure.pkcs7ActualSize ?? 0;
  const measuredBudget = structure.pkcs7BudgetSize ?? budget;
  if (actual >= measuredBudget) {
    throw new Error(
      `PKCS#7 (${actual} bytes) exceeded placeholder budget (${measuredBudget}) — increase signatureLength`,
    );
  }

  // placeholderBudget reports the requested budget (backward compatible).
  return {
    signedPdf: signed,
    placeholderBudget: budget,
    timestamped: signer.lastTimestamped,
    tsaError: signer.lastTsaError,
  };
}
