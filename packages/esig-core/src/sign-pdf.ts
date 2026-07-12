// src/lib/integrations/esig/core/sign-pdf.ts
//
// Portable PDF signing — placeholder injection + PKCS#7 detached sign.
// Uses ETSI.CAdES.detached subfilter (modern PAdES, not legacy Adobe).
//
// RFC 3161 (CAdES-T): pass `tsa` to embed an RFC 3161 TimeStampToken. When a
// TSA is supplied the default /Contents budget is raised to fit the TST + TSA
// cert chain, and an overflow guard rejects a result whose PKCS#7 exceeded the
// placeholder (which @signpdf would otherwise silently truncate).

import crypto from "node:crypto";

import { SignPdf } from "@signpdf/signpdf";
import { plainAddPlaceholder } from "./vendor/placeholder-plain/index.js";
import { PemSigner } from "./pem-signer.js";
import { verifyPdfStructure } from "./verify-pdf.js";
import type { ExternalSigner, TsaTransport } from "./types.js";
import { buildPqSeal, publicMaterialForKeys, type PqSigningKeys } from "./pq-seal.js";
import { embedPqSeal } from "./pq-embed.js";

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
  /**
   * PEM-encoded RSA private key (in-memory signing). Required unless
   * `externalSigner` is provided — the two are mutually exclusive.
   */
  keyPem?: string;
  /**
   * PEM-encoded X.509 certificate. Required with `keyPem`; with
   * `externalSigner` it defaults to `externalSigner.certificatePem`.
   */
  certPem?: string;
  /**
   * External signing seam (HSM / KMS): the RSA private key stays outside this
   * process and the PKCS#7 signature is produced by
   * `externalSigner.signRsaSha256` (sync or async — RSASSA-PKCS1-v1_5/SHA-256
   * over raw bytes, e.g. PKCS#11 CKM_SHA256_RSA_PKCS). Mutually exclusive with
   * `keyPem`. Output is byte-identical to the `keyPem` path for the same key.
   * See `ExternalSigner` in types.ts; a PKCS#11 adapter ships as
   * `@e-sig/hsm-pkcs11`.
   */
  externalSigner?: ExternalSigner;
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
  /**
   * Strict PAdES baseline mode: drop the PAdES-forbidden `signing-time` signed
   * attribute (claimed time then comes from the TSA / verifier context). The ESS
   * `signing-certificate-v2` attribute is always added regardless. Default false
   * (keeps `signing-time` for backward compatibility).
   */
  padesStrict?: boolean;
  /**
   * Optional post-quantum hybrid seal (Ed25519 + ML-DSA-65, FIPS 204). When
   * provided, a seal over SHA-256 of the pre-signature PDF is embedded FIRST (an
   * append-only incremental update), so the classical RSA /ByteRange signature
   * applied on top cryptographically covers it. The classical signature remains
   * valid in every PDF reader; the seal is the quantum-resistant layer, verified
   * by `verifyPqSeal` / `verifyDocument`.
   */
  pqSeal?: {
    /** Hybrid signing keys (see generatePqKeyBundle / loadPqSigningKeys). */
    keys: PqSigningKeys;
    /** Seal timestamp. Defaults to `signingTime` or now. */
    signedAt?: Date;
  };
}

export interface SignPdfResult {
  signedPdf: Buffer;
  placeholderBudget: number;
  /** True if an RFC 3161 TimeStampToken was embedded (CAdES-T). */
  timestamped: boolean;
  /** Present when a non-required TSA request failed (signature is CAdES-B). */
  tsaError?: string;
  /** True when a post-quantum hybrid seal was embedded (and is RSA-covered). */
  pqSealed: boolean;
  /** Seal keyId (128-bit hex over both public keys), when sealed. */
  pqKeyId?: string;
  /** ML-DSA-65 public-key fingerprint (SHA-256 hex), when sealed. */
  pqMldsa65Fpr?: string;
}

const signpdfInstance = new SignPdf();

export async function signPdf(input: SignPdfInput): Promise<SignPdfResult> {
  if (input.externalSigner && input.keyPem) {
    throw new Error("signPdf: pass either keyPem or externalSigner, not both");
  }
  if (!input.externalSigner && !input.keyPem) {
    throw new Error("signPdf: keyPem or externalSigner is required");
  }
  const budget =
    input.signatureLength ??
    (input.tsa ? TIMESTAMPED_SIGNATURE_LENGTH : DEFAULT_SIGNATURE_LENGTH);

  // Post-quantum seal FIRST (append-only), so the classical /ByteRange signature
  // applied below cryptographically covers it. The seal signs SHA-256 of the
  // pre-seal PDF (P0); coveredBytes = P0.length locates that region in the final
  // file (incremental updates never rewrite prior bytes).
  let basePdf = input.pdf;
  let pqKeyId: string | undefined;
  let pqMldsa65Fpr: string | undefined;
  if (input.pqSeal) {
    const digestHex = crypto.createHash("sha256").update(input.pdf).digest("hex");
    const seal = buildPqSeal({
      digestHex,
      coveredBytes: input.pdf.length,
      keys: input.pqSeal.keys,
      signedAt: input.pqSeal.signedAt ?? input.signingTime,
    });
    basePdf = embedPqSeal(input.pdf, seal);
    const pub = publicMaterialForKeys(input.pqSeal.keys);
    pqKeyId = pub.keyId;
    pqMldsa65Fpr = pub.mldsa65Fpr;
  }

  const withPlaceholder = plainAddPlaceholder({
    pdfBuffer: basePdf,
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
    externalSigner: input.externalSigner,
    tsa: input.tsa,
    padesStrict: input.padesStrict,
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
    pqSealed: !!input.pqSeal,
    pqKeyId,
    pqMldsa65Fpr,
  };
}
