// pq-verify.ts
//
// Verify the post-quantum hybrid seal embedded in a signed PDF, and the combined
// classical + post-quantum trust result — the "two-line" answer the product
// pitch leans on:
//
//   classical (PAdES / PKCS#7 RSA): VALID  — every PDF reader, incl. Acrobat
//   post-quantum (ML-DSA-65, FIPS 204):   VALID  — quantum-resistant
//
// The seal binds to the document by covering SHA-256 of the first `coveredBytes`
// bytes (P0, the pre-seal PDF). Because the seal is embedded append-only and the
// RSA /ByteRange signature is applied on top, tampering with the document breaks
// BOTH the classical signature AND the post-quantum digest.

import crypto from "node:crypto";

import { verifyPdfSignature, type VerifyResult } from "./verify-pdf.js";
import { verifyPqSealSignatures, type PqSeal } from "./pq-seal.js";
import { extractPqSeal } from "./pq-embed.js";
import { certMatchesPqSeal } from "./pq-cert.js";

export interface PqSealVerdict {
  /** A seal was found and parsed. */
  present: boolean;
  /** Hybrid verdict: digest binds to the document AND both signatures + fingerprint valid. */
  ok: boolean;
  /** SHA-256 over the covered document prefix equals the seal's `digest`. */
  digestBinds?: boolean;
  /** Classical Ed25519 signature valid. */
  ed25519?: boolean;
  /** Post-quantum ML-DSA-65 signature valid. */
  mldsa65?: boolean;
  /** Embedded ML-DSA fingerprint matches its public key. */
  fingerprintOk?: boolean;
  /** A `signerCert` was supplied AND it is a valid ML-DSA-65 cert for this seal's key. */
  certIdentityOk?: boolean;
  alg?: string;
  keyId?: string;
  /** ML-DSA-65 public-key fingerprint — the post-quantum signer identity to pin. */
  mldsa65Fpr?: string;
  signedAt?: string;
  coveredBytes?: number;
  failures: string[];
}

export interface VerifyPqSealOptions {
  /**
   * Pin the expected post-quantum signer. When set, the seal's ML-DSA-65
   * fingerprint MUST equal this value (case-insensitive hex) or verification
   * fails — this is how a relying party asserts "signed by THIS party" in-band
   * (the raw-key TOFU trust model). Compare against a fingerprint you published
   * or received out-of-band.
   */
  expectedMldsa65Fpr?: string;
  /**
   * A self-signed ML-DSA-65 X.509 certificate (PEM or DER) asserting the signer
   * identity. When set, the cert must be valid AND its public key must be the one
   * that produced the seal — the X.509 upgrade of `expectedMldsa65Fpr`.
   */
  signerCert?: string | Uint8Array;
}

/**
 * Verify the embedded post-quantum seal against the document bytes. Never throws;
 * a missing or malformed seal returns `{ present:false, ok:false }`. Pass
 * `expectedMldsa65Fpr` to also pin the signer identity.
 */
export function verifyPqSeal(pdf: Buffer, opts: VerifyPqSealOptions = {}): PqSealVerdict {
  const failures: string[] = [];
  const seal = extractPqSeal(pdf);
  if (!seal) {
    return { present: false, ok: false, failures: ["no post-quantum seal found"] };
  }

  const verdict: PqSealVerdict = {
    present: true,
    ok: false,
    alg: (seal as PqSeal).alg,
    keyId: (seal as PqSeal).keyId,
    mldsa65Fpr: (seal as PqSeal).keys?.mldsa65Fpr,
    signedAt: (seal as PqSeal).signedAt,
    coveredBytes: (seal as PqSeal).coveredBytes,
    failures,
  };

  // (1) Document binding: the seal must cover a real, in-bounds prefix.
  const covered = (seal as PqSeal).coveredBytes;
  let digestBinds = false;
  if (!Number.isInteger(covered) || covered <= 0 || covered > pdf.length) {
    failures.push(`seal coveredBytes (${covered}) is out of range for a ${pdf.length}-byte file`);
  } else {
    const recomputed = crypto.createHash("sha256").update(pdf.subarray(0, covered)).digest("hex");
    digestBinds = recomputed === (seal as PqSeal).digest;
    if (!digestBinds) {
      failures.push("post-quantum digest does not match the document — content altered");
    }
  }
  verdict.digestBinds = digestBinds;

  // (2) Signatures: both classical Ed25519 and post-quantum ML-DSA-65 must verify.
  const sigs = verifyPqSealSignatures(seal as PqSeal);
  verdict.ed25519 = sigs.ed25519;
  verdict.mldsa65 = sigs.mldsa65;
  verdict.fingerprintOk = sigs.fingerprintOk;
  if (!sigs.ed25519) failures.push("Ed25519 seal signature invalid");
  if (!sigs.mldsa65) failures.push("ML-DSA-65 seal signature invalid");
  if (!sigs.fingerprintOk) failures.push("ML-DSA-65 fingerprint inconsistent with its public key");
  if (!sigs.keyIdOk) failures.push("seal keyId inconsistent with its public keys");

  // (3) Optional identity pinning (in-band TOFU assertion).
  let identityOk = true;
  if (opts.expectedMldsa65Fpr) {
    identityOk = (verdict.mldsa65Fpr ?? "").toLowerCase() === opts.expectedMldsa65Fpr.toLowerCase();
    if (!identityOk) {
      failures.push("post-quantum signer fingerprint does not match the expected (pinned) identity");
    }
  }

  // (4) Optional X.509 identity: a self-signed ML-DSA-65 cert bound to this key.
  if (opts.signerCert) {
    const certOk = certMatchesPqSeal(opts.signerCert, seal as PqSeal);
    verdict.certIdentityOk = certOk;
    if (!certOk) {
      identityOk = false;
      failures.push("signer certificate is invalid or does not match the seal's post-quantum key");
    }
  }

  verdict.ok = digestBinds && sigs.ok && identityOk;
  return verdict;
}

export interface DocumentVerification {
  /**
   * Overall: the classical signature is valid AND, if a post-quantum seal is
   * present, it too is valid and lies within the classically-signed region. A
   * document with no seal is judged on the classical signature alone (backward
   * compatible); callers that REQUIRE post-quantum protection should also assert
   * `postQuantum.present`.
   */
  ok: boolean;
  /** Classical PAdES / PKCS#7 (RSA) verification. */
  classical: VerifyResult;
  /** Post-quantum hybrid seal verification. */
  postQuantum: PqSealVerdict;
}

export interface VerifyDocumentOptions extends VerifyPqSealOptions {
  /**
   * Require a valid post-quantum seal. When true, a document without a seal (or
   * with an invalid one) fails overall — use this where post-quantum protection
   * is mandatory, to prevent a silent downgrade to classical-only.
   */
  requirePq?: boolean;
}

/**
 * Full document verification: classical PAdES signature + post-quantum hybrid
 * seal. Also asserts that the seal-covered region falls within the RSA-signed
 * prefix, so the classical signature genuinely protects the seal. Pass
 * `requirePq` to reject unsealed documents and `expectedMldsa65Fpr` to pin the
 * post-quantum signer.
 */
export function verifyDocument(pdf: Buffer, opts: VerifyDocumentOptions = {}): DocumentVerification {
  const classical = verifyPdfSignature(pdf);
  const postQuantum = verifyPqSeal(pdf, {
    expectedMldsa65Fpr: opts.expectedMldsa65Fpr,
    signerCert: opts.signerCert,
  });

  let sealWithinSignedRegion = true;
  if (postQuantum.present && classical.byteRange && postQuantum.coveredBytes != null) {
    const [a, b] = classical.byteRange;
    const contentsStart = a + b; // end of the first signed chunk = start of /Contents
    if (postQuantum.coveredBytes > contentsStart) {
      sealWithinSignedRegion = false;
      postQuantum.failures.push(
        "seal covers bytes beyond the classically-signed region (not RSA-protected)",
      );
      postQuantum.ok = false;
    }
  }

  if (opts.requirePq && !postQuantum.present) {
    postQuantum.failures.push("post-quantum seal required but none present");
  }

  const pqSatisfied = postQuantum.present
    ? postQuantum.ok && sealWithinSignedRegion
    : !opts.requirePq;

  const ok = classical.ok && pqSatisfied;
  return { ok, classical, postQuantum };
}
