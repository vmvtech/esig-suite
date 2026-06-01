// src/lib/integrations/esig/core/pem-signer.ts
//
// Portable PKCS#7 signer for @signpdf/signpdf, driven by raw PEM input.
//
// Drops the PKCS#12 round-trip (broken in node-forge — see Phase 19 spike
// bug notes) by taking PEM key + cert and using forge.pkcs7.createSignedData
// directly. Project-agnostic: no DB, no storage, no project-specific assumptions.
//
// RFC 3161 (CAdES-T): when a TsaTransport is supplied, after signing we request
// a TimeStampToken over the SignerInfo signatureValue (encryptedDigest) and
// splice it into the SignerInfo as the id-aa-timeStampToken UNSIGNED attribute.
// The token is added by walking the DER and appending a hand-built [1] node to
// the SignerInfo SEQUENCE — we do NOT use forge's unauthenticatedAttributes
// auto-serialization, which is broken in 1.4.0 (a `.values` vs `.value` bug in
// the per-attribute path emits a malformed [1]).
//
// @signpdf/signpdf calls `signer.sign(pdfBuffer, signingTime)` (two args, and
// it awaits the result), so the TSA transport is supplied via the constructor,
// not per-call.

import forge from "node-forge";
import { Signer, SignPdfError } from "@signpdf/utils";

import {
  buildTimeStampReq,
  parseTimeStampResp,
  derStringToUint8,
  uint8ToDerString,
  OID_TIMESTAMP_TOKEN,
} from "./timestamp.js";
import type { TsaTransport } from "./types.js";

const asn1 = forge.asn1;

export interface PemSignerInput {
  keyPem: string;
  certPem: string;
  /**
   * Optional RFC 3161 timestamp transport. When provided, each produced
   * signature is upgraded from CAdES-B to CAdES-T by embedding a
   * TimeStampToken. The caller injects the network POST so this package never
   * performs egress (the TSA only ever receives a SHA-256 hash, never PHI).
   */
  tsa?: TsaTransport;
}

export class PemSigner extends Signer {
  private privateKey: forge.pki.rsa.PrivateKey;
  private certificate: forge.pki.Certificate;
  private tsa?: TsaTransport;

  /** True after the most recent sign() embedded a TimeStampToken (CAdES-T). */
  public lastTimestamped = false;
  /** Set when a non-required TSA call failed (signature falls back to CAdES-B). */
  public lastTsaError?: string;

  constructor({ keyPem, certPem, tsa }: PemSignerInput) {
    super();
    if (!keyPem.includes("-----BEGIN")) {
      throw new Error("PemSigner: keyPem must be PEM-encoded");
    }
    if (!certPem.includes("-----BEGIN CERTIFICATE-----")) {
      throw new Error("PemSigner: certPem must be a PEM-encoded X.509 certificate");
    }
    this.privateKey = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey;
    this.certificate = forge.pki.certificateFromPem(certPem);
    this.tsa = tsa;
  }

  async sign(pdfBuffer: Buffer, signingTime?: Date): Promise<Buffer> {
    if (!Buffer.isBuffer(pdfBuffer)) {
      throw new SignPdfError("PDF expected as Buffer.", SignPdfError.TYPE_INPUT);
    }
    // Reset per-call timestamp state (signpdf calls sign() once per signature).
    this.lastTimestamped = false;
    this.lastTsaError = undefined;

    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(pdfBuffer.toString("binary"));
    p7.addCertificate(this.certificate);
    p7.addSigner({
      key: this.privateKey,
      certificate: this.certificate,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        // @types/node-forge declares value as string but the runtime accepts
        // and prefers a Date — matches the official forge.pkcs7 docs.
        { type: forge.pki.oids.signingTime, value: (signingTime ?? new Date()) as unknown as string },
        { type: forge.pki.oids.messageDigest },
      ],
    });
    p7.sign({ detached: true });

    // No timestamp requested → original CAdES-B path, byte-identical behavior.
    if (!this.tsa) {
      return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), "binary");
    }

    // CAdES-T: request a TimeStampToken over the SignerInfo signatureValue.
    const p7Asn1 = p7.toAsn1();
    try {
      // node-forge sets `.signature` on each signer object after sign().
      const signers = (p7 as unknown as { signers: Array<{ signature?: string }> }).signers;
      const sigValue = signers?.[0]?.signature;
      if (!sigValue) {
        throw new Error("forge produced no SignerInfo signatureValue");
      }

      const reqDer = buildTimeStampReq(sigValue);
      const respBytes = await this.tsa.fetch(derStringToUint8(reqDer));
      const { token } = parseTimeStampResp(uint8ToDerString(respBytes));

      // Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }
      const attrSeq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
        asn1.create(
          asn1.Class.UNIVERSAL,
          asn1.Type.OID,
          false,
          asn1.oidToDer(OID_TIMESTAMP_TOKEN).getBytes(),
        ),
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [token]),
      ]);

      // unsignedAttrs ::= [1] IMPLICIT SET OF Attribute
      const unsignedAttrs = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 1, true, [attrSeq]);

      // Splice via DER-walk (NOT forge unauthenticatedAttributes, which is
      // broken in 1.4.0). Append the [1] node to the first SignerInfo SEQUENCE.
      spliceUnsignedAttrs(p7Asn1, unsignedAttrs);

      this.lastTimestamped = true;
    } catch (e) {
      if (this.tsa.required) {
        throw e;
      }
      // Non-required: degrade gracefully to CAdES-B.
      this.lastTimestamped = false;
      this.lastTsaError = String(e);
    }

    return Buffer.from(forge.asn1.toDer(p7Asn1).getBytes(), "binary");
  }
}

/**
 * Locate the (first) SignerInfo SEQUENCE inside a PKCS#7 SignedData ASN.1 tree
 * and append the supplied unsigned-attributes [1] node to it.
 *
 *   ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
 *   SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
 *                             certificates [0] IMPLICIT OPTIONAL,
 *                             crls [1] IMPLICIT OPTIONAL,
 *                             signerInfos SET OF SignerInfo }
 *   SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
 *                             signedAttrs [0] IMPLICIT OPTIONAL,
 *                             signatureAlgorithm, signature,
 *                             unsignedAttrs [1] IMPLICIT OPTIONAL }
 *
 * signerInfos is the last UNIVERSAL SET among SignedData's children (the first
 * SET is digestAlgorithms). We append the unsigned attrs as the final child of
 * the first SignerInfo SEQUENCE.
 */
function spliceUnsignedAttrs(
  contentInfo: forge.asn1.Asn1,
  unsignedAttrs: forge.asn1.Asn1,
): void {
  if (!Array.isArray(contentInfo.value)) {
    throw new Error("RFC3161 splice: ContentInfo has no children");
  }

  // content [0] EXPLICIT → SignedData SEQUENCE
  let signedData: forge.asn1.Asn1 | undefined;
  for (const child of contentInfo.value as forge.asn1.Asn1[]) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
      signedData = child.value[0] as forge.asn1.Asn1;
    }
  }
  if (!signedData || !Array.isArray(signedData.value)) {
    throw new Error("RFC3161 splice: SignedData not found");
  }

  // signerInfos = the last UNIVERSAL SET among SignedData children.
  let signerInfos: forge.asn1.Asn1 | undefined;
  for (const child of signedData.value as forge.asn1.Asn1[]) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.SET &&
      Array.isArray(child.value)
    ) {
      signerInfos = child; // keep the last one encountered
    }
  }
  if (!signerInfos || !Array.isArray(signerInfos.value) || signerInfos.value.length === 0) {
    throw new Error("RFC3161 splice: signerInfos SET not found");
  }

  const signerInfo = signerInfos.value[0] as forge.asn1.Asn1;
  if (!Array.isArray(signerInfo.value)) {
    throw new Error("RFC3161 splice: SignerInfo SEQUENCE malformed");
  }

  (signerInfo.value as forge.asn1.Asn1[]).push(unsignedAttrs);
}
