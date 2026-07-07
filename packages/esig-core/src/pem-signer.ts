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
import type { ExternalSigner, ExternalSignerKeyType, TsaTransport } from "./types.js";

const asn1 = forge.asn1;

/** Expected RSA modulus bit length per ExternalSigner keyType. */
const EXTERNAL_KEY_BITS: Record<ExternalSignerKeyType, number> = {
  "rsa-2048": 2048,
  "rsa-3072": 3072,
  "rsa-4096": 4096,
};

/** id-aa-signingCertificateV2 (ESS, RFC 5035) — binds the signer cert into the signed data. */
const OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";
/** id-signingTime (PKCS#9) — PAdES forbids this signed attribute (time belongs in /M). */
const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";

export interface PemSignerInput {
  /** PEM-encoded RSA private key. Required unless `externalSigner` is provided. */
  keyPem?: string;
  /**
   * PEM-encoded X.509 certificate. Required on the `keyPem` path; on the
   * `externalSigner` path it defaults to `externalSigner.certificatePem`.
   */
  certPem?: string;
  /**
   * External signing seam (HSM / KMS — see `ExternalSigner` in types.ts).
   * Mutually exclusive with `keyPem`. The private key never enters this
   * process; the PKCS#7 signature is produced by `signRsaSha256` (sync or
   * async) over the final signed-attributes SET.
   */
  externalSigner?: ExternalSigner;
  /**
   * Optional RFC 3161 timestamp transport. When provided, each produced
   * signature is upgraded from CAdES-B to CAdES-T by embedding a
   * TimeStampToken. The caller injects the network POST so this package never
   * performs egress (the TSA only ever receives a SHA-256 hash, never PHI).
   */
  tsa?: TsaTransport;
  /**
   * Strict PAdES baseline (ETSI EN 319 142-1) mode. When true, the CMS
   * `signing-time` signed attribute is removed (PAdES requires the claimed time
   * to live in the signature dictionary /M entry, not the CMS). Default false
   * keeps `signing-time` for backward compatibility with existing deployments;
   * the ESS `signing-certificate-v2` attribute is added in BOTH modes.
   */
  padesStrict?: boolean;
}

export class PemSigner extends Signer {
  /** Present on the in-memory path; absent when an ExternalSigner is used. */
  private privateKey?: forge.pki.rsa.PrivateKey;
  private externalSigner?: ExternalSigner;
  private certificate: forge.pki.Certificate;
  private tsa?: TsaTransport;
  private padesStrict: boolean;

  /** True after the most recent sign() embedded a TimeStampToken (CAdES-T). */
  public lastTimestamped = false;
  /** Set when a non-required TSA call failed (signature falls back to CAdES-B). */
  public lastTsaError?: string;

  constructor({ keyPem, certPem, tsa, padesStrict, externalSigner }: PemSignerInput) {
    super();
    if (externalSigner) {
      if (keyPem) {
        throw new Error("PemSigner: pass either keyPem or externalSigner, not both");
      }
      const pem = certPem ?? externalSigner.certificatePem;
      if (!pem || !pem.includes("-----BEGIN CERTIFICATE-----")) {
        throw new Error("PemSigner: certPem must be a PEM-encoded X.509 certificate");
      }
      this.certificate = forge.pki.certificateFromPem(pem);
      const expectedBits = EXTERNAL_KEY_BITS[externalSigner.keyType];
      if (!expectedBits) {
        throw new Error(
          `PemSigner: unsupported externalSigner.keyType "${String(externalSigner.keyType)}"`,
        );
      }
      const actualBits = (this.certificate.publicKey as forge.pki.rsa.PublicKey).n.bitLength();
      if (actualBits !== expectedBits) {
        throw new Error(
          `PemSigner: externalSigner.keyType ${externalSigner.keyType} does not match the ` +
            `certificate's RSA modulus (${actualBits} bits)`,
        );
      }
      this.externalSigner = externalSigner;
    } else {
      if (!keyPem || !keyPem.includes("-----BEGIN")) {
        throw new Error("PemSigner: keyPem must be PEM-encoded");
      }
      if (!certPem || !certPem.includes("-----BEGIN CERTIFICATE-----")) {
        throw new Error("PemSigner: certPem must be a PEM-encoded X.509 certificate");
      }
      this.privateKey = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey;
      this.certificate = forge.pki.certificateFromPem(certPem);
    }
    this.tsa = tsa;
    this.padesStrict = padesStrict ?? false;
  }

  /** RSA modulus size in bytes (a PKCS1-v1_5 signature is exactly this long). */
  private modulusBytes(): number {
    return Math.ceil(
      (this.certificate.publicKey as forge.pki.rsa.PublicKey).n.bitLength() / 8,
    );
  }

  async sign(pdfBuffer: Buffer, signingTime?: Date): Promise<Buffer> {
    if (!Buffer.isBuffer(pdfBuffer)) {
      throw new SignPdfError("PDF expected as Buffer.", SignPdfError.TYPE_INPUT);
    }
    // Reset per-call timestamp state (signpdf calls sign() once per signature).
    this.lastTimestamped = false;
    this.lastTsaError = undefined;

    // Key handed to forge's synchronous p7.sign() pass. On the externalSigner
    // path this is a placeholder shim: forge only needs an object with a
    // sign(md) method, and the signature it produces here is ALWAYS discarded —
    // addSigningCertV2AndResign() below recomputes the signature over the final
    // (spliced) signed-attributes SET on BOTH paths. Doing the real external
    // call there (in our own async code, with the raw to-be-signed bytes in
    // hand) is what makes async HSM signers possible without a two-pass sign.
    const forgeSigningKey =
      this.privateKey ??
      (placeholderForgeKey(this.modulusBytes()) as unknown as forge.pki.rsa.PrivateKey);

    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(pdfBuffer.toString("binary"));
    p7.addCertificate(this.certificate);
    p7.addSigner({
      key: forgeSigningKey,
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

    // Add the ESS signing-certificate-v2 signed attribute (binds THIS cert into
    // the signed data — required for PAdES/CAdES baseline) and re-sign the
    // modified signed-attributes set. forge cannot encode this attribute in its
    // authenticatedAttributes list, so we splice it in and recompute the RSA
    // signature over the exact bytes. Returns the NEW signatureValue.
    const p7Asn1 = p7.toAsn1();
    const sigValue = await this.addSigningCertV2AndResign(p7Asn1);

    // No timestamp requested → CAdES-B (now cert-bound).
    if (!this.tsa) {
      return Buffer.from(forge.asn1.toDer(p7Asn1).getBytes(), "binary");
    }

    // CAdES-T: request a TimeStampToken over the (final) SignerInfo signatureValue.
    try {
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

  /**
   * Insert the ESS signing-certificate-v2 signed attribute into the first
   * SignerInfo's signed-attributes set and recompute the RSA signature over the
   * modified set. In `padesStrict` mode the PAdES-forbidden signing-time
   * attribute is also removed. Returns the new signatureValue (forge binary
   * string) so the caller can timestamp the FINAL signature.
   *
   * This is the single point where the real signature is produced (the value
   * forge computed during p7.sign() is overwritten unconditionally) — so it is
   * also the ExternalSigner seam: on that path the raw DER of the SET is handed
   * to `signRsaSha256` (awaited; sync or async), instead of the in-memory key.
   */
  private async addSigningCertV2AndResign(p7Asn1: forge.asn1.Asn1): Promise<string> {
    const signerInfo = firstSignerInfoSeq(p7Asn1);
    const siChildren = signerInfo.value as forge.asn1.Asn1[];

    // signedAttrs = the [0] IMPLICIT context node; encryptedDigest = the
    // UNIVERSAL OCTET STRING (the signature to overwrite).
    let signedAttrs: forge.asn1.Asn1 | undefined;
    let sigOctet: forge.asn1.Asn1 | undefined;
    for (const child of siChildren) {
      if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && child.type === 0) {
        signedAttrs = child;
      }
      if (child.tagClass === asn1.Class.UNIVERSAL && child.type === asn1.Type.OCTETSTRING) {
        sigOctet = child;
      }
    }
    if (!signedAttrs || !Array.isArray(signedAttrs.value) || !sigOctet) {
      throw new Error("PemSigner: could not locate signed attributes to add signing-certificate-v2");
    }

    let attrs = signedAttrs.value as forge.asn1.Asn1[];
    if (this.padesStrict) {
      attrs = attrs.filter((a) => {
        const oidNode = Array.isArray(a.value) ? (a.value[0] as forge.asn1.Asn1) : undefined;
        return !(oidNode && oidNode.type === asn1.Type.OID && safeOid(oidNode.value as string) === OID_SIGNING_TIME);
      });
    }
    attrs.push(buildSigningCertV2Attr(this.certificate));
    signedAttrs.value = attrs;

    // Re-sign: RSA over DER(signedAttrs re-tagged as SET OF), SHA-256.
    const setDer = asn1.toDer(
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, attrs),
    ).getBytes();
    let newSig: string;
    if (this.externalSigner) {
      // External seam: RSASSA-PKCS1-v1_5/SHA-256 over the same raw bytes —
      // byte-identical to forge's key.sign(md) for the same key.
      const sig = await this.externalSigner.signRsaSha256(derStringToUint8(setDer));
      const expected = this.modulusBytes();
      if (!(sig instanceof Uint8Array) || sig.length !== expected) {
        throw new Error(
          `PemSigner: externalSigner.signRsaSha256 returned ${sig instanceof Uint8Array ? sig.length : typeof sig
          } bytes; expected exactly ${expected} (RSASSA-PKCS1-v1_5 signatures are modulus-sized)`,
        );
      }
      newSig = uint8ToDerString(sig);
    } else {
      const md = forge.md.sha256.create();
      md.update(setDer);
      newSig = this.privateKey!.sign(md); // RSASSA-PKCS1-V1_5 (forge default)
    }
    sigOctet.value = newSig;
    return newSig;
  }
}

/**
 * Stand-in key for forge's internal (always-discarded) signing pass on the
 * ExternalSigner path. node-forge accepts any object with a `sign(md)` method
 * as a SignerInfo key; this one emits modulus-sized zero bytes so the ASN.1
 * tree has a correctly-shaped signature OCTET STRING until
 * addSigningCertV2AndResign() overwrites it with the real external signature.
 */
function placeholderForgeKey(modulusBytes: number): {
  sign: (md: forge.md.MessageDigest, scheme?: unknown) => string;
} {
  return { sign: () => "\x00".repeat(modulusBytes) };
}

/**
 * Build the ESS signing-certificate-v2 signed attribute (RFC 5035) binding the
 * signer certificate into the signed data:
 *   Attribute { OID id-aa-signingCertificateV2, SET { SigningCertificateV2 } }
 *   SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
 *   ESSCertIDv2 ::= SEQUENCE { certHash OCTET STRING, issuerSerial IssuerSerial }
 * hashAlgorithm defaults to SHA-256 and is omitted (DEFAULT).
 */
function buildSigningCertV2Attr(cert: forge.pki.Certificate): forge.asn1.Asn1 {
  const certDer = asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(certDer);
  const certHash = md.digest().getBytes();

  // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
  const issuerName = forge.pki.distinguishedNameToAsn1(cert.issuer);
  const generalName = asn1.create(asn1.Class.CONTEXT_SPECIFIC, 4, true, [issuerName]); // directoryName [4]
  const generalNames = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [generalName]);
  let serialBytes = forge.util.hexToBytes(cert.serialNumber);
  if (serialBytes.length > 0 && (serialBytes.charCodeAt(0) & 0x80) !== 0) {
    serialBytes = "\x00" + serialBytes; // keep the INTEGER positive
  }
  const serial = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, serialBytes);
  const issuerSerial = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [generalNames, serial]);

  const essCertId = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, certHash),
    issuerSerial,
  ]);
  const certsSeq = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [essCertId]);
  const signingCertV2 = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [certsSeq]);

  return asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(OID_SIGNING_CERT_V2).getBytes()),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, [signingCertV2]),
  ]);
}

/** OID decode that never throws (returns "" on malformed input). */
function safeOid(der: string): string {
  try {
    return asn1.derToOid(der);
  } catch {
    return "";
  }
}

/** Locate the first SignerInfo SEQUENCE inside a PKCS#7 SignedData ASN.1 tree. */
function firstSignerInfoSeq(contentInfo: forge.asn1.Asn1): forge.asn1.Asn1 {
  if (!Array.isArray(contentInfo.value)) {
    throw new Error("PemSigner: ContentInfo has no children");
  }
  let signedData: forge.asn1.Asn1 | undefined;
  for (const child of contentInfo.value as forge.asn1.Asn1[]) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
      signedData = child.value[0] as forge.asn1.Asn1;
    }
  }
  if (!signedData || !Array.isArray(signedData.value)) {
    throw new Error("PemSigner: SignedData not found");
  }
  let signerInfos: forge.asn1.Asn1 | undefined;
  for (const child of signedData.value as forge.asn1.Asn1[]) {
    if (child.tagClass === asn1.Class.UNIVERSAL && child.type === asn1.Type.SET && Array.isArray(child.value)) {
      signerInfos = child; // last UNIVERSAL SET = signerInfos
    }
  }
  if (!signerInfos || !Array.isArray(signerInfos.value) || signerInfos.value.length === 0) {
    throw new Error("PemSigner: signerInfos SET not found");
  }
  const si = signerInfos.value[0] as forge.asn1.Asn1;
  if (!Array.isArray(si.value)) {
    throw new Error("PemSigner: SignerInfo SEQUENCE malformed");
  }
  return si;
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
