// src/lib/integrations/esig/core/verify-pdf.ts
//
// Portable CRYPTOGRAPHIC verifier for PKCS#7-signed PDFs. Returns diagnostics
// rather than throwing — callers decide whether to surface failures.
//
// `ok:true` means the signature is cryptographically valid over this exact
// document, i.e. ALL of:
//   1. Structure — the /ByteRange dictionary tiles the file around the
//      /Contents hole, and the PKCS#7 blob DER-parses.
//   2. Integrity (digest) — SHA-256 recomputed over the ByteRange-covered bytes
//      equals the `messageDigest` signed attribute. A single flipped byte in the
//      covered region fails this check.
//   3. Authenticity (signature) — the RSA signature over DER(signedAttrs) taken
//      as a SET verifies against the embedded signer certificate's public key.
//
// A tampered document therefore returns ok:false (not ok:true), which is the
// whole point of a signature verifier. `verifyPdfStructure` is retained as the
// historical name; `verifyPdfSignature` is the preferred alias.
//
// RFC 3161 (CAdES-T): if the SignerInfo carries an id-aa-timeStampToken
// UNSIGNED attribute, we surface `timestamped:true` plus best-effort genTime /
// TSA common name, AND enforce the §2.4.2 binding check — the TST's
// messageImprint MUST equal sha256(signerInfo.signature). A mismatch is a hard
// failure (ok:false). Absence of a timestamp is fine (backward compatible:
// timestamped:false, ok unaffected).
//
// NOTE: this validates the signature MATH against the certificate embedded in
// the document. It does NOT establish trust in that certificate (chain to a
// trust anchor, revocation, AATL/EUTL membership) — self-issued signer certs
// are their own trust root, so trust is an out-of-band, deployment-level concern.

import crypto from "node:crypto";
import forge from "node-forge";

import { OID_TIMESTAMP_TOKEN, parseTstInfo } from "./timestamp.js";

const asn1 = forge.asn1;

/** OID id-messageDigest (PKCS#9 signed attribute). */
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

export interface VerifyResult {
  ok: boolean;
  byteRange?: [number, number, number, number];
  pkcs7ActualSize?: number;
  pkcs7BudgetSize?: number;
  signerCommonName?: string;
  signerOrganization?: string;
  /**
   * True when SHA-256 over the ByteRange-covered bytes equals the messageDigest
   * signed attribute (the document has not been altered under the signature).
   */
  digestValid?: boolean;
  /**
   * True when the RSA signature over the signed attributes verifies against the
   * embedded signer certificate's public key.
   */
  signatureValid?: boolean;
  /** True if an RFC 3161 TimeStampToken (CAdES-T) is embedded. */
  timestamped: boolean;
  /** ISO genTime of the timestamp, if parseable. */
  timestampTime?: string;
  /** Common name of the TSA signer cert, if parseable. */
  tsaCommonName?: string;
  failures: string[];
}

export function verifyPdfStructure(signed: Buffer): VerifyResult {
  const failures: string[] = [];
  const text = signed.toString("binary");
  const result: VerifyResult = { ok: false, failures, timestamped: false };

  const m = text.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!m) {
    failures.push("no /ByteRange dictionary found");
    return result;
  }
  const [a, b, c, d] = m.slice(1, 5).map(Number);
  result.byteRange = [a, b, c, d];

  const covered = b + d;
  const hole = c - (a + b);
  if (covered + hole !== signed.length) {
    failures.push(`byte ranges (${covered}) + hole (${hole}) != file size (${signed.length})`);
    return result;
  }
  result.pkcs7BudgetSize = hole - 2;

  const contentsRegion = signed.slice(a + b + 1, c - 1);
  const hexBlob = contentsRegion.toString("binary").replace(/[^0-9a-fA-F]/g, "");
  // The /Contents hole is zero-padded past the end of the DER. Slice at the
  // length declared in the DER's own TLV header — trimming trailing "00" pairs
  // instead truncates any signature whose final byte is legitimately 0x00
  // (~1/256 of signatures), falsely rejecting a valid document.
  const contentsBytes = Buffer.from(hexBlob, "hex");
  const derLen = derTotalLength(contentsBytes);
  if (derLen === null || derLen > contentsBytes.length) {
    failures.push("/Contents does not hold a well-formed DER structure");
    return result;
  }
  const pkcs7Der = contentsBytes.subarray(0, derLen).toString("binary");
  result.pkcs7ActualSize = pkcs7Der.length;

  try {
    const root = forge.asn1.fromDer(pkcs7Der);
    const p7 = forge.pkcs7.messageFromAsn1(root) as forge.pkcs7.PkcsSignedData;
    if (!p7.certificates || p7.certificates.length === 0) {
      failures.push("PKCS#7 has no embedded certificates");
      return result;
    }
    const signerCert = p7.certificates[0];
    const subject = signerCert.subject;
    result.signerCommonName = subject.getField("CN")?.value as string | undefined;
    result.signerOrganization = subject.getField("O")?.value as string | undefined;

    // ---- Cryptographic verification (integrity + authenticity) ----
    // Recompute the digest over the ByteRange-covered bytes and RSA-verify the
    // signature over the signed attributes. This is what makes ok:true mean
    // "valid signature", not merely "well-formed structure".
    const covered = Buffer.concat([
      signed.subarray(a, a + b),
      signed.subarray(c, c + d),
    ]);
    const crypto_ = verifySignerCrypto(root, signerCert, covered);
    result.digestValid = crypto_.digestValid;
    result.signatureValid = crypto_.signatureValid;
    for (const f of crypto_.failures) failures.push(f);

    // RFC 3161: inspect the first SignerInfo for an id-aa-timeStampToken.
    const ts = inspectTimestamp(root);
    if (ts.present) {
      result.timestamped = true;
      result.timestampTime = ts.timestampTime;
      result.tsaCommonName = ts.tsaCommonName;

      // §2.4.2 binding: TST messageImprint == sha256(signatureValue).
      if (ts.sigValueHex && ts.messageImprintHashHex) {
        const expected = sha256Hex(ts.sigValueHex);
        if (expected !== ts.messageImprintHashHex.toLowerCase()) {
          failures.push("timestamp messageImprint does not match signature value");
        }
      } else if (!ts.messageImprintHashHex) {
        failures.push("timestamp present but messageImprint could not be read");
      }
    }
  } catch (e) {
    failures.push(`PKCS#7 parse error: ${(e as Error).message}`);
    return result;
  }

  result.ok = failures.length === 0;
  return result;
}

/**
 * Preferred name for {@link verifyPdfStructure}. Performs full cryptographic
 * verification (structure + digest + signature); `ok:true` means the signature
 * is valid over the exact document bytes.
 */
export const verifyPdfSignature = verifyPdfStructure;

/**
 * Cryptographically verify the first SignerInfo of a detached PKCS#7:
 *   digestValid    — SHA-256(coveredContent) === messageDigest signed attribute
 *   signatureValid — RSA-verify(signature) over DER(signedAttrs re-tagged SET)
 *                    against the signer certificate's public key
 *
 * node-forge's high-level `pkcs7.verify()` does not support externally-detached
 * content (the signed bytes live in the PDF, not the CMS), so we walk the ASN.1
 * directly. The re-encoding of the [0] IMPLICIT signedAttrs as a UNIVERSAL SET
 * OF reproduces exactly the bytes forge signed (same element order), so a
 * forge-produced signature verifies byte-for-byte.
 */
function verifySignerCrypto(
  contentInfo: forge.asn1.Asn1,
  signerCert: forge.pki.Certificate,
  coveredContent: Buffer,
): { digestValid: boolean; signatureValid: boolean; failures: string[] } {
  const failures: string[] = [];
  let digestValid = false;
  let signatureValid = false;

  try {
    const signerInfo = firstSignerInfo(contentInfo);
    if (!signerInfo) {
      failures.push("could not locate SignerInfo for cryptographic verification");
      return { digestValid, signatureValid, failures };
    }

    // signedAttrs = the [0] IMPLICIT context node; signature = the UNIVERSAL
    // OCTET STRING (encryptedDigest). unsignedAttrs would be [1] — skip it.
    let signedAttrs: forge.asn1.Asn1 | undefined;
    let signatureValue: string | undefined;
    for (const child of signerInfo.value as forge.asn1.Asn1[]) {
      if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && child.type === 0) {
        signedAttrs = child;
      }
      if (
        child.tagClass === asn1.Class.UNIVERSAL &&
        child.type === asn1.Type.OCTETSTRING &&
        typeof child.value === "string"
      ) {
        signatureValue = child.value;
      }
    }

    if (!signedAttrs || !Array.isArray(signedAttrs.value)) {
      failures.push("SignerInfo has no signed attributes (cannot verify)");
      return { digestValid, signatureValid, failures };
    }

    // (1) messageDigest signed attribute vs recomputed digest of covered bytes.
    const messageDigest = extractSignedAttrValue(signedAttrs, OID_MESSAGE_DIGEST);
    if (!messageDigest) {
      failures.push("messageDigest signed attribute missing");
    } else {
      const recomputed = crypto.createHash("sha256").update(coveredContent).digest();
      const claimed = Buffer.from(messageDigest, "binary");
      digestValid =
        recomputed.length === claimed.length &&
        crypto.timingSafeEqual(recomputed, claimed);
      if (!digestValid) {
        failures.push(
          "document digest does not match messageDigest attribute — content altered after signing",
        );
      }
    }

    // (2) RSA signature over DER(signedAttrs as SET OF) vs signer public key.
    if (!signatureValue) {
      failures.push("SignerInfo signature value missing");
    } else {
      const setDer = asn1.toDer(
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, signedAttrs.value),
      ).getBytes();
      const md = forge.md.sha256.create();
      md.update(setDer);
      try {
        signatureValid = (signerCert.publicKey as forge.pki.rsa.PublicKey).verify(
          md.digest().getBytes(),
          signatureValue,
        );
        if (!signatureValid) {
          failures.push("signature does not verify against the signer certificate");
        }
      } catch (e) {
        signatureValid = false;
        failures.push(`signature verification threw: ${(e as Error).message}`);
      }
    }
  } catch (e) {
    failures.push(`cryptographic verification error: ${(e as Error).message}`);
  }

  return { digestValid, signatureValid, failures };
}

/** Locate the first SignerInfo SEQUENCE inside a PKCS#7 SignedData ASN.1 tree. */
function firstSignerInfo(contentInfo: forge.asn1.Asn1): forge.asn1.Asn1 | undefined {
  if (!Array.isArray(contentInfo.value)) return undefined;
  let signedData: forge.asn1.Asn1 | undefined;
  for (const child of contentInfo.value as forge.asn1.Asn1[]) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
      signedData = child.value[0] as forge.asn1.Asn1;
    }
  }
  if (!signedData || !Array.isArray(signedData.value)) return undefined;
  let signerInfos: forge.asn1.Asn1 | undefined;
  for (const child of signedData.value as forge.asn1.Asn1[]) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.SET &&
      Array.isArray(child.value)
    ) {
      signerInfos = child; // last UNIVERSAL SET = signerInfos (first = digestAlgorithms)
    }
  }
  if (!signerInfos || !Array.isArray(signerInfos.value) || signerInfos.value.length === 0) {
    return undefined;
  }
  return signerInfos.value[0] as forge.asn1.Asn1;
}

/**
 * From a signed-attributes node ([0] IMPLICIT SET OF Attribute), return the
 * value bytes (forge binary string) of the attribute with the given OID, or
 * undefined. Attribute ::= SEQUENCE { OID, SET OF AttributeValue }.
 */
function extractSignedAttrValue(
  signedAttrs: forge.asn1.Asn1,
  oid: string,
): string | undefined {
  for (const attr of signedAttrs.value as forge.asn1.Asn1[]) {
    if (!Array.isArray(attr.value) || attr.value.length < 2) continue;
    const oidNode = attr.value[0] as forge.asn1.Asn1;
    if (oidNode.type !== asn1.Type.OID || safeOid(oidNode.value as string) !== oid) continue;
    const set = attr.value[1] as forge.asn1.Asn1;
    if (!Array.isArray(set.value) || set.value.length === 0) return undefined;
    const val = set.value[0] as forge.asn1.Asn1;
    return typeof val.value === "string" ? val.value : undefined;
  }
  return undefined;
}

/**
 * Walk the parsed PKCS#7 ASN.1 to the first SignerInfo, returning its
 * signatureValue (hex) and, if present, the embedded TimeStampToken metadata.
 */
function inspectTimestamp(contentInfo: forge.asn1.Asn1): {
  present: boolean;
  sigValueHex?: string;
  messageImprintHashHex?: string;
  timestampTime?: string;
  tsaCommonName?: string;
} {
  if (!Array.isArray(contentInfo.value)) return { present: false };

  // content [0] EXPLICIT → SignedData SEQUENCE
  let signedData: forge.asn1.Asn1 | undefined;
  for (const child of contentInfo.value as forge.asn1.Asn1[]) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
      signedData = child.value[0] as forge.asn1.Asn1;
    }
  }
  if (!signedData || !Array.isArray(signedData.value)) return { present: false };

  // signerInfos = the last UNIVERSAL SET among SignedData children.
  let signerInfos: forge.asn1.Asn1 | undefined;
  for (const child of signedData.value as forge.asn1.Asn1[]) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.SET &&
      Array.isArray(child.value)
    ) {
      signerInfos = child;
    }
  }
  if (!signerInfos || !Array.isArray(signerInfos.value) || signerInfos.value.length === 0) {
    return { present: false };
  }

  const signerInfo = signerInfos.value[0] as forge.asn1.Asn1;
  if (!Array.isArray(signerInfo.value)) return { present: false };
  const siChildren = signerInfo.value as forge.asn1.Asn1[];

  // SignerInfo signature is the last UNIVERSAL OCTET STRING (encryptedDigest).
  // unsignedAttrs, if present, is a [1] IMPLICIT context-specific node.
  let sigValueHex: string | undefined;
  let unsignedAttrs: forge.asn1.Asn1 | undefined;
  for (const child of siChildren) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.OCTETSTRING &&
      typeof child.value === "string"
    ) {
      sigValueHex = forge.util.bytesToHex(child.value);
    }
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && child.type === 1) {
      unsignedAttrs = child;
    }
  }

  if (!unsignedAttrs || !Array.isArray(unsignedAttrs.value)) {
    return { present: false, sigValueHex };
  }

  // Find the Attribute whose attrType OID is id-aa-timeStampToken.
  for (const attr of unsignedAttrs.value as forge.asn1.Asn1[]) {
    if (!Array.isArray(attr.value) || attr.value.length < 2) continue;
    const oidNode = attr.value[0] as forge.asn1.Asn1;
    if (oidNode.type !== asn1.Type.OID || safeOid(oidNode.value as string) !== OID_TIMESTAMP_TOKEN) {
      continue;
    }
    const setNode = attr.value[1] as forge.asn1.Asn1;
    if (!Array.isArray(setNode.value) || setNode.value.length === 0) continue;
    const token = setNode.value[0] as forge.asn1.Asn1;

    const info = parseTstInfo(token);
    return {
      present: true,
      sigValueHex,
      messageImprintHashHex: info.messageImprintHashHex,
      timestampTime: toIsoGeneralizedTime(info.genTime),
      tsaCommonName: info.tsaCommonName,
    };
  }

  return { present: false, sigValueHex };
}

/**
 * Total encoded length (header + content) of the DER value starting at byte 0,
 * or null if the bytes cannot start a DER SEQUENCE (wrong tag, indefinite/BER
 * length, or a length-of-length that cannot be a real PKCS#7 blob).
 */
function derTotalLength(buf: Buffer): number | null {
  if (buf.length < 2 || buf[0] !== 0x30) return null; // ContentInfo is a SEQUENCE
  const l0 = buf[1];
  if (l0 < 0x80) return 2 + l0;
  const n = l0 & 0x7f;
  if (n === 0 || n > 4 || buf.length < 2 + n) return null;
  let v = 0;
  for (let k = 0; k < n; k++) v = v * 256 + buf[2 + k];
  return 2 + n + v;
}

function safeOid(der: string): string {
  try {
    return asn1.derToOid(der);
  } catch {
    return "";
  }
}

/** sha256 of a hex string, returned as lowercase hex. */
function sha256Hex(hex: string): string {
  const md = forge.md.sha256.create();
  md.update(forge.util.hexToBytes(hex));
  return md.digest().toHex().toLowerCase();
}

/** Convert an ASN.1 GeneralizedTime (e.g. 20260528123456Z) to ISO 8601. */
function toIsoGeneralizedTime(gt?: string): string | undefined {
  if (!gt) return undefined;
  const m = gt.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$/);
  if (!m) return gt;
  const [, y, mo, d, h, mi, s] = m;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? gt : parsed.toISOString();
}
