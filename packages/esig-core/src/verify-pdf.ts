// src/lib/integrations/esig/core/verify-pdf.ts
//
// Portable structural verifier for PKCS#7-signed PDFs. Returns diagnostics
// rather than throwing — callers decide whether to surface failures.
//
// RFC 3161 (CAdES-T): if the SignerInfo carries an id-aa-timeStampToken
// UNSIGNED attribute, we surface `timestamped:true` plus best-effort genTime /
// TSA common name, AND enforce the §2.4.2 binding check — the TST's
// messageImprint MUST equal sha256(signerInfo.signature). A mismatch is a hard
// failure (ok:false). Absence of a timestamp is fine (backward compatible:
// timestamped:false, ok unaffected).

import forge from "node-forge";

import { OID_TIMESTAMP_TOKEN, parseTstInfo } from "./timestamp.js";

const asn1 = forge.asn1;

export interface VerifyResult {
  ok: boolean;
  byteRange?: [number, number, number, number];
  pkcs7ActualSize?: number;
  pkcs7BudgetSize?: number;
  signerCommonName?: string;
  signerOrganization?: string;
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
  const trimmedHex = hexBlob.replace(/(00)+$/, "");
  const pkcs7Der = Buffer.from(trimmedHex, "hex").toString("binary");
  result.pkcs7ActualSize = pkcs7Der.length;

  try {
    const root = forge.asn1.fromDer(pkcs7Der);
    const p7 = forge.pkcs7.messageFromAsn1(root) as forge.pkcs7.PkcsSignedData;
    if (!p7.certificates || p7.certificates.length === 0) {
      failures.push("PKCS#7 has no embedded certificates");
      return result;
    }
    const subject = p7.certificates[0].subject;
    result.signerCommonName = subject.getField("CN")?.value as string | undefined;
    result.signerOrganization = subject.getField("O")?.value as string | undefined;

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
