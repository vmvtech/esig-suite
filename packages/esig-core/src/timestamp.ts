// src/lib/integrations/esig/core/timestamp.ts
//
// RFC 3161 Time-Stamp Protocol (TSP) primitives — pure node-forge, dep-free.
//
// Implements the minimum needed to upgrade a CAdES-B signature to CAdES-T by
// embedding an RFC 3161 TimeStampToken (TST) as an UNSIGNED attribute
// (id-aa-timeStampToken, OID 1.2.840.113549.1.9.16.2.14) inside the PKCS#7
// SignerInfo. The timestamp is computed over the SignerInfo signatureValue
// (encryptedDigest) per RFC 3161 §2.4.1.
//
// The actual network POST to the TSA is injected by the caller (see
// TsaTransport in ./types) so this package never performs egress itself — the
// TSA only ever receives a SHA-256 hash, never any PHI.

import forge from "node-forge";

const asn1 = forge.asn1;

/** OID for the id-aa-timeStampToken unsigned attribute (RFC 3161). */
export const OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";

const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"; // id-ct-TSTInfo
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2"; // id-signedData
const OID_COMMON_NAME = "2.5.4.3"; // id-at-commonName

/** Convert a forge binary string (DER) to a Uint8Array. */
export function derStringToUint8(der: string): Uint8Array {
  const out = new Uint8Array(der.length);
  for (let i = 0; i < der.length; i++) out[i] = der.charCodeAt(i) & 0xff;
  return out;
}

/** Convert a Uint8Array to a forge binary string (DER). */
export function uint8ToDerString(bytes: Uint8Array): string {
  let s = "";
  // Chunk to avoid String.fromCharCode argument-count limits on large inputs.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(
      null,
      bytes.subarray(i, i + CHUNK) as unknown as number[],
    );
  }
  return s;
}

/**
 * Build an RFC 3161 TimeStampReq (DER, forge binary string) over the given
 * signatureValue bytes.
 *
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     reqPolicy      TSAPolicyId OPTIONAL,   -- omitted
 *     nonce          INTEGER OPTIONAL,
 *     certReq        BOOLEAN DEFAULT FALSE }
 *
 *   MessageImprint ::= SEQUENCE {
 *     hashAlgorithm AlgorithmIdentifier,
 *     hashedMessage OCTET STRING }
 *
 * The messageImprint hash input is the RAW signatureValue bytes (a forge
 * binary string), hashed with SHA-256.
 */
export function buildTimeStampReq(sigValueBinary: string): string {
  const md = forge.md.sha256.create();
  md.update(sigValueBinary);
  const hashed = md.digest().getBytes(); // forge binary string

  // AlgorithmIdentifier ::= SEQUENCE { OID sha256, NULL }
  const hashAlgorithm = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(
      asn1.Class.UNIVERSAL,
      asn1.Type.OID,
      false,
      asn1.oidToDer(OID_SHA256).getBytes(),
    ),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ""),
  ]);

  // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage OCTET STRING }
  const messageImprint = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    hashAlgorithm,
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, hashed),
  ]);

  // version INTEGER (1)
  const version = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.INTEGER,
    false,
    asn1.integerToDer(1).getBytes(),
  );

  // nonce INTEGER (16 random bytes; prepend 0x00 if the high bit is set so the
  // value is interpreted as a positive integer).
  let nonceBytes = forge.random.getBytesSync(16);
  if ((nonceBytes.charCodeAt(0) & 0x80) !== 0) {
    nonceBytes = "\x00" + nonceBytes;
  }
  const nonce = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, nonceBytes);

  // certReq BOOLEAN TRUE
  const certReq = asn1.create(
    asn1.Class.UNIVERSAL,
    asn1.Type.BOOLEAN,
    false,
    String.fromCharCode(0xff),
  );

  const req = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    version,
    messageImprint,
    nonce,
    certReq,
  ]);

  return asn1.toDer(req).getBytes();
}

/**
 * Parse an RFC 3161 TimeStampResp (DER forge binary string) and return the
 * embedded TimeStampToken as a forge ASN.1 object.
 *
 *   TimeStampResp ::= SEQUENCE {
 *     status         PKIStatusInfo,
 *     timeStampToken TimeStampToken OPTIONAL }
 *
 *   PKIStatusInfo ::= SEQUENCE {
 *     status       PKIStatus (INTEGER),
 *     statusString PKIFreeText OPTIONAL,
 *     failInfo     PKIFailureInfo OPTIONAL }
 *
 * Accepts status 0 (granted) or 1 (grantedWithMods); throws otherwise, with the
 * integer status and (if present) failInfo bits.
 */
export function parseTimeStampResp(respBinary: string): { token: forge.asn1.Asn1 } {
  const resp = asn1.fromDer(respBinary);
  if (!Array.isArray(resp.value) || resp.value.length < 1) {
    throw new Error("RFC3161: malformed TimeStampResp (no PKIStatusInfo)");
  }

  const statusInfo = resp.value[0] as forge.asn1.Asn1;
  if (!Array.isArray(statusInfo.value) || statusInfo.value.length < 1) {
    throw new Error("RFC3161: malformed PKIStatusInfo");
  }

  const statusNode = statusInfo.value[0] as forge.asn1.Asn1;
  const status = derIntToNumber(statusNode.value as string);

  if (status !== 0 && status !== 1) {
    // Best-effort failInfo (BIT STRING) for diagnostics.
    let failInfo = "";
    for (const child of statusInfo.value as forge.asn1.Asn1[]) {
      if (child.type === asn1.Type.BITSTRING && typeof child.value === "string") {
        failInfo = ` failInfo=0x${forge.util.bytesToHex(child.value)}`;
        break;
      }
    }
    throw new Error(`RFC3161: TSA rejected request (PKIStatus=${status})${failInfo}`);
  }

  const token = resp.value[1] as forge.asn1.Asn1 | undefined;
  if (!token) {
    throw new Error("RFC3161: TimeStampResp granted but no timeStampToken present");
  }

  return { token };
}

/**
 * Parse a TimeStampToken (a CMS SignedData ContentInfo whose eContentType is
 * id-ct-TSTInfo) and extract best-effort metadata. Only
 * `messageImprintHashHex` is treated as load-bearing (used by the verifier's
 * §2.4.2 binding check); the rest are returned as undefined on any parse miss
 * rather than throwing.
 */
export function parseTstInfo(tokenAsn1: forge.asn1.Asn1): {
  genTime?: string;
  serialHex?: string;
  tsaCommonName?: string;
  messageImprintHashHex?: string;
} {
  const result: {
    genTime?: string;
    serialHex?: string;
    tsaCommonName?: string;
    messageImprintHashHex?: string;
  } = {};

  try {
    if (!Array.isArray(tokenAsn1.value)) return result;

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    let signedData: forge.asn1.Asn1 | undefined;
    for (const child of tokenAsn1.value as forge.asn1.Asn1[]) {
      if (
        child.type === asn1.Type.OID &&
        safeOid(child.value as string) === OID_SIGNED_DATA
      ) {
        continue;
      }
      if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
        signedData = child.value[0] as forge.asn1.Asn1;
      }
    }
    if (!signedData || !Array.isArray(signedData.value)) return result;

    // SignedData -> EncapsulatedContentInfo ::= SEQUENCE {
    //   eContentType OID (== id-ct-TSTInfo),
    //   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    let tstInfoBytes: string | undefined;
    for (const sdChild of signedData.value as forge.asn1.Asn1[]) {
      if (sdChild.type !== asn1.Type.SEQUENCE || !Array.isArray(sdChild.value)) continue;
      const seq = sdChild.value as forge.asn1.Asn1[];
      const first = seq[0];
      if (
        first &&
        first.type === asn1.Type.OID &&
        safeOid(first.value as string) === OID_TST_INFO
      ) {
        const explicit = seq[1];
        if (explicit && Array.isArray(explicit.value)) {
          const oct = explicit.value[0] as forge.asn1.Asn1;
          if (oct && oct.type === asn1.Type.OCTETSTRING) {
            if (typeof oct.value === "string") {
              tstInfoBytes = oct.value;
            } else if (Array.isArray(oct.value) && oct.value.length > 0) {
              // Constructed/definite OCTET STRING wrapper.
              tstInfoBytes = (oct.value[0] as forge.asn1.Asn1).value as string;
            }
          }
        }
        break;
      }
    }
    if (!tstInfoBytes) return result;

    // TSTInfo ::= SEQUENCE {
    //   version INTEGER, policy OID, messageImprint MessageImprint,
    //   serialNumber INTEGER, genTime GeneralizedTime, ... }
    const tstInfo = asn1.fromDer(tstInfoBytes);
    if (!Array.isArray(tstInfo.value)) return result;
    const fields = tstInfo.value as forge.asn1.Asn1[];

    // messageImprint is the first SEQUENCE child; its last element is the
    // hashedMessage OCTET STRING.
    for (const f of fields) {
      if (f.type === asn1.Type.SEQUENCE && Array.isArray(f.value)) {
        const mi = f.value as forge.asn1.Asn1[];
        const hashed = mi[mi.length - 1];
        if (hashed && hashed.type === asn1.Type.OCTETSTRING && typeof hashed.value === "string") {
          result.messageImprintHashHex = forge.util.bytesToHex(hashed.value);
          break;
        }
      }
    }

    // genTime GeneralizedTime.
    for (const f of fields) {
      if (f.type === asn1.Type.GENERALIZEDTIME && typeof f.value === "string") {
        result.genTime = f.value;
      }
    }

    // serialNumber heuristic: among the INTEGER fields (version + serialNumber),
    // serialNumber is the larger-byte one.
    let bestSerial: string | undefined;
    let bestLen = 0;
    for (const f of fields) {
      if (f.type === asn1.Type.INTEGER && typeof f.value === "string" && f.value.length > bestLen) {
        bestLen = f.value.length;
        bestSerial = f.value;
      }
    }
    if (bestSerial) result.serialHex = forge.util.bytesToHex(bestSerial);

    // TSA common name: best-effort from the signer certificate(s).
    result.tsaCommonName = extractFirstCommonName(signedData);
  } catch {
    // Best-effort: swallow parse errors, returning whatever we have.
  }

  return result;
}

/** Best-effort scan for the first commonName (OID 2.5.4.3) string value. */
function extractFirstCommonName(node: forge.asn1.Asn1): string | undefined {
  let found: string | undefined;
  const walk = (n: forge.asn1.Asn1) => {
    if (found) return;
    if (!Array.isArray(n.value)) return;
    const children = n.value as forge.asn1.Asn1[];
    for (let i = 0; i < children.length; i++) {
      const c = children[i];
      if (
        c.type === asn1.Type.OID &&
        typeof c.value === "string" &&
        safeOid(c.value) === OID_COMMON_NAME &&
        i + 1 < children.length
      ) {
        const v = children[i + 1];
        if (typeof v.value === "string" && v.value.length > 0) {
          found = v.value;
          return;
        }
      }
    }
    for (const c of children) walk(c);
  };
  walk(node);
  return found;
}

function safeOid(der: string): string {
  try {
    return asn1.derToOid(der);
  } catch {
    return "";
  }
}

/** Decode a DER INTEGER content (forge binary string) to a JS number. */
function derIntToNumber(bytes: string): number {
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    n = n * 256 + (bytes.charCodeAt(i) & 0xff);
  }
  return n;
}
