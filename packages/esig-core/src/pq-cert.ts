// src/pq-cert.ts
//
// Self-signed ML-DSA-65 X.509 certificate (RFC 9881).
//
// The raw-key TOFU identity (pq-seal) is enough to pin a signer, but enterprise
// relying parties expect an X.509 container: a human-readable subject bound to a
// public key by a signature. This issues a self-signed certificate whose
// SubjectPublicKeyInfo AND signatureAlgorithm are id-ml-dsa-65
// (2.16.840.1.101.3.4.3.18), per RFC 9881 — parseable by OpenSSL 3.5+ and
// self-verifying with the same ML-DSA-65 primitive the seal uses.
//
// The cert does NOT add a root of trust (it is self-signed — still TOFU on the
// key), but it upgrades the identity from an opaque fingerprint to a portable,
// standards-shaped assertion "CN=<subject> controls this ML-DSA-65 key", which
// `certMatchesPqSeal` ties back to a seal by public-key fingerprint.

import forge from "node-forge";
import crypto from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import type { PqSigningKeys, PqSeal } from "./pq-seal.js";

/** RFC 9881 / NIST: id-ml-dsa-65. Used for BOTH the SPKI alg and the cert signature alg. */
export const ID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18" as const;

const MLDSA65_PUBLIC_LEN = 1952;
const MLDSA65_SIGNATURE_LEN = 3309;

const OID_COMMON_NAME = "2.5.4.3";
const OID_ORG_NAME = "2.5.4.10";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";

const DEFAULT_VALIDITY_DAYS = 365;

const asn1 = forge.asn1;
const { Class, Type } = asn1;

// ---------- binary <-> Uint8Array (node-forge speaks binary strings) ----------

function u8ToBin(u8: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return s;
}
function binToU8(bin: string): Uint8Array {
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i) & 0xff;
  return u8;
}
function sha256Hex(bytes: Uint8Array): string {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

// ---------- ASN.1 builders ----------

function oidNode(oid: string) {
  return asn1.create(Class.UNIVERSAL, Type.OID, false, asn1.oidToDer(oid).getBytes());
}

/** AlgorithmIdentifier for ML-DSA: SEQUENCE { OID } — parameters field ABSENT (RFC 9881 §4). */
function mlDsaAlgId() {
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [oidNode(ID_ML_DSA_65)]);
}

/** DER BIT STRING with 0 unused bits wrapping raw bytes (keys, signatures). */
function bitStringNode(bytes: Uint8Array) {
  return asn1.create(Class.UNIVERSAL, Type.BITSTRING, false, String.fromCharCode(0x00) + u8ToBin(bytes));
}

function utf8Node(value: string) {
  return asn1.create(Class.UNIVERSAL, Type.UTF8, false, forge.util.encodeUtf8(value));
}

/** RDNSequence for a CN + O subject. */
function nameNode(commonName: string, org: string) {
  const rdn = (oid: string, value: string) =>
    asn1.create(Class.UNIVERSAL, Type.SET, true, [
      asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [oidNode(oid), utf8Node(value)]),
    ]);
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    rdn(OID_COMMON_NAME, commonName),
    rdn(OID_ORG_NAME, org),
  ]);
}

/** SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING(raw pubkey) } (RFC 9881). */
function spkiNode(pub: Uint8Array) {
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [mlDsaAlgId(), bitStringNode(pub)]);
}

function timeNode(d: Date) {
  // UTCTime for years < 2050 (RFC 5280 §4.1.2.5), GeneralizedTime beyond.
  if (d.getUTCFullYear() < 2050) {
    return asn1.create(Class.UNIVERSAL, Type.UTCTIME, false, asn1.dateToUtcTime(d));
  }
  return asn1.create(Class.UNIVERSAL, Type.GENERALIZEDTIME, false, asn1.dateToGeneralizedTime(d));
}

/** Extension: SEQUENCE { OID, [critical BOOLEAN], OCTET STRING(DER of value) }. */
function extensionNode(oid: string, critical: boolean, value: forge.asn1.Asn1) {
  const children: forge.asn1.Asn1[] = [oidNode(oid)];
  if (critical) children.push(asn1.create(Class.UNIVERSAL, Type.BOOLEAN, false, String.fromCharCode(0xff)));
  children.push(asn1.create(Class.UNIVERSAL, Type.OCTETSTRING, false, asn1.toDer(value).getBytes()));
  return asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, children);
}

export interface IssueMlDsaCertOptions {
  /** The signing keys — the ML-DSA-65 keypair is both subject and issuer (self-signed). */
  keys: PqSigningKeys;
  /** Subject CN / O seed. ASCII-only (matches cert-issuer's node-forge round-trip guard). */
  subjectName: string;
  /** Validity window in days. Default 365. */
  validityDays?: number;
  /** Optional 16-byte serial; a CSPRNG positive serial is generated otherwise. */
  serial?: Uint8Array;
  /** Backdate notBefore by this many seconds to tolerate clock skew. Default 0. */
  notBefore?: Date;
}

export interface MlDsaCertificate {
  certPem: string;
  certDer: Uint8Array;
  /** SHA-256 hex of the DER-encoded certificate. */
  fingerprint: string;
  /** SHA-256 hex of the raw ML-DSA-65 public key — equals a seal's `keys.mldsa65Fpr`. */
  publicKeyFingerprint: string;
  notBefore: Date;
  notAfter: Date;
}

/**
 * Issue a self-signed ML-DSA-65 X.509 certificate for the given signing keys.
 * The certificate's public key is the raw 1952-byte ML-DSA-65 key, and its own
 * signature is ML-DSA-65 over the TBSCertificate.
 */
export function issueMlDsaCertificate(opts: IssueMlDsaCertOptions): MlDsaCertificate {
  const { keys, subjectName, validityDays = DEFAULT_VALIDITY_DAYS } = opts;
  if (!/^[\x20-\x7e]+$/.test(subjectName)) {
    throw new Error(`subjectName "${subjectName}" contains non-ASCII characters`);
  }
  const pub = keys.mldsa65PublicKey;
  if (pub.length !== MLDSA65_PUBLIC_LEN) {
    throw new Error(`ML-DSA-65 public key must be ${MLDSA65_PUBLIC_LEN} bytes, got ${pub.length}`);
  }

  // Serial: 128 bits CSPRNG, top bit cleared (positive DER INTEGER), nonzero lead.
  let serial: Uint8Array;
  if (opts.serial) {
    serial = opts.serial;
  } else {
    const s = crypto.randomBytes(16);
    s[0] = (s[0] & 0x7f) | 0x40;
    serial = s;
  }

  const notBefore = opts.notBefore ?? new Date();
  const notAfter = new Date(notBefore.getTime() + validityDays * 86_400_000);

  const cn = `E-sig PQ (${subjectName})`;
  const name = () => nameNode(cn, subjectName);

  const version = asn1.create(Class.CONTEXT_SPECIFIC, 0, true, [
    asn1.create(Class.UNIVERSAL, Type.INTEGER, false, String.fromCharCode(0x02)), // v3
  ]);
  const serialNode = asn1.create(Class.UNIVERSAL, Type.INTEGER, false, u8ToBin(serial));
  const validity = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [timeNode(notBefore), timeNode(notAfter)]);

  // basicConstraints (CA:FALSE = empty SEQUENCE) + keyUsage (digitalSignature + nonRepudiation).
  const basicConstraints = extensionNode(
    OID_BASIC_CONSTRAINTS,
    true,
    asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, []),
  );
  const keyUsage = extensionNode(
    OID_KEY_USAGE,
    true,
    // bits 0 (digitalSignature) + 1 (nonRepudiation) set → 0xC0, 6 unused bits.
    asn1.create(Class.UNIVERSAL, Type.BITSTRING, false, String.fromCharCode(0x06) + String.fromCharCode(0xc0)),
  );
  const extensions = asn1.create(Class.CONTEXT_SPECIFIC, 3, true, [
    asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [basicConstraints, keyUsage]),
  ]);

  const tbs = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    version,
    serialNode,
    mlDsaAlgId(), // signature algorithm
    name(), // issuer
    validity,
    name(), // subject (self-signed → issuer == subject)
    spkiNode(pub),
    extensions,
  ]);

  const tbsDer = binToU8(asn1.toDer(tbs).getBytes());
  const signature = ml_dsa65.sign(tbsDer, keys.mldsa65SecretKey);

  const certAsn1 = asn1.create(Class.UNIVERSAL, Type.SEQUENCE, true, [
    tbs,
    mlDsaAlgId(),
    bitStringNode(signature),
  ]);
  const certDer = binToU8(asn1.toDer(certAsn1).getBytes());
  const certPem = derToPem(certDer);

  return {
    certPem,
    certDer,
    fingerprint: sha256Hex(certDer),
    publicKeyFingerprint: sha256Hex(pub),
    notBefore,
    notAfter,
  };
}

function derToPem(der: Uint8Array): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// ---------- Parse + verify ----------

interface Tlv {
  tag: number;
  start: number;
  contentStart: number;
  end: number;
}

/** Read one definite-length DER TLV starting at `offset`. */
function readTlv(der: Uint8Array, offset: number): Tlv {
  if (offset + 1 >= der.length) throw new Error("DER: truncated TLV");
  const tag = der[offset];
  let i = offset + 1;
  let len = der[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("DER: unsupported length encoding");
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | der[i++];
  }
  const contentStart = i;
  const end = contentStart + len;
  if (end > der.length) throw new Error("DER: length exceeds buffer");
  return { tag, start: offset, contentStart, end };
}

export interface ParsedMlDsaCertificate {
  subjectCommonName: string;
  notBefore: Date;
  notAfter: Date;
  /** Raw ML-DSA-65 public key (1952 bytes). */
  publicKey: Uint8Array;
  /** SHA-256 hex of `publicKey` — compare to a seal's `keys.mldsa65Fpr`. */
  publicKeyFingerprint: string;
  /** signatureAlgorithm OID (must be ID_ML_DSA_65). */
  signatureAlgOid: string;
  /** Exact DER of the TBSCertificate (byte-sliced, not re-encoded) — what the signature covers. */
  tbsDer: Uint8Array;
  /** Raw ML-DSA-65 signature (3309 bytes). */
  signature: Uint8Array;
}

/**
 * Parse a self-signed ML-DSA-65 certificate. The TBS bytes are recovered by a
 * raw TLV slice of the original DER (never re-encoded), so signature
 * verification is over the exact signed bytes.
 */
export function parseMlDsaCertificate(cert: string | Uint8Array): ParsedMlDsaCertificate {
  const der = typeof cert === "string" ? pemToDer(cert) : cert;

  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const outer = readTlv(der, 0);
  const tbs = readTlv(der, outer.contentStart);
  const sigAlg = readTlv(der, tbs.end);
  const sigVal = readTlv(der, sigAlg.end);

  const tbsDer = der.slice(tbs.start, tbs.end);
  // signatureValue is a BIT STRING: first content byte = unused-bits count (0).
  const signature = der.slice(sigVal.contentStart + 1, sigVal.end);

  // Human-readable + key fields via node-forge (structure is standard X.509).
  const parsed = asn1.fromDer(forge.util.createBuffer(u8ToBin(der)));
  const tbsNode = parsed.value[0] as forge.asn1.Asn1;
  const kids = tbsNode.value as forge.asn1.Asn1[];
  // With explicit version [0], fields are: [0]=version [1]=serial [2]=sigAlg
  // [3]=issuer [4]=validity [5]=subject [6]=spki [7]=extensions.
  const validityNode = kids[4];
  const subjectNode = kids[5];
  const spkiNode = kids[6];

  const notBefore = asn1.utcTimeToDate((validityNode.value as forge.asn1.Asn1[])[0].value as string);
  const notAfter = asn1.utcTimeToDate((validityNode.value as forge.asn1.Asn1[])[1].value as string);

  const subjectCommonName = extractCommonName(subjectNode);

  const spkiKids = spkiNode.value as forge.asn1.Asn1[];
  const algOid = asn1.derToOid((spkiKids[0].value as forge.asn1.Asn1[])[0].value as string);
  const bitStr = spkiKids[1].value as string; // leading unused-bits byte
  const publicKey = binToU8(bitStr.slice(1));

  return {
    subjectCommonName,
    notBefore,
    notAfter,
    publicKey,
    publicKeyFingerprint: sha256Hex(publicKey),
    signatureAlgOid: algOid,
    tbsDer,
    signature,
  };
}

function extractCommonName(nameNode: forge.asn1.Asn1): string {
  for (const rdn of nameNode.value as forge.asn1.Asn1[]) {
    for (const atv of rdn.value as forge.asn1.Asn1[]) {
      const [oidNode, valNode] = atv.value as forge.asn1.Asn1[];
      if (asn1.derToOid(oidNode.value as string) === OID_COMMON_NAME) {
        return forge.util.decodeUtf8(valNode.value as string);
      }
    }
  }
  return "";
}

export interface MlDsaCertVerdict {
  ok: boolean;
  /** signatureAlgorithm is id-ml-dsa-65. */
  algOk: boolean;
  /** The ML-DSA-65 self-signature over the TBS verifies against the cert's own public key. */
  selfSignatureOk: boolean;
  /** `now` is within [notBefore, notAfter]. */
  timeValid: boolean;
  failures: string[];
}

/**
 * Verify a self-signed ML-DSA-65 certificate: correct algorithm, the self
 * signature validates against the embedded public key, and it is within its
 * validity window. Never throws.
 */
export function verifyMlDsaCertificate(cert: string | Uint8Array, now: Date = new Date()): MlDsaCertVerdict {
  const failures: string[] = [];
  try {
    const p = parseMlDsaCertificate(cert);

    const algOk = p.signatureAlgOid === ID_ML_DSA_65;
    if (!algOk) failures.push(`unexpected signature algorithm ${p.signatureAlgOid}`);

    let selfSignatureOk = false;
    if (
      p.publicKey.length === MLDSA65_PUBLIC_LEN &&
      p.signature.length === MLDSA65_SIGNATURE_LEN
    ) {
      try {
        selfSignatureOk = ml_dsa65.verify(p.signature, p.tbsDer, p.publicKey);
      } catch {
        selfSignatureOk = false;
      }
    }
    if (!selfSignatureOk) failures.push("ML-DSA-65 self-signature invalid");

    const t = now.getTime();
    const timeValid = t >= p.notBefore.getTime() && t <= p.notAfter.getTime();
    if (!timeValid) failures.push("certificate is outside its validity window");

    return { ok: algOk && selfSignatureOk && timeValid, algOk, selfSignatureOk, timeValid, failures };
  } catch (e) {
    return {
      ok: false,
      algOk: false,
      selfSignatureOk: false,
      timeValid: false,
      failures: [`certificate parse error: ${(e as Error).message}`],
    };
  }
}

/**
 * Bind a certificate to a post-quantum seal: the cert must be valid AND its
 * public key must be the one that produced the seal (fingerprint match). This
 * is how a relying party upgrades from raw-fingerprint pinning to an X.509
 * identity without changing the seal format.
 */
export function certMatchesPqSeal(cert: string | Uint8Array, seal: PqSeal, now: Date = new Date()): boolean {
  const verdict = verifyMlDsaCertificate(cert, now);
  if (!verdict.ok) return false;
  const p = parseMlDsaCertificate(cert);
  return p.publicKeyFingerprint === seal.keys.mldsa65Fpr;
}
