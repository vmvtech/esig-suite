// src/lib/integrations/esig/core/cert-issuer.ts
//
// Portable self-signed cert issuance. Project-agnostic — given a subject name
// (e.g. organization name), produces an RSA-2048 X.509 + PEM bundle ready
// to feed into PemSigner.
//
// Includes app-side AES-256-GCM key wrapping so callers can persist keys at
// rest without leaning on pgsodium / KMS / Vault. The wrapped blob is opaque;
// only callers that know the passphrase can unwrap.

import forge from "node-forge";
import crypto from "node:crypto";

const ENC_VERSION = "v1"; // scheme version prefix for future rotation
const DEFAULT_CERT_VALIDITY_DAYS = 365;
// PBKDF: scrypt N=2^15 ≈ 32MB / 100ms on modern CPU. Adequate at-rest
// derivation when passphrase is a high-entropy 24+ char env var.
const SCRYPT_N = 1 << 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
const IV_LEN = 12;
const SALT_LEN = 16;
const MIN_PASSPHRASE_LEN = 24;

export interface GenerateCertOptions {
  /** Subject CN seed — embedded in the cert's commonName + organizationName. ASCII-only. */
  subjectName: string;
  /** Validity period in days. Default 365. */
  validityDays?: number;
  /**
   * Override the OID extensions — defaults to a digital-signature-capable
   * end-entity cert suitable for PKCS#7 detached PDF signing.
   */
  extensions?: Parameters<ReturnType<typeof forge.pki.createCertificate>["setExtensions"]>[0];
  /** Override the prefix added to commonName. Default: "E-sig". */
  commonNamePrefix?: string;
}

export interface GeneratedCert {
  keyPem: string;
  certPem: string;
  /** SHA-256 hex of the DER-encoded cert. */
  fingerprint: string;
  notBefore: Date;
  notAfter: Date;
}

/**
 * Generate a self-signed RSA-2048 X.509 certificate suitable for PDF e-signing.
 *
 * ASCII-only subject — node-forge's `certificateFromPem` mis-counts byte length
 * for non-ASCII values when round-tripping (concrete bug: em-dash in OU breaks
 * parsing with "Too few bytes to parse DER"). The guard here prevents that.
 */
export function generateSelfSignedCert(opts: GenerateCertOptions): GeneratedCert {
  const { subjectName, validityDays = DEFAULT_CERT_VALIDITY_DAYS, commonNamePrefix = "E-sig" } = opts;
  if (!/^[\x20-\x7e]+$/.test(subjectName)) {
    throw new Error(
      `subjectName "${subjectName}" contains non-ASCII characters — would break node-forge cert round-trip`
    );
  }
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  const now = new Date();
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getTime() + validityDays * 86400_000);

  const subject = [
    { name: "commonName", value: `${commonNamePrefix} (${subjectName})` },
    { name: "organizationName", value: subjectName },
    { name: "organizationalUnitName", value: "E-signature" },
    { name: "countryName", value: "US" },
  ];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions(
    opts.extensions ?? [
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true, nonRepudiation: true },
      { name: "extKeyUsage", emailProtection: true, clientAuth: true },
    ]
  );
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const fingerprint = crypto.createHash("sha256").update(Buffer.from(der, "binary")).digest("hex");

  return {
    keyPem,
    certPem,
    fingerprint,
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
  };
}

// ---------- App-side key wrapping ----------

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return crypto.scryptSync(passphrase, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
}

/**
 * AES-256-GCM-encrypt a PEM-encoded private key for at-rest persistence.
 * Layout: version(2) | salt(16) | iv(12) | authTag(16) | ciphertext.
 *
 * @param keyPem  PEM-encoded private key string.
 * @param passphrase  ≥24 char high-entropy secret. Derived via scrypt with
 *                    per-call random salt.
 */
export function encryptKeyPem(keyPem: string, passphrase: string): Uint8Array {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new Error(`encryptKeyPem: passphrase must be ≥${MIN_PASSPHRASE_LEN} chars`);
  }
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(keyPem, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from(ENC_VERSION, "utf8"), salt, iv, authTag, ciphertext]);
}

/**
 * Inverse of encryptKeyPem. Throws on:
 *   - unknown version prefix (future-compat detection)
 *   - wrong passphrase (AES-GCM auth-tag mismatch surfaces as error)
 *   - tampered ciphertext (same as above)
 */
export function decryptKeyPem(blob: Uint8Array, passphrase: string): string {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new Error(`decryptKeyPem: passphrase must be ≥${MIN_PASSPHRASE_LEN} chars`);
  }
  const buf = Buffer.from(blob);
  const version = buf.slice(0, 2).toString("utf8");
  if (version !== ENC_VERSION) {
    throw new Error(`Unknown key encryption version: ${version}`);
  }
  const salt = buf.slice(2, 2 + SALT_LEN);
  const iv = buf.slice(2 + SALT_LEN, 2 + SALT_LEN + IV_LEN);
  const authTag = buf.slice(2 + SALT_LEN + IV_LEN, 2 + SALT_LEN + IV_LEN + 16);
  const ciphertext = buf.slice(2 + SALT_LEN + IV_LEN + 16);
  const key = deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
