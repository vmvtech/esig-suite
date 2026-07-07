// @e-sig/hsm-pkcs11
//
// PKCS#11 (Cryptoki) adapter for @e-sig/core's ExternalSigner seam: the RSA
// signing key lives inside an HSM (AWS CloudHSM, YubiHSM 2, SoftHSM2, Luna,
// nShield, …) and never enters this process's memory. `Pkcs11Signer` plugs
// straight into `signPdf({ externalSigner })` / `new PemSigner({ externalSigner })`.
//
// Dependency-light by design: this package never imports a PKCS#11 binding.
// You inject a minimal session provider (Pkcs11SessionProvider) implemented
// over `pkcs11js` (optional peer dependency) or any other Cryptoki bridge —
// only the four calls this adapter actually makes are typed. Tests inject a
// fake backed by node:crypto. See the README for the real pkcs11js wiring.
//
// Every signature uses mechanism CKM_SHA256_RSA_PKCS: the HSM hashes the raw
// to-be-signed bytes itself and applies RSASSA-PKCS1-v1_5 — exactly the
// primitive ExternalSigner.signRsaSha256 promises to @e-sig/core.

import type { ExternalSigner, ExternalSignerKeyType } from "@e-sig/core";

/** The only mechanism this adapter uses (HSM-side SHA-256 + PKCS1-v1_5 pad). */
export type Pkcs11Mechanism = "CKM_SHA256_RSA_PKCS";

/** Opaque token-side object handle (pkcs11js uses Buffer; typed loosely on purpose). */
export type Pkcs11KeyHandle = unknown;

/** How to locate the private key on the token (CKA_LABEL and/or CKA_ID). */
export interface Pkcs11KeyQuery {
  /** CKA_LABEL of the private key object. */
  label?: string;
  /** CKA_ID of the private key object. */
  id?: Uint8Array;
}

/**
 * Minimal structural view of one open PKCS#11 session — just the calls
 * `Pkcs11Signer` makes. Implement it over `pkcs11js` (README recipe) or any
 * Cryptoki bridge; every method may be sync or async.
 */
export interface Pkcs11Session {
  /** C_Login with CKU_USER. Throw on failure (e.g. CKR_PIN_INCORRECT). */
  login(pin: string): void | Promise<void>;
  /**
   * Locate the private key (C_FindObjectsInit/C_FindObjects with
   * CKO_PRIVATE_KEY + the query attributes). Return null when not found.
   */
  findKey(query: Pkcs11KeyQuery): Pkcs11KeyHandle | null | Promise<Pkcs11KeyHandle | null>;
  /** C_SignInit + C_Sign over `data` with the given mechanism. */
  sign(
    mechanism: Pkcs11Mechanism,
    key: Pkcs11KeyHandle,
    data: Uint8Array,
  ): Uint8Array | Promise<Uint8Array>;
  /** C_Logout (best-effort) + C_CloseSession. Always called, even on failure. */
  close(): void | Promise<void>;
}

/** Opens a fresh session per signature (C_OpenSession under the hood). */
export interface Pkcs11SessionProvider {
  open(): Pkcs11Session | Promise<Pkcs11Session>;
}

export interface Pkcs11SignerOptions {
  /** RSA modulus size of the HSM key. @e-sig/core validates it against the cert. */
  keyType: ExternalSignerKeyType;
  /**
   * PEM-encoded X.509 certificate whose public key matches the HSM-resident
   * private key. The cert is public material and lives outside the HSM.
   */
  certificatePem: string;
  /** Session source — your thin wrapper over pkcs11js (see README). */
  provider: Pkcs11SessionProvider;
  /**
   * CKU_USER PIN (CloudHSM: "CU_user:password"). May be "" for tokens using a
   * protected authentication path (PIN pad). Never logged or echoed in errors.
   */
  pin: string;
  /** Private-key lookup — at least one of `label` / `id` is required. */
  key: Pkcs11KeyQuery;
}

/** PKCS1-v1_5 signature length (bytes) per key type — used to fail closed. */
const SIGNATURE_BYTES: Record<ExternalSignerKeyType, number> = {
  "rsa-2048": 256,
  "rsa-3072": 384,
  "rsa-4096": 512,
};

/**
 * ExternalSigner over an injected PKCS#11 session. Each `signRsaSha256` call
 * runs a full open → login → findKey → sign cycle and always closes the
 * session (finally), so no logged-in session outlives a signature. All error
 * paths fail closed: login failure, missing key, and a malformed signature
 * each throw — nothing ever falls back to software signing.
 */
export class Pkcs11Signer implements ExternalSigner {
  public readonly keyType: ExternalSignerKeyType;
  public readonly certificatePem: string;
  private readonly provider: Pkcs11SessionProvider;
  private readonly pin: string;
  private readonly key: Pkcs11KeyQuery;

  constructor(options: Pkcs11SignerOptions) {
    const { keyType, certificatePem, provider, pin, key } = options;
    if (!SIGNATURE_BYTES[keyType]) {
      throw new Error(`Pkcs11Signer: unsupported keyType "${String(keyType)}"`);
    }
    if (!certificatePem || !certificatePem.includes("-----BEGIN CERTIFICATE-----")) {
      throw new Error("Pkcs11Signer: certificatePem must be a PEM-encoded X.509 certificate");
    }
    if (!provider || typeof provider.open !== "function") {
      throw new Error("Pkcs11Signer: provider with an open() method is required");
    }
    if (typeof pin !== "string") {
      throw new Error("Pkcs11Signer: pin is required (may be \"\" for protected auth path)");
    }
    if (!key || (!key.label && !key.id)) {
      throw new Error("Pkcs11Signer: key query needs at least one of label / id");
    }
    this.keyType = keyType;
    this.certificatePem = certificatePem;
    this.provider = provider;
    this.pin = pin;
    this.key = key;
  }

  async signRsaSha256(data: Uint8Array): Promise<Uint8Array> {
    const session = await this.provider.open();
    try {
      try {
        await session.login(this.pin);
      } catch (e) {
        // Fail closed; never echo the PIN (driver messages carry CKR_* codes only).
        throw new Error(`Pkcs11Signer: PKCS#11 login failed: ${e instanceof Error ? e.message : String(e)}`);
      }
      const keyHandle = await session.findKey(this.key);
      if (keyHandle === null || keyHandle === undefined) {
        throw new Error(`Pkcs11Signer: private key not found on token (${describeQuery(this.key)})`);
      }
      const sig = await session.sign("CKM_SHA256_RSA_PKCS", keyHandle, data);
      const expected = SIGNATURE_BYTES[this.keyType];
      if (!(sig instanceof Uint8Array) || sig.length !== expected) {
        throw new Error(
          `Pkcs11Signer: token returned ${sig instanceof Uint8Array ? sig.length : typeof sig
          } bytes; expected exactly ${expected} for ${this.keyType} (RSASSA-PKCS1-v1_5)`,
        );
      }
      return sig;
    } finally {
      // Best-effort close — the signature outcome (success or the error above)
      // is already decided; a close failure must not mask it.
      try {
        await session.close();
      } catch {
        /* ignore */
      }
    }
  }
}

/** PIN-free, id-hex description of a key query for error messages. */
function describeQuery(q: Pkcs11KeyQuery): string {
  const parts: string[] = [];
  if (q.label) parts.push(`label="${q.label}"`);
  if (q.id) parts.push(`id=0x${Array.from(q.id, (b) => b.toString(16).padStart(2, "0")).join("")}`);
  return parts.join(", ") || "empty query";
}
