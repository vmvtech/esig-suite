// Pkcs11Signer tests — fake PKCS#11 session backed by node:crypto.
//
// End-to-end proof: Pkcs11Signer (over a fake HSM whose CKM_SHA256_RSA_PKCS is
// node:crypto RSASSA-PKCS1-v1_5/SHA-256) + @e-sig/core signPdf → a signed PDF
// that verifyPdfStructure validates cryptographically. Error paths (bad PIN,
// missing key, malformed token output) fail closed and always close the
// session. Tests run against the BUILT package (../dist).

import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";

import { generateSelfSignedCert, signPdf, verifyPdfStructure } from "@e-sig/core";
import {
  Pkcs11Signer,
  type Pkcs11KeyHandle,
  type Pkcs11KeyQuery,
  type Pkcs11Session,
  type Pkcs11SessionProvider,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

const PIN = "1234";
const KEY_LABEL = "esig-signing-key";

interface FakeHsmOptions {
  failLogin?: boolean;
  truncateSignature?: boolean;
}

/**
 * Fake Cryptoki token: one RSA-2048 private key under CKA_LABEL
 * "esig-signing-key"; CKM_SHA256_RSA_PKCS implemented with node:crypto.
 * Methods are async to exercise the awaited seam end to end.
 */
function fakeHsm(keyPem: string, opts: FakeHsmOptions = {}) {
  const key = crypto.createPrivateKey(keyPem);
  const KEY_HANDLE: Pkcs11KeyHandle = { handle: 7 };
  const calls = { opened: 0, loggedIn: 0, signed: 0, closed: 0 };

  const provider: Pkcs11SessionProvider = {
    open(): Pkcs11Session {
      calls.opened++;
      return {
        async login(pin: string) {
          if (opts.failLogin || pin !== PIN) throw new Error("CKR_PIN_INCORRECT");
          calls.loggedIn++;
        },
        async findKey(query: Pkcs11KeyQuery) {
          return query.label === KEY_LABEL ? KEY_HANDLE : null;
        },
        async sign(mechanism, keyHandle, data) {
          if (mechanism !== "CKM_SHA256_RSA_PKCS") throw new Error("CKR_MECHANISM_INVALID");
          if (keyHandle !== KEY_HANDLE) throw new Error("CKR_KEY_HANDLE_INVALID");
          calls.signed++;
          const sig = new Uint8Array(crypto.sign("sha256", Buffer.from(data), key));
          return opts.truncateSignature ? sig.subarray(0, 16) : sig;
        },
        async close() {
          calls.closed++;
        },
      };
    },
  };
  return { provider, calls };
}

function signer(certPem: string, provider: Pkcs11SessionProvider, pin = PIN, label = KEY_LABEL) {
  return new Pkcs11Signer({
    keyType: "rsa-2048",
    certificatePem: certPem,
    provider,
    pin,
    key: { label },
  });
}

describe("Pkcs11Signer + @e-sig/core end to end", () => {
  it("signs a PDF through the fake HSM and verifies cryptographically", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider, calls } = fakeHsm(cert.keyPem);
    const { signedPdf } = await signPdf({
      pdf: SAMPLE_PDF,
      externalSigner: signer(cert.certPem, provider),
      reason: "hsm e2e",
      location: "",
      contactInfo: "",
      name: "HSM Signer",
      signingTime: new Date(),
    });
    const v = verifyPdfStructure(Buffer.from(signedPdf));
    expect(v.ok).toBe(true);
    expect(v.digestValid).toBe(true);
    expect(v.signatureValid).toBe(true);
    // Exactly one full session cycle, and it was closed.
    expect(calls).toEqual({ opened: 1, loggedIn: 1, signed: 1, closed: 1 });
  });

  it("a tampered HSM-signed PDF fails verification", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider } = fakeHsm(cert.keyPem);
    const { signedPdf } = await signPdf({
      pdf: SAMPLE_PDF,
      externalSigner: signer(cert.certPem, provider),
      reason: "tamper",
      location: "",
      contactInfo: "",
      name: "HSM Signer",
    });
    const tampered = Buffer.from(signedPdf);
    tampered[100] ^= 0xff;
    expect(verifyPdfStructure(tampered).ok).toBe(false);
  });
});

describe("Pkcs11Signer fail-closed error paths", () => {
  const data = new Uint8Array([1, 2, 3]);

  it("login failure rejects and still closes the session", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider, calls } = fakeHsm(cert.keyPem, { failLogin: true });
    await expect(signer(cert.certPem, provider).signRsaSha256(data)).rejects.toThrow(
      /login failed: CKR_PIN_INCORRECT/,
    );
    expect(calls.signed).toBe(0);
    expect(calls.closed).toBe(1);
  });

  it("wrong PIN rejects without exposing the PIN", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider } = fakeHsm(cert.keyPem);
    const err = await signer(cert.certPem, provider, "0000").signRsaSha256(data).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/login failed/);
    expect((err as Error).message).not.toContain("0000");
  });

  it("missing key rejects with the query in the message and closes the session", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider, calls } = fakeHsm(cert.keyPem);
    await expect(
      signer(cert.certPem, provider, PIN, "no-such-key").signRsaSha256(data),
    ).rejects.toThrow(/private key not found on token \(label="no-such-key"\)/);
    expect(calls.signed).toBe(0);
    expect(calls.closed).toBe(1);
  });

  it("wrong-sized token output rejects (never returns a bad signature)", async () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider, calls } = fakeHsm(cert.keyPem, { truncateSignature: true });
    await expect(signer(cert.certPem, provider).signRsaSha256(data)).rejects.toThrow(
      /expected exactly 256 for rsa-2048/,
    );
    expect(calls.closed).toBe(1);
  });

  it("constructor validates its inputs", () => {
    const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
    const { provider } = fakeHsm(cert.keyPem);
    expect(
      () =>
        new Pkcs11Signer({
          keyType: "rsa-2048",
          certificatePem: "not a pem",
          provider,
          pin: PIN,
          key: { label: KEY_LABEL },
        }),
    ).toThrow(/certificatePem/);
    expect(
      () =>
        new Pkcs11Signer({
          keyType: "rsa-2048",
          certificatePem: cert.certPem,
          provider,
          pin: PIN,
          key: {},
        }),
    ).toThrow(/at least one of label \/ id/);
  });
});
