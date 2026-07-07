# @e-sig/hsm-pkcs11

PKCS#11 (Cryptoki) adapter for [`@e-sig/core`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-core) —
keep the RSA signing key inside an HSM (AWS CloudHSM, YubiHSM 2, SoftHSM2,
Luna, nShield, …). The private key never enters process memory: `Pkcs11Signer`
implements core's `ExternalSigner` seam, so the PKCS#7 signature is produced by
the token via mechanism `CKM_SHA256_RSA_PKCS` (HSM-side SHA-256 +
RSASSA-PKCS1-v1_5 — byte-identical to core's in-memory `keyPem` path).

```bash
npm i @e-sig/hsm-pkcs11 pkcs11js   # pkcs11js is an OPTIONAL peer — see below
```

## Quickstart

```ts
import { signPdf } from "@e-sig/core";
import { Pkcs11Signer } from "@e-sig/hsm-pkcs11";

const externalSigner = new Pkcs11Signer({
  keyType: "rsa-2048",                       // must match the cert's modulus
  certificatePem: readFileSync("signer.crt", "utf8"), // public; lives outside the HSM
  provider,                                  // your pkcs11js wrapper (below)
  pin: process.env.HSM_PIN!,                 // CloudHSM: "CU_user:password"
  key: { label: "esig-signing-key" },        // CKA_LABEL and/or CKA_ID
});

const { signedPdf } = await signPdf({
  pdf,
  externalSigner,                            // instead of keyPem/certPem
  reason: "Approved", location: "", contactInfo: "", name: "Acme Inc",
});
```

Each signature runs a full `open → login → findKey → sign → close` cycle and
**fails closed**: a login failure, a missing key, or a wrong-sized token
response throws — nothing ever falls back to software signing, no logged-in
session outlives a call, and the PIN is never echoed in errors.

## Wiring the real `pkcs11js`

This package is dependency-light: it never imports a PKCS#11 binding itself.
You inject a `Pkcs11SessionProvider` — a thin wrapper over
[`pkcs11js`](https://github.com/PeculiarVentures/pkcs11js) typed to just the
four calls the adapter makes:

```ts
import pkcs11js from "pkcs11js";
import type { Pkcs11Session, Pkcs11SessionProvider } from "@e-sig/hsm-pkcs11";

export function pkcs11jsProvider(modulePath: string, slotIndex = 0): Pkcs11SessionProvider {
  const p11 = new pkcs11js.PKCS11();
  p11.load(modulePath);
  p11.C_Initialize();

  return {
    open(): Pkcs11Session {
      const slot = p11.C_GetSlotList(true)[slotIndex];
      const session = p11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION);
      return {
        login: (pin) => p11.C_Login(session, pkcs11js.CKU_USER, pin),
        findKey: ({ label, id }) => {
          const template = [{ type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY }];
          if (label) template.push({ type: pkcs11js.CKA_LABEL, value: label });
          if (id) template.push({ type: pkcs11js.CKA_ID, value: Buffer.from(id) });
          p11.C_FindObjectsInit(session, template);
          const [handle] = p11.C_FindObjects(session, 1);
          p11.C_FindObjectsFinal(session);
          return handle ?? null;
        },
        sign: (_mechanism, key, data) => {
          p11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, key as Buffer);
          return new Uint8Array(p11.C_Sign(session, Buffer.from(data), Buffer.alloc(512)));
        },
        close: () => {
          try { p11.C_Logout(session); } catch { /* not logged in */ }
          p11.C_CloseSession(session);
        },
      };
    },
  };
}
```

Module paths for common tokens:

| Token          | `modulePath`                                        |
| -------------- | --------------------------------------------------- |
| AWS CloudHSM   | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`            |
| YubiHSM 2      | `yubihsm_pkcs11.so` (set `YUBIHSM_PKCS11_CONF`)      |
| SoftHSM2 (dev) | `/usr/lib/softhsm/libsofthsm2.so`                    |

CloudHSM notes: the PIN is `"CU_user:password"` (a Crypto User), and the
certificate is *not* stored in the HSM — generate the keypair on the token,
CSR it out, and keep the issued/self-signed cert as a PEM next to your app.
YubiHSM 2 exposes asymmetric keys via the yubihsm-pkcs11 module with
`CKA_LABEL` equal to the object label.

`pkcs11js` is declared as an **optional** peer dependency: installs without it
work fine (e.g. CI running the fake-session tests), and nothing in this package
loads it at runtime — only your provider does.

## Testing without an HSM

Tests inject a fake `Pkcs11Session` backed by `node:crypto` (see
`test/pkcs11-signer.test.ts`) and prove the full chain:
`Pkcs11Signer → signPdf({ externalSigner }) → verifyPdfStructure ok:true`,
plus fail-closed login/missing-key/short-signature paths. Use the same pattern
(or SoftHSM2) in your own suite.

## License

MIT
