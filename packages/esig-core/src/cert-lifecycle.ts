// cert-lifecycle.ts
//
// Stack-agnostic "ensure an active signing cert for this tenant" helper. Depends
// only on the CertStore interface + the crypto in cert-issuer — no DB, no stack.
// Creates a cert on first call; on expiry, deactivates the old one and issues a
// fresh cert with `rotatedFromId` pointing at the predecessor.

import {
  generateSelfSignedCert,
  encryptKeyPem,
  decryptKeyPem,
} from "./cert-issuer.js";
import type { CertStore, StoredCert } from "./adapters.js";

export interface EnsureCertResult {
  cert: StoredCert;
  certPem: string;
  /** Decrypted PEM private key — keep in memory only; never persist plaintext. */
  keyPem: string;
}

export async function ensureActiveCert(opts: {
  store: CertStore;
  tenantId: string;
  /** Cert subject CN (e.g. the tenant/org display name). ASCII-clean it upstream. */
  subjectName: string;
  /** Passphrase used to encrypt/decrypt the key at rest in the CertStore. */
  passphrase: string;
}): Promise<EnsureCertResult> {
  const existing = await opts.store.findActive(opts.tenantId);
  if (existing && existing.notAfter > new Date()) {
    return {
      cert: existing,
      certPem: existing.certPem,
      keyPem: decryptKeyPem(existing.keyPemEncrypted, opts.passphrase),
    };
  }

  if (existing) {
    await opts.store.deactivate(existing.id);
  }

  const generated = generateSelfSignedCert({ subjectName: opts.subjectName });
  const keyPemEncrypted = encryptKeyPem(generated.keyPem, opts.passphrase);
  const cert = await opts.store.insert({
    tenantId: opts.tenantId,
    generated,
    keyPemEncrypted,
    rotatedFromId: existing?.id ?? null,
  });
  return { cert, certPem: generated.certPem, keyPem: generated.keyPem };
}
