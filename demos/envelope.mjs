// Multi-signer envelope demo — ordered signing plus one final PDF seal.
//
// This stays Chrome-free by sealing the repository's pre-rendered sample PDF.
// All state and output live in a temporary directory that is removed on exit.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  composeEnvelopeHtml,
  createEnvelope,
  ensureActiveCert,
  recordSignature,
  resolveSigningToken,
  signPdf,
  verifyPdfSignature,
} from "@e-sig/core";
import {
  FsAuditLogStore,
  FsCertStore,
  FsEnvelopeStore,
  FsPdfStorageStore,
} from "@e-sig/core/fs";

const SIGNATURE_IMAGE =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
const TENANT_ID = "example-tenant";

function maskedSigningLink(token) {
  return `https://example.com/sign/${token.slice(0, 8)}…`;
}

const workDir = await mkdtemp(join(tmpdir(), "esig-envelope-demo-"));

try {
  const envelopeStore = new FsEnvelopeStore(workDir);
  const { envelope, signingTokens } = await createEnvelope({
    store: envelopeStore,
    tenantId: TENANT_ID,
    title: "Example agreement",
    html: "<h1>Example agreement</h1><p>Demonstration document.</p>",
    signers: [
      { name: "Alice Example", email: "alice@example.com", order: 1 },
      { name: "Bob Example", email: "bob@example.com", order: 2 },
    ],
  });
  const [aliceToken, bobToken] = signingTokens;

  console.log(`1. created envelope  id=${envelope.id} signers=${envelope.signers.length}`);
  console.log(`2. alice link       ${maskedSigningLink(aliceToken.token)} (masked)`);
  console.log(`3. bob link         ${maskedSigningLink(bobToken.token)} (masked)`);

  const aliceGate = await resolveSigningToken({ store: envelopeStore, token: aliceToken.token });
  const bobGate = await resolveSigningToken({ store: envelopeStore, token: bobToken.token });
  assert.equal(aliceGate.status, "ok");
  assert.equal(aliceGate.signer.status, "pending");
  assert.equal(bobGate.status, "not_your_turn");
  console.log(
    `4. signing gates    alice=${aliceGate.signer.status} bob=${bobGate.status} (not yet your turn)`,
  );

  const afterAlice = await recordSignature({
    store: envelopeStore,
    token: aliceToken.token,
    signatureImageDataUrl: SIGNATURE_IMAGE,
  });
  assert.equal(afterAlice.status, "partially_signed");
  console.log(`5. alice signed     status=${afterAlice.status}`);

  const completed = await recordSignature({
    store: envelopeStore,
    token: bobToken.token,
    signatureImageDataUrl: SIGNATURE_IMAGE,
  });
  assert.equal(completed.status, "completed");
  assert.equal(completed.signers.every((signer) => signer.status === "signed"), true);
  console.log(`6. bob signed       status=${completed.status}`);

  const composedHtml = composeEnvelopeHtml(completed, { platformLabel: "e-sig demo" });
  assert.match(composedHtml, /Alice Example/);
  assert.match(composedHtml, /Bob Example/);

  const certStore = new FsCertStore(workDir);
  const auditStore = new FsAuditLogStore(workDir);
  const storage = new FsPdfStorageStore(workDir);
  const cert = await ensureActiveCert({
    store: certStore,
    tenantId: TENANT_ID,
    subjectName: "Example Organization",
    passphrase: randomBytes(24).toString("base64url"),
  });
  const unsignedPdf = await readFile(new URL("../examples/quickstart/sample.pdf", import.meta.url));
  const { signedPdf } = await signPdf({
    pdf: unsignedPdf,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: `Signed via e-sig envelope ${completed.id} by ${completed.signers.length} signer(s)`,
    location: "",
    contactInfo: "signing@example.com",
    name: completed.signers.map((signer) => signer.name).join(", "),
  });
  const sealed = await storage.upload({
    path: `envelopes/${completed.id}/sealed.pdf`,
    bytes: signedPdf,
    contentType: "application/pdf",
  });
  await auditStore.insert({
    tenantId: TENANT_ID,
    action: "envelope.completed",
    targetId: completed.id,
    certId: cert.cert.id,
    certFingerprint: cert.cert.certFingerprint,
    signedPdfUrl: sealed.url,
    metadata: { signer_count: completed.signers.length },
  });

  const verification = verifyPdfSignature(await readFile(sealed.url));
  assert.equal(verification.ok, true, `sealed PDF verification failed: ${verification.failures.join("; ")}`);
  console.log(
    `7. completed + verified  status=${completed.status} ok=${verification.ok} ` +
      `digestValid=${verification.digestValid} signatureValid=${verification.signatureValid}`,
  );
} finally {
  await rm(workDir, { recursive: true, force: true });
}
