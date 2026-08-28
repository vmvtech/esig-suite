// demo.mjs — the README's 5-step walkthrough, automated, offline, in one
// process, against the bundled stub-carrier.mjs. Run: node demo.mjs

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { loadPillar, PillarIdentity, CarrierClient } from "@e-sig/pillar-bridge";

import { startStubCarrier } from "./stub-carrier.mjs";
import { loadOrCreateIdentity, pollOnce } from "./index.mjs";

async function main() {
  const stub = await startStubCarrier();
  console.log(`[demo] stub carrier listening at ${stub.url}`);

  const pillar = await loadPillar();

  // 1. Sender identity — stands in for the esig-mcp operator.
  const senderHome = mkdtempSync(path.join(tmpdir(), "pillar-agent-demo-sender-"));
  const sender = await PillarIdentity.generate({ home: senderHome, passphrase: "pillar-agent-demo-passphrase-01" });
  console.log(`[demo] 1. sender identity:    ${sender.uuaid}`);

  // 2. Recipient identity — the reference agent from index.mjs, in its own home dir.
  const recipientHome = mkdtempSync(path.join(tmpdir(), "pillar-agent-demo-recipient-"));
  const recipient = await loadOrCreateIdentity({ home: recipientHome, passphrase: "pillar-agent-demo-passphrase-01" });
  console.log(`[demo] 2. recipient identity: ${recipient.uuaid}`);

  // 3. Sender delivers a sign-request that ALSO carries a challenge (sealed
  //    directly with the loaded pillar primitives — a real esig-mcp Stage B
  //    sender would relay one from `esig_identity_challenge`,
  //    docs/architecture/esig-mcp.md §12; PillarDelivery's own payload shape
  //    (delivery.ts) has no challenge field, so this demo goes one level
  //    below it to exercise index.mjs's "carries a challenge" branch).
  const senderCarrier = await CarrierClient.open({ identity: sender, carriers: [stub.url] });
  const challenge = {
    type: "esig-signer-challenge/v1",
    envelopeId: "env-demo-001",
    signerId: "signer-1",
    htmlSha256: "0".repeat(64),
    nonce: "demo-nonce-not-random",
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
  };
  const signRequestEnvelope = pillar.envelope.seal(sender._keychain(), {
    recipient: recipient.uuaid,
    recipientPublicKey: recipient.publicKeyHex,
    kind: "esig:sign-request",
    payload: {
      v: 1,
      envelopeId: "env-demo-001",
      title: "Vendor Services Agreement",
      url: "https://esig.example.test/sign/DEMO-TOKEN",
      // Required (RT-2026-08-28-01 F5/G3 e) — index.mjs's handleSignRequest
      // drops any sign-request with no expiresAt, or an expired one.
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      note: "please review + sign",
      sender: sender.uuaid,
      createdAt: new Date().toISOString(),
      challenge,
    },
  });
  await senderCarrier.deliver(signRequestEnvelope);
  console.log(`[demo] 3. sender delivered esig:sign-request (envelope ${signRequestEnvelope.id})`);

  // 4. The recipient agent polls its inbox once and replies with a proof.
  const recipientCarrier = await CarrierClient.open({ identity: recipient, carriers: [stub.url] });
  await pollOnce({ pillar, identity: recipient, carrier: recipientCarrier, since: 0, waitS: 1 });
  console.log("[demo] 4. recipient polled + replied (see [pillar-agent] lines above)");

  // 5. The sender polls its own inbox and sees the identity-proof envelope.
  const senderInbox = await senderCarrier.fetchInbox({ since: 0, waitS: 1 });
  const proofRow = senderInbox.envelopes.find((e) => e.envelope.kind === "esig:identity-proof");
  if (!proofRow) throw new Error("demo: no esig:identity-proof envelope arrived");
  const proofPayload = pillar.envelope.decrypt(sender._keychain(), proofRow.envelope);
  console.log(
    `[demo] 5. sender received proof: uuaid=${proofPayload.uuaid} cryptosuite=${proofPayload.proof.cryptosuite} verificationMethod=${proofPayload.proof.verificationMethod}`
  );

  await stub.close();
  console.log("[demo] done.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
