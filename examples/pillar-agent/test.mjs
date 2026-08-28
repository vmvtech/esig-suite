#!/usr/bin/env node
// test.mjs — lightweight assertions for RT-2026-08-28-01 F5/G3 (f): this
// reference recipient replies only for envelopes addressed to its own
// uuaid, and only when the DECRYPTED payload's own `sender` matches the
// envelope's transport-verified `sender`. Plain node:assert/strict, no test
// framework/dependency beyond what the example already needs — run:
//   node test.mjs
// (offline, against the bundled stub-carrier.mjs, exactly like demo.mjs.)

import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { loadPillar, CarrierClient } from "@e-sig/pillar-bridge";

import { startStubCarrier } from "./stub-carrier.mjs";
import { loadOrCreateIdentity, pollOnce } from "./index.mjs";

async function freshIdentity(prefix) {
  const home = mkdtempSync(path.join(tmpdir(), `${prefix}-`));
  return loadOrCreateIdentity({ home, passphrase: "pillar-agent-test-fixture-passphrase-01" });
}

function futureExpiry() {
  return new Date(Date.now() + 15 * 60_000).toISOString();
}

/**
 * (f), first half: an envelope not addressed to this agent's own uuaid is
 * ignored — even one the agent could otherwise fully decrypt/act on. No
 * real carrier is needed here: `pollOnce` is handed a fake `carrier` whose
 * `fetchInbox` hands back the mis-addressed envelope directly, so this
 * proves the AGENT's own recipient check, independent of whatever
 * filtering the real carrier's inbox endpoint happens to do.
 */
async function testIgnoresEnvelopeNotAddressedToUs() {
  const pillar = await loadPillar();
  const sender = await freshIdentity("test-recipient-mismatch-sender");
  const recipient = await freshIdentity("test-recipient-mismatch-recipient");
  const bystander = await freshIdentity("test-recipient-mismatch-bystander");

  // Well-formed, validly sealed — but addressed to `bystander`, not `recipient`.
  const envelope = pillar.envelope.seal(sender._keychain(), {
    recipient: bystander.uuaid,
    recipientPublicKey: bystander.publicKeyHex,
    kind: "esig:sign-request",
    payload: {
      v: 1,
      envelopeId: "env-test-not-addressed",
      title: "t",
      url: "https://esig.example.test/sign/x",
      expiresAt: futureExpiry(),
      sender: sender.uuaid,
      createdAt: new Date().toISOString(),
    },
  });

  let deliverCalled = false;
  const fakeCarrier = {
    fetchInbox: async () => ({ envelopes: [{ seq: 1, envelope }], now: Date.now() }),
    deliver: async () => {
      deliverCalled = true;
      return { seq: 1 };
    },
  };

  await pollOnce({ pillar, identity: recipient, carrier: fakeCarrier, since: 0, waitS: 0 });
  assert.equal(deliverCalled, false, "must not reply to an envelope not addressed to our own uuaid");
  console.log("PASS: (f) envelope not addressed to us is ignored, no reply sent");
}

/**
 * (f), second half + (e): a sign-request validly sealed BY `sender` (so
 * `envelope.sender` — transport-verified via `open()` — really is
 * `sender.uuaid`) whose DECRYPTED PAYLOAD claims a different `sender` is
 * dropped, not acted on. This is a real round trip through a stub carrier
 * (open()/decrypt() must genuinely succeed for the mismatch check itself to
 * be exercised) — if the agent incorrectly replied, that reply would land
 * in the real sender's real inbox, which this asserts stays empty.
 */
async function testDropsPayloadSenderMismatch() {
  const pillar = await loadPillar();
  const stub = await startStubCarrier();
  try {
    const sender = await freshIdentity("test-sender-mismatch-sender");
    const impersonated = await freshIdentity("test-sender-mismatch-impersonated");
    const recipient = await freshIdentity("test-sender-mismatch-recipient");

    const envelope = pillar.envelope.seal(sender._keychain(), {
      recipient: recipient.uuaid,
      recipientPublicKey: recipient.publicKeyHex,
      kind: "esig:sign-request",
      payload: {
        v: 1,
        envelopeId: "env-test-sender-mismatch",
        title: "t",
        url: "https://esig.example.test/sign/y",
        expiresAt: futureExpiry(),
        sender: impersonated.uuaid, // the payload lies about who sent it
        createdAt: new Date().toISOString(),
      },
    });
    assert.equal(envelope.sender, sender.uuaid, "sanity: the transport-verified sender is the real signer");
    assert.notEqual(envelope.sender, impersonated.uuaid, "sanity: the payload's claimed sender really does differ");

    const senderCarrier = await CarrierClient.open({ identity: sender, carriers: [stub.url] });
    await senderCarrier.deliver(envelope);

    const recipientCarrier = await CarrierClient.open({ identity: recipient, carriers: [stub.url] });
    await pollOnce({ pillar, identity: recipient, carrier: recipientCarrier, since: 0, waitS: 1 });

    const senderInbox = await senderCarrier.fetchInbox({ since: 0, waitS: 0 });
    assert.equal(senderInbox.envelopes.length, 0, "must not reply when payload.sender != the verified envelope.sender");
    console.log("PASS: (f) payload.sender mismatching the verified envelope sender is dropped, no reply sent");
  } finally {
    await stub.close();
  }
}

/** (e): a sign-request with no top-level expiresAt is dropped, not acted on. */
async function testDropsMissingExpiresAt() {
  const pillar = await loadPillar();
  const stub = await startStubCarrier();
  try {
    const sender = await freshIdentity("test-missing-expiry-sender");
    const recipient = await freshIdentity("test-missing-expiry-recipient");

    const envelope = pillar.envelope.seal(sender._keychain(), {
      recipient: recipient.uuaid,
      recipientPublicKey: recipient.publicKeyHex,
      kind: "esig:sign-request",
      payload: {
        v: 1,
        envelopeId: "env-test-missing-expiry",
        title: "t",
        url: "https://esig.example.test/sign/z",
        // no expiresAt
        sender: sender.uuaid,
        createdAt: new Date().toISOString(),
      },
    });

    const senderCarrier = await CarrierClient.open({ identity: sender, carriers: [stub.url] });
    await senderCarrier.deliver(envelope);

    const recipientCarrier = await CarrierClient.open({ identity: recipient, carriers: [stub.url] });
    await pollOnce({ pillar, identity: recipient, carrier: recipientCarrier, since: 0, waitS: 1 });

    const senderInbox = await senderCarrier.fetchInbox({ since: 0, waitS: 0 });
    assert.equal(senderInbox.envelopes.length, 0, "must not reply to a sign-request with no expiresAt");
    console.log("PASS: (e) sign-request with no expiresAt is dropped, no reply sent");
  } finally {
    await stub.close();
  }
}

async function main() {
  await testIgnoresEnvelopeNotAddressedToUs();
  await testDropsPayloadSenderMismatch();
  await testDropsMissingExpiresAt();
  console.log("test.mjs: all assertions passed");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
