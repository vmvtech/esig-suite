import { describe, expect, it, afterEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { loadPillar } from "../src/shim.js";
import { PillarIdentity } from "../src/identity.js";
import { CarrierClient } from "../src/carrier.js";
import { StubCarrier } from "./helpers/stub-carrier.js";

describe("carrier: CarrierClient against a local stub implementing the real signed-auth scheme", () => {
  let stub: StubCarrier;

  afterEach(async () => {
    await stub?.close();
  });

  it("delivers an envelope (POST /v1/envelopes) and fetches it back via a signed inbox poll (GET /v1/inbox/<uuaid>)", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const senderHome = mkdtempSync(path.join(tmpdir(), "carrier-sender-"));
    const recipientHome = mkdtempSync(path.join(tmpdir(), "carrier-recipient-"));
    const sender = await PillarIdentity.generate({ home: senderHome, passphrase: "sender-carrier-test-passphrase" });
    const recipient = await PillarIdentity.generate({ home: recipientHome, passphrase: "recipient-carrier-test-passphrase" });

    const senderCarrier = await CarrierClient.open({ identity: sender, carriers: [baseUrl] });
    const recipientCarrier = await CarrierClient.open({ identity: recipient, carriers: [baseUrl] });

    const envelope = pillar.envelope.seal(sender._keychain(), {
      recipient: recipient.uuaid,
      recipientPublicKey: recipient.publicKeyHex,
      kind: "esig:m",
      payload: { hello: "world" },
    });

    const deliverResult = await senderCarrier.deliver(envelope);
    expect(deliverResult.seq).toBe(1);
    expect(deliverResult.duplicate).toBe(false);
    expect(stub.envelopeCount).toBe(1);

    const inbox = await recipientCarrier.fetchInbox({ since: 0, waitS: 0 });
    expect(inbox.envelopes.length).toBe(1);
    expect(inbox.envelopes[0].envelope.id).toBe(envelope.id);

    const decrypted = pillar.envelope.decrypt(recipient._keychain(), inbox.envelopes[0].envelope);
    expect(decrypted).toEqual({ hello: "world" });
  });

  it("re-delivering the same envelope id reports duplicate:true and does not grow the store", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const senderHome = mkdtempSync(path.join(tmpdir(), "carrier-dup-sender-"));
    const recipientHome = mkdtempSync(path.join(tmpdir(), "carrier-dup-recipient-"));
    const sender = await PillarIdentity.generate({ home: senderHome, passphrase: "sender-carrier-test-passphrase" });
    const recipient = await PillarIdentity.generate({ home: recipientHome, passphrase: "recipient-carrier-test-passphrase" });
    const senderCarrier = await CarrierClient.open({ identity: sender, carriers: [baseUrl] });

    const envelope = pillar.envelope.seal(sender._keychain(), {
      recipient: recipient.uuaid,
      recipientPublicKey: recipient.publicKeyHex,
      kind: "esig:m",
      payload: { n: 1 },
    });

    const first = await senderCarrier.deliver(envelope);
    const second = await senderCarrier.deliver(envelope);
    expect(first.duplicate).toBe(false);
    expect(second.duplicate).toBe(true);
    expect(second.seq).toBe(first.seq);
    expect(stub.envelopeCount).toBe(1);
  });

  it("an inbox request with a forged/absent signature is refused (401), matching the real carrier's auth check", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const recipientHome = mkdtempSync(path.join(tmpdir(), "carrier-forge-"));
    const recipient = await PillarIdentity.generate({ home: recipientHome, passphrase: "recipient-carrier-test-passphrase" });

    const res = await fetch(`${baseUrl}/v1/inbox/${encodeURIComponent(recipient.uuaid)}?since=0&wait=0`);
    expect(res.status).toBe(401);
  });
});
