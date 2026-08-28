import { describe, expect, it, afterEach } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { loadPillar } from "../src/shim.js";
import { PillarIdentity } from "../src/identity.js";
import { PillarDelivery } from "../src/delivery.js";
import { PillarEventSink } from "../src/events.js";
import { PillarProofSource } from "../src/proofs.js";
import { CarrierClient } from "../src/carrier.js";
import type { EsigEvent, IdentityProofEvent } from "../src/types.js";
import { StubCarrier } from "./helpers/stub-carrier.js";

async function freshIdentity(prefix: string, passphrase = "e2e-test-fixture-passphrase-01"): Promise<PillarIdentity> {
  const home = mkdtempSync(path.join(tmpdir(), `${prefix}-`));
  return PillarIdentity.generate({ home, passphrase });
}

describe("end-to-end: PillarDelivery / PillarEventSink / PillarProofSource against the stub carrier", () => {
  let stub: StubCarrier;

  afterEach(async () => {
    await stub?.close();
  });

  it("PillarDelivery seals a sign-request the recipient can open() and decrypt to see the url", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const sender = await freshIdentity("e2e-sender");
    const recipient = await freshIdentity("e2e-recipient");

    const delivery = await PillarDelivery.open({ identity: sender, carriers: [baseUrl] });
    const receipts = await delivery.deliver(
      { id: "env-abc123", title: "Please sign the NDA", expiresAt: "2026-09-01T00:00:00.000Z", message: "urgent" },
      [
        {
          signerId: "signer-1",
          name: "Recipient Agent",
          email: "recipient@example.test",
          url: "https://esig.example.test/sign/SECRET-TOKEN",
          pillar: { uuaid: recipient.uuaid, publicKey: recipient.publicKeyHex },
        },
      ]
    );

    expect(receipts).toHaveLength(1);
    expect(receipts[0].ok).toBe(true);
    expect(receipts[0].signerId).toBe("signer-1");
    expect(receipts[0].messageId).toBeDefined();
    // Never the url in the receipt.
    expect(receipts[0].detail ?? "").not.toContain("SECRET-TOKEN");
    expect(JSON.stringify(receipts[0])).not.toContain("SECRET-TOKEN");

    const inboxRes = await fetch(
      `${baseUrl}/v1/inbox/${encodeURIComponent(recipient.uuaid)}?since=0&wait=0`,
      {
        headers: signedInboxHeaders(pillar, recipient, 0),
      }
    );
    const inbox = (await inboxRes.json()) as { envelopes: Array<{ seq: number; envelope: import("../src/pillar-types.js").PillarEnvelope }> };
    expect(inbox.envelopes).toHaveLength(1);
    const envelope = inbox.envelopes[0].envelope;
    expect(envelope.kind).toBe("esig:sign-request");

    // The recipient verifies + decrypts with THEIR OWN loaded pillar module —
    // using the same shim singleton here (loadPillar() is memoized) since
    // this is a single-process test, but the call is exactly what a
    // separate recipient process would make.
    const openVerdict = pillar.envelope.open(envelope);
    expect(openVerdict.ok).toBe(true);

    const payload = pillar.envelope.decrypt(recipient._keychain(), envelope) as Record<string, unknown>;
    expect(payload.url).toBe("https://esig.example.test/sign/SECRET-TOKEN");
    expect(payload.title).toBe("Please sign the NDA");
    expect(payload.sender).toBe(sender.uuaid);
    expect(payload.note).toBe("urgent");
  });

  it("a link whose publicKey does not derive the stated uuaid is refused, ok:false, and nothing is delivered", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const sender = await freshIdentity("e2e-mismatch-sender");
    const recipient = await freshIdentity("e2e-mismatch-recipient");
    const otherKeyIdentity = await freshIdentity("e2e-mismatch-other");

    const delivery = await PillarDelivery.open({ identity: sender, carriers: [baseUrl] });
    const receipts = await delivery.deliver({ id: "env-mismatch", title: "t" }, [
      {
        signerId: "signer-mismatch",
        name: "n",
        email: "e@example.test",
        url: "https://esig.example.test/sign/x",
        // uuaid says `recipient`, but the key is `otherKeyIdentity`'s — must be refused.
        pillar: { uuaid: recipient.uuaid, publicKey: otherKeyIdentity.publicKeyHex },
      },
    ]);

    expect(receipts).toHaveLength(1);
    expect(receipts[0].ok).toBe(false);
    expect(receipts[0].detail).toMatch(/does not derive/);
    expect(stub.envelopeCount).toBe(0);
  });

  it("RT-2026-08-28-01 F5/G3: refuses to seal a sign-request with no meta.expiresAt", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const sender = await freshIdentity("e2e-noexpiry-sender");
    const recipient = await freshIdentity("e2e-noexpiry-recipient");

    const delivery = await PillarDelivery.open({ identity: sender, carriers: [baseUrl] });
    const receipts = await delivery.deliver({ id: "env-noexpiry", title: "t" }, [
      {
        signerId: "signer-noexpiry",
        name: "n",
        email: "e@example.test",
        url: "https://esig.example.test/sign/x",
        pillar: { uuaid: recipient.uuaid, publicKey: recipient.publicKeyHex },
      },
    ]);

    expect(receipts).toEqual([
      {
        signerId: "signer-noexpiry",
        channel: "pillar",
        ok: false,
        detail: "meta.expiresAt is required for esig:sign-request over Pillar (RT-2026-08-28-01 G3)",
      },
    ]);
    expect(stub.envelopeCount).toBe(0);
  });

  it("a link with no pillar target is refused, ok:false, detail 'no pillar target'", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const sender = await freshIdentity("e2e-nopillar-sender");
    const delivery = await PillarDelivery.open({ identity: sender, carriers: [baseUrl] });
    const receipts = await delivery.deliver({ id: "env-nopillar", title: "t" }, [
      { signerId: "s", name: "n", email: "e@example.test", url: "https://x/sign/y" },
    ]);
    expect(receipts).toEqual([{ signerId: "s", channel: "pillar", ok: false, detail: "no pillar target" }]);
  });

  it("PillarEventSink publishes an event to two subscribers, each independently decryptable", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const sender = await freshIdentity("e2e-events-sender");
    const subA = await freshIdentity("e2e-events-sub-a");
    const subB = await freshIdentity("e2e-events-sub-b");

    const receipts: Array<{ uuaid: string; ok: boolean }> = [];
    const sink = await PillarEventSink.open({
      identity: sender,
      carriers: [baseUrl],
      subscribers: [
        { uuaid: subA.uuaid, publicKey: subA.publicKeyHex },
        { uuaid: subB.uuaid, publicKey: subB.publicKeyHex },
      ],
      onReceipt: (r) => receipts.push({ uuaid: r.uuaid, ok: r.ok }),
    });

    const event: EsigEvent = {
      id: "evt-1",
      type: "envelope.signed",
      createdAt: new Date().toISOString(),
      envelopeId: "env-xyz",
      phase: "completed",
      data: { count: 1 },
    };
    await sink.publish(event);

    expect(receipts).toEqual([
      { uuaid: subA.uuaid, ok: true },
      { uuaid: subB.uuaid, ok: true },
    ]);
    expect(stub.envelopeCount).toBe(2);

    for (const sub of [subA, subB]) {
      const res = await fetch(`${baseUrl}/v1/inbox/${encodeURIComponent(sub.uuaid)}?since=0&wait=0`, {
        headers: signedInboxHeaders(pillar, sub, 0),
      });
      const body = (await res.json()) as { envelopes: Array<{ envelope: import("../src/pillar-types.js").PillarEnvelope }> };
      expect(body.envelopes).toHaveLength(1);
      expect(body.envelopes[0].envelope.kind).toBe("esig:event");
      const decrypted = pillar.envelope.decrypt(sub._keychain(), body.envelopes[0].envelope) as { v: number; event: EsigEvent };
      expect(decrypted.v).toBe(1);
      expect(decrypted.event).toEqual(event);
    }
  });

  it("PillarProofSource accepts a well-formed esig:identity-proof, ignores a foreign kind, and ignores a replay", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();

    const operator = await freshIdentity("e2e-proofs-operator");
    const signerAgent = await freshIdentity("e2e-proofs-signer");
    const proofsHome = mkdtempSync(path.join(tmpdir(), "e2e-proofs-state-"));

    const kindCountsSeen: Record<string, number>[] = [];
    const source = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home: proofsHome,
      waitS: 1,
      onKindCounts: (c) => kindCountsSeen.push(c),
      isAllowedSender: (s) => s === signerAgent.uuaid,
    });

    // The signer's own identity seals the proof reply to the operator.
    const proofPayload = {
      v: 1,
      envelopeId: "env-abc123",
      signerId: "signer-1",
      uuaid: signerAgent.uuaid,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      proof: {
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        created: new Date().toISOString(),
        verificationMethod: `did:key:z6MkFAKEFAKEFAKE#sk-1`,
        proofPurpose: "authentication",
        proofValue: "zFAKESIGNATUREVALUE",
      },
    };
    const proofEnvelope = pillar.envelope.seal(signerAgent._keychain(), {
      recipient: operator.uuaid,
      recipientPublicKey: operator.publicKeyHex,
      kind: "esig:identity-proof",
      payload: proofPayload,
    });

    // A foreign kind, delivered first — must be ignored (counted, not surfaced).
    const foreignEnvelope = pillar.envelope.seal(signerAgent._keychain(), {
      recipient: operator.uuaid,
      recipientPublicKey: operator.publicKeyHex,
      kind: "esig:sealed",
      payload: { v: 1, envelopeId: "env-abc123", sha256: "deadbeef", size: 1 },
    });

    const deliverer = await CarrierClient.open({ identity: signerAgent, carriers: [baseUrl] });
    await deliverer.deliver(foreignEnvelope);
    await deliverer.deliver(proofEnvelope);

    const received: IdentityProofEvent[] = [];
    await source.pollOnce((evt) => received.push(evt));

    expect(received).toHaveLength(1);
    expect(received[0]).toEqual({
      envelopeId: "env-abc123",
      signerId: "signer-1",
      uuaid: signerAgent.uuaid,
      proof: proofPayload.proof,
      credential: undefined,
      senderUuaid: signerAgent.uuaid,
      pillarEnvelopeId: proofEnvelope.id,
    });
    expect(kindCountsSeen.length).toBeGreaterThan(0);
    expect(kindCountsSeen[0]).toEqual({ "esig:sealed": 1, "esig:identity-proof": 1 });

    // Replay: roll the persisted cursor back to 0 (simulating a
    // carrier/at-least-once redelivery of both rows) while KEEPING the
    // persisted seen-envelope-id set, then poll again with a fresh source
    // instance pointed at the same `home`. Both envelopes are refetched
    // (kind counts show it), but the identity-proof one is dropped by the
    // replay guard specifically — proving the guard, not the cursor, is
    // what's doing the work.
    const statePath = path.join(proofsHome, "esig-proofs.json");
    const persisted = JSON.parse(readFileSync(statePath, "utf-8")) as { since: number; seenEnvelopeIds: Record<string, number> };
    expect(Object.keys(persisted.seenEnvelopeIds)).toEqual([proofEnvelope.id]);
    expect(typeof persisted.seenEnvelopeIds[proofEnvelope.id]).toBe("number");
    writeFileSync(statePath, JSON.stringify({ since: 0, seenEnvelopeIds: persisted.seenEnvelopeIds }));

    const receivedAfterReplay: IdentityProofEvent[] = [];
    const replayKindCounts: Record<string, number>[] = [];
    const reloadedSource = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home: proofsHome,
      waitS: 1,
      onKindCounts: (c) => replayKindCounts.push(c),
      isAllowedSender: (s) => s === signerAgent.uuaid,
    });
    await reloadedSource.pollOnce((evt) => receivedAfterReplay.push(evt));

    expect(replayKindCounts[0]).toEqual({ "esig:sealed": 1, "esig:identity-proof": 1 });
    expect(receivedAfterReplay).toHaveLength(0);
  });
});

describe("PillarProofSource: RT-2026-08-28-01 F5/G3 listener hardening (a-e; (f) is examples/pillar-agent/test.mjs)", () => {
  let stub: StubCarrier;

  afterEach(async () => {
    await stub?.close();
  });

  function buildProofPayload(
    signerAgent: PillarIdentity,
    overrides: { envelopeId?: string; expiresAt?: string } = {}
  ): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      v: 1,
      envelopeId: overrides.envelopeId ?? "env-hardening-001",
      signerId: "signer-1",
      uuaid: signerAgent.uuaid,
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      proof: {
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        created: new Date().toISOString(),
        verificationMethod: `did:key:z6MkFAKEFAKEFAKE#sk-1`,
        proofPurpose: "authentication",
        proofValue: "zFAKESIGNATUREVALUE",
      },
    };
    if (overrides.expiresAt !== undefined) payload.expiresAt = overrides.expiresAt;
    return payload;
  }

  async function sealAndDeliver(
    pillar: Awaited<ReturnType<typeof loadPillar>>,
    signerAgent: PillarIdentity,
    operator: PillarIdentity,
    baseUrl: string,
    payload: Record<string, unknown>
  ) {
    const envelope = pillar.envelope.seal(signerAgent._keychain(), {
      recipient: operator.uuaid,
      recipientPublicKey: operator.publicKeyHex,
      kind: "esig:identity-proof",
      payload,
    });
    const deliverer = await CarrierClient.open({ identity: signerAgent, carriers: [baseUrl] });
    await deliverer.deliver(envelope);
    return envelope;
  }

  it("(a) default deny: with no isAllowedSender configured, a well-formed proof from any sender is dropped", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const operator = await freshIdentity("f5a-default-deny-operator");
    const signerAgent = await freshIdentity("f5a-default-deny-signer");
    const home = mkdtempSync(path.join(tmpdir(), "f5a-default-deny-"));

    const source = await PillarProofSource.open({ identity: operator, carriers: [baseUrl], home, waitS: 1 });
    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, buildProofPayload(signerAgent));

    const received: IdentityProofEvent[] = [];
    await source.pollOnce((evt) => received.push(evt));
    expect(received).toHaveLength(0);
  });

  it("(a) an isAllowedSender that returns false for this sender drops the proof", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const operator = await freshIdentity("f5a-explicit-deny-operator");
    const signerAgent = await freshIdentity("f5a-explicit-deny-signer");
    const home = mkdtempSync(path.join(tmpdir(), "f5a-explicit-deny-"));

    const source = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home,
      waitS: 1,
      isAllowedSender: () => false,
    });
    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, buildProofPayload(signerAgent));

    const received: IdentityProofEvent[] = [];
    await source.pollOnce((evt) => received.push(evt));
    expect(received).toHaveLength(0);
  });

  it("(b) per-sender rate cap drops envelopes beyond the configured per-minute budget", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const operator = await freshIdentity("f5b-operator");
    const signerAgent = await freshIdentity("f5b-signer");
    const home = mkdtempSync(path.join(tmpdir(), "f5b-proofs-"));

    const source = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home,
      waitS: 1,
      isAllowedSender: (s) => s === signerAgent.uuaid,
      maxEnvelopesPerSenderPerMinute: 1,
    });

    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, buildProofPayload(signerAgent, { envelopeId: "env-rate-1" }));
    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, buildProofPayload(signerAgent, { envelopeId: "env-rate-2" }));

    const received: IdentityProofEvent[] = [];
    await source.pollOnce((evt) => received.push(evt));
    // Both envelopes are fetched in the same batch; the cap of 1/min admits
    // only the first — proving the cap counts ACCEPTED envelopes within the
    // window, not just "did we see more than one at all".
    expect(received).toHaveLength(1);
    expect(received[0].envelopeId).toBe("env-rate-1");
  });

  it("(c) pre-decrypt size cap drops an oversized envelope before open() is ever called", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const operator = await freshIdentity("f5c-operator");
    const signerAgent = await freshIdentity("f5c-signer");
    const home = mkdtempSync(path.join(tmpdir(), "f5c-proofs-"));

    const source = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home,
      waitS: 1,
      isAllowedSender: (s) => s === signerAgent.uuaid,
      maxEnvelopeBytes: 10, // every real sealed envelope is far bigger than 10 bytes
    });

    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, buildProofPayload(signerAgent));

    const received: IdentityProofEvent[] = [];
    await source.pollOnce((evt) => received.push(evt));
    expect(received).toHaveLength(0);
  });

  it("(d) seen-set entries older than 14 days are pruned from persisted state on the next accepted proof", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const operator = await freshIdentity("f5d-operator");
    const signerAgent = await freshIdentity("f5d-signer");
    const home = mkdtempSync(path.join(tmpdir(), "f5d-proofs-"));
    const statePath = path.join(home, "esig-proofs.json");

    const FOURTEEN_DAYS_MS = 14 * 24 * 60 * 60 * 1000;
    const staleId = "stale-envelope-id-from-15-days-ago";
    const freshId = "fresh-envelope-id-from-1-hour-ago";
    writeFileSync(
      statePath,
      JSON.stringify({
        since: 0,
        seenEnvelopeIds: {
          [staleId]: Date.now() - FOURTEEN_DAYS_MS - 24 * 60 * 60 * 1000, // 15 days old
          [freshId]: Date.now() - 60 * 60 * 1000, // 1 hour old
        },
      })
    );

    const source = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home,
      waitS: 1,
      isAllowedSender: (s) => s === signerAgent.uuaid,
    });
    // Deliver + accept one fresh proof to trigger a state save (pruning runs on markSeen).
    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, buildProofPayload(signerAgent, { envelopeId: "env-prune-trigger" }));
    await source.pollOnce(() => {});

    const persisted = JSON.parse(readFileSync(statePath, "utf-8")) as { seenEnvelopeIds: Record<string, number> };
    expect(persisted.seenEnvelopeIds[staleId]).toBeUndefined();
    expect(typeof persisted.seenEnvelopeIds[freshId]).toBe("number");
  });

  it("(e) requires expiresAt on the proof payload, and refuses one that has already expired", async () => {
    const pillar = await loadPillar();
    stub = new StubCarrier(pillar);
    const baseUrl = await stub.listen();
    const operator = await freshIdentity("f5e-operator");
    const signerAgent = await freshIdentity("f5e-signer");
    const home = mkdtempSync(path.join(tmpdir(), "f5e-proofs-"));

    const source = await PillarProofSource.open({
      identity: operator,
      carriers: [baseUrl],
      home,
      waitS: 1,
      isAllowedSender: (s) => s === signerAgent.uuaid,
    });

    const missingExpiry = buildProofPayload(signerAgent, { envelopeId: "env-e-missing" });
    delete missingExpiry.expiresAt;
    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, missingExpiry);

    const expired = buildProofPayload(signerAgent, {
      envelopeId: "env-e-expired",
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    await sealAndDeliver(pillar, signerAgent, operator, baseUrl, expired);

    const received: IdentityProofEvent[] = [];
    await source.pollOnce((evt) => received.push(evt));
    expect(received).toHaveLength(0);
  });
});

function signedInboxHeaders(
  pillar: Awaited<ReturnType<typeof loadPillar>>,
  identity: PillarIdentity,
  since: number
): Record<string, string> {
  const path = `GET /v1/inbox/${identity.uuaid}?since=${since}`;
  const ts = String(Date.now());
  const sig = identity.sign(Buffer.from(`${path}\n${ts}`, "utf-8")).toString("hex");
  return {
    "x-pillar-pubkey": identity.publicKeyHex,
    "x-pillar-ts": ts,
    "x-pillar-sig": sig,
  };
}
