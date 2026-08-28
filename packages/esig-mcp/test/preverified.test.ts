// preverified.test.ts — §17 seam 3 "Identity proof over Pillar" (build
// ticket item 6): a fake `IdentityProofSource` emits real
// `IdentityProofEvent`s straight into `EnvelopeService.acceptPreVerifiedIdentity`
// (never through the real Pillar bridge — this file never imports
// "@e-sig/pillar-bridge"/"@uuaid/pillar"), then `POST /sign` (the real HTTP
// endpoint) is exercised WITHOUT `identityProof` to prove the human just
// signs. L1p derivation lives in test/l1p.test.ts; the delivery/events seams
// live in test/pillar-seams.test.ts.

import { generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";

import { encodeMultibase, jcsBytes, type DataIntegrityProof } from "@e-sig/uaid-exch";
import { FsAuditLogStore } from "@e-sig/core/fs";

import {
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  createApprovalServer,
  uuaidFromEd25519Key,
  type IdentityProofEvent,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

function makeSelfAuthenticatingWallet() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublic = spki.subarray(spki.length - 32);
  const multicodecPrefixed = Buffer.concat([Buffer.from([0xed, 0x01]), rawPublic]);
  const did = `did:key:${encodeMultibase(multicodecPrefixed, "z")}`;
  const verificationMethod = `${did}#${did.slice("did:key:".length)}`;
  const uuaid = uuaidFromEd25519Key(rawPublic);

  function sign(document: object): DataIntegrityProof {
    const signature = ed25519Sign(null, jcsBytes(document), privateKey);
    return {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      created: new Date().toISOString(),
      verificationMethod,
      proofPurpose: "authentication",
      proofValue: encodeMultibase(signature, "z"),
    };
  }

  return { uuaid, sign };
}

/**
 * A fake `IdentityProofSource` (§17 seam 3): `emit()` calls straight into
 * whatever `onProof` `start()` was given — the SAME shape a real
 * `PillarProofSource` would call, minus any Pillar transport at all.
 */
class FakeProofSource {
  private onProof?: (event: IdentityProofEvent) => void;
  start(onProof: (event: IdentityProofEvent) => void): void {
    this.onProof = onProof;
  }
  stop(): void {
    this.onProof = undefined;
  }
  emit(event: IdentityProofEvent): void {
    this.onProof?.(event);
  }
}

async function buildHarness(overrides: Parameters<typeof makeConfig>[0] = {}) {
  const config = await makeConfig(overrides);
  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new CapturingDelivery();
  const envelopes = new EnvelopeService({ config, ...stores, documents, delivery, render: async () => SAMPLE_PDF });
  return { config, stores, envelopes, delivery };
}

async function startHttp(config: Awaited<ReturnType<typeof makeConfig>>, envelopes: EnvelopeService) {
  const server = createApprovalServer({ config, envelopes });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, base: `http://127.0.0.1:${port}` };
}

describe("EnvelopeService.acceptPreVerifiedIdentity (§17 seam 3)", () => {
  it("a valid L1p proof over the REAL challenge, relayed by a fake proof source -> POST /sign succeeds WITHOUT identityProof, audits identity_preverified_used", async () => {
    const { config, envelopes, delivery, stores } = await buildHarness();
    const { base, server } = await startHttp(config, envelopes);
    const wallet = makeSelfAuthenticatingWallet();
    const proofSource = new FakeProofSource();
    proofSource.start((evt) => {
      void envelopes.acceptPreVerifiedIdentity(evt);
    });

    const created = await envelopes.create({
      title: "Pre-verified L1p",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const token = tokenFromLink(link.url);

    // The sender-side agent issues the challenge first (exactly as the
    // human-facing flow does) — the signer's own agent then signs it and
    // relays the proof back over Pillar. Here: relay it via the fake source.
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    proofSource.emit({
      envelopeId: created.envelopeId,
      signerId: link.signerId,
      uuaid: wallet.uuaid,
      proof,
      senderUuaid: wallet.uuaid,
      pillarEnvelopeId: "pillar-env-1",
    });
    // acceptPreVerifiedIdentity is async but fire-and-forget from onProof —
    // give its microtask/IO a moment to land before asserting.
    await new Promise((r) => setTimeout(r, 50));

    // The human just signs — NO identityProof in the POST body.
    const res = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { completed: boolean };
    expect(body.completed).toBe(true);

    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity?.level).toBe("L1p");
    expect(status.signers[0].identity?.uuaid).toBe(wallet.uuaid);

    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    expect(
      auditRows.some(
        (r) => r.action === "signer.identity_preverified_used" && (r.metadata as { uuaid?: string })?.uuaid === wallet.uuaid,
      ),
    ).toBe(true);
    // The verification itself was audited too (identical to the direct-proof path).
    expect(auditRows.some((r) => r.action === "signer.identity_verified")).toBe(true);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("an explicit identityProof presented anyway (redundant with an already-accepted pre-verified record) is IGNORED — the pre-verified path wins, no re-verification, no nonce conflict", async () => {
    const { config, envelopes, delivery } = await buildHarness();
    const { base, server } = await startHttp(config, envelopes);
    const wallet = makeSelfAuthenticatingWallet();

    const created = await envelopes.create({
      title: "Pre-verified wins over explicit",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const token = tokenFromLink(link.url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    await envelopes.acceptPreVerifiedIdentity({
      envelopeId: created.envelopeId,
      signerId: link.signerId,
      uuaid: wallet.uuaid,
      proof,
      senderUuaid: wallet.uuaid,
      pillarEnvelopeId: "pillar-env-2",
    });

    // The SAME (now-consumed) proof presented again explicitly would fail
    // re-verification (nonce already consumed) if it were re-checked — the
    // pre-verified branch must short-circuit BEFORE that ever happens.
    const res = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true, identityProof: { uuaid: wallet.uuaid, proof } }),
    });
    expect(res.status).toBe(200);
    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity?.level).toBe("L1p");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("a proof for a DIFFERENT envelope is refused (envelope not found under that policy) and never stored as verified", async () => {
    const { envelopes, delivery, stores } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();

    const created = await envelopes.create({
      title: "Envelope A",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const otherCreated = await envelopes.create({
      title: "Envelope B",
      html: "<p>terms</p>",
      signers: [{ name: "Bob", email: "bob@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const linkA = delivery.calls[0].links[0];
    const linkB = delivery.calls[1].links[0];

    // A challenge was issued for envelope A's signer, but the proof is
    // relayed claiming envelope B's id/signerId — a cross-envelope replay
    // attempt (T11 class).
    const challengeA = await envelopes.issueIdentityChallenge(created.envelopeId, linkA.signerId);
    const proof = wallet.sign(challengeA);

    const record = await envelopes.acceptPreVerifiedIdentity({
      envelopeId: otherCreated.envelopeId,
      signerId: linkB.signerId,
      uuaid: wallet.uuaid,
      proof,
      senderUuaid: wallet.uuaid,
      pillarEnvelopeId: "pillar-env-3",
    });
    expect(record).toBeUndefined();

    const statusB = await envelopes.status(otherCreated.envelopeId);
    expect(statusB.signers[0].identity).toBeUndefined();

    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    expect(auditRows.some((r) => r.action === "signer.identity_rejected")).toBe(true);
  });

  it("a proof over the WRONG nonce (no challenge issued for that signer yet) is refused and never stored", async () => {
    const { envelopes, delivery, stores } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();

    const created = await envelopes.create({
      title: "No challenge issued yet",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];

    // A forged/self-constructed challenge document — no real challenge was
    // ever issued for this signer, so `verifySignerIdentity` refuses
    // L1_NO_CHALLENGE (the nonce it names does not exist on the signer at
    // all).
    const forgedChallenge = {
      type: "esig-signer-challenge/v1",
      envelopeId: created.envelopeId,
      signerId: link.signerId,
      htmlSha256: "0".repeat(64),
      nonce: "forged-nonce",
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const proof = wallet.sign(forgedChallenge);

    const record = await envelopes.acceptPreVerifiedIdentity({
      envelopeId: created.envelopeId,
      signerId: link.signerId,
      uuaid: wallet.uuaid,
      proof,
      senderUuaid: wallet.uuaid,
      pillarEnvelopeId: "pillar-env-4",
    });
    expect(record).toBeUndefined();

    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity).toBeUndefined();

    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    const rejected = auditRows.find((r) => r.action === "signer.identity_rejected");
    expect(rejected).toBeTruthy();
    expect((rejected!.metadata as { reason?: string })?.reason).toBe("L1_NO_CHALLENGE");
  });

  it("returns undefined (never throws) for an unknown envelopeId", async () => {
    const { envelopes } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();
    const record = await envelopes.acceptPreVerifiedIdentity({
      envelopeId: "does-not-exist",
      signerId: "nope",
      uuaid: wallet.uuaid,
      proof: wallet.sign({ nonsense: true }),
      senderUuaid: wallet.uuaid,
      pillarEnvelopeId: "pillar-env-5",
    });
    expect(record).toBeUndefined();
  });

  it("returns undefined for an envelope with no identity requirement (minLevel none) — nothing to verify", async () => {
    const { envelopes, delivery } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();
    const created = await envelopes.create({
      title: "No identity required",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const link = delivery.calls[0].links[0];
    const record = await envelopes.acceptPreVerifiedIdentity({
      envelopeId: created.envelopeId,
      signerId: link.signerId,
      uuaid: wallet.uuaid,
      proof: wallet.sign({ nonsense: true }),
      senderUuaid: wallet.uuaid,
      pillarEnvelopeId: "pillar-env-6",
    });
    expect(record).toBeUndefined();
  });
});
