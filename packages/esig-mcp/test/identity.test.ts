// identity.test.ts — signer identity via UUAID + IAASO
// (docs/architecture/esig-mcp.md §12, build ticket item 7). Through the real
// MCP client + HTTP against the real approval endpoint for the primary
// flows (a happy L1 signature, forged proofs, L2 against a local stub
// registry, the MCP tool surface); direct `EnvelopeService`/
// `verifySignerIdentity` calls (the SAME code http.ts itself calls) for the
// cases that need precise clock/state control a raw HTTP round trip can't
// give cleanly (nonce replay, cross-envelope reuse, expiry).

import { createHash, generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import http from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { encodeMultibase, jcsBytes, type DataIntegrityProof, type UaidSigningCredential } from "@e-sig/uaid-exch";
import { FsAuditLogStore } from "@e-sig/core/fs";

import {
  createMcpServer,
  createApprovalServer,
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  IdentityError,
  loadConfig,
  ConfigError,
  RegistryClient,
  verifySignerIdentity,
  type IdentityProofInput,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

// ---------- test wallet: a real Ed25519 keypair + eddsa-jcs-2022 signer ----------

function makeTestWallet() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // SPKI DER for Ed25519 is a fixed 12-byte prefix + the 32 raw key bytes
  // (RFC 8410) — same fact @e-sig/uaid-exch's verify.ts relies on.
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublic = spki.subarray(spki.length - 32);
  const multicodecPrefixed = Buffer.concat([Buffer.from([0xed, 0x01]), rawPublic]);
  const did = `did:key:${encodeMultibase(multicodecPrefixed, "z")}`;
  const verificationMethod = `${did}#${did.slice("did:key:".length)}`;

  function sign(document: object, proofPurpose: DataIntegrityProof["proofPurpose"] = "authentication"): DataIntegrityProof {
    const signature = ed25519Sign(null, jcsBytes(document), privateKey);
    return {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      created: new Date().toISOString(),
      verificationMethod,
      proofPurpose,
      proofValue: encodeMultibase(signature, "z"),
    };
  }

  return { did, verificationMethod, rawPublic, sign };
}

// v0.5 (§17 seam 1, L1p): deliberately NOT a `uuaid:foundation:agent:` uuaid —
// this file's whole L0/L1/L2 suite predates L1p and never claims a
// self-authenticating identity (the test wallet's key has no relationship to
// this literal string), so a foundation:agent-shaped placeholder would now
// trip the new opportunistic L1p derivation check (`L1P_KEY_UUAID_MISMATCH`,
// identity/verify.ts) on every one of these tests. The federated-profile
// form (`uuaid:<subjectClass>:<jurisdiction>:<authority>:<localId>`, still
// well-formed per core's `isWellFormedUuaidAssertion`) sidesteps that
// entirely, leaving every assertion below (`level: "L1"`, etc.) unchanged.
// L1p's own dedicated coverage lives in test/l1p.test.ts.
const TEST_UUAID = "uuaid:person:us:ca:11111111-1111-1111-1111-111111111111";

async function connectedClient(mcpServer: McpServer): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

async function buildHarness(overrides: Parameters<typeof makeConfig>[0] = {}) {
  const config = await makeConfig(overrides);
  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new CapturingDelivery();
  const envelopes = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });
  const deps: McpServerDeps = {
    config,
    envelopes,
    documents,
    certStore: stores.certStore,
    pqKeyStore: stores.pqKeyStore,
    auditStore: stores.auditStore,
  };
  return { config, stores, envelopes, documents, delivery, deps, mcpServer: createMcpServer(deps) };
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

// A minimal local node:http stub for the L2 registry surface (§12
// "Bindings": GET /iaaso/v1/badge/{uuaid} — the registry-signed badge, the
// ONLY registry surface carrying an agent's presentation key — and
// GET /verify/{credentialId}).
function startRegistryStub(opts: {
  badgeBody?: unknown;
  badgeStatus?: number;
  verifyBody?: unknown;
}): Promise<{ server: http.Server; base: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/iaaso/v1/badge/")) {
        res.writeHead(opts.badgeStatus ?? 200);
        res.end(JSON.stringify(opts.badgeBody ?? {}));
        return;
      }
      if (req.url?.startsWith("/verify/")) {
        res.writeHead(200);
        res.end(JSON.stringify(opts.verifyBody ?? {}));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

async function closeStub(stub: { server: http.Server }): Promise<void> {
  await new Promise<void>((resolve) => stub.server.close(() => resolve()));
}

// ---------- test registry key + badge sealer (uuaid-core wire format) ----------
//
// Badge = SignatureEnvelope { payload, payloadHash: "0x"+sha256hex(JCS(payload)),
// signatures: [{alg:"ed25519", keyId, publicKey: hex, signature: hex, created}] },
// Ed25519 over UTF8(JCS(payload)) — see identity/badge.ts's module header.

const REGISTRY_KEY = (() => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return { publicKeyHex: Buffer.from(spki.subarray(spki.length - 32)).toString("hex"), privateKey };
})();
/** The PINNED key as config carries it: 64 lowercase hex. */
const PINNED_KEY_HEX = REGISTRY_KEY.publicKeyHex;

function sealBadgeEnvelope(payload: object, signer = REGISTRY_KEY, keyId = "uuaid-registry-1") {
  const payloadHash = "0x" + createHash("sha256").update(jcsBytes(payload)).digest("hex");
  const signature = ed25519Sign(null, jcsBytes(payload), signer.privateKey).toString("hex");
  return {
    payload,
    payloadHash,
    signatures: [{ alg: "ed25519", keyId, publicKey: signer.publicKeyHex, signature, created: new Date().toISOString() }],
  };
}

function makeBadgeEnvelope(presentationKey: unknown, payloadOverrides: Record<string, unknown> = {}) {
  return sealBadgeEnvelope({
    "@type": "UUAIDVerifiableBadge",
    spec: "IAASO-0003",
    v: "1.0",
    subject: { uuaid: TEST_UUAID, nameVerified: false, presentationKey },
    status: "active",
    credentials: [],
    issuer: { id: "uuaid-registry", name: "UUAID Registry", keyId: "uuaid-registry-1" },
    issuedAt: new Date().toISOString(),
    freshUntil: new Date(Date.now() + 60_000).toISOString(),
    resolve: `https://registry.example/iaaso/v1/resolve/${TEST_UUAID}`,
    ...payloadOverrides,
  });
}

describe("(a) L0 — asserted uuaid, pin match/mismatch", () => {
  it("pin match passes, mismatch -> 403 + signer.identity_rejected audit", async () => {
    const harness = await buildHarness();
    const { config, envelopes, delivery, stores } = harness;
    const { base, server } = await startHttp(config, envelopes);

    const created = await envelopes.create({
      title: "L0 pin test",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L0", signers: [{ index: 0, uuaid: TEST_UUAID }] },
    });
    expect(created.identityPolicy?.minLevel).toBe("L0");
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    // Mismatch first (the SAME token, an unused nonce — L0 does not consume one).
    const mismatch = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signatureImageDataUrl: PNG_DATA_URL,
        consent: true,
        identityProof: { uuaid: "uuaid:foundation:agent:22222222-2222-2222-2222-222222222222" },
      }),
    });
    expect(mismatch.status).toBe(403);
    const mismatchBody = (await mismatch.json()) as { error: string; reason: string };
    expect(mismatchBody.reason).toBe("L0_UUAID_MISMATCH");

    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    expect(auditRows.some((r) => r.action === "signer.identity_rejected" && (r.metadata as any)?.reason === "L0_UUAID_MISMATCH")).toBe(true);

    // Now the correct pin — passes, signature recorded.
    const ok = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true, identityProof: { uuaid: TEST_UUAID } }),
    });
    expect(ok.status).toBe(200);
    expect(auditRows.length).toBeGreaterThan(0); // sanity: sweep wasn't vacuous

    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity).toEqual({ level: "L0", uuaid: TEST_UUAID, verifiedAt: expect.any(String) });

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("(b) L1 — happy path through a real MCP client + HTTP", () => {
  it("wallet proof over the issued challenge -> signature recorded, identity_verified audit, status/outbox/composed HTML all show it", async () => {
    const harness = await buildHarness({ pq: true });
    const { config, envelopes, delivery, mcpServer, stores } = harness;
    const client = await connectedClient(mcpServer);
    const { base, server } = await startHttp(config, envelopes);
    const wallet = makeTestWallet();

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "L1 happy path",
        html: "<p>Consulting terms.</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        identity: { minLevel: "L1" },
      },
    });
    expect(created.isError).not.toBe(true);
    const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;
    const signerId = (created.structuredContent as Record<string, any>).signers[0].signerId as string;
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    // Same challenge via the MCP tool (esig_identity_challenge).
    const challengeResult = await client.callTool({
      name: "esig_identity_challenge",
      arguments: { envelopeId, signerId },
    });
    expect(challengeResult.isError).not.toBe(true);
    const challenge = challengeResult.structuredContent as Record<string, any>;
    expect(challenge.type).toBe("esig-signer-challenge/v1");

    const proof = wallet.sign(challenge);
    const identityProof: IdentityProofInput = { uuaid: TEST_UUAID, proof };

    const signRes = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true, identityProof }),
    });
    expect(signRes.status).toBe(200);
    const signBody = (await signRes.json()) as { completed: boolean; sealedPdf?: string };
    expect(signBody.completed).toBe(true);

    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    const verifiedRow = auditRows.find((r) => r.action === "signer.identity_verified");
    expect(verifiedRow).toBeTruthy();
    expect((verifiedRow!.metadata as any).level).toBe("L1");

    const status = await client.callTool({ name: "esig_envelope_status", arguments: { envelopeId } });
    const statusInfo = status.structuredContent as Record<string, any>;
    expect(statusInfo.signers[0].identity.level).toBe("L1");
    expect(statusInfo.signers[0].identity.uuaid).toBe(TEST_UUAID);
    expect(statusInfo.signers[0].identity.keyFingerprint).toBeTruthy();

    await new Promise<void>((resolve) => server.close(() => resolve()));
    await client.close();
  });

  it("file-outbox receipt includes the identity requirement, and composed (sealed) HTML contains the identity attestation line", async () => {
    const { FileDelivery } = await import("../dist/index.js");
    const config = await makeConfig({ pq: false });
    const stores = buildStores(config);
    const delivery = new (FileDelivery as any)(config.dataDir);
    let composedHtmlSeen = "";
    const envelopes = new EnvelopeService({
      config,
      ...stores,
      delivery,
      render: async (html: string) => {
        composedHtmlSeen = html;
        return SAMPLE_PDF;
      },
    });
    const wallet = makeTestWallet();

    const created = await envelopes.create({
      title: "Outbox + composed HTML test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1", signers: [{ index: 0, uuaid: TEST_UUAID }] },
    });

    const outboxFile = join(config.dataDir, "outbox", `${created.envelopeId}.json`);
    const receipt = JSON.parse(readFileSync(outboxFile, "utf8"));
    expect(receipt.signers[0].identity).toEqual({ minLevel: "L1", expectedUuaid: TEST_UUAID });

    const token = tokenFromLink(receipt.signers[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const afterSign = await envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof });
    expect(afterSign.status).toBe("completed");
    expect(composedHtmlSeen).toContain("Identity attestations");
    expect(composedHtmlSeen).toContain(TEST_UUAID);
    expect(composedHtmlSeen).toContain("L1");
  });
});

describe("(c) forged proof (different key) -> 403", () => {
  it("a proof signed with a DIFFERENT key than the wallet's own is rejected", async () => {
    const harness = await buildHarness();
    const { config, envelopes, delivery } = harness;
    const { base, server } = await startHttp(config, envelopes);
    const realWallet = makeTestWallet();
    const attackerWallet = makeTestWallet();

    const created = await envelopes.create({
      title: "Forged proof test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);

    // Signed by the attacker's key but CLAIMS the real wallet's verificationMethod.
    const forgedProof = attackerWallet.sign(challenge);
    forgedProof.verificationMethod = realWallet.verificationMethod;

    const res = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true, identityProof: { uuaid: TEST_UUAID, proof: forgedProof } }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { reason: string };
    expect(body.reason).toBe("L1_PROOF_INVALID");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("(d) replay: the same proof/nonce presented twice -> second attempt fails with nonce-consumed", () => {
  it("verifySignerIdentity twice with the same challenge: first ok, second L1_NONCE_CONSUMED", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF });
    const wallet = makeTestWallet();

    const created = await envelopes.create({
      title: "Replay test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const signerId = created.signers[0].signerId;
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, signerId);
    const proof = wallet.sign(challenge);
    const identityProof: IdentityProofInput = { uuaid: TEST_UUAID, proof };

    const first = await verifySignerIdentity({
      store: stores.envelopeStore,
      tenantId: config.tenant,
      envelopeId: created.envelopeId,
      signerId,
      minLevel: "L1",
      proof: identityProof,
    });
    expect(first?.level).toBe("L1");

    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        signerId,
        minLevel: "L1",
        proof: identityProof,
      }),
    ).rejects.toMatchObject({ reason: "L1_NONCE_CONSUMED" });
  });
});

describe("(e) cross-envelope: a proof over envelope A's challenge presented against envelope B -> rejected", () => {
  it("fails signature verification (the reconstructed document uses B's own nonce)", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF });
    const wallet = makeTestWallet();

    const a = await envelopes.create({
      title: "Envelope A",
      html: "<p>A</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const b = await envelopes.create({
      title: "Envelope B",
      html: "<p>B</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });

    const challengeA = await envelopes.issueIdentityChallenge(a.envelopeId, a.signers[0].signerId);
    // Envelope B needs its OWN issued challenge for the "no challenge" guard
    // not to fire first — the point being tested is that B's stored nonce
    // does not match what was actually signed (A's), not that B never had one.
    await envelopes.issueIdentityChallenge(b.envelopeId, b.signers[0].signerId);

    const proofOverA = wallet.sign(challengeA);

    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: b.envelopeId,
        signerId: b.signers[0].signerId,
        minLevel: "L1",
        proof: { uuaid: TEST_UUAID, proof: proofOverA },
      }),
    ).rejects.toMatchObject({ reason: "L1_PROOF_INVALID" });
  });
});

describe("(f) expired challenge -> 403", () => {
  it("a proof presented after the challenge's expiresAt is rejected", async () => {
    const config = await makeConfig({ identityChallengeTtlSec: 1 });
    const stores = buildStores(config);
    const t0 = new Date("2026-01-01T00:00:00.000Z");
    const issuer = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF, now: () => t0 });
    const wallet = makeTestWallet();

    const created = await issuer.create({
      title: "Expiry test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const challenge = await issuer.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const tLate = new Date(t0.getTime() + 5000); // 5s past the 1s TTL
    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        signerId: created.signers[0].signerId,
        minLevel: "L1",
        proof: { uuaid: TEST_UUAID, proof },
        now: () => tLate,
      }),
    ).rejects.toMatchObject({ reason: "L1_CHALLENGE_EXPIRED" });
  });
});

describe("(g) minLevel raise-only: config floor L1 + request L0 -> effective L1", () => {
  it("create() resolves the effective level to the STRONGER of the two, never the weaker", async () => {
    const config = await makeConfig({ identityMinLevel: "L1" });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    const created = await envelopes.create({
      title: "Raise-only test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L0" }, // requests something WEAKER than the floor
    });
    expect(created.identityPolicy?.minLevel).toBe("L1");
  });

  it("an envelope REQUESTING L2 with no registry configured refuses at CREATE time (fail closed), even though the server-wide floor is \"none\"", async () => {
    const config = await makeConfig(); // identityMinLevel defaults to "none", no uuaidRegistryUrl
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    await expect(
      envelopes.create({
        title: "L2 without registry",
        html: "<p>body</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        identity: { minLevel: "L2" },
      }),
    ).rejects.toThrow(/ESIG_MCP_UUAID_REGISTRY_URL/);
  });

  it("an envelope REQUESTING L2 with a registry URL but NO pinned signing key refuses at CREATE time (fail closed)", async () => {
    const config = await makeConfig({ uuaidRegistryUrl: "https://registry.example" }); // no uuaidRegistrySigningKey
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    await expect(
      envelopes.create({
        title: "L2 without pinned key",
        html: "<p>body</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        identity: { minLevel: "L2" },
      }),
    ).rejects.toThrow(/ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY/);
  });
});

// Shared L2 fixture: stub registry + config + envelope + one issued challenge
// signed by the fixture's test wallet. `run()` invokes the REAL verifier (the
// same function EnvelopeService.sign calls); every rejection below asserts the
// IdentityError `reason`. By default the stub serves a badge SEALED BY THE
// PINNED KEY attesting the wallet's own key — each test tweaks one thing.
async function l2Fixture(opts: {
  /** presentationKey placed in the badge; `null` = bearer badge. Default: the proof wallet's own key. */
  presentationKey?: unknown;
  /** Badge payload overrides (status, freshUntil, …) applied BEFORE sealing. */
  payloadOverrides?: Record<string, unknown>;
  /** Seal with a NON-pinned key to simulate a badge that signed itself. */
  sealWith?: { publicKeyHex: string; privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"] };
  /** Serve this instead of a normally-sealed badge (tamper tests). */
  badgeBody?: unknown;
  badgeStatus?: number;
  verifyBody?: unknown;
  withCredential?: boolean;
  registryKeyHex?: string;
  /** The uuaid presented in `identityProof.uuaid` — default TEST_UUAID (equal to the badge's own `subject.uuaid` unless `payloadOverrides.subject` says otherwise). */
  proofUuaid?: string;
}) {
  const wallet = makeTestWallet();
  // G1(b): credentialSubject.key.publicKey MUST equal the proof's own key
  // (the real tae/v1 schema field, schema.json:80-89) — `wallet.did` is a
  // `did:key:` string decoding to the SAME raw bytes as the proof's
  // `verificationMethod` (which additionally carries a `#fragment`).
  const credential = {
    id: "uuaid:foundation:signing-credential:test-cred-1",
    credentialSubject: { key: { keyId: "test-key-1", publicKey: wallet.did } },
  } as unknown as UaidSigningCredential;
  const badgeBody =
    opts.badgeBody ??
    sealBadgeEnvelope(
      {
        "@type": "UUAIDVerifiableBadge",
        spec: "IAASO-0003",
        v: "1.0",
        subject: {
          uuaid: TEST_UUAID,
          nameVerified: false,
          // Deliberate `in` check, not `??`: `presentationKey: null` (a bearer
          // badge) must survive as null.
          presentationKey: "presentationKey" in opts ? opts.presentationKey : { alg: "ed25519", publicKey: wallet.rawPublic.toString("hex"), keyId: "wallet-key" },
        },
        status: "active",
        credentials: [],
        issuer: { id: "uuaid-registry", name: "UUAID Registry", keyId: "uuaid-registry-1" },
        issuedAt: new Date().toISOString(),
        freshUntil: new Date(Date.now() + 60_000).toISOString(),
        resolve: `https://registry.example/iaaso/v1/resolve/${TEST_UUAID}`,
        ...opts.payloadOverrides,
      },
      opts.sealWith ?? REGISTRY_KEY,
    );
  const stub = await startRegistryStub({ badgeBody, badgeStatus: opts.badgeStatus, verifyBody: opts.verifyBody });
  const registryKeyHex = opts.registryKeyHex ?? PINNED_KEY_HEX;
  const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: registryKeyHex });
  const stores = buildStores(config);
  const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF });

  const created = await envelopes.create({
    title: "L2 test",
    html: "<p>body</p>",
    signers: [{ name: "Alice", email: "alice@example.com" }],
    identity: { minLevel: "L2" },
  });
  const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
  const proof = wallet.sign(challenge);

  const run = () =>
    verifySignerIdentity({
      store: stores.envelopeStore,
      tenantId: config.tenant,
      envelopeId: created.envelopeId,
      signerId: created.signers[0].signerId,
      minLevel: "L2",
      proof: { uuaid: opts.proofUuaid ?? TEST_UUAID, proof, ...(opts.withCredential ? { credential } : {}) },
      registry: new RegistryClient(stub.base),
      registrySigningKey: registryKeyHex,
    });
  return { wallet, credential, stub, config, stores, envelopes, created, run };
}

describe("(h) L2 — local node:http stub registry (registry-signed badge)", () => {
  it("badge signed by the pinned key attests the proof's key + credential verifies (matching agent_uuaid) -> L2 verified", async () => {
    const fixture = await l2Fixture({
      verifyBody: {
        credential_id: "uuaid:foundation:signing-credential:test-cred-1",
        agent_uuaid: TEST_UUAID,
        valid: true,
        active: true,
        notExpired: true,
      },
      withCredential: true,
    });
    const record = await fixture.run();
    expect(record?.level).toBe("L2");
    expect(record?.registry?.credentialId).toBe("uuaid:foundation:signing-credential:test-cred-1");
    expect(record?.registry?.credentialValid).toBe(true);
    // R1: digests are always computed (even with no blobStore wired in this
    // direct call) — proofDigest already existed; credentialDigest and
    // registrySnapshotDigest are new.
    expect(record?.proofDigest).toBeTruthy();
    expect(record?.credentialDigest).toBeTruthy();
    expect(record?.registry?.registrySnapshotDigest).toBeTruthy();

    await closeStub(fixture.stub);
  });

  it("badge presentationKey null (no key bound — the registry's current norm: n=2 sampled, both null) -> L2_KEY_NOT_BOUND", async () => {
    const fixture = await l2Fixture({ presentationKey: null });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_KEY_NOT_BOUND" });
    await closeStub(fixture.stub);
  });

  it("badge attests a DIFFERENT key than the proof's -> L2_KEY_MISMATCH", async () => {
    const fixture = await l2Fixture({
      presentationKey: { alg: "ed25519", publicKey: REGISTRY_KEY.publicKeyHex, keyId: "other-pk" },
    });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_KEY_MISMATCH" });
    await closeStub(fixture.stub);
  });

  it("registry-signed badge for a DIFFERENT uuaid B, whose presentationKey happens to equal the proof's own key, presented for uuaid A -> 403 L2_BADGE_SUBJECT_MISMATCH, no identity record", async () => {
    // Not foundation:agent form (see TEST_UUAID's own comment above) — this
    // test is about L2_BADGE_SUBJECT_MISMATCH specifically, not L1p.
    const UUAID_A = "uuaid:person:us:ca:33333333-3333-3333-3333-333333333333";
    // Badge's own subject.uuaid stays the fixture default (TEST_UUAID = "B"),
    // and its presentationKey stays the fixture default (the wallet's OWN
    // key — so the key check alone would pass); only the PROVING uuaid (A)
    // is different, which is exactly what the registry's blind pinned-key
    // check cannot catch on its own.
    const fixture = await l2Fixture({ proofUuaid: UUAID_A });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_BADGE_SUBJECT_MISMATCH" });
    const status = await fixture.envelopes.status(fixture.created.envelopeId);
    expect(status.signers[0].identity).toBeUndefined();
    await closeStub(fixture.stub);
  });

  it("badge status superseded (a retired agent still yields a VALID badge) -> L2_UUAID_NOT_ACTIVE", async () => {
    const fixture = await l2Fixture({
      payloadOverrides: { status: "superseded", statusReasonCode: "superseded-by-survivor" },
    });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_UUAID_NOT_ACTIVE" });
    await closeStub(fixture.stub);
  });

  it("badge 404 (absent, or tombstoned where /resolve would still 200) -> L2_UUAID_NOT_FOUND", async () => {
    const fixture = await l2Fixture({ badgeStatus: 404, badgeBody: { error: "tombstoned" } });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_UUAID_NOT_FOUND" });
    await closeStub(fixture.stub);
  });

  it("badge signed by a key OTHER than the pinned one (the badge carried its own signer key — only the pin decides) -> L2_BADGE_ISSUER_UNTRUSTED", async () => {
    const impostor = (() => {
      const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
      return { publicKeyHex: Buffer.from(spki.subarray(spki.length - 32)).toString("hex"), privateKey };
    })();
    const fixture = await l2Fixture({ sealWith: impostor });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_BADGE_ISSUER_UNTRUSTED" });
    await closeStub(fixture.stub);
  });

  it("tampered badge payload (pinned signature is over the ORIGINAL bytes) -> L2_BADGE_HASH_MISMATCH", async () => {
    const fixture = await l2Fixture({
      badgeBody: (() => {
        const envelope = makeBadgeEnvelope(null) as { payload: Record<string, unknown>; payloadHash: string; signatures: unknown[] };
        return { ...envelope, payload: { ...envelope.payload, issuer: { id: "evil", name: "Evil", keyId: "x" } } };
      })(),
    });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_BADGE_HASH_MISMATCH" });
    await closeStub(fixture.stub);
  });

  it("stale badge (freshUntil in the past) -> L2_BADGE_STALE", async () => {
    const fixture = await l2Fixture({
      payloadOverrides: { freshUntil: new Date(Date.now() - 60_000).toISOString() },
    });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_BADGE_STALE" });
    await closeStub(fixture.stub);
  });

  it("valid credential bound to a DIFFERENT uuaid (minted through a path that never checked the caller owns the handle) -> L2_CREDENTIAL_UUAID_MISMATCH", async () => {
    const fixture = await l2Fixture({
      // An ABSENT agent_uuaid fails the same assert (undefined !== proof.uuaid).
      verifyBody: { credential_id: "uuaid:foundation:signing-credential:test-cred-1", agent_uuaid: "uuaid:foundation:agent:99999999-9999-9999-9999-999999999999", valid: true, active: true, notExpired: true },
      withCredential: true,
    });
    await expect(fixture.run()).rejects.toMatchObject({ reason: "L2_CREDENTIAL_UUAID_MISMATCH" });
    await closeStub(fixture.stub);
  });

  it("registry down -> 403, and NO downgrade to L1 (no record persisted at all)", async () => {
    const wallet = makeTestWallet();
    const stub = await startRegistryStub({});
    const deadPort = (stub.server.address() as { port: number }).port;
    await closeStub(stub);
    // `deadPort` is now guaranteed unbound — nothing else in this test process races to claim it.
    const deadBase = `http://127.0.0.1:${deadPort}`;

    const config = await makeConfig({ uuaidRegistryUrl: deadBase, uuaidRegistrySigningKey: PINNED_KEY_HEX });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF });

    const created = await envelopes.create({
      title: "L2 down test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        signerId: created.signers[0].signerId,
        minLevel: "L2",
        proof: { uuaid: TEST_UUAID, proof },
        registry: new RegistryClient(deadBase),
        registrySigningKey: PINNED_KEY_HEX,
      }),
    ).rejects.toMatchObject({ reason: "L2_REGISTRY_UNAVAILABLE" });

    // Never downgrades: no partial/L1 record was left behind by the failed L2 attempt.
    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity).toBeUndefined();
  });

  it("http:// registry URL -> ConfigError", () => {
    expect(() =>
      loadConfig({
        ESIG_MCP_PASSPHRASE: "a".repeat(24),
        ESIG_MCP_DELIVERY: "file",
        ESIG_MCP_UUAID_REGISTRY_URL: "http://example.com",
      }),
    ).toThrow(ConfigError);
  });

  it('ESIG_MCP_IDENTITY_MIN_LEVEL="L2" with no registry URL -> ConfigError', () => {
    expect(() =>
      loadConfig({
        ESIG_MCP_PASSPHRASE: "a".repeat(24),
        ESIG_MCP_DELIVERY: "file",
        ESIG_MCP_IDENTITY_MIN_LEVEL: "L2",
      }),
    ).toThrow(ConfigError);
  });

  it('ESIG_MCP_IDENTITY_MIN_LEVEL="L2" with a registry URL but no signing key -> ConfigError', () => {
    expect(() =>
      loadConfig({
        ESIG_MCP_PASSPHRASE: "a".repeat(24),
        ESIG_MCP_DELIVERY: "file",
        ESIG_MCP_IDENTITY_MIN_LEVEL: "L2",
        ESIG_MCP_UUAID_REGISTRY_URL: "https://registry.example",
      }),
    ).toThrow(/ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY/);
  });

  it("a malformed signing key (not 64 hex chars) -> ConfigError", () => {
    expect(() =>
      loadConfig({
        ESIG_MCP_PASSPHRASE: "a".repeat(24),
        ESIG_MCP_DELIVERY: "file",
        ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY: "not-hex",
      }),
    ).toThrow(/64 hex/);
  });
});

describe("(i) toolError is JSON-first", () => {
  it("content[0] parses to {error}; content[1] is the same plain-text message", async () => {
    const harness = await buildHarness();
    const client = await connectedClient(harness.mcpServer);

    const result = await client.callTool({
      name: "esig_identity_challenge",
      arguments: { envelopeId: "does-not-exist", signerId: "does-not-exist" },
    });
    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content).toHaveLength(2);
    const parsed = JSON.parse(content[0].text);
    expect(parsed.error).toBe(content[1].text);
    expect(content[1].text).not.toMatch(/^\{/);

    await client.close();
  });
});

describe("(j) esig_identity_challenge (MCP) vs GET /sign/<token>/challenge (HTTP) — same target", () => {
  it("both name the same envelopeId/signerId/htmlSha256/type — and, since re-issue is idempotent within TTL (G5), the SAME live nonce too", async () => {
    const harness = await buildHarness();
    const { config, envelopes, delivery, mcpServer } = harness;
    const client = await connectedClient(mcpServer);
    const { base, server } = await startHttp(config, envelopes);

    const created = await envelopes.create({
      title: "j test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const signerId = created.signers[0].signerId;
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const mcpResult = await client.callTool({
      name: "esig_identity_challenge",
      arguments: { envelopeId: created.envelopeId, signerId },
    });
    const mcpChallenge = mcpResult.structuredContent as Record<string, any>;

    const httpRes = await fetch(`${base}/sign/${token}/challenge`);
    expect(httpRes.status).toBe(200);
    const httpChallenge = await httpRes.json();

    for (const field of ["type", "envelopeId", "signerId", "htmlSha256"]) {
      expect(httpChallenge[field]).toBe(mcpChallenge[field]);
    }
    // G5 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, LOW): re-issue is
    // now IDEMPOTENT within TTL — the second call (HTTP) returns the SAME
    // live, unconsumed challenge the first call (MCP) already issued, nonce
    // included, rather than rotating it out from under whoever holds it.
    expect(httpChallenge.nonce).toBe(mcpChallenge.nonce);
    expect(httpChallenge.issuedAt).toBe(mcpChallenge.issuedAt);
    expect(httpChallenge.expiresAt).toBe(mcpChallenge.expiresAt);

    await new Promise<void>((resolve) => server.close(() => resolve()));
    await client.close();
  });

  it("same gate states as GET /sign: not this signer's turn -> 409, unknown token -> 404", async () => {
    const harness = await buildHarness();
    const { config, envelopes, delivery } = harness;
    const { base, server } = await startHttp(config, envelopes);

    await envelopes.create({
      title: "gate states",
      html: "<p>body</p>",
      signers: [
        { name: "Alice", email: "alice@example.com", order: 1 },
        { name: "Bob", email: "bob@example.com", order: 2 },
      ],
      identity: { minLevel: "L1" },
    });
    const bobToken = tokenFromLink(delivery.calls[0].links.find((l) => l.name === "Bob")!.url);

    const notYourTurn = await fetch(`${base}/sign/${bobToken}/challenge`);
    expect(notYourTurn.status).toBe(409);

    const unknown = await fetch(`${base}/sign/not-a-real-token/challenge`);
    expect(unknown.status).toBe(404);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("(k) G2 — htmlSha256 anchoring: pinned base html, never composed/render html", () => {
  it("a signer's challenge always names the IMMUTABLE base-html digest pinned at creation, even after another signer has already signed (which would change composeEnvelopeHtml's output)", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });
    const wallet = makeTestWallet();

    const created = await envelopes.create({
      title: "G2 anchoring test",
      html: "<p>terms</p>",
      signers: [
        { name: "Alice", email: "alice@example.com", order: 1 },
        { name: "Bob", email: "bob@example.com", order: 2 },
      ],
      identity: { minLevel: "L1" },
    });

    const aliceChallenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const aliceProof = wallet.sign(aliceChallenge);
    const aliceToken = tokenFromLink(delivery.calls[0].links.find((l) => l.name === "Alice")!.url);
    await envelopes.sign(aliceToken, PNG_DATA_URL, { uuaid: TEST_UUAID, proof: aliceProof });

    // Bob's challenge, issued for the FIRST time only now — AFTER Alice's
    // signature is recorded on the envelope. If this were ever derived from
    // `composeEnvelopeHtml(envelope)` (which now includes Alice's signature
    // block) rather than the pinned `metadata.mcp.htmlSha256`, this would
    // differ from `created.htmlSha256`.
    const bobChallenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[1].signerId);
    expect(bobChallenge.htmlSha256).toBe(created.htmlSha256);
  });
});

describe("(l) G3 — registry URL pinned at creation; refuses if the server's current one differs", () => {
  it("create() pins identityPolicy.registryUrl to config.uuaidRegistryUrl when minLevel is L2", async () => {
    const stub = await startRegistryStub({});
    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: PINNED_KEY_HEX });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    const created = await envelopes.create({
      title: "G3 pin test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    expect(created.identityPolicy?.registryUrl).toBe(stub.base);

    await new Promise<void>((resolve) => stub.server.close(() => resolve()));
  });

  it("verifySignerIdentity refuses BEFORE any registry call when configuredRegistryUrl differs from the pinned one (L2_REGISTRY_URL_CHANGED)", async () => {
    const wallet = makeTestWallet();
    const stub = await startRegistryStub({ badgeBody: makeBadgeEnvelope({ alg: "ed25519", publicKey: wallet.rawPublic.toString("hex"), keyId: "test-pk" }) });
    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: PINNED_KEY_HEX });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF });

    const created = await envelopes.create({
      title: "G3 mismatch test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);
    const RegistryClientCtor = (await import("../dist/index.js")).RegistryClient;

    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        signerId: created.signers[0].signerId,
        minLevel: "L2",
        proof: { uuaid: TEST_UUAID, proof },
        registry: new RegistryClientCtor(stub.base),
        pinnedRegistryUrl: created.identityPolicy!.registryUrl,
        configuredRegistryUrl: "https://a-different-registry.example",
      }),
    ).rejects.toMatchObject({ reason: "L2_REGISTRY_URL_CHANGED" });

    // Never even partially verified: no record persisted (same T13-class discipline as a down registry).
    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity).toBeUndefined();

    await new Promise<void>((resolve) => stub.server.close(() => resolve()));
  });
});

describe("(m) G4 — identity verification sits structurally OUTSIDE seal()'s error-swallowing catch", () => {
  it("an injected identity verifier that THROWS (a plain Error, not IdentityError): signature never recorded, POST /sign never 2xx, no envelope.signed audit row", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const brokenVerifier: typeof verifySignerIdentity = async () => {
      throw new Error("simulated identity-verifier crash (not an IdentityError)");
    };
    const envelopes = new EnvelopeService({
      config,
      ...stores,
      delivery,
      render: async () => SAMPLE_PDF,
      verifySignerIdentity: brokenVerifier,
    });
    const { base, server } = await startHttp(config, envelopes);

    const created = await envelopes.create({
      title: "G4 test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    // No identityProof needed — the injected verifier throws unconditionally,
    // before it ever looks at its input.
    const res = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
    });
    expect(res.status).not.toBe(200);
    expect(res.status).not.toBe(202);
    expect([403, 500]).toContain(res.status);

    // The signature was never recorded — the envelope is still "sent".
    const status = await envelopes.status(created.envelopeId);
    expect(status.status).toBe("sent");
    expect(status.signers[0].signedAt).toBeUndefined();

    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    expect(auditRows.some((r) => r.action === "envelope.signed")).toBe(false);
    expect(auditRows.some((r) => r.action === "envelope.completed")).toBe(false);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("(n) R1 — identity artifacts persisted to blobs/identity/<digest>.json, never raw JSON in audit metadata", () => {
  it("the real EnvelopeService.sign() persists the proof JSON blob; the identity record's digest names that exact file", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });
    const wallet = makeTestWallet();

    const created = await envelopes.create({
      title: "R1 blob test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    await envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof });

    const status = await envelopes.status(created.envelopeId);
    const proofDigest = status.signers[0].identity!.proofDigest!;
    expect(proofDigest).toBeTruthy();

    const blobFile = join(config.dataDir, "blobs", "identity", `${proofDigest}.json`);
    expect(existsSync(blobFile)).toBe(true);
    const blobContent = JSON.parse(readFileSync(blobFile, "utf8"));
    expect(blobContent.proofValue).toBe(proof.proofValue);

    // R1: never the raw artifact in audit metadata — only digests/identifiers.
    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    const verifiedRow = auditRows.find((r) => r.action === "signer.identity_verified");
    expect(verifiedRow).toBeTruthy();
    expect(JSON.stringify(verifiedRow!.metadata)).not.toContain(proof.proofValue);
  });
});

describe("(o) R2 — outbox COMPLETION receipt on sealed / seal_failed (distinct from the creation receipt)", () => {
  it("sealed: <dataDir>/outbox/<envelopeId>.completed.json carries signers[].identity and sealedPdfUrl; the creation receipt is untouched", async () => {
    // FileDelivery (not CapturingDelivery) so the pre-existing CREATION
    // receipt (delivery.ts, unchanged by this ticket) is actually on disk to
    // compare against.
    const { FileDelivery } = await import("../dist/index.js");
    const config = await makeConfig({ pq: false });
    const stores = buildStores(config);
    const delivery = new (FileDelivery as any)(config.dataDir);
    const envelopes = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });
    const wallet = makeTestWallet();

    const created = await envelopes.create({
      title: "R2 sealed test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const creationFile = join(config.dataDir, "outbox", `${created.envelopeId}.json`);
    const creationReceipt = JSON.parse(readFileSync(creationFile, "utf8"));
    const token = tokenFromLink(creationReceipt.signers[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const result = await envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof });
    expect(result.phase).toBe("sealed");

    const completedFile = join(config.dataDir, "outbox", `${created.envelopeId}.completed.json`);
    const receipt = JSON.parse(readFileSync(completedFile, "utf8"));
    expect(receipt.status).toBe("sealed");
    expect(receipt.envelopeId).toBe(created.envelopeId);
    expect(receipt.signers[0].identity.level).toBe("L1");
    expect(receipt.signers[0].identity.uuaid).toBe(TEST_UUAID);
    expect(receipt.sealedPdfUrl).toBeTruthy();

    // The CREATION receipt is untouched — still there, unchanged shape.
    const creationReceiptAfter = JSON.parse(readFileSync(creationFile, "utf8"));
    expect(creationReceiptAfter.signers[0].url).toBeTruthy();
  });

  it("seal_failed: the completion receipt still writes, status seal_failed, no sealedPdfUrl", async () => {
    const config = await makeConfig({ pq: false });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({
      config,
      ...stores,
      delivery,
      render: async () => {
        throw new Error("simulated Chrome failure");
      },
    });

    const created = await envelopes.create({
      title: "R2 seal_failed test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const result = await envelopes.sign(token, PNG_DATA_URL);
    expect(result.phase).toBe("seal_failed");

    const completedFile = join(config.dataDir, "outbox", `${created.envelopeId}.completed.json`);
    const receipt = JSON.parse(readFileSync(completedFile, "utf8"));
    expect(receipt.status).toBe("seal_failed");
    expect(receipt.sealedPdfUrl).toBeUndefined();
    expect(receipt.error).toBeTruthy();
  });
});

describe("IdentityError sanity", () => {
  it("is a real Error subclass carrying reason/uuaid/level", () => {
    const e = new IdentityError("nope", "SOME_REASON", TEST_UUAID, "L1");
    expect(e).toBeInstanceOf(Error);
    expect(e.reason).toBe("SOME_REASON");
    expect(e.uuaid).toBe(TEST_UUAID);
    expect(e.level).toBe("L1");
  });
});

describe("(p) input validation — malformed uuaid rejected at the boundary, via the real MCP client + HTTP", () => {
  it("uuaid containing '<script>' and a control character -> 403 L0_MALFORMED_UUAID", async () => {
    const harness = await buildHarness();
    const { config, envelopes, delivery, mcpServer } = harness;
    const client = await connectedClient(mcpServer);
    const { base, server } = await startHttp(config, envelopes);

    // esig_create_envelope (real MCP tool call) — L0 needs no registry.
    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "Malformed uuaid test",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        identity: { minLevel: "L0" },
      },
    });
    expect(created.isError).not.toBe(true);
    const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    // POST /sign/<token> (real HTTP approval endpoint) with a uuaid carrying
    // both an HTML-special payload and a control character — well outside
    // isWellFormedUuaidAssertion's `[A-Za-z0-9_-]` charset (pq-seal.ts) —
    // must fail L0 well-formedness before anything else runs.
    const maliciousUuaid = "<script>alert(1)</script>\x07";
    const res = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        signatureImageDataUrl: PNG_DATA_URL,
        consent: true,
        identityProof: { uuaid: maliciousUuaid },
      }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string; reason: string };
    expect(body.reason).toBe("L0_MALFORMED_UUAID");

    // Rejected before recordSignature ever ran — no identity, no signature.
    const status = await envelopes.status(envelopeId);
    expect(status.signers[0].identity).toBeUndefined();
    expect(status.signers[0].signedAt).toBeFalsy();

    await new Promise<void>((resolve) => server.close(() => resolve()));
    await client.close();
  });
});

describe("(q) G7 — untrusted registry verifyCredential 'reason' text never reaches an unsafe sink", () => {
  it("rejected path: '<b>' in the registry's reason never appears in the signer.identity_rejected audit metadata", async () => {
    const wallet = makeTestWallet();
    const credential = {
      id: "uuaid:foundation:signing-credential:q-rejected",
      credentialSubject: { key: { keyId: "q-key-1", publicKey: wallet.did } },
    } as unknown as UaidSigningCredential;
    const badgeBody = makeBadgeEnvelope({ alg: "ed25519", publicKey: wallet.rawPublic.toString("hex"), keyId: "wallet-key" });
    const stub = await startRegistryStub({
      badgeBody,
      verifyBody: {
        credential_id: credential.id,
        agent_uuaid: TEST_UUAID,
        valid: false,
        active: false,
        notExpired: false,
        reason: "<b>revoked</b>",
      },
    });
    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: PINNED_KEY_HEX });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });

    const created = await envelopes.create({
      title: "Q rejected reason test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    await expect(
      envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof, credential }),
    ).rejects.toMatchObject({ reason: "L2_CREDENTIAL_INVALID" });

    // Only the machine-readable reason CODE (e.reason) is audited
    // (envelopes.ts's `signer.identity_rejected` insert) — never e.message,
    // which is where the registry's raw reason text lives.
    const auditRows = await (stores.auditStore as FsAuditLogStore).readAll();
    const rejectedRow = auditRows.find((r) => r.action === "signer.identity_rejected");
    expect(rejectedRow).toBeTruthy();
    expect(JSON.stringify(rejectedRow!.metadata)).not.toContain("<b>");

    await closeStub(stub);
  });

  it("accepted path: '<b>' in the registry's reason (present alongside an otherwise-valid credential) never appears in composed HTML", async () => {
    const wallet = makeTestWallet();
    const credential = {
      id: "uuaid:foundation:signing-credential:q-accepted",
      credentialSubject: { key: { keyId: "q-key-2", publicKey: wallet.did } },
    } as unknown as UaidSigningCredential;
    const badgeBody = makeBadgeEnvelope({ alg: "ed25519", publicKey: wallet.rawPublic.toString("hex"), keyId: "wallet-key" });
    const stub = await startRegistryStub({
      badgeBody,
      verifyBody: {
        credential_id: credential.id,
        agent_uuaid: TEST_UUAID,
        valid: true,
        active: true,
        notExpired: true,
        reason: "<b>informational</b>",
      },
    });
    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: PINNED_KEY_HEX });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    let composedHtmlSeen = "";
    const envelopes = new EnvelopeService({
      config,
      ...stores,
      delivery,
      render: async (html: string) => {
        composedHtmlSeen = html;
        return SAMPLE_PDF;
      },
    });

    const created = await envelopes.create({
      title: "Q accepted reason test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const result = await envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof, credential });
    expect(result.status).toBe("completed");

    // identity/verify.ts stores ONLY credentialId/credentialValid from a
    // successful registry credential check (verify.ts ~L543-544) — the
    // registry's `reason` text is never assigned onto the record at all
    // (G7's `assertSafeIdentityString` bound-and-scrub exists as
    // defense-in-depth for it regardless). `identityAttestationsHtml`
    // (envelopes.ts) composes only uuaid/level/keyFingerprint/verifiedAt,
    // each passed through `escapeHtml` — so composed HTML can carry the
    // registry's raw reason neither unescaped nor escaped: there is no path
    // for it to reach the rendered document at all.
    expect(composedHtmlSeen).not.toContain("<b>");
    expect(composedHtmlSeen).not.toContain("informational");

    await closeStub(stub);
  });
});

describe("(r) R1 — FULL L2 path through EnvelopeService.sign(): blobs/identity/ holds proof, credential, and registry-snapshot files, each named by its own sha256, matching the signer record's digests", () => {
  it("all three blob files exist, are content-addressed, and match record digests", async () => {
    const wallet = makeTestWallet();
    const credential = {
      id: "uuaid:foundation:signing-credential:r1-full-l2",
      credentialSubject: { key: { keyId: "r1-key", publicKey: wallet.did } },
    } as unknown as UaidSigningCredential;
    const badgeBody = makeBadgeEnvelope({ alg: "ed25519", publicKey: wallet.rawPublic.toString("hex"), keyId: "wallet-key" });
    const stub = await startRegistryStub({
      badgeBody,
      verifyBody: { credential_id: credential.id, agent_uuaid: TEST_UUAID, valid: true, active: true, notExpired: true },
    });

    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: PINNED_KEY_HEX });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });

    const created = await envelopes.create({
      title: "R1 full L2 blob test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const result = await envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof, credential });
    expect(result.status).toBe("completed");

    const status = await envelopes.status(created.envelopeId);
    const record = status.signers[0].identity!;
    expect(record.level).toBe("L2");
    expect(record.proofDigest).toBeTruthy();
    expect(record.credentialDigest).toBeTruthy();
    expect(record.registry?.registrySnapshotDigest).toBeTruthy();

    // Every digest names a real file under blobs/identity/, and that file's
    // OWN sha256 equals the name it is stored under (content-addressed).
    for (const digest of [record.proofDigest!, record.credentialDigest!, record.registry!.registrySnapshotDigest!]) {
      const blobFile = join(config.dataDir, "blobs", "identity", `${digest}.json`);
      expect(existsSync(blobFile)).toBe(true);
      const bytes = readFileSync(blobFile);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(digest);
    }

    // Content sanity: each file holds the artifact its name claims.
    const proofBlob = JSON.parse(readFileSync(join(config.dataDir, "blobs", "identity", `${record.proofDigest}.json`), "utf8"));
    expect(proofBlob.proofValue).toBe(proof.proofValue);
    const credentialBlob = JSON.parse(
      readFileSync(join(config.dataDir, "blobs", "identity", `${record.credentialDigest}.json`), "utf8"),
    );
    expect(credentialBlob.id).toBe(credential.id);
    const snapshotBlob = JSON.parse(
      readFileSync(join(config.dataDir, "blobs", "identity", `${record.registry!.registrySnapshotDigest}.json`), "utf8"),
    );
    expect(snapshotBlob.payload.subject.uuaid).toBe(TEST_UUAID);

    await closeStub(stub);
  });
});
