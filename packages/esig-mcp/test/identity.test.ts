// identity.test.ts — signer identity via UUAID + IAASO
// (docs/architecture/esig-mcp.md §12, build ticket item 7). Through the real
// MCP client + HTTP against the real approval endpoint for the primary
// flows (a happy L1 signature, forged proofs, L2 against a local stub
// registry, the MCP tool surface); direct `EnvelopeService`/
// `verifySignerIdentity` calls (the SAME code http.ts itself calls) for the
// cases that need precise clock/state control a raw HTTP round trip can't
// give cleanly (nonce replay, cross-envelope reuse, expiry).

import { generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
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

const TEST_UUAID = "uuaid:foundation:agent:11111111-1111-1111-1111-111111111111";

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
// "Bindings": GET /resolve/{uuaid}, GET /verify/{credentialId}).
function startRegistryStub(opts: {
  resolveBody: unknown;
  verifyBody: unknown;
}): Promise<{ server: http.Server; base: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/resolve/")) {
        res.writeHead(200);
        res.end(JSON.stringify(opts.resolveBody));
        return;
      }
      if (req.url?.startsWith("/verify/")) {
        res.writeHead(200);
        res.end(JSON.stringify(opts.verifyBody));
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
});

describe("(h) L2 — local node:http stub registry", () => {
  it("resolve lists the key + verify says valid -> L2 verified", async () => {
    const wallet = makeTestWallet();
    // G1(b): credentialSubject.key.publicKey MUST equal the proof's own key
    // (the real tae/v1 schema field, schema.json:80-89) — `wallet.did` is a
    // `did:key:` string decoding to the SAME raw bytes as the proof's
    // `verificationMethod` (which additionally carries a `#fragment`).
    const credential = {
      id: "uuaid:foundation:signing-credential:test-cred-1",
      credentialSubject: { key: { keyId: "test-key-1", publicKey: wallet.did } },
    } as unknown as UaidSigningCredential;
    const stub = await startRegistryStub({
      resolveBody: { keys: [{ verificationMethod: wallet.verificationMethod }] },
      verifyBody: { valid: true, active: true, notExpired: true },
    });

    const config = await makeConfig({ uuaidRegistryUrl: stub.base });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery(), render: async () => SAMPLE_PDF });

    const created = await envelopes.create({
      title: "L2 up test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L2" },
    });
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const record = await verifySignerIdentity({
      store: stores.envelopeStore,
      tenantId: config.tenant,
      envelopeId: created.envelopeId,
      signerId: created.signers[0].signerId,
      minLevel: "L2",
      proof: { uuaid: TEST_UUAID, proof, credential },
      registry: new (await import("../dist/index.js")).RegistryClient(stub.base),
    });
    expect(record?.level).toBe("L2");
    expect(record?.registry?.credentialId).toBe(credential.id);
    expect(record?.registry?.credentialValid).toBe(true);
    // R1: digests are always computed (even with no blobStore wired in this
    // direct call) — proofDigest already existed; credentialDigest and
    // registrySnapshotDigest are new.
    expect(record?.proofDigest).toBeTruthy();
    expect(record?.credentialDigest).toBeTruthy();
    expect(record?.registry?.registrySnapshotDigest).toBeTruthy();

    await new Promise<void>((resolve) => stub.server.close(() => resolve()));
  });

  it("registry down -> 403, and NO downgrade to L1 (no record persisted at all)", async () => {
    const wallet = makeTestWallet();
    const stub = await startRegistryStub({ resolveBody: {}, verifyBody: {} });
    const deadPort = (stub.server.address() as { port: number }).port;
    await new Promise<void>((resolve) => stub.server.close(() => resolve()));
    // `deadPort` is now guaranteed unbound — nothing else in this test process races to claim it.
    const deadBase = `http://127.0.0.1:${deadPort}`;

    const config = await makeConfig({ uuaidRegistryUrl: deadBase });
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

    const RegistryClientCtor = (await import("../dist/index.js")).RegistryClient;
    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        signerId: created.signers[0].signerId,
        minLevel: "L2",
        proof: { uuaid: TEST_UUAID, proof },
        registry: new RegistryClientCtor(deadBase),
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
    const stub = await startRegistryStub({ resolveBody: {}, verifyBody: {} });
    const config = await makeConfig({ uuaidRegistryUrl: stub.base });
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
    const stub = await startRegistryStub({
      resolveBody: { keys: [{ verificationMethod: wallet.verificationMethod }] },
      verifyBody: { valid: true, active: true, notExpired: true },
    });
    const config = await makeConfig({ uuaidRegistryUrl: stub.base });
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
