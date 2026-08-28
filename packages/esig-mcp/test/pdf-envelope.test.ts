// pdf-envelope.test.ts — PDF envelopes (design doc §13): esig_ingest_document
// -> esig_create_envelope(docId) -> GET document.pdf (byte-identical, headers)
// -> sign -> sealed WITHOUT Chrome (render always throws) -> verifyDocument
// ok:true -> tamper flips it. Plus the html/docId validation matrix, identity
// L1 on a PDF envelope, and confirmation that HTML envelopes are unchanged.

import crypto from "node:crypto";
import { generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { encodeMultibase, jcsBytes, type DataIntegrityProof } from "@e-sig/uaid-exch";

import {
  createMcpServer,
  createApprovalServer,
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
// §13 build ticket: examples/quickstart/sample.pdf, copied into this
// package's own test fixtures (checked to exist before copying).
const SAMPLE_PDF = readFileSync(join(here, "fixtures", "sample.pdf"));
const SAMPLE_PDF_SHA256 = crypto.createHash("sha256").update(SAMPLE_PDF).digest("hex");

/** Never called for a PDF envelope — proves seal() takes no rendering path. */
async function throwingRender(): Promise<Buffer> {
  throw new Error("render must never be called for a PDF envelope (§13: no Chrome anywhere on this path)");
}

async function buildHarness(overrides: Parameters<typeof makeConfig>[0] = {}) {
  const config = await makeConfig(overrides);
  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new CapturingDelivery();
  const envelopes = new EnvelopeService({ config, ...stores, documents, delivery, render: throwingRender });
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

async function connectedClient(mcpServer: McpServer): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

// ---------- test wallet (same pattern as identity.test.ts) ----------

function makeTestWallet() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
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

  return { did, sign };
}

// v0.5 (§17 seam 1): NOT a foundation:agent uuaid — see identity.test.ts's
// TEST_UUAID for why (this test's wallet key has no relationship to this
// literal string, so a foundation:agent form would trip the new
// opportunistic L1p derivation check).
const TEST_UUAID = "uuaid:person:us:ca:22222222-2222-2222-2222-222222222222";

describe("PDF envelopes (design doc §13) — full flow, Chrome-free", () => {
  it(
    "ingest -> create(docId) -> GET document.pdf byte-identical -> sign -> sealed -> verify ok, tamper flips it",
    async () => {
      const harness = await buildHarness({ pq: true });
      const { delivery, mcpServer } = harness;
      const client = await connectedClient(mcpServer);

      const httpServer = createApprovalServer({ config: harness.config, envelopes: harness.envelopes });
      await new Promise<void>((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(0, "127.0.0.1", () => resolve());
      });
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : 0;
      const base = `http://127.0.0.1:${port}`;

      const ingested = await client.callTool({
        name: "esig_ingest_document",
        arguments: { base64: SAMPLE_PDF.toString("base64") },
      });
      expect(ingested.isError).not.toBe(true);
      const docId = (ingested.structuredContent as Record<string, any>).docId as string;
      expect(docId).toBe(SAMPLE_PDF_SHA256);

      const created = await client.callTool({
        name: "esig_create_envelope",
        arguments: {
          title: "Sign this PDF",
          docId,
          signers: [{ name: "Alice", email: "alice@example.com" }],
        },
      });
      expect(created.isError).not.toBe(true);
      const createdInfo = created.structuredContent as Record<string, any>;
      expect(createdInfo.document).toEqual({ docId, sha256: SAMPLE_PDF_SHA256, size: SAMPLE_PDF.length, kind: "pdf" });

      const token = tokenFromLink(delivery.calls[delivery.calls.length - 1].links[0].url);

      // GET the approval page: plain same-origin iframe (not sandboxed
      // srcdoc), an "open in new tab" link, and the document sha256 shown.
      const page = await fetch(`${base}/sign/${token}`);
      expect(page.status).toBe(200);
      const html = await page.text();
      expect(html).toMatch(new RegExp(`<iframe class="pdf" src="/sign/${token}/document\\.pdf"`));
      expect(html).not.toContain("srcdoc=");
      expect(html).toContain("Open the PDF in a new tab");
      expect(html).toContain(SAMPLE_PDF_SHA256);

      // GET the raw document bytes: byte-identical, with the required headers.
      const doc = await fetch(`${base}/sign/${token}/document.pdf`);
      expect(doc.status).toBe(200);
      expect(doc.headers.get("content-type")).toBe("application/pdf");
      expect(doc.headers.get("x-content-type-options")).toBe("nosniff");
      expect(doc.headers.get("cache-control")).toBe("no-store");
      expect(doc.headers.get("content-disposition")).toMatch(/^inline; filename="/);
      const docBytes = Buffer.from(await doc.arrayBuffer());
      expect(docBytes.equals(SAMPLE_PDF)).toBe(true);

      // Sign — the injected renderer THROWS if it is ever called; sealing a
      // PDF envelope must never call it (§13: "NO render call on this path").
      const sign = await fetch(`${base}/sign/${token}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
      });
      expect(sign.status).toBe(200);
      const signBody = (await sign.json()) as { completed: boolean; sealedPdf?: string };
      expect(signBody.completed).toBe(true);
      expect(signBody.sealedPdf).toBeTruthy();

      const status = await client.callTool({
        name: "esig_envelope_status",
        arguments: { envelopeId: createdInfo.envelopeId },
      });
      const statusInfo = status.structuredContent as Record<string, any>;
      expect(statusInfo.phase).toBe("sealed");
      expect(statusInfo.document).toEqual({ docId, sha256: SAMPLE_PDF_SHA256, size: SAMPLE_PDF.length, kind: "pdf" });

      const sealedBytes = readFileSync(signBody.sealedPdf!);
      const verify = await client.callTool({
        name: "esig_verify_document",
        arguments: { base64: sealedBytes.toString("base64"), requirePq: true },
      });
      const verification = verify.structuredContent as Record<string, any>;
      expect(verification.ok).toBe(true);
      expect(verification.classical.digestValid).toBe(true);

      const tampered = Buffer.from(sealedBytes);
      tampered[Math.floor(tampered.length / 2)] ^= 0xff;
      const verifyTampered = await client.callTool({
        name: "esig_verify_document",
        arguments: { base64: tampered.toString("base64"), requirePq: true },
      });
      expect((verifyTampered.structuredContent as Record<string, any>).ok).toBe(false);

      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      await client.close();
    },
    30_000,
  );

  it("GET /sign/<token>/document.pdf for an HTML envelope -> 404, no PDF document", async () => {
    const harness = await buildHarness();
    const { delivery, envelopes } = harness;

    const httpServer = createApprovalServer({ config: harness.config, envelopes });
    await new Promise<void>((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(0, "127.0.0.1", () => resolve());
    });
    const address = httpServer.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const base = `http://127.0.0.1:${port}`;

    await envelopes.create({
      title: "Plain HTML envelope",
      html: "<p>unchanged</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const res = await fetch(`${base}/sign/${token}/document.pdf`);
    expect(res.status).toBe(404);

    // The approval page itself still uses the sandboxed srcdoc iframe.
    const page = await fetch(`${base}/sign/${token}`);
    const html = await page.text();
    expect(html).toMatch(/<iframe\s+sandbox\s+srcdoc="/);
    expect(html).not.toContain('class="pdf"');

    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it("GET /sign/<token>/document.pdf with an invalid token -> 404", async () => {
    const harness = await buildHarness();
    const httpServer = createApprovalServer({ config: harness.config, envelopes: harness.envelopes });
    await new Promise<void>((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(0, "127.0.0.1", () => resolve());
    });
    const address = httpServer.address();
    const port = typeof address === "object" && address ? address.port : 0;

    const res = await fetch(`http://127.0.0.1:${port}/sign/not-a-real-token/document.pdf`);
    expect(res.status).toBe(404);

    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });
});

describe("esig_create_envelope — html/docId validation (§13)", () => {
  it("html AND docId both provided -> isError", async () => {
    const { mcpServer, documents } = await buildHarness();
    const client = await connectedClient(mcpServer);
    const { docId } = await documents.ingest(SAMPLE_PDF);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "both",
        html: "<p>x</p>",
        docId,
        signers: [{ name: "Alice", email: "alice@example.com" }],
      },
    });
    expect(result.isError).toBe(true);

    await client.close();
  });

  it("neither html nor docId provided -> isError", async () => {
    const { mcpServer } = await buildHarness();
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "neither", signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    expect(result.isError).toBe(true);

    await client.close();
  });

  it("non-PDF docId -> isError 'docId is not a PDF'", async () => {
    const { mcpServer, documents } = await buildHarness();
    const client = await connectedClient(mcpServer);
    const { docId } = await documents.ingest(Buffer.from("this is definitely not a PDF"));

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "not a pdf", docId, signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    expect(result.isError).toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[1].text).toBe("docId is not a PDF");

    await client.close();
  });

  it("EnvelopeService.create() enforces the same invariant directly (library level, not only the MCP tool)", async () => {
    const { envelopes, documents } = await buildHarness();

    await expect(
      envelopes.create({ title: "neither", signers: [{ name: "Alice", email: "alice@example.com" }] }),
    ).rejects.toThrow(/exactly one/);

    const { docId } = await documents.ingest(SAMPLE_PDF);
    await expect(
      envelopes.create({
        title: "both",
        html: "<p>x</p>",
        docId,
        signers: [{ name: "Alice", email: "alice@example.com" }],
      }),
    ).rejects.toThrow(/exactly one/);
  });
});

describe("PDF envelope + identity L1 (§12 x §13)", () => {
  it("a PDF envelope's cover sheet embeds the document sha256, so the identity challenge binds it transitively", async () => {
    const { envelopes, documents, stores, config } = await buildHarness();
    const { docId } = await documents.ingest(SAMPLE_PDF);

    const created = await envelopes.create({
      title: "PDF + identity",
      docId,
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });

    const envelope = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(envelope!.html).toContain(SAMPLE_PDF_SHA256);

    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const expectedHtmlSha256 = crypto.createHash("sha256").update(envelope!.html, "utf8").digest("hex");
    expect(challenge.htmlSha256).toBe(expectedHtmlSha256);
  });

  it("L1 signature on a PDF envelope succeeds end to end (proof verified, signature recorded, sealed)", async () => {
    const { envelopes, documents, delivery } = await buildHarness({ pq: false });
    const { docId } = await documents.ingest(SAMPLE_PDF);
    const wallet = makeTestWallet();

    const created = await envelopes.create({
      title: "PDF + L1 signing",
      docId,
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, created.signers[0].signerId);
    const proof = wallet.sign(challenge);

    const result = await envelopes.sign(token, PNG_DATA_URL, { uuaid: TEST_UUAID, proof });
    expect(result.phase).toBe("sealed");
    expect(result.signers[0].identity?.uuaid).toBe(TEST_UUAID);
    expect(result.signers[0].identity?.level).toBe("L1");
  });
});

describe("HTML envelopes are unchanged by §13", () => {
  it("create() with html (no docId) never touches the document store and returns no document field", async () => {
    const { envelopes } = await buildHarness();
    const created = await envelopes.create({
      title: "Plain HTML",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    expect(created.document).toBeUndefined();

    const status = await envelopes.status(created.envelopeId);
    expect(status.document).toBeUndefined();
  });
});
