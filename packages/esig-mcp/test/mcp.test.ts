// mcp.test.ts — MCP-level integration test through a REAL MCP client session
// (design doc §7: "the consumer path, not internal calls"). Uses the SDK's
// own `Client` over `InMemoryTransport.createLinkedPair()` — verified against
// the installed 1.30 types (client/index.d.ts, inMemory.d.ts, server/mcp.d.ts).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import {
  createMcpServer,
  createApprovalServer,
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  V0_1_TOOL_NAMES,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
// Same Chrome-free fixture core's own tests and the gateway's tests use.
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

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
  return { config, envelopes, documents, delivery, deps, mcpServer: createMcpServer(deps) };
}

async function connectedClient(mcpServer: McpServer): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

describe("tools/list — exact v0.1 tool surface (design doc §4)", () => {
  it("lists exactly the v0.1 read + prepare tools, sorted, nothing else", async () => {
    const { mcpServer } = await buildHarness();
    const client = await connectedClient(mcpServer);

    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();

    expect(names).toEqual([...V0_1_TOOL_NAMES].sort());
    // v0.2 sign tools must never be registered (I2: fail closed by design).
    expect(names).not.toContain("esig_sign_as_agent");
    expect(names).not.toContain("esig_cosign_start");

    await client.close();
  });
});

describe("tool results — JSON-first content ordering (D5)", () => {
  it("content[0] is a JSON text block that JSON.parses to structuredContent; content[1] is the human summary", async () => {
    const { mcpServer } = await buildHarness({ pq: true });
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({ name: "esig_whoami", arguments: {} });
    expect(result.isError).not.toBe(true);

    const content = result.content as Array<{ type: string; text: string }>;
    expect(content).toHaveLength(2);
    expect(content[0].type).toBe("text");
    expect(content[1].type).toBe("text");

    // content[0] must be parseable JSON mirroring structuredContent — the
    // whole point (D5): a client that only reads content[] can JSON.parse it.
    expect(() => JSON.parse(content[0].text)).not.toThrow();
    expect(JSON.parse(content[0].text)).toEqual(result.structuredContent);

    // content[1] is the same human-readable summary line as before —
    // just no longer at index 0.
    expect(content[1].text).toMatch(/tenant "test-tenant"/);
    expect(content[1].text).not.toMatch(/^\{/); // prose, not JSON

    await client.close();
  });

  it("holds for a second tool too (esig_create_envelope)", async () => {
    const { mcpServer } = await buildHarness();
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "D5", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content[0].text)).toEqual(result.structuredContent);
    expect(content[1].text).toContain("envelope");
    expect(content[1].text).not.toMatch(/^\{/);

    await client.close();
  });
});

describe("esig_whoami — I1 (no key egress)", () => {
  it("reports identity/caps/fingerprints and never serializes key material", async () => {
    const { mcpServer } = await buildHarness({ pq: true });
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({ name: "esig_whoami", arguments: {} });
    expect(result.isError).not.toBe(true);

    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/PRIVATE KEY/);
    expect(serialized).not.toMatch(/BEGIN CERTIFICATE/);
    expect(serialized).not.toMatch(/mldsa65SecretKey|ed25519Pkcs8|mldsa65Seed|keyBundleEncrypted/);

    const info = result.structuredContent as Record<string, any>;
    expect(info.enabledModes).toEqual(["H"]);
    expect(info.cert.certFingerprint).toBeTruthy();
    expect(info.postQuantum.mldsa65Fpr).toBeTruthy();

    await client.close();
  });
});

describe("esig_create_envelope — token custody (I8)", () => {
  it("withholds raw links by default", async () => {
    const { mcpServer, delivery } = await buildHarness({ returnLinks: false });
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "NDA",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
      },
    });
    expect(result.isError).not.toBe(true);

    const token = tokenFromLink(delivery.calls[0].links[0].url);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("/sign/");
    expect(serialized).not.toContain(token);
    expect((result.structuredContent as Record<string, any>).links).toBeUndefined();

    await client.close();
  });

  it("includes raw links when returnLinks is set", async () => {
    const { mcpServer } = await buildHarness({ returnLinks: true });
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "NDA",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
      },
    });
    expect(result.isError).not.toBe(true);
    const serialized = JSON.stringify(result);
    expect(serialized).toContain("/sign/");
    expect((result.structuredContent as Record<string, any>).links).toHaveLength(1);

    await client.close();
  });
});

describe("full flow through a real MCP client session (design doc §7)", () => {
  it(
    "create -> approval page over HTTP (I9) -> sign each signer -> completed -> verify ok, tamper flips it",
    async () => {
      const harness = await buildHarness({ pq: true });
      const { envelopes, delivery, mcpServer } = harness;
      const client = await connectedClient(mcpServer);

      const httpServer = createApprovalServer({ config: harness.config, envelopes });
      await new Promise<void>((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(0, "127.0.0.1", () => resolve());
      });
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : 0;
      const base = `http://127.0.0.1:${port}`;

      // Injection payload: sanitize.ts strips this at creation (library
      // layer), and the approval page HTML-attribute-escapes whatever
      // remains before embedding it in the iframe's srcdoc (second,
      // independent layer) — both are asserted below.
      const created = await client.callTool({
        name: "esig_create_envelope",
        arguments: {
          title: "Consulting Agreement",
          html: '<p>Terms.</p><script>alert(1)</script><b onload="alert(2)">bold</b>',
          signers: [
            { name: "Alice", email: "alice@example.com", order: 1 },
            { name: "Bob", email: "bob@example.com", order: 2 },
          ],
        },
      });
      expect(created.isError).not.toBe(true);
      const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;

      const links = delivery.calls[delivery.calls.length - 1].links;
      const aliceToken = tokenFromLink(links.find((l) => l.name === "Alice")!.url);
      const bobToken = tokenFromLink(links.find((l) => l.name === "Bob")!.url);

      const page = await fetch(`${base}/sign/${aliceToken}`);
      expect(page.status).toBe(200);
      expect(page.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
      expect(page.headers.get("referrer-policy")).toBe("no-referrer");
      expect(page.headers.get("cache-control")).toBe("no-store");
      expect(page.headers.get("x-content-type-options")).toBe("nosniff");

      const html = await page.text();
      expect(html).toContain("<iframe");
      expect(html).toMatch(/<iframe\s+sandbox\s+srcdoc="/);
      // I9: neither the raw script nor the event-handler attribute survive,
      // whether escaped-but-visible or (worse) unescaped-and-live.
      expect(html).not.toContain("alert(1)");
      expect(html).not.toContain("alert(2)");
      expect(html).not.toMatch(/onload\s*=/);

      const signAlice = await fetch(`${base}/sign/${aliceToken}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
      });
      expect(signAlice.status).toBe(200);
      const aliceBody = (await signAlice.json()) as { status: string; completed: boolean };
      expect(aliceBody.completed).toBe(false);
      expect(aliceBody.status).toBe("partially_signed");

      const signBob = await fetch(`${base}/sign/${bobToken}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
      });
      expect(signBob.status).toBe(200);
      const bobBody = (await signBob.json()) as { status: string; completed: boolean; sealedPdf?: string };
      expect(bobBody.completed).toBe(true);
      expect(bobBody.sealedPdf).toBeTruthy();

      const status = await client.callTool({ name: "esig_envelope_status", arguments: { envelopeId } });
      const statusInfo = status.structuredContent as Record<string, any>;
      expect(statusInfo.status).toBe("completed");
      expect(statusInfo.sealedPdfUrl).toBe(bobBody.sealedPdf);

      // D6: `esig_verify_document`'s `path` input is now confined to
      // ESIG_MCP_DOCS_ROOT (an "inbox", not this server's own blob storage),
      // so the sealed PDF this server just produced under `blobs/` is
      // verified by `base64` here instead — see test/docs-root.test.ts for
      // the confinement behavior itself.
      const sealedBytes = readFileSync(bobBody.sealedPdf!);
      const verify = await client.callTool({
        name: "esig_verify_document",
        arguments: { base64: sealedBytes.toString("base64"), requirePq: true },
      });
      const verification = verify.structuredContent as Record<string, any>;
      expect(verification.ok).toBe(true);
      expect(verification.postQuantum.present).toBe(true);

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
});
