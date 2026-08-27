// docs-root.test.ts — D6: `esig_verify_document` / `esig_ingest_document`'s
// `path` input must be confined to ESIG_MCP_DOCS_ROOT. Unit-tests
// `resolveDocPath` directly, then exercises the confinement through the real
// MCP tool surface (same pattern as mcp.test.ts: a real client session over
// InMemoryTransport, not internal calls).

import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import os from "node:os";
import path, { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import {
  createMcpServer,
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  resolveDocPath,
  PathEscapesRootError,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

async function connectedClient(mcpServer: McpServer): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

async function buildHarness() {
  const config = await makeConfig();
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
  return { config, mcpServer: createMcpServer(deps) };
}

describe("resolveDocPath (unit)", () => {
  it("accepts a relative path that resolves inside root", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-docsroot-"));
    await writeFile(path.join(root, "doc.pdf"), "x");
    const resolved = await resolveDocPath(root, "doc.pdf");
    expect(resolved).toBe(path.join(root, "doc.pdf"));
  });

  it("accepts an absolute path already inside root", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-docsroot-"));
    const file = path.join(root, "doc.pdf");
    await writeFile(file, "x");
    expect(await resolveDocPath(root, file)).toBe(file);
  });

  it("rejects a '..' segment even if the arithmetic result stays inside root", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-docsroot-"));
    await mkdir(path.join(root, "sub"), { recursive: true });
    await writeFile(path.join(root, "doc.pdf"), "x");
    await expect(resolveDocPath(root, "sub/../doc.pdf")).rejects.toBeInstanceOf(PathEscapesRootError);
  });

  it("rejects an absolute path outside root, naming the root in the message", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-docsroot-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-outside-"));
    const secret = path.join(outside, "secret.pdf");
    await writeFile(secret, "x");
    await expect(resolveDocPath(root, secret)).rejects.toThrow(new RegExp(root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });

  it("rejects a symlink placed inside root that points outside it", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-docsroot-"));
    const outside = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-outside-"));
    const secret = path.join(outside, "secret.pdf");
    await writeFile(secret, "x");
    const link = path.join(root, "innocuous.pdf");
    await symlink(secret, link);
    await expect(resolveDocPath(root, "innocuous.pdf")).rejects.toBeInstanceOf(PathEscapesRootError);
  });
});

describe("esig_ingest_document / esig_verify_document — path confined to ESIG_MCP_DOCS_ROOT (D6)", () => {
  it("refuses a path outside the root with a clear, root-naming error", async () => {
    const { config, mcpServer } = await buildHarness();
    const client = await connectedClient(mcpServer);

    const outside = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-outside-"));
    const outsideFile = path.join(outside, "not-yours.pdf");
    await writeFile(outsideFile, SAMPLE_PDF);

    const ingest = await client.callTool({ name: "esig_ingest_document", arguments: { path: outsideFile } });
    expect(ingest.isError).toBe(true);
    expect((ingest.content as any[])[0]?.text).toContain(config.docsRoot);

    const verify = await client.callTool({ name: "esig_verify_document", arguments: { path: outsideFile } });
    expect(verify.isError).toBe(true);
    expect((verify.content as any[])[0]?.text).toContain(config.docsRoot);

    await client.close();
  });

  it("refuses a '..' escape attempt even when the target happens to be inside the root", async () => {
    const { config, mcpServer } = await buildHarness();
    const client = await connectedClient(mcpServer);

    await mkdir(config.docsRoot, { recursive: true });
    await writeFile(path.join(config.docsRoot, "doc.pdf"), SAMPLE_PDF);

    const ingest = await client.callTool({
      name: "esig_ingest_document",
      arguments: { path: "../inbox/doc.pdf" },
    });
    expect(ingest.isError).toBe(true);

    await client.close();
  });

  it("works for a path inside the root", async () => {
    const { config, mcpServer } = await buildHarness();
    const client = await connectedClient(mcpServer);

    await mkdir(config.docsRoot, { recursive: true });
    await writeFile(path.join(config.docsRoot, "doc.pdf"), SAMPLE_PDF);

    const ingest = await client.callTool({
      name: "esig_ingest_document",
      arguments: { path: path.join(config.docsRoot, "doc.pdf") },
    });
    expect(ingest.isError).not.toBe(true);
    const docId = (ingest.structuredContent as Record<string, any>).docId as string;
    expect(docId).toMatch(/^[0-9a-f]{64}$/);

    const verify = await client.callTool({
      name: "esig_verify_document",
      arguments: { path: path.join(config.docsRoot, "doc.pdf") },
    });
    expect(verify.isError).not.toBe(true);

    await client.close();
  });
});
