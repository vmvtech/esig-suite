// chrome-preflight.test.ts — D2: a Chrome/Chromium preflight the server runs
// at startup, WITHOUT ever launching a browser (fs existence/executable-bit
// checks only — mirrors render-pdf.ts's resolution rules, which core does
// not export; see chrome-preflight.ts's own header for the citations), plus
// its wiring into esig_whoami / esig_create_envelope.

import { mkdtemp, writeFile, chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import {
  checkSealReadiness,
  createMcpServer,
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig } from "./helpers.js";

// A platform key with NO entry in chrome-preflight.ts's own CHROME_CANDIDATES
// table, so these tests can never accidentally pass because THIS machine
// happens to have a real Chrome installed at one of the scanned paths.
const NO_CANDIDATES_PLATFORM = "aix" as NodeJS.Platform;

describe("checkSealReadiness (D2)", () => {
  it("sealReady:false, naming the env var, when nothing points at Chrome and there's no platform install to scan", async () => {
    const result = await checkSealReadiness({}, NO_CANDIDATES_PLATFORM);
    expect(result.sealReady).toBe(false);
    expect(result.sealReadyReason).toMatch(/ESIG_CHROME_PATH/);
  });

  it("sealReady:false, naming the specific env var, when it points at a path that isn't executable", async () => {
    const result = await checkSealReadiness(
      { ESIG_CHROME_PATH: "/definitely/not/a/real/chrome/binary" },
      NO_CANDIDATES_PLATFORM,
    );
    expect(result.sealReady).toBe(false);
    expect(result.sealReadyReason).toMatch(/ESIG_CHROME_PATH/);
  });

  it("sealReady:true when ESIG_CHROME_PATH points at an executable file", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-chrome-stub-"));
    const stub = path.join(dir, "chrome-stub.sh");
    await writeFile(stub, "#!/bin/sh\necho stub\n", "utf8");
    await chmod(stub, 0o755);

    const result = await checkSealReadiness({ ESIG_CHROME_PATH: stub }, NO_CANDIDATES_PLATFORM);
    expect(result.sealReady).toBe(true);
    expect(result.sealReadyReason).toContain("ESIG_CHROME_PATH");
  });

  it("falls through to PUPPETEER_EXECUTABLE_PATH / CHROME_PATH in order when earlier ones are unset", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-chrome-stub-"));
    const stub = path.join(dir, "chrome-stub.sh");
    await writeFile(stub, "#!/bin/sh\necho stub\n", "utf8");
    await chmod(stub, 0o755);

    const result = await checkSealReadiness({ CHROME_PATH: stub }, NO_CANDIDATES_PLATFORM);
    expect(result.sealReady).toBe(true);
    expect(result.sealReadyReason).toContain("CHROME_PATH");
  });

  it("Lambda/Vercel environment reads as ready without any Chrome env var", async () => {
    expect((await checkSealReadiness({ AWS_LAMBDA_FUNCTION_NAME: "esig" }, NO_CANDIDATES_PLATFORM)).sealReady).toBe(
      true,
    );
    expect((await checkSealReadiness({ VERCEL_ENV: "production" }, NO_CANDIDATES_PLATFORM)).sealReady).toBe(true);
  });
});

async function connectedClient(mcpServer: McpServer): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

async function buildDeps(overrides: Partial<McpServerDeps> = {}): Promise<McpServerDeps> {
  const config = await makeConfig();
  const stores = buildStores(config);
  const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
  return {
    config,
    envelopes,
    documents: new FsDocumentStore(config.dataDir, config.maxPdfBytes),
    certStore: stores.certStore,
    pqKeyStore: stores.pqKeyStore,
    auditStore: stores.auditStore,
    ...overrides,
  };
}

describe("sealReady wiring — esig_whoami / esig_create_envelope (D2)", () => {
  it("esig_whoami reports sealReady:true and no warning when ready", async () => {
    const deps = await buildDeps({ sealReady: true, sealReadyReason: "found via ESIG_CHROME_PATH=/x" });
    const client = await connectedClient(createMcpServer(deps));

    const result = await client.callTool({ name: "esig_whoami", arguments: {} });
    const info = result.structuredContent as Record<string, any>;
    expect(info.sealReady).toBe(true);
    expect(info.sealReadyReason).toContain("ESIG_CHROME_PATH");

    await client.close();
  });

  it("esig_whoami reports sealReady:false + the reason, and esig_create_envelope adds a warning field", async () => {
    const deps = await buildDeps({
      sealReady: false,
      sealReadyReason: "no Chrome/Chromium executable found on this system",
    });
    const client = await connectedClient(createMcpServer(deps));

    const whoami = await client.callTool({ name: "esig_whoami", arguments: {} });
    const whoamiInfo = whoami.structuredContent as Record<string, any>;
    expect(whoamiInfo.sealReady).toBe(false);
    expect(whoamiInfo.sealReadyReason).toMatch(/no Chrome/);

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "No Chrome yet",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
      },
    });
    expect(created.isError).not.toBe(true);
    const info = created.structuredContent as Record<string, any>;
    expect(info.sealReady).toBe(false);
    expect(info.warning).toMatch(/no Chrome/i);
    expect(info.warning).toMatch(/esig_reseal/);

    await client.close();
  });

  it("esig_create_envelope has no warning field when sealReady is unset (defaults to ready)", async () => {
    const deps = await buildDeps();
    const client = await connectedClient(createMcpServer(deps));

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "Default harness",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
      },
    });
    const info = created.structuredContent as Record<string, any>;
    expect(info.sealReady).toBe(true);
    expect(info.warning).toBeUndefined();

    await client.close();
  });
});
