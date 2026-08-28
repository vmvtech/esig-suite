// events.test.ts — §16 "Event log": appendEvent/listEvents capping + trim
// audit, the full lifecycle event order + payload safety for a PDF
// envelope, esig_envelope_status's "last 10 events", esig_list_events via a
// real MCP client, and the expiry tick.

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
  appendEvent,
  listEvents,
  expiryTick,
  MAX_EVENTS,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "fixtures", "sample.pdf"));

async function throwingRender(): Promise<Buffer> {
  throw new Error("render must never be called for a PDF envelope");
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

// ---------- appendEvent / listEvents — capping + trim audit ----------

describe("events/log.ts — appendEvent caps at MAX_EVENTS and audits the trim", () => {
  it(`keeps exactly ${200} events, oldest trimmed, with an events.trimmed audit row naming the trimmed ids`, async () => {
    expect(MAX_EVENTS).toBe(200);
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    const created = await envelopes.create({
      title: "Trim test",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    // create() itself already appended one "envelope.created" event.
    const totalToAppend = MAX_EVENTS + 5;
    for (let i = 0; i < totalToAppend; i++) {
      await appendEvent({
        store: stores.envelopeStore,
        auditStore: stores.auditStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        build: (envelope) => ({
          type: "envelope.reminder_sent",
          envelopeId: envelope.id,
          phase: "sent",
          data: { i },
        }),
      });
    }

    const envelope = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    const events = listEvents(envelope!);
    expect(events).toHaveLength(MAX_EVENTS);
    // The newest event appended is the last one in the log.
    expect(events[events.length - 1].data.i).toBe(totalToAppend - 1);

    const { readFile } = await import("node:fs/promises");
    const { default: path } = await import("node:path");
    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const trimRows = auditRows.filter((r) => r.action === "events.trimmed");
    expect(trimRows.length).toBeGreaterThan(0);
    const totalTrimmed = trimRows.reduce((sum, r) => sum + r.metadata.trimmedIds.length, 0);
    // 1 (envelope.created) + totalToAppend events were appended in total;
    // MAX_EVENTS survive, the rest were trimmed off the front.
    expect(totalTrimmed).toBe(1 + totalToAppend - MAX_EVENTS);
  });
});

// ---------- Full PDF-envelope lifecycle: event order + payload safety ----------

describe("Full PDF-envelope flow — event order + payload safety (§16)", () => {
  it("created -> viewed (once) -> signed -> completed -> sealed, in order, no /sign/, token, or proofValue anywhere", async () => {
    const harness = await buildHarness({ pq: true });
    const { delivery, mcpServer, envelopes } = harness;
    const client = await connectedClient(mcpServer);

    const httpServer = createApprovalServer({ config: harness.config, envelopes });
    await new Promise<void>((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(0, "127.0.0.1", () => resolve());
    });
    const address = httpServer.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const base = `http://127.0.0.1:${port}`;

    const ingested = await client.callTool({ name: "esig_ingest_document", arguments: { base64: SAMPLE_PDF.toString("base64") } });
    const docId = (ingested.structuredContent as Record<string, any>).docId as string;

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "Events order test", docId, signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;
    const token = tokenFromLink(delivery.calls[delivery.calls.length - 1].links[0].url);

    // GET twice — envelope.viewed must appear exactly once.
    await fetch(`${base}/sign/${token}`);
    await fetch(`${base}/sign/${token}`);

    const sign = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
    });
    expect(sign.status).toBe(200);

    const events = await envelopes.listEvents(envelopeId);
    const types = events.map((e) => e.type);
    expect(types).toEqual(["envelope.created", "envelope.viewed", "envelope.signed", "envelope.completed", "envelope.sealed"]);
    expect(types.filter((t) => t === "envelope.viewed")).toHaveLength(1);

    // Every event carries a monotonically non-decreasing createdAt.
    for (let i = 1; i < events.length; i++) {
      expect(events[i].createdAt >= events[i - 1].createdAt).toBe(true);
    }

    const serialized = JSON.stringify(events);
    expect(serialized).not.toMatch(/\/sign\//);
    expect(serialized).not.toContain(token);
    expect(serialized).not.toMatch(/proofValue/i);
    expect(serialized).not.toMatch(/signatureImageDataUrl/i);

    await httpServer.close();
  });
});

// ---------- esig_envelope_status: events (last 10) ----------

describe("esig_envelope_status — events field", () => {
  it("includes the lifecycle events for this envelope, oldest first", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
    const deps: McpServerDeps = { config, envelopes, documents: new FsDocumentStore(config.dataDir, config.maxPdfBytes), certStore: stores.certStore, pqKeyStore: stores.pqKeyStore, auditStore: stores.auditStore };
    const client = await connectedClient(createMcpServer(deps));

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "Status events", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;

    const status = await client.callTool({ name: "esig_envelope_status", arguments: { envelopeId } });
    const info = status.structuredContent as Record<string, any>;
    expect(Array.isArray(info.events)).toBe(true);
    expect(info.events.length).toBeGreaterThanOrEqual(1);
    expect(info.events[0].type).toBe("envelope.created");
  });
});

// ---------- esig_list_events — via MCP client ----------

describe("esig_list_events — via a real MCP client", () => {
  it("lists events for an envelope and respects `since`", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
    const deps: McpServerDeps = { config, envelopes, documents: new FsDocumentStore(config.dataDir, config.maxPdfBytes), certStore: stores.certStore, pqKeyStore: stores.pqKeyStore, auditStore: stores.auditStore };
    const client = await connectedClient(createMcpServer(deps));

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "List events test", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;
    await client.callTool({ name: "esig_void_envelope", arguments: { envelopeId } });

    const listed = await client.callTool({ name: "esig_list_events", arguments: { envelopeId } });
    expect(listed.isError).not.toBe(true);
    const info = listed.structuredContent as Record<string, any>;
    expect(info.events.map((e: any) => e.type)).toEqual(["envelope.created", "envelope.voided"]);
    expect(JSON.stringify(info)).not.toMatch(/\/sign\//);

    const sinceCreated = info.events[0].createdAt as string;
    const filtered = await client.callTool({ name: "esig_list_events", arguments: { envelopeId, since: sinceCreated } });
    const filteredInfo = filtered.structuredContent as Record<string, any>;
    expect(filteredInfo.events.map((e: any) => e.type)).toEqual(["envelope.voided"]);
  });

  it("refuses cleanly for an unknown envelopeId", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
    const deps: McpServerDeps = { config, envelopes, documents: new FsDocumentStore(config.dataDir, config.maxPdfBytes), certStore: stores.certStore, pqKeyStore: stores.pqKeyStore, auditStore: stores.auditStore };
    const client = await connectedClient(createMcpServer(deps));

    const result = await client.callTool({ name: "esig_list_events", arguments: { envelopeId: "does-not-exist" } });
    expect(result.isError).toBe(true);
  });
});

// ---------- Expiry tick ----------

describe("events/expiry.ts — tick()", () => {
  it("marks a past-expiry envelope expired and emits envelope.expired exactly once, even ticked twice", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    const created = await envelopes.create({
      title: "Expiring soon",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      expiresAt: new Date(Date.now() + 60_000), // valid at creation (core requires expiresAt in the future)
    });

    const deps = { store: stores.envelopeStore, auditStore: stores.auditStore, dataDir: config.dataDir, tenantId: config.tenant };
    const past = new Date(Date.now() + 120_000); // now past the envelope's expiresAt

    await expiryTick(deps, past);
    await expiryTick(deps, past); // second tick must be a no-op

    const status = await envelopes.status(created.envelopeId);
    expect(status.status).toBe("expired");
    const expiredEvents = status.events.filter((e) => e.type === "envelope.expired");
    expect(expiredEvents).toHaveLength(1);

    const { readFile } = await import("node:fs/promises");
    const { default: path } = await import("node:path");
    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(auditRows.filter((r) => r.action === "envelope.expired")).toHaveLength(1);
  });

  it("catches an envelope core already expired lazily (via token resolution) and emits the event once", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });

    const created = await envelopes.create({
      title: "Lazily expired",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      expiresAt: new Date(Date.now() + 50),
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);
    await new Promise((r) => setTimeout(r, 80)); // let it pass expiresAt for real

    // core's own lazy expiry (resolveSigningToken, packages/esig-core/src/
    // envelope.ts:190-195) — flips status to "expired" and persists it,
    // WITHOUT ever touching this package's event log.
    const resolution = await envelopes.resolve(token);
    expect(resolution.status).toBe("expired");
    const statusBefore = await envelopes.status(created.envelopeId);
    expect(statusBefore.status).toBe("expired");
    expect(statusBefore.events.some((e) => e.type === "envelope.expired")).toBe(false);

    const deps = { store: stores.envelopeStore, auditStore: stores.auditStore, dataDir: config.dataDir, tenantId: config.tenant };
    await expiryTick(deps, new Date());
    const status = await envelopes.status(created.envelopeId);
    expect(status.events.filter((e) => e.type === "envelope.expired")).toHaveLength(1);

    await expiryTick(deps, new Date());
    const status2 = await envelopes.status(created.envelopeId);
    expect(status2.events.filter((e) => e.type === "envelope.expired")).toHaveLength(1);
  });
});
