// pillar-seams.test.ts — Pillar integration seams (docs/architecture/esig-mcp.md
// §17, build ticket items 2 + 6). Every seam is exercised through the REAL
// `EnvelopeService`/config code with a FAKE channel/sink/loader — this file
// never imports "@e-sig/pillar-bridge" or "@uuaid/pillar" (loader-absence /
// "loader override env" coverage lives in test/bin-cli.test.ts, which spawns
// the real dist/bin.js; L1p itself is test/l1p.test.ts; the pre-verified
// identity fan-in seam is test/preverified.test.ts).

import { generateKeyPairSync, createHash, sign as ed25519Sign } from "node:crypto";
import http from "node:http";

import { describe, it, expect } from "vitest";

import { jcsBytes } from "@e-sig/uaid-exch";

import {
  buildStores,
  loadConfig,
  ConfigError,
  EnvelopeService,
  FsDocumentStore,
  EventQueue,
  EventDispatcher,
  uuaidFromEd25519Key,
  getPillarUnregisteredSignerIds,
  type DeliveryChannel,
  type DeliveryLink,
  type DeliveryEnvelopeMeta,
  type Receipt,
  type EventSink,
  type EsigEvent,
} from "../dist/index.js";
import { makeConfig } from "./helpers.js";

function randomPillarTarget() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublic = spki.subarray(spki.length - 32);
  const publicKeyHex = rawPublic.toString("hex");
  return { uuaid: uuaidFromEd25519Key(rawPublic), publicKey: publicKeyHex };
}

/** A fake `DeliveryChannel` — captures exactly what it was handed, delivers nothing anywhere (never imports the real Pillar bridge). */
class FakeChannel implements DeliveryChannel {
  readonly calls: Array<{ meta: DeliveryEnvelopeMeta; links: DeliveryLink[] }> = [];
  async deliver(meta: DeliveryEnvelopeMeta, links: DeliveryLink[]): Promise<Receipt[]> {
    this.calls.push({ meta, links });
    return links.map((l) => ({ signerId: l.signerId, ok: true }));
  }
}

/** A fake `EventSink` — captures published events; can be made to throw once. */
class FakeSink implements EventSink {
  readonly published: EsigEvent[] = [];
  private failNext = false;
  failOnce(): void {
    this.failNext = true;
  }
  async publish(event: EsigEvent): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error("fake sink deliberately failing");
    }
    this.published.push(event);
  }
}

// =====================================================================
// config.ts: ESIG_MCP_DELIVERY=pillar / ESIG_PILLAR_SUBSCRIBERS
// =====================================================================

describe("config.ts: pillar settings (§17 seams 2-4)", () => {
  const BASE_ENV = {
    ESIG_MCP_PASSPHRASE: "a".repeat(24),
    ESIG_MCP_DATA_DIR: "/tmp/esig-mcp-pillar-config-test",
  };

  it('ESIG_MCP_DELIVERY="pillar" + required vars -> Config.delivery.kind === "pillar", Config.pillar populated', () => {
    const config = loadConfig({
      ...BASE_ENV,
      ESIG_MCP_DELIVERY: "pillar",
      ESIG_PILLAR_PASSPHRASE: "b".repeat(24),
      ESIG_PILLAR_CARRIERS: "https://pillar.example.com/v1/envelopes, https://backup.example.com/v1/envelopes",
      ESIG_PILLAR_PROOF_POLL: "5",
    });
    expect(config.delivery.kind).toBe("pillar");
    expect(config.pillar?.passphrase).toBe("b".repeat(24));
    expect(config.pillar?.carriers).toEqual([
      "https://pillar.example.com/v1/envelopes",
      "https://backup.example.com/v1/envelopes",
    ]);
    expect(config.pillar?.proofPollSec).toBe(5);
    expect(config.pillar?.home).toBe("/tmp/esig-mcp-pillar-config-test/pillar");
  });

  it("ESIG_PILLAR_SUBSCRIBERS alone (delivery=file) still populates Config.pillar — seam 4 is independent of seam 2's channel", () => {
    const target = randomPillarTarget();
    const config = loadConfig({
      ...BASE_ENV,
      ESIG_MCP_DELIVERY: "file",
      ESIG_PILLAR_PASSPHRASE: "b".repeat(24),
      ESIG_PILLAR_CARRIERS: "https://pillar.example.com/v1/envelopes",
      ESIG_PILLAR_SUBSCRIBERS: JSON.stringify([target]),
    });
    expect(config.delivery.kind).toBe("file");
    expect(config.pillar?.subscribers).toEqual([target]);
  });

  it("a subscriber whose publicKey does NOT derive the configured uuaid -> ConfigError", () => {
    const target = randomPillarTarget();
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ESIG_MCP_DELIVERY: "file",
        ESIG_PILLAR_PASSPHRASE: "b".repeat(24),
        ESIG_PILLAR_CARRIERS: "https://pillar.example.com/v1/envelopes",
        ESIG_PILLAR_SUBSCRIBERS: JSON.stringify([{ uuaid: "uuaid:foundation:agent:00000000-0000-0000-0000-000000000000", publicKey: target.publicKey }]),
      }),
    ).toThrow(ConfigError);
  });

  it('ESIG_MCP_DELIVERY="pillar" with no ESIG_PILLAR_PASSPHRASE -> ConfigError naming it (RT G4 floor)', () => {
    expect(() =>
      loadConfig({
        ...BASE_ENV,
        ESIG_MCP_DELIVERY: "pillar",
        ESIG_PILLAR_CARRIERS: "https://pillar.example.com/v1/envelopes",
      }),
    ).toThrowError(/ESIG_PILLAR_PASSPHRASE/);
  });
});

// =====================================================================
// DeliveryLink.pillar plumbing (seam 2) — envelopes.ts create()
// =====================================================================

describe("envelopes.ts create(): signers[].pillar -> DeliveryLink.pillar on whatever channel is injected", () => {
  it("a well-formed pillar target flows through unmodified; the returned Receipt carries no url", async () => {
    const config = await makeConfig({ delivery: { kind: "pillar" } });
    const stores = buildStores(config);
    const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
    const channel = new FakeChannel();
    const envelopes = new EnvelopeService({ config, ...stores, documents, delivery: channel });

    const target = randomPillarTarget();
    const result = await envelopes.create({
      title: "Pillar delivery",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com", pillar: target }],
    });

    expect(channel.calls).toHaveLength(1);
    const link = channel.calls[0].links[0];
    expect(link.pillar).toEqual(target);
    expect(link.url).toMatch(/^http/); // still present — a channel that doesn't understand pillar can fall back to it

    // I8 unchanged: the tool-facing Receipt never carries a raw URL — true
    // before this ticket too (delivery.ts's Receipt shape), reaffirmed here.
    expect(result.delivery[0]).not.toHaveProperty("url");
    expect(result.delivery[0].signerId).toBe(link.signerId);
  });

  it("publicKey that does NOT derive uuaid -> refused BEFORE any write", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel() });

    await expect(
      envelopes.create({
        title: "Bad pillar target",
        html: "<p>terms</p>",
        signers: [
          {
            name: "Alice",
            email: "alice@example.com",
            pillar: { uuaid: "uuaid:foundation:agent:00000000-0000-0000-0000-000000000000", publicKey: "ab".repeat(32) },
          },
        ],
      }),
    ).rejects.toThrow(/derives uuaid/);
  });

  it("publicKey that is not 64 hex chars -> refused", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel() });
    const target = randomPillarTarget();

    await expect(
      envelopes.create({
        title: "Short key",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com", pillar: { uuaid: target.uuaid, publicKey: "ab12" } }],
      }),
    ).rejects.toThrow(/64 hex/);
  });
});

// =====================================================================
// RT G2 — registry cross-check for pillar signers at creation
// =====================================================================

describe("envelopes.ts create(): RT G2 — registry badge cross-check for signers[].pillar", () => {
  const REGISTRY_KEY = (() => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
    return { publicKeyHex: Buffer.from(spki.subarray(spki.length - 32)).toString("hex"), privateKey };
  })();

  function sealBadge(payload: object) {
    const payloadHash = "0x" + createHash("sha256").update(jcsBytes(payload)).digest("hex");
    const signature = ed25519Sign(null, jcsBytes(payload), REGISTRY_KEY.privateKey).toString("hex");
    return {
      payload,
      payloadHash,
      signatures: [{ alg: "ed25519", keyId: "uuaid-registry-1", publicKey: REGISTRY_KEY.publicKeyHex, signature, created: new Date().toISOString() }],
    };
  }

  async function withRegistryStub(handler: (uuaid: string) => { status: number; body: unknown }) {
    const server = http.createServer((req, res) => {
      const m = /^\/iaaso\/v1\/badge\/(.+)$/.exec(req.url ?? "");
      const { status, body } = handler(m ? decodeURIComponent(m[1]) : "");
      res.setHeader("content-type", "application/json");
      res.writeHead(status);
      res.end(JSON.stringify(body));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    return {
      base: `http://127.0.0.1:${port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it("badge presentationKey matches -> envelope created normally", async () => {
    const target = randomPillarTarget();
    const stub = await withRegistryStub((uuaid) => ({
      status: 200,
      body: sealBadge({
        "@type": "UUAIDVerifiableBadge",
        subject: { uuaid, presentationKey: { alg: "ed25519", publicKey: target.publicKey, keyId: "k1" } },
        status: "active",
        freshUntil: new Date(Date.now() + 60_000).toISOString(),
      }),
    }));

    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: REGISTRY_KEY.publicKeyHex });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel() });

    const result = await envelopes.create({
      title: "Registered pillar signer",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com", pillar: target }],
    });
    expect(result.envelopeId).toBeTruthy();

    await stub.close();
  });

  it("badge presentationKey MISMATCHES -> refused, fail-closed", async () => {
    const target = randomPillarTarget();
    const other = randomPillarTarget();
    const stub = await withRegistryStub((uuaid) => ({
      status: 200,
      body: sealBadge({
        "@type": "UUAIDVerifiableBadge",
        subject: { uuaid, presentationKey: { alg: "ed25519", publicKey: other.publicKey, keyId: "k1" } },
        status: "active",
        freshUntil: new Date(Date.now() + 60_000).toISOString(),
      }),
    }));

    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: REGISTRY_KEY.publicKeyHex });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel() });

    await expect(
      envelopes.create({
        title: "Mismatched pillar signer",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com", pillar: target }],
      }),
    ).rejects.toThrow(/does not attest/);

    await stub.close();
  });

  it("badge 404 -> refused by default", async () => {
    const target = randomPillarTarget();
    const stub = await withRegistryStub(() => ({ status: 404, body: {} }));

    const config = await makeConfig({ uuaidRegistryUrl: stub.base, uuaidRegistrySigningKey: REGISTRY_KEY.publicKeyHex });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel() });

    await expect(
      envelopes.create({
        title: "Unregistered pillar signer",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com", pillar: target }],
      }),
    ).rejects.toThrow(/ESIG_MCP_PILLAR_ALLOW_UNREGISTERED/);

    await stub.close();
  });

  it("badge 404 + ESIG_MCP_PILLAR_ALLOW_UNREGISTERED opt-in -> accepted, audited signer.pillar_unregistered, surfaced via getPillarUnregisteredSignerIds", async () => {
    const target = randomPillarTarget();
    const stub = await withRegistryStub(() => ({ status: 404, body: {} }));

    const config = await makeConfig({
      uuaidRegistryUrl: stub.base,
      uuaidRegistrySigningKey: REGISTRY_KEY.publicKeyHex,
      pillarAllowUnregistered: true,
    });
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel() });

    const result = await envelopes.create({
      title: "Opted-in unregistered pillar signer",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com", pillar: target }],
    });
    expect(result.envelopeId).toBeTruthy();

    const envelope = await stores.envelopeStore.findById(config.tenant, result.envelopeId);
    expect(getPillarUnregisteredSignerIds(envelope!)).toEqual([result.signers[0].signerId]);

    const rows = await (stores.auditStore as unknown as { readAll(): Promise<Array<{ action: string; metadata?: unknown }>> }).readAll();
    const row = rows.find((r) => r.action === "signer.pillar_unregistered");
    expect(row).toBeTruthy();
    expect((row!.metadata as { uuaid?: string })?.uuaid).toBe(target.uuaid);

    await stub.close();
  });
});

// =====================================================================
// Events fan-out (seam 4) — the fake sink AND the webhook queue, together
// =====================================================================

describe("EventDispatcher (§17 seam 4): events fan out to registered sinks AND the existing webhook queue", () => {
  it("one envelope.created event reaches BOTH a fake sink and the webhook queue", async () => {
    const config = await makeConfig({
      events: { webhook: { url: "https://webhook.example.com/esig-events", secret: "s".repeat(32) } },
    });
    const stores = buildStores(config);

    const eventQueue = new EventQueue({
      dataDir: config.dataDir,
      webhook: { url: config.events.webhook!.url, secret: config.events.webhook!.secret, allowInsecureWebhook: false, allowPrivateWebhook: false },
      auditStore: stores.auditStore,
      tenantId: config.tenant,
      packageVersion: "0.0.0-test",
    }); // never .start()'d — enqueue() alone writes the pending file, no network call

    const sink = new FakeSink();
    const eventDispatcher = new EventDispatcher({ auditStore: stores.auditStore, tenantId: config.tenant, sinks: [sink] });

    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel(), eventQueue, eventDispatcher });

    const created = await envelopes.create({
      title: "Fan-out test",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });

    // The fake sink got it.
    expect(sink.published.some((e) => e.type === "envelope.created" && e.envelopeId === created.envelopeId)).toBe(true);

    // The webhook queue ALSO got it, independently (persisted before any
    // delivery attempt — events/queue.ts's own header comment).
    const status = await envelopes.status(created.envelopeId);
    const createdEvent = status.events.find((e) => e.type === "envelope.created")!;
    expect(await eventQueue.statusOf(createdEvent.id)).toEqual({ status: "pending", attempts: 0 });
  });

  it("a throwing sink is isolated: never blocks the webhook queue, never blocks a SECOND sink, and is audited events.sink_failed", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);

    const failingSink = new FakeSink();
    failingSink.failOnce();
    const healthySink = new FakeSink();
    const eventDispatcher = new EventDispatcher({ auditStore: stores.auditStore, tenantId: config.tenant, sinks: [failingSink, healthySink] });

    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel(), eventDispatcher });

    const created = await envelopes.create({
      title: "Sink isolation test",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });

    // The failing sink never got its event recorded (it threw before push) —
    // but the SECOND sink still did, and create() itself never threw.
    expect(failingSink.published).toHaveLength(0);
    expect(healthySink.published.some((e) => e.type === "envelope.created" && e.envelopeId === created.envelopeId)).toBe(true);

    const rows = await (stores.auditStore as unknown as { readAll(): Promise<Array<{ action: string }>> }).readAll();
    expect(rows.some((r) => r.action === "events.sink_failed")).toBe(true);
  });

  it("register() adds a sink after construction (bin.ts's own ordering: the sink is registered once the bridge loads, after EventDispatcher is already constructed)", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const eventDispatcher = new EventDispatcher({ auditStore: stores.auditStore, tenantId: config.tenant });
    const sink = new FakeSink();
    eventDispatcher.register(sink);

    const envelopes = new EnvelopeService({ config, ...stores, delivery: new FakeChannel(), eventDispatcher });
    const created = await envelopes.create({
      title: "Late-registered sink",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    expect(sink.published.some((e) => e.envelopeId === created.envelopeId)).toBe(true);
  });
});
