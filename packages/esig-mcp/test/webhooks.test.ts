// webhooks.test.ts — §16 "Webhook delivery" + "At-least-once with backoff":
// config validation, HMAC signing, the SSRF target check, and the queue's
// persist-before-delivery / ordering / retry / dead-letter / restart
// semantics against a real local node:http receiver.

import crypto from "node:crypto";
import http from "node:http";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect, afterEach } from "vitest";

import {
  loadConfig,
  ConfigError,
  buildStores,
  EnvelopeService,
  CapturingDelivery,
  createApprovalServer,
  signPayload,
  assertSafeWebhookTarget,
  sendWebhook,
  WebhookSsrfError,
  WebhookDeliveryError,
  EventQueue,
  type EsigEvent,
  type PinnedRequestFn,
} from "../dist/index.js";
import { makeConfig, tokenFromLink, PNG_DATA_URL } from "./helpers.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const BASE = { ESIG_MCP_PASSPHRASE: "a".repeat(24), ESIG_MCP_DELIVERY: "file" };
const SECRET = "s".repeat(32);

// ---------- Local HTTP receiver ----------

interface ReceivedRequest {
  headers: http.IncomingHttpHeaders;
  body: string;
}

async function startReceiver(handler: (req: ReceivedRequest, res: http.ServerResponse) => void) {
  const requests: ReceivedRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const received = { headers: req.headers, body };
      requests.push(received);
      handler(received, res);
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, url: `http://127.0.0.1:${port}/hook`, port, requests };
}

const openServers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(openServers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
});

// ---------- Config validation ----------

describe("config — ESIG_MCP_EVENTS_WEBHOOK_URL / _SECRET", () => {
  it("refuses URL without SECRET, and SECRET without URL", () => {
    expect(() => loadConfig({ ...BASE, ESIG_MCP_EVENTS_WEBHOOK_URL: "https://example.com/hook" })).toThrow(ConfigError);
    expect(() => loadConfig({ ...BASE, ESIG_MCP_EVENTS_WEBHOOK_SECRET: SECRET })).toThrow(ConfigError);
  });

  it("refuses a secret shorter than 32 characters", () => {
    expect(() =>
      loadConfig({ ...BASE, ESIG_MCP_EVENTS_WEBHOOK_URL: "https://example.com/hook", ESIG_MCP_EVENTS_WEBHOOK_SECRET: "short" }),
    ).toThrow(/32 characters/);
  });

  // G5 (RedTeam RT-2026-08-27-05): the events webhook's own insecure-http
  // opt-out is ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK — deliberately separate
  // from ESIG_MCP_ALLOW_INSECURE_WEBHOOK, which is the ESIG_MCP_DELIVERY=
  // webhook link-delivery channel only (see the next describe block).
  it("refuses http:// without ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK, accepts it with the flag (and the link-delivery flag alone does NOT suffice)", () => {
    expect(() =>
      loadConfig({ ...BASE, ESIG_MCP_EVENTS_WEBHOOK_URL: "http://example.com/hook", ESIG_MCP_EVENTS_WEBHOOK_SECRET: SECRET }),
    ).toThrow(/https/);
    expect(() =>
      loadConfig({
        ...BASE,
        ESIG_MCP_EVENTS_WEBHOOK_URL: "http://example.com/hook",
        ESIG_MCP_EVENTS_WEBHOOK_SECRET: SECRET,
        ESIG_MCP_ALLOW_INSECURE_WEBHOOK: "1", // the OTHER channel's flag — must not leak across
      }),
    ).toThrow(/https/);
    const cfg = loadConfig({
      ...BASE,
      ESIG_MCP_EVENTS_WEBHOOK_URL: "http://example.com/hook",
      ESIG_MCP_EVENTS_WEBHOOK_SECRET: SECRET,
      ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK: "1",
    });
    expect(cfg.events.webhook).toEqual({ url: "http://example.com/hook", secret: SECRET });
  });

  it("ESIG_MCP_ALLOW_INSECURE_WEBHOOK (link-delivery) and ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK are independent flags on Config", () => {
    const neither = loadConfig(BASE);
    expect(neither.allowInsecureWebhook).toBe(false);
    expect(neither.allowInsecureEventsWebhook).toBe(false);

    const onlyDelivery = loadConfig({ ...BASE, ESIG_MCP_ALLOW_INSECURE_WEBHOOK: "1" });
    expect(onlyDelivery.allowInsecureWebhook).toBe(true);
    expect(onlyDelivery.allowInsecureEventsWebhook).toBe(false);

    const onlyEvents = loadConfig({ ...BASE, ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK: "1" });
    expect(onlyEvents.allowInsecureWebhook).toBe(false);
    expect(onlyEvents.allowInsecureEventsWebhook).toBe(true);
  });

  it("succeeds with a valid https URL + secret, and is absent (undefined) when unset", () => {
    const cfg = loadConfig({ ...BASE, ESIG_MCP_EVENTS_WEBHOOK_URL: "https://example.com/hook", ESIG_MCP_EVENTS_WEBHOOK_SECRET: SECRET });
    expect(cfg.events.webhook).toEqual({ url: "https://example.com/hook", secret: SECRET });

    const unset = loadConfig(BASE);
    expect(unset.events.webhook).toBeUndefined();
  });
});

// ---------- signPayload ----------

describe("signPayload", () => {
  it("computes sha256=HMAC(secret, timestamp + '.' + body), hex-encoded", () => {
    const secret = "topsecret";
    const timestamp = "2026-01-01T00:00:00.000Z";
    const body = '{"id":"x"}';
    const expected = "sha256=" + crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`, "utf8").digest("hex");
    expect(signPayload(secret, timestamp, body)).toBe(expected);
  });

  it("differs when the body or timestamp changes", () => {
    const sig1 = signPayload("k", "t1", "body1");
    const sig2 = signPayload("k", "t1", "body2");
    const sig3 = signPayload("k", "t2", "body1");
    expect(sig1).not.toBe(sig2);
    expect(sig1).not.toBe(sig3);
  });
});

// ---------- assertSafeWebhookTarget (T18 SSRF) ----------

describe("assertSafeWebhookTarget — T18", () => {
  const allowAll = { allowInsecureWebhook: true, allowPrivateWebhook: true };

  it("refuses http:// unless allowInsecureWebhook", async () => {
    await expect(assertSafeWebhookTarget(new URL("http://example.com/"), { allowInsecureWebhook: false, allowPrivateWebhook: true })).rejects.toThrow(
      WebhookSsrfError,
    );
    await expect(assertSafeWebhookTarget(new URL("http://example.com/"), { allowInsecureWebhook: true, allowPrivateWebhook: true })).resolves.toBeUndefined();
  });

  it("refuses loopback (127.0.0.1, ::1) unless allowPrivateWebhook", async () => {
    await expect(assertSafeWebhookTarget(new URL("https://127.0.0.1/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).rejects.toThrow(
      WebhookSsrfError,
    );
    await expect(assertSafeWebhookTarget(new URL("https://[::1]/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).rejects.toThrow(
      WebhookSsrfError,
    );
    await expect(assertSafeWebhookTarget(new URL("https://127.0.0.1/"), allowAll)).resolves.toBeUndefined();
  });

  it("refuses link-local (169.254/16, incl. cloud metadata) unless allowPrivateWebhook", async () => {
    await expect(
      assertSafeWebhookTarget(new URL("https://169.254.169.254/"), { allowInsecureWebhook: true, allowPrivateWebhook: false }),
    ).rejects.toThrow(WebhookSsrfError);
  });

  it("refuses RFC1918 ranges (10/8, 172.16/12, 192.168/16) unless allowPrivateWebhook", async () => {
    for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1"]) {
      await expect(assertSafeWebhookTarget(new URL(`https://${ip}/`), { allowInsecureWebhook: true, allowPrivateWebhook: false })).rejects.toThrow(
        WebhookSsrfError,
      );
    }
    // 172.32.x.x is OUTSIDE 172.16/12 — must NOT be refused as private.
    await expect(assertSafeWebhookTarget(new URL("https://172.32.0.1/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).resolves.toBeUndefined();
  });

  it("refuses unspecified (0.0.0.0, ::) unless allowPrivateWebhook", async () => {
    await expect(assertSafeWebhookTarget(new URL("https://0.0.0.0/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).rejects.toThrow(
      WebhookSsrfError,
    );
  });

  it("refuses unique-local IPv6 (fc00::/7) and link-local IPv6 (fe80::/10) unless allowPrivateWebhook", async () => {
    await expect(assertSafeWebhookTarget(new URL("https://[fd00::1]/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).rejects.toThrow(
      WebhookSsrfError,
    );
    await expect(assertSafeWebhookTarget(new URL("https://[fe80::1]/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).rejects.toThrow(
      WebhookSsrfError,
    );
  });

  it("allows a public-looking literal IP address (a literal IP goes through the identical check, and a non-private one passes it)", async () => {
    await expect(assertSafeWebhookTarget(new URL("https://8.8.8.8/"), { allowInsecureWebhook: true, allowPrivateWebhook: false })).resolves.toBeUndefined();
  });

  // G1(a): IPv4-mapped IPv6 literals, both textual forms.
  it("refuses an IPv4-mapped IPv6 literal wrapping a private address, in dotted form (::ffff:10.0.0.1)", async () => {
    await expect(
      assertSafeWebhookTarget(new URL("https://[::ffff:10.0.0.1]/"), { allowInsecureWebhook: true, allowPrivateWebhook: false }),
    ).rejects.toThrow(WebhookSsrfError);
  });

  it("refuses an IPv4-mapped IPv6 literal wrapping a private address, in all-hex form (::ffff:0a00:0001 == 10.0.0.1)", async () => {
    await expect(
      assertSafeWebhookTarget(new URL("https://[::ffff:0a00:0001]/"), { allowInsecureWebhook: true, allowPrivateWebhook: false }),
    ).rejects.toThrow(WebhookSsrfError);
  });

  it("an IPv4-mapped IPv6 literal wrapping a PUBLIC address is allowed (the mapped form is checked, not blanket-refused)", async () => {
    await expect(
      assertSafeWebhookTarget(new URL("https://[::ffff:8.8.8.8]/"), { allowInsecureWebhook: true, allowPrivateWebhook: false }),
    ).resolves.toBeUndefined();
  });

  // G1(b): refuses if ANY returned A/AAAA record is private, even when others are public.
  it("refuses when ANY resolved address is private, even if another one is public", async () => {
    const lookupFn = async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ];
    await expect(
      assertSafeWebhookTarget(new URL("https://multi-answer.example/"), { allowInsecureWebhook: true, allowPrivateWebhook: false }, lookupFn),
    ).rejects.toThrow(WebhookSsrfError);
  });

  // G1(c)+(d): the whole point of pinning is that vetting must never be a
  // one-shot, cacheable decision — a DNS answer that changes between calls
  // has to be caught on the LATER call, every time, not grandfathered in
  // because an earlier call already passed. This is what makes connecting to
  // the vetted address (rather than letting the HTTP client re-resolve the
  // hostname itself) matter: without re-vetting on every attempt, a
  // rebinding attacker just waits for the retry.
  it("re-resolves and re-vets on EVERY call — a DNS answer that changes between calls is caught on the call where it turns private (rebinding TOCTOU)", async () => {
    let calls = 0;
    const lookupFn = async (_host: string, _opts: { all: true }) => {
      calls++;
      return calls === 1 ? [{ address: "203.0.113.7", family: 4 }] : [{ address: "127.0.0.1", family: 4 }];
    };
    const policy = { allowInsecureWebhook: true, allowPrivateWebhook: false };
    const url = new URL("http://rebinding.example/hook");

    await expect(assertSafeWebhookTarget(url, policy, lookupFn)).resolves.toBeUndefined();
    expect(calls).toBe(1);
    await expect(assertSafeWebhookTarget(url, policy, lookupFn)).rejects.toThrow(WebhookSsrfError);
    expect(calls).toBe(2);
  });

  // R4 (verifier finding): the private/local classification must key off the
  // ADDRESS itself (net.isIP), never the lookup result's own `family` label —
  // a resolver that returns a private v4 address mislabeled `family: 6` used
  // to slip past the vet (the code took the `isPrivateOrLocalV6` branch,
  // which cannot parse a dotted-quad, and returned "not private").
  it("refuses a private v4 address even when the lookup result mislabels it family:6", async () => {
    const lookupFn = async () => [{ address: "127.0.0.1", family: 6 }];
    await expect(
      assertSafeWebhookTarget(new URL("https://mislabeled.example/"), { allowInsecureWebhook: true, allowPrivateWebhook: false }, lookupFn),
    ).rejects.toThrow(WebhookSsrfError);
  });
});

// ---------- sendWebhook — pinned connection (G1(c)) ----------

describe("sendWebhook — connects to the vetted address, not the hostname (G1(c))", () => {
  it("passes the RESOLVED address (never the hostname) to the request implementation, with Host/SNI kept on the original hostname", async () => {
    const lookupFn = async () => [{ address: "203.0.113.42", family: 4 }];
    const calls: Array<Parameters<PinnedRequestFn>[0]> = [];
    const requestImpl: PinnedRequestFn = async (args) => {
      calls.push(args);
      return { status: 200 };
    };

    const event: EsigEvent = { id: "evt-1", type: "envelope.created", createdAt: new Date().toISOString(), envelopeId: "env-1", phase: "sent", data: {} };
    await sendWebhook(
      { url: "https://pin-target.example/hook", secret: SECRET, allowInsecureWebhook: false, allowPrivateWebhook: false },
      event,
      "0.0.0-test",
      { lookupFn, requestImpl },
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].address).toBe("203.0.113.42"); // the RESOLVED address, not "pin-target.example"
    expect(calls[0].family).toBe(4);
    expect(calls[0].url.hostname).toBe("pin-target.example"); // Host / SNI source
    expect(calls[0].headers["x-esig-event-id"]).toBe("evt-1");
  });

  it("a redirect status from the pinned path is a failure, exactly like the unpinned (fetch) path", async () => {
    const lookupFn = async () => [{ address: "203.0.113.42", family: 4 }];
    const requestImpl = async () => ({ status: 302 });

    const event: EsigEvent = { id: "evt-2", type: "envelope.created", createdAt: new Date().toISOString(), envelopeId: "env-1", phase: "sent", data: {} };
    await expect(
      sendWebhook(
        { url: "https://pin-target.example/hook", secret: SECRET, allowInsecureWebhook: false, allowPrivateWebhook: false },
        event,
        "0.0.0-test",
        { lookupFn, requestImpl },
      ),
    ).rejects.toThrow(WebhookDeliveryError);
  });

  it("re-resolves and re-vets on every sendWebhook call, refusing once the DNS answer turns private (end-to-end rebinding TOCTOU, not just assertSafeWebhookTarget in isolation)", async () => {
    let calls = 0;
    const lookupFn = async () => {
      calls++;
      return calls === 1 ? [{ address: "203.0.113.42", family: 4 }] : [{ address: "127.0.0.1", family: 4 }];
    };
    const requestImpl = async () => ({ status: 200 });
    const cfg = { url: "https://rebind-target.example/hook", secret: SECRET, allowInsecureWebhook: false, allowPrivateWebhook: false };
    const event: EsigEvent = { id: "evt-3", type: "envelope.created", createdAt: new Date().toISOString(), envelopeId: "env-1", phase: "sent", data: {} };

    await expect(sendWebhook(cfg, event, "0.0.0-test", { lookupFn, requestImpl })).resolves.toBeUndefined();
    await expect(sendWebhook(cfg, event, "0.0.0-test", { lookupFn, requestImpl })).rejects.toThrow(WebhookSsrfError);
    expect(calls).toBe(2);
  });
});

// ---------- EventQueue: persist-before-delivery, ordering, retry, dead-letter, restart ----------

function makeAuditStore() {
  const rows: Array<Record<string, unknown>> = [];
  return {
    rows,
    insert: async (row: Record<string, unknown>) => {
      rows.push(row);
    },
  };
}

function fakeEvent(overrides: Partial<EsigEvent> = {}): EsigEvent {
  return {
    id: crypto.randomUUID(),
    type: "envelope.created",
    createdAt: new Date().toISOString(),
    envelopeId: "env-1",
    phase: "sent",
    data: {},
    ...overrides,
  };
}

describe("EventQueue — persist-before-delivery + ordering + retry + dead-letter + restart", () => {
  it("persists the event to disk BEFORE any delivery attempt (enqueue never calls the network)", async () => {
    const { server, url, requests } = await startReceiver((_req, res) => {
      res.writeHead(200);
      res.end("{}");
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-"));
    const audit = makeAuditStore();
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: audit,
      tenantId: "t",
      packageVersion: "0.0.0-test",
    });

    const event = fakeEvent();
    await queue.enqueue(event);

    // The file exists on disk before tick() (and therefore before any HTTP
    // request) is ever called.
    const queueFile = path.join(dir, "events", "queue", `${event.id}.json`);
    const onDisk = JSON.parse(await fs.readFile(queueFile, "utf8"));
    expect(onDisk.status).toBe("pending");
    expect(requests).toHaveLength(0);

    // G4: the queue dir/file carry signer name + email (via the event
    // payload's `signer` field) — 0700/0600 is the only thing standing
    // between "operator-only" and "world-readable" on a shared host, same
    // discipline as the `file` outbox (delivery.ts).
    if (process.platform !== "win32") {
      const dirStat = await fs.stat(path.join(dir, "events", "queue"));
      expect(dirStat.mode & 0o777).toBe(0o700);
      const fileStat = await fs.stat(queueFile);
      expect(fileStat.mode & 0o777).toBe(0o600);
    }

    await queue.tick();
    expect(requests).toHaveLength(1);

    if (process.platform !== "win32") {
      const deliveredDirStat = await fs.stat(path.join(dir, "events", "delivered"));
      expect(deliveredDirStat.mode & 0o777).toBe(0o700);
      const deliveredFileStat = await fs.stat(path.join(dir, "events", "delivered", `${event.id}.json`));
      expect(deliveredFileStat.mode & 0o777).toBe(0o600);
    }
  });

  it("delivers strictly in creation order per envelope", async () => {
    const received: string[] = [];
    const { server, url } = await startReceiver((req, res) => {
      received.push((JSON.parse(req.body) as EsigEvent).id);
      res.writeHead(200);
      res.end("{}");
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-order-"));
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: makeAuditStore(),
      tenantId: "t",
      packageVersion: "0.0.0-test",
    });

    const first = fakeEvent({ envelopeId: "env-order", createdAt: "2026-01-01T00:00:00.000Z" });
    const second = fakeEvent({ envelopeId: "env-order", createdAt: "2026-01-01T00:00:01.000Z" });
    // Enqueue out of order — the queue must still deliver oldest-first.
    await queue.enqueue(second);
    await queue.enqueue(first);

    await queue.tick(); // delivers only the oldest (first)
    await queue.tick(); // now delivers second

    expect(received).toEqual([first.id, second.id]);
  });

  it("retries a failing-then-succeeding receiver with the injected backoff, delivers exactly once, idempotent id", async () => {
    let attempts = 0;
    const { server, url, requests } = await startReceiver((_req, res) => {
      attempts++;
      if (attempts < 2) {
        res.writeHead(500);
        res.end("nope");
      } else {
        res.writeHead(200);
        res.end("{}");
      }
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-retry-"));
    const audit = makeAuditStore();
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: audit,
      tenantId: "t",
      packageVersion: "0.0.0-test",
      backoffSec: [0, 0, 0], // injected: due again immediately on the next tick()
    });

    const event = fakeEvent();
    await queue.enqueue(event);

    await queue.tick(); // attempt 1: fails
    expect(requests).toHaveLength(1);
    const afterFirst = JSON.parse(await fs.readFile(path.join(dir, "events", "queue", `${event.id}.json`), "utf8"));
    expect(afterFirst.status).toBe("pending");
    expect(afterFirst.attempts).toBe(1);

    await queue.tick(); // attempt 2: succeeds
    expect(requests).toHaveLength(2);
    expect(requests.every((r) => (JSON.parse(r.body) as EsigEvent).id === event.id)).toBe(true); // same event id both times (idempotency key)

    // Moved to delivered/, no longer in queue/.
    await expect(fs.readFile(path.join(dir, "events", "queue", `${event.id}.json`), "utf8")).rejects.toThrow();
    const delivered = JSON.parse(await fs.readFile(path.join(dir, "events", "delivered", `${event.id}.json`), "utf8"));
    expect(delivered.attempts).toBe(2);

    // A third tick delivers nothing new (already delivered).
    await queue.tick();
    expect(requests).toHaveLength(2);
  });

  it("dead-letters an always-failing receiver after the backoff schedule is exhausted, with an audit row", async () => {
    const { server, url, requests } = await startReceiver((_req, res) => {
      res.writeHead(503);
      res.end("down");
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-dead-"));
    const audit = makeAuditStore();
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: audit,
      tenantId: "t",
      packageVersion: "0.0.0-test",
      backoffSec: [0, 0], // 2 attempts total before dead-lettering
    });

    const event = fakeEvent({ envelopeId: "env-dead" });
    await queue.enqueue(event);

    await queue.tick(); // attempt 1
    await queue.tick(); // attempt 2 -> dead

    expect(requests).toHaveLength(2);
    const file = JSON.parse(await fs.readFile(path.join(dir, "events", "queue", `${event.id}.json`), "utf8"));
    expect(file.status).toBe("dead");
    expect(file.attempts).toBe(2);

    const deadRow = audit.rows.find((r) => r.action === "webhook.dead_lettered");
    expect(deadRow).toBeTruthy();
    expect((deadRow as any).targetId).toBe("env-dead");
    expect((deadRow as any).metadata.eventId).toBe(event.id);
    expect((deadRow as any).metadata.attempts).toBe(2);

    // A dead event is never retried again.
    await queue.tick();
    expect(requests).toHaveLength(2);
  });

  it("restart safety: a NEW EventQueue over the same dataDir delivers a pending event left by a previous instance", async () => {
    const { server, url, requests } = await startReceiver((_req, res) => {
      res.writeHead(200);
      res.end("{}");
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-restart-"));
    const webhook = { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true };

    const first = new EventQueue({ dataDir: dir, webhook, auditStore: makeAuditStore(), tenantId: "t", packageVersion: "0.0.0-test" });
    const event = fakeEvent();
    await first.enqueue(event);
    // `first` is discarded without ever ticking — simulating a process restart.

    const second = new EventQueue({ dataDir: dir, webhook, auditStore: makeAuditStore(), tenantId: "t", packageVersion: "0.0.0-test" });
    await second.tick();
    expect(requests).toHaveLength(1);
    const delivered = JSON.parse(await fs.readFile(path.join(dir, "events", "delivered", `${event.id}.json`), "utf8"));
    expect(delivered.event.id).toBe(event.id);
  });

  it("refuses a private-range target even when configured (SSRF check runs on every send) — receiver is never reached", async () => {
    const { server, url, requests } = await startReceiver((_req, res) => {
      res.writeHead(200);
      res.end("{}");
    });
    openServers.push(server); // never actually hit — 127.0.0.1 is refused without allowPrivateWebhook

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-ssrf-"));
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: false },
      auditStore: makeAuditStore(),
      tenantId: "t",
      packageVersion: "0.0.0-test",
      backoffSec: [3600, 3600], // 2 entries so 1 failed attempt stays "pending" (scheduled far out), not dead-lettered
    });

    const event = fakeEvent();
    await queue.enqueue(event);
    await queue.tick();

    expect(requests).toHaveLength(0);
    const file = JSON.parse(await fs.readFile(path.join(dir, "events", "queue", `${event.id}.json`), "utf8"));
    expect(file.status).toBe("pending"); // scheduled to retry, not delivered
    expect(file.attempts).toBe(1);
  });

  it("treats any 3xx redirect as a failure (W2/G1(e): redirect: 'error', never followed)", async () => {
    const { server, url, requests } = await startReceiver((_req, res) => {
      res.writeHead(302, { location: "https://evil.example/" });
      res.end();
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-redirect-"));
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: makeAuditStore(),
      tenantId: "t",
      packageVersion: "0.0.0-test",
      backoffSec: [3600, 3600],
    });

    const event = fakeEvent();
    await queue.enqueue(event);
    await queue.tick();

    expect(requests).toHaveLength(1); // the redirect response WAS received...
    const file = JSON.parse(await fs.readFile(path.join(dir, "events", "queue", `${event.id}.json`), "utf8"));
    expect(file.status).toBe("pending"); // ...but treated as a failed delivery, not a success
    expect(file.attempts).toBe(1);
  });

  it("HMAC signature verification snippet (documented in the README): a receiver that recomputes and compares the signature", async () => {
    let verified = false;
    const { server, url } = await startReceiver((req, res) => {
      const timestamp = req.headers["x-esig-timestamp"] as string;
      const signature = req.headers["x-esig-signature"] as string;
      const expected = signPayload(SECRET, timestamp, req.body);
      verified = signature === expected && Math.abs(Date.now() - Date.parse(timestamp)) < 5 * 60_000;
      res.writeHead(verified ? 200 : 401);
      res.end("{}");
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-hmac-"));
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: makeAuditStore(),
      tenantId: "t",
      packageVersion: "0.0.0-test",
    });
    await queue.enqueue(fakeEvent());
    await queue.tick();

    expect(verified).toBe(true);
  });

  it("statusOf reports pending/dead (queue/) and delivered (delivered/), undefined when never enqueued", async () => {
    const { server, url } = await startReceiver((_req, res) => {
      res.writeHead(200);
      res.end("{}");
    });
    openServers.push(server);

    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-q-status-"));
    const queue = new EventQueue({
      dataDir: dir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: makeAuditStore(),
      tenantId: "t",
      packageVersion: "0.0.0-test",
    });

    const event = fakeEvent();
    await queue.enqueue(event);
    expect(await queue.statusOf(event.id)).toEqual({ status: "pending", attempts: 0 });

    await queue.tick();
    expect(await queue.statusOf(event.id)).toEqual({ status: "delivered", attempts: 1 });

    expect(await queue.statusOf("no-such-event")).toBeUndefined();
  });
});

// ---------- Delivery never blocks the HTTP handler ----------

describe("Webhook delivery never blocks the signing HTTP handlers", () => {
  it("POST /sign returns in well under the receiver's own 3s sleep", async () => {
    const { server, url } = await startReceiver((_req, res) => {
      setTimeout(() => {
        res.writeHead(200);
        res.end("{}");
      }, 3000);
    });
    openServers.push(server);

    const config = await makeConfig({
      events: { webhook: { url, secret: SECRET } },
      allowInsecureWebhook: true,
      allowPrivateWebhook: true,
    });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const eventQueue = new EventQueue({
      dataDir: config.dataDir,
      webhook: { url, secret: SECRET, allowInsecureWebhook: true, allowPrivateWebhook: true },
      auditStore: stores.auditStore,
      tenantId: config.tenant,
      packageVersion: "0.0.0-test",
    });
    // Deliberately never started (`.start()`) — this test only needs to
    // prove `enqueue()` (called synchronously inside the sign() request
    // path) never blocks; delivery timing is a separate concern (the
    // retry/backoff tests above). `render` is injected (a real sample PDF)
    // per this ticket's hard rail — never launch Chrome in tests.
    const SAMPLE_PDF = await fs.readFile(path.join(here, "fixtures", "sample.pdf"));
    const envelopes = new EnvelopeService({ config, ...stores, delivery, eventQueue, render: async () => SAMPLE_PDF });
    const httpServer = createApprovalServer({ config, envelopes });
    await new Promise<void>((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(0, "127.0.0.1", () => resolve());
    });
    openServers.push(httpServer);
    const address = httpServer.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const base = `http://127.0.0.1:${port}`;

    const created = await envelopes.create({ title: "Slow webhook", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const started = Date.now();
    const res = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
    });
    const elapsedMs = Date.now() - started;
    expect(res.status).toBeLessThan(500); // may be 200 or 202 depending on seal readiness — either way, not a network-bound failure
    // Generous relative to the receiver's 3000ms sleep (not a tight
    // absolute bound — this suite runs many test files in parallel, and the
    // point being proven is "didn't wait ~3s for the webhook", not a
    // specific millisecond figure).
    expect(elapsedMs).toBeLessThan(2000);
    void created;
  });
});
