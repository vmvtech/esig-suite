// reminders.test.ts — §15 "Reminders" (docs/architecture/esig-mcp.md).
// `computeDue()` is pure (no I/O) and tested directly against constructed
// envelope shapes; `Scheduler` and `esig_send_reminder` are tested against a
// real `EnvelopeService`/MCP server with an injected clock and a
// `CapturingTransport`-backed `EmailDelivery`.

import type { Envelope } from "@e-sig/core";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  computeDue,
  Scheduler,
  EnvelopeService,
  buildStores,
  CapturingTransport,
  EmailDelivery,
  createMcpServer,
  FsDocumentStore,
  expiryTick,
  type McpServerDeps,
  type EmailMessage,
  type SendResult,
} from "../dist/index.js";
import { makeConfig } from "./helpers.js";

const HOUR = 3_600_000;

function fakeEnvelope(overrides: Partial<Envelope> = {}): Envelope {
  return {
    id: "env-1",
    tenantId: "t",
    title: "NDA",
    html: "<p>hi</p>",
    status: "sent",
    signers: [
      { id: "s1", name: "Alice", email: "a@example.com", order: 1, status: "pending", tokenHash: "h1" },
    ],
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    metadata: {},
    ...overrides,
  } as Envelope;
}

// ---------- computeDue (pure) ----------

describe("computeDue", () => {
  const t0 = new Date("2026-01-01T00:00:00.000Z");
  const schedule = [24 * HOUR, 72 * HOUR];

  it("is not due before the first scheduled duration", () => {
    const envelope = fakeEnvelope({ createdAt: t0 });
    expect(computeDue(envelope, new Date(t0.getTime() + 23 * HOUR), schedule, 3)).toEqual([]);
  });

  it("is due at exactly the first duration (index 0)", () => {
    const envelope = fakeEnvelope({ createdAt: t0 });
    expect(computeDue(envelope, new Date(t0.getTime() + 24 * HOUR), schedule, 3)).toEqual([
      { signerId: "s1", index: 0 },
    ]);
  });

  it("is due at the second duration (index 1) once the first has already been sent", () => {
    const envelope = fakeEnvelope({
      createdAt: t0,
      metadata: { mcp: { delivery: { reminders: { s1: { sentAt: [new Date(t0.getTime() + 24 * HOUR).toISOString()], nextAt: null } } } } },
    });
    expect(computeDue(envelope, new Date(t0.getTime() + 23 * HOUR), schedule, 3)).toEqual([]); // not yet 72h
    expect(computeDue(envelope, new Date(t0.getTime() + 72 * HOUR), schedule, 3)).toEqual([
      { signerId: "s1", index: 1 },
    ]);
  });

  it("never exceeds max, even with more schedule entries left", () => {
    const envelope = fakeEnvelope({
      createdAt: t0,
      metadata: {
        mcp: {
          delivery: {
            reminders: {
              s1: {
                sentAt: [new Date(t0.getTime() + 24 * HOUR).toISOString(), new Date(t0.getTime() + 72 * HOUR).toISOString()],
                nextAt: null,
              },
            },
          },
        },
      },
    });
    // max = 2, already sent 2 — never due again, however far `now` moves.
    expect(computeDue(envelope, new Date(t0.getTime() + 1000 * HOUR), schedule, 2)).toEqual([]);
  });

  it("skips voided, expired, and completed envelopes entirely", () => {
    const far = new Date(t0.getTime() + 1000 * HOUR);
    for (const status of ["voided", "expired", "completed"] as const) {
      const envelope = fakeEnvelope({ createdAt: t0, status });
      expect(computeDue(envelope, far, schedule, 3)).toEqual([]);
    }
  });

  it("skips a signer who is not pending (e.g. already signed) even on an otherwise-pending envelope", () => {
    const envelope = fakeEnvelope({
      createdAt: t0,
      status: "partially_signed",
      signers: [
        { id: "s1", name: "Alice", email: "a@example.com", order: 1, status: "signed", tokenHash: "h1" },
        { id: "s2", name: "Bob", email: "b@example.com", order: 1, status: "pending", tokenHash: "h2" },
      ],
    });
    const due = computeDue(envelope, new Date(t0.getTime() + 24 * HOUR), schedule, 3);
    expect(due).toEqual([{ signerId: "s2", index: 0 }]);
  });

  it("is a no-op when no schedule is configured", () => {
    const envelope = fakeEnvelope({ createdAt: t0 });
    expect(computeDue(envelope, new Date(t0.getTime() + 1000 * HOUR), [], 3)).toEqual([]);
  });
});

// ---------- Scheduler + EnvelopeService, injected clock ----------

async function buildReminderHarness(overrides: Parameters<typeof makeConfig>[0] = {}) {
  // core's `createEnvelope` stamps `envelope.createdAt` with the REAL wall
  // clock (`envelope.ts:159`, `new Date()` — not injectable), so this
  // harness's own clock must track real time too (just offset forward as the
  // test advances it) rather than some fixed fictional date, or `computeDue`
  // would compare a real `createdAt` against an unrelated fake `now`.
  let currentTime = new Date();
  const clock = (): Date => currentTime;
  const setNow = (d: Date): void => {
    currentTime = d;
  };

  const transport = new CapturingTransport();
  const config = await makeConfig({
    delivery: { kind: "email", transport: "smtp", from: "Ops <ops@example.com>" },
    reminders: { durationsMs: [24 * HOUR, 72 * HOUR], max: 3 },
    ...overrides,
  });
  const stores = buildStores(config);
  const delivery = new EmailDelivery({ transport, from: "Ops <ops@example.com>" });
  const envelopes = new EnvelopeService({ config, ...stores, delivery, now: clock });
  const scheduler = new Scheduler({ envelopes, config, now: clock });

  return { config, envelopes, scheduler, transport, setNow, clock, stores };
}

describe("Scheduler.tick — automatic reminders", () => {
  it("not before 24h; sent at 24h and 72h; not again after (max reached at 2 of 2 configured durations)", async () => {
    const { envelopes, scheduler, transport, setNow, clock } = await buildReminderHarness();

    const created = await envelopes.create({
      title: "NDA",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    // create() itself already sent the ORIGINAL signing-link email over the
    // same (email) delivery channel — that's the baseline every count below
    // is relative to, not a reminder.
    expect(transport.sent).toHaveLength(1);

    setNow(new Date(clock().getTime() + 23 * HOUR));
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(1); // still just the creation email

    setNow(new Date(clock().getTime() + 2 * HOUR)); // t0 + 25h
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(2); // + first reminder
    expect(transport.sent[1].to).toBe("alice@example.com");

    // Ticking again at the same time must not double-send.
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(2);

    setNow(new Date(clock().getTime() + 48 * HOUR)); // t0 + 73h
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(3); // + second reminder

    setNow(new Date(clock().getTime() + 500 * HOUR)); // far past both durations
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(3); // schedule exhausted (2 of 2)

    const status = await envelopes.status(created.envelopeId);
    expect(status.status).toBe("sent"); // still pending, never voided/expired/completed
  });

  it("stops once the envelope is voided, even with due reminders remaining", async () => {
    const { envelopes, scheduler, transport, setNow, clock } = await buildReminderHarness();
    const created = await envelopes.create({
      title: "NDA",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    expect(transport.sent).toHaveLength(1); // the creation email
    await envelopes.void(created.envelopeId);

    setNow(new Date(clock().getTime() + 500 * HOUR));
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(1); // no reminder — envelope is voided
  });

  // F1 (verifier finding): a single in-memory Envelope object used to be
  // reused across every due signer within one tick — `sendOneReminder`'s
  // `store.update` CAS-failed for the SECOND+ signer AFTER that signer's
  // email had already been sent, so the scheduler silently under-counted
  // the audit trail (and re-sent on the NEXT tick, since the schedule state
  // never actually persisted). A 3-signer envelope, all due at once, is the
  // exact shape that reproduced it.
  it("3-signer envelope: 24h tick sends exactly 3 emails + 3 audit rows (F1 — no CAS-conflict drop across signers); repeat tick sends 0; 72h tick sends exactly 3 more", async () => {
    const { config, envelopes, scheduler, transport, setNow, clock } = await buildReminderHarness();

    await envelopes.create({
      title: "3-signer NDA",
      html: "<p>hi</p>",
      signers: [
        { name: "Alice", email: "alice@example.com" },
        { name: "Bob", email: "bob@example.com" },
        { name: "Carol", email: "carol@example.com" },
      ],
    });
    expect(transport.sent).toHaveLength(3); // 3 creation emails, not a reminder

    setNow(new Date(clock().getTime() + 25 * HOUR)); // t0 + 25h — all 3 signers due
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(6); // + exactly 3 first reminders
    expect(transport.sent.slice(3).map((m) => m.to).sort()).toEqual(["alice@example.com", "bob@example.com", "carol@example.com"]);

    const auditAfterFirst = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const reminderRowsAfterFirst = auditAfterFirst.filter((r) => r.action === "envelope.reminder_sent");
    expect(reminderRowsAfterFirst).toHaveLength(3);
    expect(reminderRowsAfterFirst.every((r) => r.metadata.ok === true)).toBe(true);

    // Ticking again at the same time must not double-send (idempotent per signer).
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(6);

    setNow(new Date(clock().getTime() + 48 * HOUR)); // t0 + 73h — all 3 due for the SECOND reminder
    await scheduler.tick(clock());
    expect(transport.sent).toHaveLength(9); // + exactly 3 second reminders

    const auditFinal = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(auditFinal.filter((r) => r.action === "envelope.reminder_sent")).toHaveLength(6);
  });

  it("sends no reminders (but start()/stop() still work) when ESIG_MCP_REMINDERS is unset", async () => {
    // §16: Scheduler.start() now ALWAYS arms a timer (it also drives the
    // shared expiry tick — reminders.ts's own header comment) — the
    // assertion here is that reminder-SENDING is a no-op with an empty
    // schedule (already covered by computeDue's own "no-op with no
    // schedule" test), and that start()/stop() don't throw either way. No
    // `expiry` deps are supplied in this harness, so the expiry half of
    // tick() is itself a no-op too.
    const { scheduler } = await buildReminderHarness({ reminders: { durationsMs: [], max: 3 } });
    scheduler.start(50);
    scheduler.stop();
  });
});

// ---------- R1 (verifier finding): manual reminders never consume a scheduled slot ----------

describe("R1 — a manual esig_send_reminder call never advances/cancels the automatic schedule", () => {
  it(
    "3-signer envelope, schedule 24h/72h, max 3: 24h tick sends 3, a manual sendReminder sends 3 more, " +
      "72h tick STILL sends 3 (the manual send did not consume the 72h slot) — 9 total, 3 audit rows per " +
      "wave; a 4th (manual) attempt is then refused per signer with a clear reason",
    async () => {
      const { config, envelopes, scheduler, transport, setNow, clock } = await buildReminderHarness();

      const created = await envelopes.create({
        title: "3-signer NDA",
        html: "<p>hi</p>",
        signers: [
          { name: "Alice", email: "alice@example.com" },
          { name: "Bob", email: "bob@example.com" },
          { name: "Carol", email: "carol@example.com" },
        ],
      });
      expect(transport.sent).toHaveLength(3); // 3 creation emails, not a reminder

      // Wave 1 — scheduled, 24h.
      setNow(new Date(clock().getTime() + 25 * HOUR));
      await scheduler.tick(clock());
      expect(transport.sent).toHaveLength(6); // + exactly 3 scheduled reminders

      // Wave 2 — manual, at the same moment. Must NOT touch the 72h slot.
      const manualResult = await envelopes.sendReminder(created.envelopeId);
      expect(manualResult.sent.every((s) => s.ok === true)).toBe(true);
      expect(transport.sent).toHaveLength(9); // + exactly 3 manual reminders

      // Wave 3 — scheduled, 72h. Still fires: the manual wave above did not
      // consume this slot (the R1 bug would have made it never fire).
      setNow(new Date(clock().getTime() + 48 * HOUR));
      await scheduler.tick(clock());
      expect(transport.sent).toHaveLength(12); // + exactly 3 scheduled reminders (9 reminders + 3 creation = 12)

      const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l));
      const reminderSentRows = auditRows.filter((r) => r.action === "envelope.reminder_sent");
      expect(reminderSentRows).toHaveLength(9); // 3 signers x 3 waves, 3 audit rows per wave

      // Wave 4 — manual. Each signer has now had 3 reminders (2 scheduled +
      // 1 manual) == max — refused per signer, with a clear reason, not
      // thrown for the whole batch.
      const fourthAttempt = await envelopes.sendReminder(created.envelopeId);
      expect(fourthAttempt.sent).toHaveLength(3);
      expect(fourthAttempt.sent.every((s) => s.ok === false)).toBe(true);
      expect(fourthAttempt.sent.every((s) => /reminder limit reached/.test(s.error ?? ""))).toBe(true);
      expect(transport.sent).toHaveLength(12); // unchanged — nothing was actually sent on the refused wave
    },
  );
});

// ---------- R3 (verifier finding): a transport failure rolls back the persisted slot ----------

describe("R3 — a failed send rolls back its slot so the scheduler retries on the next tick", () => {
  /** Fails on exactly the Nth call to `send()`, succeeds on every other call. */
  class FlakyTransport {
    readonly sent: EmailMessage[] = [];
    private calls = 0;
    constructor(private readonly failOnCall: number) {}
    async send(msg: EmailMessage): Promise<SendResult> {
      this.calls += 1;
      if (this.calls === this.failOnCall) {
        throw new Error("smtp exploded (simulated, R3 test)");
      }
      this.sent.push(msg);
      return { messageId: `capture-${this.sent.length}` };
    }
  }

  it("transport fails once then succeeds — second tick sends; audit has one reminder_failed + one reminder_sent", async () => {
    // call 1 = the creation email (must succeed); call 2 = the first
    // scheduled reminder attempt (fails).
    const transport = new FlakyTransport(2);
    let currentTime = new Date();
    const clock = (): Date => currentTime;
    const setNow = (d: Date): void => {
      currentTime = d;
    };

    const config = await makeConfig({
      delivery: { kind: "email", transport: "smtp", from: "Ops <ops@example.com>" },
      reminders: { durationsMs: [24 * HOUR], max: 3 },
    });
    const stores = buildStores(config);
    const delivery = new EmailDelivery({ transport, from: "Ops <ops@example.com>" });
    const envelopes = new EnvelopeService({ config, ...stores, delivery, now: clock });
    const scheduler = new Scheduler({ envelopes, config, now: clock });

    await envelopes.create({
      title: "NDA",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    expect(transport.sent).toHaveLength(1); // creation email (call 1) succeeded

    setNow(new Date(clock().getTime() + 25 * HOUR));
    await scheduler.tick(clock()); // call 2 — fails, rolled back
    expect(transport.sent).toHaveLength(1); // still just the creation email — nothing durably sent

    // Ticking again at the SAME `now` must retry (the rollback left the
    // signer still due) — before the R3 fix this slot would already have
    // been (wrongly) marked sent, and a re-tick would never resend it.
    await scheduler.tick(clock()); // call 3 — succeeds
    expect(transport.sent).toHaveLength(2);

    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(auditRows.filter((r) => r.action === "envelope.reminder_failed")).toHaveLength(1);
    expect(auditRows.filter((r) => r.action === "envelope.reminder_sent")).toHaveLength(1);
  });
});

// ---------- esig_send_reminder (manual, MCP) ----------

async function buildMcpHarness(overrides: Parameters<typeof makeConfig>[0] = {}) {
  const transport = new CapturingTransport();
  const config = await makeConfig({
    delivery: { kind: "email", transport: "smtp", from: "Ops <ops@example.com>" },
    reminders: { durationsMs: [24 * HOUR], max: 3 },
    ...overrides,
  });
  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new EmailDelivery({ transport, from: "Ops <ops@example.com>" });
  const envelopes = new EnvelopeService({ config, ...stores, documents, delivery });
  const deps: McpServerDeps = {
    config,
    envelopes,
    documents,
    certStore: stores.certStore,
    pqKeyStore: stores.pqKeyStore,
    auditStore: stores.auditStore,
  };
  return { config, envelopes, transport, deps, mcpServer: createMcpServer(deps) };
}

async function connectedClient(mcpServer: ReturnType<typeof createMcpServer>): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

describe("esig_send_reminder — manual, via a real MCP client", () => {
  it("resends the stored link by email, audits envelope.reminder_sent, and never echoes a URL", async () => {
    const { config, transport, mcpServer } = await buildMcpHarness();
    const client = await connectedClient(mcpServer);

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "NDA",
        html: "<p>hi</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
      },
    });
    const envelopeId = (created.structuredContent as Record<string, unknown>).envelopeId as string;
    const signerId = ((created.structuredContent as Record<string, unknown>).signers as Array<{ signerId: string }>)[0]
      .signerId;
    expect(transport.sent).toHaveLength(1); // the original creation email

    const result = await client.callTool({
      name: "esig_send_reminder",
      arguments: { envelopeId, signerId },
    });
    expect(result.isError).not.toBe(true);
    expect(JSON.stringify(result)).not.toMatch(/\/sign\//);
    const structured = result.structuredContent as { sent: Array<{ signerId: string; ok: boolean; messageId?: string }> };
    expect(structured.sent).toEqual([{ signerId, ok: true, messageId: expect.any(String) }]);

    expect(transport.sent).toHaveLength(2); // creation + one manual reminder
    expect(transport.sent[1].to).toBe("alice@example.com");
    expect(transport.sent[1].html).toMatch(/https?:\/\/[^"]*\/sign\//);

    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const reminderRow = auditRows.find((r) => r.action === "envelope.reminder_sent");
    expect(reminderRow).toBeTruthy();
    expect(reminderRow.metadata.signerId).toBe(signerId);
    expect(reminderRow.metadata.ok).toBe(true);
    expect(JSON.stringify(reminderRow)).not.toMatch(/\/sign\//);

    await client.close();
  });

  // F1 (verifier finding): omitting `signerId` sends to every pending signer
  // in a per-signer loop over the SAME in-hand envelope object — before the
  // fix, the second and third signer's own persist would CAS-fail (their
  // email already sent) and get reported back as a bogus `ok:false`.
  it("3-signer envelope: esig_send_reminder with no signerId sends to all 3 pending signers — 3 ok, no failures (F1)", async () => {
    const { config, transport, mcpServer } = await buildMcpHarness();
    const client = await connectedClient(mcpServer);

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "3-signer NDA",
        html: "<p>hi</p>",
        signers: [
          { name: "Alice", email: "alice@example.com" },
          { name: "Bob", email: "bob@example.com" },
          { name: "Carol", email: "carol@example.com" },
        ],
      },
    });
    const envelopeId = (created.structuredContent as Record<string, unknown>).envelopeId as string;
    expect(transport.sent).toHaveLength(3); // 3 creation emails

    const result = await client.callTool({ name: "esig_send_reminder", arguments: { envelopeId } });
    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as { sent: Array<{ signerId: string; ok: boolean; error?: string }> };
    expect(structured.sent).toHaveLength(3);
    expect(structured.sent.every((s) => s.ok === true)).toBe(true);
    expect(structured.sent.every((s) => s.error === undefined)).toBe(true);

    expect(transport.sent).toHaveLength(6); // 3 creation + exactly 3 reminders — none dropped

    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const reminderRows = auditRows.filter((r) => r.action === "envelope.reminder_sent");
    expect(reminderRows).toHaveLength(3);
    expect(reminderRows.every((r) => r.metadata.ok === true)).toBe(true);

    await client.close();
  });

  it("is refused with a clear error when reminders are not configured", async () => {
    const { mcpServer } = await buildMcpHarness({ reminders: { durationsMs: [], max: 3 } });
    const client = await connectedClient(mcpServer);

    const created = await client.callTool({
      name: "esig_create_envelope",
      arguments: { title: "NDA", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] },
    });
    const envelopeId = (created.structuredContent as Record<string, unknown>).envelopeId as string;

    const result = await client.callTool({ name: "esig_send_reminder", arguments: { envelopeId } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toMatch(/ESIG_MCP_REMINDERS/);

    await client.close();
  });
});

// ---------- G3 (RedTeam RT-2026-08-27-05): stored links erased at terminal states ----------

function storedLinks(envelope: Envelope | null): Record<string, string> | undefined {
  return (envelope?.metadata as any)?.mcp?.delivery?.links; // eslint-disable-line @typescript-eslint/no-explicit-any
}

describe("G3 — stored signing links erased at terminal states", () => {
  it("signed (per signer) erases only that signer's own stored link; the other pending signer's link survives", async () => {
    const { config, envelopes, stores } = await buildReminderHarness();
    const created = await envelopes.create({
      title: "2-signer NDA",
      html: "<p>hi</p>",
      signers: [
        { name: "Alice", email: "alice@example.com" },
        { name: "Bob", email: "bob@example.com" },
      ],
    });
    const [aliceId, bobId] = created.signers.map((s) => s.signerId);

    const before = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(before) ?? {}).sort()).toEqual([aliceId, bobId].sort());

    // Sign Alice the way the approval page does: decrypt her stored link
    // (the only place it exists once reminders are on) to get her real
    // signing token, then call sign() with it.
    const encrypted = storedLinks(before)![aliceId];
    const { decryptKeyPem } = await import("@e-sig/core");
    const url = decryptKeyPem(Buffer.from(encrypted, "base64"), config.passphrase);
    const token = new URL(url).pathname.split("/").pop()!;

    await envelopes.sign(token, "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");

    const afterAliceSigned = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    const linksAfterAlice = storedLinks(afterAliceSigned) ?? {};
    expect(aliceId in linksAfterAlice).toBe(false); // erased
    expect(bobId in linksAfterAlice).toBe(true); // Bob still pending — his link survives
  });

  it("voided erases every stored link", async () => {
    const { config, envelopes, stores } = await buildReminderHarness();
    const created = await envelopes.create({
      title: "2-signer NDA",
      html: "<p>hi</p>",
      signers: [
        { name: "Alice", email: "alice@example.com" },
        { name: "Bob", email: "bob@example.com" },
      ],
    });
    const before = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(before) ?? {})).toHaveLength(2);

    await envelopes.void(created.envelopeId);

    const after = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(after) ?? {})).toHaveLength(0);
  });

  it("declined erases every stored link (declineEnvelope voids the whole envelope)", async () => {
    const { config, envelopes, stores } = await buildReminderHarness();
    const created = await envelopes.create({
      title: "2-signer NDA",
      html: "<p>hi</p>",
      signers: [
        { name: "Alice", email: "alice@example.com" },
        { name: "Bob", email: "bob@example.com" },
      ],
    });
    const before = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    const aliceId = created.signers[0].signerId;
    const encrypted = storedLinks(before)![aliceId];
    const { decryptKeyPem } = await import("@e-sig/core");
    const url = decryptKeyPem(Buffer.from(encrypted, "base64"), config.passphrase);
    const token = new URL(url).pathname.split("/").pop()!;

    await envelopes.decline(token, "changed my mind");

    const after = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(after) ?? {})).toHaveLength(0);
  });

  it("expired (via the shared expiry tick) erases every stored link", async () => {
    const { config, envelopes, stores, clock } = await buildReminderHarness();
    const created = await envelopes.create({
      title: "Expiring NDA",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      expiresAt: new Date(clock().getTime() + 60_000),
    });
    const before = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(before) ?? {})).toHaveLength(1);

    const deps = { store: stores.envelopeStore, auditStore: stores.auditStore, dataDir: config.dataDir, tenantId: config.tenant };
    await expiryTick(deps, new Date(clock().getTime() + 120_000));

    const after = await stores.envelopeStore.findById(config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(after) ?? {})).toHaveLength(0);
  });

  it("purges stale reminder links once, on the first tick, when reminders are OFF this run — links a prior (reminders-on) run left behind", async () => {
    const dataDir = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-g3-purge-"));
    const withReminders = await buildReminderHarness({ dataDir, docsRoot: path.join(dataDir, "inbox") });
    const created = await withReminders.envelopes.create({
      title: "NDA",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const before = await withReminders.stores.envelopeStore.findById(withReminders.config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(before) ?? {})).toHaveLength(1);

    // A SEPARATE harness over the SAME dataDir/tenant, reminders OFF —
    // simulates a restart with ESIG_MCP_REMINDERS unset.
    const noReminders = await buildReminderHarness({
      dataDir,
      docsRoot: path.join(dataDir, "inbox"),
      reminders: { durationsMs: [], max: 3 },
    });
    await noReminders.scheduler.tick(noReminders.clock());

    const after = await noReminders.stores.envelopeStore.findById(noReminders.config.tenant, created.envelopeId);
    expect(Object.keys(storedLinks(after) ?? {})).toHaveLength(0);
  });
});
