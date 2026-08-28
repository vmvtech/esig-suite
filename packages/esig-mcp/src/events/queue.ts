// events/queue.ts
//
// §16 "At-least-once with backoff": every event is persisted to
// `<DATA_DIR>/events/queue/<eventId>.json` BEFORE any delivery attempt is
// ever made. `enqueue()` only ever writes this file — it never calls the
// webhook itself, so it can never block or delay the HTTP handler that
// triggered the emission (the ticket's own wording: "Delivery must never
// block or delay the HTTP handlers"). A separate `tick()` (run on its own
// timer via `start()`/`stop()`, or driven directly by tests with an
// injected clock/backoff) delivers due events IN ORDER PER ENVELOPE: for
// each envelope with at least one pending event, only the OLDEST is ever
// attempted in a given tick — the next one is never even looked at until
// the oldest has been delivered (moved to `events/delivered/`) or
// dead-lettered (marked `status:"dead"` in place). That single rule is what
// keeps a multi-event envelope's deliveries strictly ordered with no extra
// bookkeeping.
//
// Restart safety is inherent, not a separate code path: `tick()` always
// re-reads the queue directory from scratch, so a brand-new `EventQueue`
// constructed over the same `dataDir` after a restart picks up every
// still-pending file exactly where the last process left it.

import { promises as fs } from "node:fs";
import path from "node:path";

import type { AuditLogStore } from "@e-sig/core";

import type { EsigEvent } from "./types.js";
import { sendWebhook, type LookupFn, type PinnedRequestFn, type WebhookConfig } from "./webhook.js";

/** 1m → 2m → 4m → 8m → 16m → 32m, matching the default `ESIG_MCP_EVENTS_WEBHOOK_URL` retry schedule in the design doc. */
export const DEFAULT_BACKOFF_SEC = [60, 120, 240, 480, 960, 1920];

/** How long a delivered receipt is kept under `events/delivered/` before being pruned (best-effort, swept once per tick). */
const DELIVERED_RETENTION_MS = 24 * 60 * 60 * 1000;

interface QueueFile {
  event: EsigEvent;
  attempts: number;
  /** ISO-8601 — this event is not attempted again before this time. */
  nextAt: string;
  status: "pending" | "dead";
}

interface DeliveredFile {
  event: EsigEvent;
  attempts: number;
  deliveredAt: string;
}

export interface EventQueueDeps {
  dataDir: string;
  webhook: WebhookConfig;
  auditStore: AuditLogStore;
  tenantId: string;
  packageVersion: string;
  /** Default {@link DEFAULT_BACKOFF_SEC}. Injectable so tests don't wait real minutes. */
  backoffSec?: number[];
  /** Injectable clock, for deterministic tests. */
  now?: () => Date;
  /** Injectable fetch, for deterministic tests (a local receiver, a failing-then-succeeding stub, ...) — used only on `sendWebhook`'s unpinned (`allowPrivateWebhook`) path. */
  fetchImpl?: typeof fetch;
  /** Injectable DNS lookup, for deterministic tests (e.g. a DNS-rebinding TOCTOU stub — G1(d)). Defaults to `dns.promises.lookup`. */
  lookupFn?: LookupFn;
  /** Injectable pinned-request implementation, for deterministic tests of `sendWebhook`'s pinned (G1(c)) path without a real socket. */
  requestImpl?: PinnedRequestFn;
}

export interface EventDeliveryStatus {
  status: "pending" | "delivered" | "dead";
  attempts: number;
}

export class EventQueue {
  private readonly queueDir: string;
  private readonly deliveredDir: string;
  private readonly backoffSec: number[];
  private readonly now: () => Date;
  private timer?: NodeJS.Timeout;
  private ticking = false;

  constructor(private readonly deps: EventQueueDeps) {
    this.queueDir = path.join(deps.dataDir, "events", "queue");
    this.deliveredDir = path.join(deps.dataDir, "events", "delivered");
    this.backoffSec = deps.backoffSec ?? DEFAULT_BACKOFF_SEC;
    this.now = deps.now ?? (() => new Date());
  }

  /** Persist `event` to the queue BEFORE any delivery attempt (see the module header comment). Enqueue-only — never delivers, never touches the network. */
  async enqueue(event: EsigEvent): Promise<void> {
    await fs.mkdir(this.queueDir, { recursive: true, mode: 0o700 });
    await fs.chmod(this.queueDir, 0o700).catch(() => {});
    const file: QueueFile = { event, attempts: 0, nextAt: this.now().toISOString(), status: "pending" };
    await this.writeAtomic(path.join(this.queueDir, `${event.id}.json`), file);
  }

  private async writeAtomic(target: string, value: unknown): Promise<void> {
    const tmp = `${target}.${process.pid}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(value, null, 2), { encoding: "utf8", mode: 0o600 });
    await fs.rename(tmp, target);
  }

  private async readQueueFiles(): Promise<Array<{ file: string; data: QueueFile }>> {
    let names: string[];
    try {
      names = await fs.readdir(this.queueDir);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw e;
    }
    const out: Array<{ file: string; data: QueueFile }> = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      const file = path.join(this.queueDir, name);
      try {
        out.push({ file, data: JSON.parse(await fs.readFile(file, "utf8")) as QueueFile });
      } catch {
        // A torn write from a crash mid-`writeAtomic` should not happen in
        // practice (rename only follows a completed write) — skip rather
        // than fail the whole tick either way.
      }
    }
    return out;
  }

  /**
   * One delivery pass: for every envelope with at least one PENDING queued
   * event, attempt only the oldest (by `event.createdAt`) if it is due —
   * see the module header comment for why this preserves per-envelope
   * ordering with no extra bookkeeping. Also sweeps `events/delivered/` for
   * anything past its 24h retention. A single event's delivery failure
   * never aborts the rest of the tick; re-entrant calls (a slow receiver
   * still running when the next timer fires) are no-ops.
   */
  async tick(): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    try {
      const pending = (await this.readQueueFiles()).filter((f) => f.data.status === "pending");
      const byEnvelope = new Map<string, Array<{ file: string; data: QueueFile }>>();
      for (const f of pending) {
        const list = byEnvelope.get(f.data.event.envelopeId) ?? [];
        list.push(f);
        byEnvelope.set(f.data.event.envelopeId, list);
      }

      const now = this.now();
      for (const list of byEnvelope.values()) {
        list.sort((a, b) => a.data.event.createdAt.localeCompare(b.data.event.createdAt));
        const head = list[0];
        if (new Date(head.data.nextAt).getTime() > now.getTime()) continue; // not due yet
        try {
          await this.attempt(head.file, head.data);
        } catch (e) {
          process.stderr.write(
            `[esig-mcp] WARNING: webhook delivery attempt failed for event ${head.data.event.id}: ${e instanceof Error ? e.message : String(e)}\n`,
          );
        }
      }

      await this.pruneDelivered(now);
    } finally {
      this.ticking = false;
    }
  }

  private async attempt(file: string, data: QueueFile): Promise<void> {
    const attempts = data.attempts + 1;
    try {
      await sendWebhook(this.deps.webhook, data.event, this.deps.packageVersion, {
        fetchImpl: this.deps.fetchImpl,
        lookupFn: this.deps.lookupFn,
        requestImpl: this.deps.requestImpl,
      });
      const delivered: DeliveredFile = { event: data.event, attempts, deliveredAt: this.now().toISOString() };
      await fs.mkdir(this.deliveredDir, { recursive: true, mode: 0o700 });
      await fs.chmod(this.deliveredDir, 0o700).catch(() => {});
      await this.writeAtomic(path.join(this.deliveredDir, `${data.event.id}.json`), delivered);
      await fs.rm(file, { force: true });
    } catch {
      if (attempts >= this.backoffSec.length) {
        const dead: QueueFile = { ...data, attempts, status: "dead" };
        await this.writeAtomic(file, dead);
        await this.deps.auditStore.insert({
          tenantId: this.deps.tenantId,
          action: "webhook.dead_lettered",
          targetTable: "envelope",
          targetId: data.event.envelopeId,
          metadata: { eventId: data.event.id, eventType: data.event.type, attempts },
        });
        return;
      }
      const waitSec = this.backoffSec[attempts - 1];
      const nextAt = new Date(this.now().getTime() + waitSec * 1000).toISOString();
      const retried: QueueFile = { ...data, attempts, nextAt, status: "pending" };
      await this.writeAtomic(file, retried);
    }
  }

  private async pruneDelivered(now: Date): Promise<void> {
    let names: string[];
    try {
      names = await fs.readdir(this.deliveredDir);
    } catch {
      return;
    }
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      const file = path.join(this.deliveredDir, name);
      try {
        const data = JSON.parse(await fs.readFile(file, "utf8")) as DeliveredFile;
        if (now.getTime() - Date.parse(data.deliveredAt) > DELIVERED_RETENTION_MS) {
          await fs.rm(file, { force: true });
        }
      } catch {
        // best-effort cleanup only
      }
    }
  }

  /** `esig_list_events`'s per-event delivery status: `pending`/`dead` (queue/), `delivered` (delivered/), or `undefined` when neither file exists (webhook not configured, event never enqueued, or a delivered receipt already pruned past 24h). */
  async statusOf(eventId: string): Promise<EventDeliveryStatus | undefined> {
    try {
      const data = JSON.parse(await fs.readFile(path.join(this.queueDir, `${eventId}.json`), "utf8")) as QueueFile;
      return { status: data.status, attempts: data.attempts };
    } catch {
      // fall through to delivered/
    }
    try {
      const data = JSON.parse(await fs.readFile(path.join(this.deliveredDir, `${eventId}.json`), "utf8")) as DeliveredFile;
      return { status: "delivered", attempts: data.attempts };
    } catch {
      return undefined;
    }
  }

  start(intervalMs = 5_000): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.tick();
    }, intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
