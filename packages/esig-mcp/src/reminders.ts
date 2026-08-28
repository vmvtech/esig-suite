// reminders.ts
//
// §15 "Reminders": a pure `computeDue()` (envelope + clock + schedule + max
// in, due signers out — no I/O, fully unit-testable with an injected clock)
// plus `Scheduler`, the in-process 60s-tick loop `bin.ts` starts/stops. All
// the actual sending/persistence/audit logic lives on `EnvelopeService`
// (`sendScheduledReminder` -> private `sendOneReminder`, envelopes.ts) —
// this module only decides WHEN, never HOW.
//
// §16 "envelope.expired is emitted once by a lazy expiry tick" — the ticket
// explicitly asks for the expiry tick to SHARE this same 60s loop rather
// than run its own timer, so `Scheduler.tick()` below also calls
// `events/expiry.ts`'s `tick()` on every pass. Unlike reminder-sending
// (off entirely with no `ESIG_MCP_REMINDERS`), expiry must run regardless
// of whether reminders are configured — `start()` therefore always arms the
// timer now; only reminder-SENDING inside `tick()` is still gated on
// `config.reminders.durationsMs.length > 0`. `expiry` is optional purely so
// existing harnesses that only care about reminders (most tests) don't need
// to supply store/auditStore/dataDir plumbing they don't use — `bin.ts`
// always supplies it.

import type { Envelope } from "@e-sig/core";

import type { Config } from "./config.js";
import type { EnvelopeService } from "./envelopes.js";
import { tick as expiryTick, type ExpiryTickDeps } from "./events/expiry.js";
import { listEnvelopes } from "./stores.js";

export interface ReminderDueEntry {
  signerId: string;
  /** 0-based index into the configured duration schedule — which scheduled reminder this is. */
  index: number;
}

/**
 * Pure. For one envelope, which currently-pending signers have a reminder
 * due right now, and which schedule index it is.
 *
 * - Skips the envelope entirely once it is voided/expired/completed (no
 *   pending signer left to remind).
 * - Skips any individual signer who is not `"pending"` (declined, or already
 *   signed on a partially-signed multi-signer envelope).
 * - Reminder N (0-based) is due at `envelope.createdAt + scheduleMs[N]` —
 *   durations are offsets from the ORIGINAL send time, not cumulative from
 *   the previous reminder (§15: "durations after send").
 * - Never sends more than `min(max, scheduleMs.length)` SCHEDULED reminders
 *   to one signer, counting only `sentAt` (never `manualSentAt` — R1 fix,
 *   verifier finding: a manual `esig_send_reminder` call must never advance
 *   or cancel the automatic schedule). `max` is still an overall spam bound
 *   across BOTH kinds combined: once `sentAt.length + manualSentAt.length`
 *   reaches `max`, no further reminder (scheduled or manual) is sent to that
 *   signer, even if the schedule itself has entries left.
 */
export function computeDue(envelope: Envelope, now: Date, scheduleMs: number[], max: number): ReminderDueEntry[] {
  const due: ReminderDueEntry[] = [];
  if (scheduleMs.length === 0) return due;
  if (envelope.status === "voided" || envelope.status === "expired" || envelope.status === "completed") return due;

  const baseTime = envelope.createdAt.getTime();
  const nowTime = now.getTime();

  for (const signer of envelope.signers) {
    if (signer.status !== "pending") continue;
    const meta = (
      envelope.metadata as
        | { mcp?: { delivery?: { reminders?: Record<string, { sentAt: string[]; manualSentAt?: string[] }> } } }
        | undefined
    )?.mcp?.delivery?.reminders?.[signer.id];
    const sentCount = meta?.sentAt.length ?? 0; // scheduled sends only — drives the schedule index
    const manualCount = meta?.manualSentAt?.length ?? 0;
    if (sentCount >= scheduleMs.length) continue; // schedule itself exhausted
    if (sentCount + manualCount >= max) continue; // overall spam bound reached (scheduled + manual combined)
    const dueAt = baseTime + scheduleMs[sentCount];
    if (nowTime >= dueAt) {
      due.push({ signerId: signer.id, index: sentCount });
    }
  }
  return due;
}

export interface SchedulerDeps {
  envelopes: EnvelopeService;
  config: Config;
  /** §16: run on every tick, sharing this 60s loop — see the module header comment. `bin.ts` always supplies this; tests that only exercise reminders can omit it. */
  expiry?: ExpiryTickDeps;
  now?: () => Date;
}

/** The `bin.ts`-owned 60s-default tick loop: reminder-sending (a no-op with no `ESIG_MCP_REMINDERS` configured) plus the §16 expiry tick (always runs, when `expiry` deps are supplied). */
export class Scheduler {
  private timer?: NodeJS.Timeout;
  private readonly now: () => Date;
  /** RedTeam RT-2026-08-27-05 G3: "purge any stored links on first tick" when reminders are not configured — a one-shot flag so the sweep runs exactly once, not on every tick. */
  private purgedStaleLinks = false;

  constructor(private readonly deps: SchedulerDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  start(intervalMs = 60_000): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.tick(this.now());
    }, intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** One pass: reminder-sending (skipped entirely with no schedule configured) over every envelope this tenant owns (Fs-backed `listEnvelopes` — same limitation as `esig_list_envelopes`, stores.ts's own header note), then the §16 expiry tick. A single envelope/signer's reminder failure is logged to stderr and never aborts the rest of the tick; `events/expiry.ts`'s own `tick()` applies the identical per-envelope isolation. */
  async tick(now: Date): Promise<void> {
    const { config, envelopes, expiry } = this.deps;

    if (config.reminders.durationsMs.length > 0) {
      const all = await listEnvelopes(config.dataDir, config.tenant);
      for (const envelope of all) {
        const due = computeDue(envelope, now, config.reminders.durationsMs, config.reminders.max);
        for (const entry of due) {
          try {
            await envelopes.sendScheduledReminder(envelope, entry.signerId);
          } catch (e) {
            process.stderr.write(
              `[esig-mcp] WARNING: scheduled reminder failed for envelope ${envelope.id} signer ` +
                `${entry.signerId}: ${e instanceof Error ? e.message : String(e)}\n`,
            );
          }
        }
      }
    } else if (!this.purgedStaleLinks) {
      // G3: reminders are OFF on this run — any signing links a PRIOR run
      // (with reminders configured) left encrypted at rest can never be read
      // again; purge them once, on this first tick, rather than leaving that
      // ciphertext on disk indefinitely.
      this.purgedStaleLinks = true;
      try {
        await envelopes.purgeStaleReminderLinks();
      } catch (e) {
        process.stderr.write(
          `[esig-mcp] WARNING: stale reminder-link purge failed: ${e instanceof Error ? e.message : String(e)}\n`,
        );
      }
    }

    if (expiry) await expiryTick(expiry, now);
  }
}
