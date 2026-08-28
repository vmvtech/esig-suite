// events/expiry.ts
//
// §16 "`envelope.expired` is emitted once by a lazy expiry tick (core
// expires on token resolution; the scheduler catches the rest)".
//
// Core already expires an envelope LAZILY, but only ever on token
// resolution: `resolveSigningToken` (packages/esig-core/src/envelope.ts:
// 190-195) flips `status` to `"expired"` and persists it the moment anyone
// resolves a signing token past `expiresAt` — but that path never touches
// this package's event log, and an envelope nobody happens to poll (no
// signer ever revisits an expired link) would sit expired-but-silent
// forever. `tick()` below is the catch-all this package's 60s scheduler
// (reminders.ts's `Scheduler`, shared per the ticket) runs every pass. Two
// cases, same emission:
//
//   1. An envelope still `"sent"`/`"partially_signed"` whose `expiresAt` has
//      already passed, never resolved by anyone — this function mirrors
//      core's OWN lazy-expiry assignment verbatim (`envelope.ts:192`,
//      `status = "expired"`; core exposes no standalone `expireEnvelope()`
//      helper to call instead, only the inline check inside
//      `resolveSigningToken`) and persists it.
//   2. An envelope core's lazy path ALREADY expired (some signer resolved
//      an expired token before this tick ever ran) but whose
//      `envelope.expired` event was never emitted — caught by the
//      `expiredEmittedAt` flag (metadata.mcp.expiredEmittedAt, ISO-8601)
//      being absent.
//
// Either way, `envelope.expired` fires exactly ONCE per envelope, guarded
// by that persisted flag (the ticket's own wording) rather than by scanning
// the capped/trimmable event log for a prior occurrence.

import type { AuditLogStore, Envelope, EnvelopeStore } from "@e-sig/core";

import { listEnvelopes } from "../stores.js";
import { appendEvent } from "./log.js";
import type { EventQueue } from "./queue.js";

export interface ExpiryTickDeps {
  store: EnvelopeStore;
  auditStore: AuditLogStore;
  dataDir: string;
  tenantId: string;
  /** Present only when a webhook is configured (bin.ts) — an emitted `envelope.expired` is enqueued for delivery the same way every other emission site enqueues one. */
  eventQueue?: EventQueue;
}

interface ExpiryMetadataBucket {
  mcp?: { expiredEmittedAt?: string; delivery?: { links?: Record<string, string>; [key: string]: unknown }; [key: string]: unknown };
  [key: string]: unknown;
}

function expiredEmittedAt(envelope: Envelope): string | undefined {
  return (envelope.metadata as ExpiryMetadataBucket | undefined)?.mcp?.expiredEmittedAt;
}

function markExpiredEmitted(envelope: Envelope, at: string): void {
  const metadata = (envelope.metadata ?? {}) as ExpiryMetadataBucket;
  const mcp = (metadata.mcp ?? {}) as Record<string, unknown>;
  mcp.expiredEmittedAt = at;
  metadata.mcp = mcp;
  envelope.metadata = metadata;
}

/**
 * RedTeam RT-2026-08-27-05 G3: expiry is terminal for the whole envelope —
 * erase every stored §15 signing link (envelopes.ts's own `eraseStoredLinks`
 * duplicated narrowly here, matching this module's existing pattern of a
 * local, narrow view over the shared `metadata.mcp` bag rather than
 * importing envelopes.ts's private types — see `ExpiryMetadataBucket`
 * above). No-op if there is nothing to erase.
 */
function eraseStoredLinks(envelope: Envelope): void {
  const metadata = envelope.metadata as ExpiryMetadataBucket | undefined;
  const links = metadata?.mcp?.delivery?.links;
  if (!links || Object.keys(links).length === 0) return;
  const mcp = { ...metadata!.mcp };
  mcp.delivery = { ...mcp.delivery, links: {} };
  envelope.metadata = { ...metadata, mcp };
}

function isLive(envelope: Envelope): boolean {
  return envelope.status === "sent" || envelope.status === "partially_signed";
}

function isPastExpiry(envelope: Envelope, now: Date): boolean {
  return envelope.expiresAt !== undefined && envelope.expiresAt.getTime() <= now.getTime();
}

async function expireOne(deps: ExpiryTickDeps, envelopeId: string, now: Date): Promise<void> {
  const result = await appendEvent({
    store: deps.store,
    auditStore: deps.auditStore,
    tenantId: deps.tenantId,
    envelopeId,
    now: () => now,
    build: (envelope) => {
      if (isLive(envelope) && isPastExpiry(envelope, now)) {
        // Mirror core's own lazy expiry assignment verbatim
        // (packages/esig-core/src/envelope.ts:190-195, resolveSigningToken).
        envelope.status = "expired";
      } else if (envelope.status !== "expired") {
        return false; // raced past expiry some other way (voided/completed since this tick started) — nothing to emit
      }
      if (expiredEmittedAt(envelope) !== undefined) return false; // already emitted (persisted flag) — no-op

      markExpiredEmitted(envelope, now.toISOString());
      eraseStoredLinks(envelope); // G3
      return { type: "envelope.expired", envelopeId: envelope.id, phase: "expired", data: {} };
    },
  });

  if (!result.event) return; // idempotency guard fired — nothing new happened

  await deps.auditStore.insert({
    tenantId: deps.tenantId,
    action: "envelope.expired",
    targetTable: "envelope",
    targetId: envelopeId,
  });
  await deps.eventQueue?.enqueue(result.event);
}

/**
 * One pass over every envelope this tenant owns (same Fs-backed
 * `listEnvelopes` limitation as the reminder scheduler and
 * `esig_list_envelopes` — stores.ts's own header note). A single envelope's
 * expiry failure is logged to stderr and never aborts the rest of the tick
 * (mirrors `Scheduler.tick`'s own per-envelope isolation, reminders.ts).
 */
export async function tick(deps: ExpiryTickDeps, now: Date): Promise<void> {
  const all = await listEnvelopes(deps.dataDir, deps.tenantId);
  for (const envelope of all) {
    const candidate = (isLive(envelope) && isPastExpiry(envelope, now)) || (envelope.status === "expired" && expiredEmittedAt(envelope) === undefined);
    if (!candidate) continue;
    try {
      await expireOne(deps, envelope.id, now);
    } catch (e) {
      process.stderr.write(
        `[esig-mcp] WARNING: expiry tick failed for envelope ${envelope.id}: ${e instanceof Error ? e.message : String(e)}\n`,
      );
    }
  }
}
