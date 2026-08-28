// events/log.ts
//
// §16 "Event log": every state change appends an event to
// `metadata.mcp.events[]`, capped at 200 — oldest entries trimmed off and
// their ids recorded in an `events.trimmed` audit row. Two layers, same
// split as `identity/challenge.ts`'s `issueChallenge`/`finalizeChallenge`:
//
//   - `appendEventInMemory` — pure, synchronous: push + cap onto an
//     already-in-hand `Envelope` object. No I/O.
//   - `appendEvent` — the real entry point every emission site calls. Reads
//     the envelope FRESH from the store, lets the caller's `build` callback
//     both mutate it (for state this emission ALSO persists — e.g. flipping
//     `status` to "expired", or recording a signer's `viewedAt`) and decide
//     the event to append (or skip entirely, for idempotency guards like
//     "already viewed" / "already expired-and-notified" — `build` returns
//     `false`), then writes it back. On a concurrent-update conflict
//     (`ConcurrencySafeEnvelopeStore`, stores.ts — I3 class) it retries from
//     a fresh read, bounded, the exact pattern `finalizeChallenge` already
//     uses for the same reason: "under the store mutex" (the ticket's
//     wording) is `EnvelopeStore.update()` funnelling through that store's
//     single per-file mutex — this function's job is the read-CAS-write
//     loop around it, not a second lock of its own.
//
// A fresh-by-id read (rather than taking the caller's in-hand `Envelope`
// object directly) is deliberate: several callers (expiry, viewed) need to
// re-apply their OWN mutation on every retry attempt too (a stale in-memory
// object would silently drop it on conflict), and every other caller has
// already durably persisted its primary state change via its own earlier
// `store.update()` before ever calling this — so a fresh read reflects
// exactly what they just wrote.

import crypto from "node:crypto";

import type { AuditLogStore, Envelope, EnvelopeStore } from "@e-sig/core";

import type { EsigEvent, EsigEventInput } from "./types.js";

export const MAX_EVENTS = 200;

interface EventsMetadataBucket {
  mcp?: { events?: EsigEvent[]; [key: string]: unknown };
  [key: string]: unknown;
}

function eventsOf(envelope: Envelope): EsigEvent[] {
  const mcp = (envelope.metadata as EventsMetadataBucket | undefined)?.mcp;
  return Array.isArray(mcp?.events) ? mcp!.events! : [];
}

function setEvents(envelope: Envelope, events: EsigEvent[]): void {
  const metadata = (envelope.metadata ?? {}) as EventsMetadataBucket;
  const mcp = (metadata.mcp ?? {}) as Record<string, unknown>;
  mcp.events = events;
  metadata.mcp = mcp;
  envelope.metadata = metadata;
}

/** Every event on `envelope`, oldest first, optionally filtered to `createdAt > since` (exclusive — pass the `createdAt` of the last event you've already seen). */
export function listEvents(envelope: Envelope, since?: string): EsigEvent[] {
  const all = eventsOf(envelope);
  return since ? all.filter((e) => e.createdAt > since) : all;
}

/**
 * Pure: push `input` (already stamped with `id`/`createdAt`) onto
 * `envelope`'s in-memory event log, capping at {@link MAX_EVENTS}. Returns
 * the events trimmed off the front so the caller can audit their ids
 * (`events.trimmed`) — never the events themselves, which may carry PII
 * (signer name/email in `signer`).
 */
function appendEventInMemory(envelope: Envelope, input: EsigEventInput, id: string, createdAt: string): { event: EsigEvent; trimmed: EsigEvent[] } {
  const event: EsigEvent = { id, createdAt, ...input };
  const next = [...eventsOf(envelope), event];
  let trimmed: EsigEvent[] = [];
  if (next.length > MAX_EVENTS) {
    trimmed = next.splice(0, next.length - MAX_EVENTS);
  }
  setEvents(envelope, next);
  return { event, trimmed };
}

export interface AppendEventInput {
  store: EnvelopeStore;
  auditStore: AuditLogStore;
  tenantId: string;
  envelopeId: string;
  now?: () => Date;
  /**
   * Called with the freshly-read envelope on every attempt (including
   * retries). Mutate it in place for any additional state this emission
   * also persists, then return the event to append — or `false` to skip
   * this emission entirely (no event, no write): the idempotency guards
   * `envelope.viewed`/`envelope.expired` use this to no-op once the signer/
   * envelope has already been marked, even under a concurrent retry.
   */
  build: (envelope: Envelope) => EsigEventInput | false;
}

const MAX_ATTEMPTS = 5;

/** See the module header comment. */
export async function appendEvent(input: AppendEventInput): Promise<{ envelope: Envelope; event?: EsigEvent }> {
  const now = input.now ?? (() => new Date());
  let lastError: unknown;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const envelope = await input.store.findById(input.tenantId, input.envelopeId);
    if (!envelope) throw new Error(`envelope not found: ${input.envelopeId}`);

    const built = input.build(envelope);
    if (built === false) return { envelope };

    const id = crypto.randomUUID();
    const createdAt = now().toISOString();
    const { event, trimmed } = appendEventInMemory(envelope, built, id, createdAt);

    try {
      const updated = await input.store.update(envelope);
      if (trimmed.length > 0) {
        await input.auditStore.insert({
          tenantId: input.tenantId,
          action: "events.trimmed",
          targetTable: "envelope",
          targetId: input.envelopeId,
          metadata: { trimmedIds: trimmed.map((e) => e.id) },
        });
      }
      return { envelope: updated, event };
    } catch (e) {
      lastError = e;
      // A concurrent writer won the CAS (EnvelopeConflictError, or any other
      // store failure) — retry from a fresh read, same as
      // identity/challenge.ts's finalizeChallenge.
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error(`could not append event for envelope ${input.envelopeId} (concurrent update contention)`);
}
