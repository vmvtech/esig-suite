// events/sinks.ts
//
// §17 seam 4 "Events over Pillar (EventSink = pillar)" — the fan-out surface
// esig-mcp exposes so an optional bridge (e.g. `@e-sig/pillar-bridge`) can
// subscribe to every lifecycle event alongside the existing webhook queue
// (§16), WITHOUT `@e-sig/mcp` depending on it: `EventSink` below is
// structurally identical to the bridge contract
// (packages/esig-pillar-bridge/src/types.ts `EventSink`, lines 79-81) — same
// shape, defined locally so this package carries no import of the bridge
// package (docs/architecture/esig-mcp.md §17 "Packaging decision").
//
// `EventDispatcher` is purely additive: `EnvelopeService.emit()` (envelopes.ts)
// calls `dispatch()` AFTER it has already enqueued the event for webhook
// delivery (§16) — a sink failure never blocks the webhook queue, another
// sink, or the caller. Each sink runs in its own try/catch; a failure is
// audited as `events.sink_failed` (never thrown).

import type { AuditLogStore } from "@e-sig/core";

import type { EsigEvent } from "./types.js";

/** A pluggable sink that publishes lifecycle events — structurally identical to `@e-sig/pillar-bridge`'s `EventSink` (types.ts:79-81). */
export interface EventSink {
  publish(event: EsigEvent): Promise<void>;
}

export interface EventDispatcherDeps {
  auditStore: AuditLogStore;
  tenantId: string;
  /** Initial set of sinks. `register()` can add more later (bin.ts registers the Pillar sink only once the optional bridge module has loaded). */
  sinks?: EventSink[];
}

/** Fans one event out to every registered sink, in order, with per-sink isolation (see the module header comment). */
export class EventDispatcher {
  readonly sinks: EventSink[];

  constructor(private readonly deps: EventDispatcherDeps) {
    this.sinks = deps.sinks ?? [];
  }

  /** Add a sink after construction. */
  register(sink: EventSink): void {
    this.sinks.push(sink);
  }

  /**
   * Publish `event` to every sink. Never throws: a sink that rejects is
   * caught, audited as `events.sink_failed` (best-effort — an audit-insert
   * failure itself is swallowed to stderr, never propagated), and the loop
   * continues to the next sink.
   */
  async dispatch(event: EsigEvent): Promise<void> {
    for (const sink of this.sinks) {
      try {
        await sink.publish(event);
      } catch (e) {
        const detail = e instanceof Error ? e.message : String(e);
        try {
          await this.deps.auditStore.insert({
            tenantId: this.deps.tenantId,
            action: "events.sink_failed",
            targetTable: "envelope",
            targetId: event.envelopeId,
            metadata: { eventId: event.id, eventType: event.type, error: detail },
          });
        } catch {
          process.stderr.write(
            `[esig-mcp] WARNING: events.sink_failed (and its own audit insert also failed) for event ${event.id}: ${detail}\n`,
          );
        }
      }
    }
  }
}
