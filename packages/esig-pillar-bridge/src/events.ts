// events.ts
//
// `PillarEventSink` implements the `EventSink` contract (types.ts) by
// sealing each lifecycle event as a wire-kind `esig:event` Pillar envelope
// to every configured subscriber. docs/architecture/esig-mcp.md §17 seam 4.
//
// PII/secret minimization: the sealed payload is `{v:1, event}` — the
// `EsigEvent` shape itself (docs/architecture/esig-mcp.md §16: "never
// links, tokens, proofs, or document bytes" in `data`) — this module adds
// nothing else to the payload, so it inherits that discipline from
// whatever produced the event rather than re-deriving it here.

import { loadPillar } from "./shim.js";
import { localIdFromEd25519Key } from "./identity.js";
import type { PillarIdentity } from "./identity.js";
import { CarrierClient } from "./carrier.js";
import type { EsigEvent, EventSink } from "./types.js";
import type { PillarModules } from "./pillar-types.js";

const HEX64 = /^[0-9a-f]{64}$/i;

export interface PillarEventSubscriber {
  uuaid: string;
  publicKey: string;
}

export interface PillarEventReceipt {
  uuaid: string;
  ok: boolean;
  detail?: string;
  messageId?: string;
}

export interface PillarEventSinkOptions {
  identity: PillarIdentity;
  carriers: string[];
  subscribers: PillarEventSubscriber[];
  timeoutMs?: number;
  /**
   * `EventSink.publish` returns `Promise<void>` (types.ts) — this is the
   * only way to observe the per-subscriber outcome the design calls for.
   * Never throws from within `publish()`.
   */
  onReceipt?: (receipt: PillarEventReceipt) => void;
}

export class PillarEventSink implements EventSink {
  private constructor(
    private readonly pillar: PillarModules,
    private readonly identity: PillarIdentity,
    private readonly carrier: CarrierClient,
    private readonly subscribers: PillarEventSubscriber[],
    private readonly timeoutMs: number | undefined,
    private readonly onReceipt: ((receipt: PillarEventReceipt) => void) | undefined
  ) {}

  static async open(opts: PillarEventSinkOptions): Promise<PillarEventSink> {
    const pillar = await loadPillar();
    const carrier = await CarrierClient.open({ identity: opts.identity, carriers: opts.carriers });
    return new PillarEventSink(pillar, opts.identity, carrier, opts.subscribers, opts.timeoutMs, opts.onReceipt);
  }

  async publish(event: EsigEvent): Promise<void> {
    for (const sub of this.subscribers) {
      const receipt = await this.publishOne(event, sub);
      this.onReceipt?.(receipt);
    }
  }

  private async publishOne(event: EsigEvent, sub: PillarEventSubscriber): Promise<PillarEventReceipt> {
    if (!HEX64.test(sub.publicKey)) {
      return { uuaid: sub.uuaid, ok: false, detail: `publicKey must be 64 lowercase hex chars, got ${JSON.stringify(sub.publicKey)}` };
    }
    const derived = localIdFromEd25519Key(Buffer.from(sub.publicKey, "hex"));
    if (derived !== sub.uuaid.split(":")[3]) {
      return { uuaid: sub.uuaid, ok: false, detail: `publicKey does not derive ${sub.uuaid}` };
    }
    try {
      const envelope = this.pillar.envelope.seal(this.identity._keychain(), {
        recipient: sub.uuaid,
        recipientPublicKey: sub.publicKey,
        kind: "esig:event",
        payload: { v: 1, event },
      });
      const result = await this.carrier.deliver(envelope, { timeoutMs: this.timeoutMs });
      return { uuaid: sub.uuaid, ok: true, messageId: `${envelope.id}#${result.seq}` };
    } catch (err) {
      return { uuaid: sub.uuaid, ok: false, detail: err instanceof Error ? err.message : String(err) };
    }
  }
}
