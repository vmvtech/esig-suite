// carrier.ts
//
// A thin wrapper over Pillar's real `CarrierClient` (net/carrier-client.mjs)
// — HTTP(S)-only delivery/inbox-polling against one or more carrier servers
// (default `https://pillar.uuaid.org`). Mirrors the real class's signed-auth
// scheme exactly (it does the signing; this wrapper just supplies the
// keychain and picks which configured carrier `fetchInbox` targets, since
// the real method requires an explicit base URL per call).

import { loadPillar } from "./shim.js";
import type { PillarIdentity } from "./identity.js";
import type {
  PillarCarrierClientInstance,
  PillarCarrierDeliverResult,
  PillarCarrierInboxResult,
  PillarEnvelope,
  PillarModules,
  PillarTierGrant,
} from "./pillar-types.js";

export interface CarrierOptions {
  identity: PillarIdentity;
  /** Base URLs, e.g. `["https://pillar.uuaid.org"]`. `deliver` fans out to all of them; `fetchInbox` targets the first. */
  carriers: string[];
}

export interface CarrierDeliverOptions {
  /** A signed tier grant (tier.mjs) — raises rate/size budgets at carriers that trust its issuer. Per-call; building a fresh underlying client only when this differs from the constructor default. */
  tierGrant?: PillarTierGrant;
  timeoutMs?: number;
}

export interface CarrierFetchInboxOptions {
  since?: number;
  /** Long-poll seconds; the real carrier server caps this at 30. */
  waitS?: number;
  timeoutMs?: number;
}

export class CarrierClient {
  private constructor(
    private readonly pillar: PillarModules,
    private readonly identity: PillarIdentity,
    private readonly carriers: string[],
    private readonly defaultClient: PillarCarrierClientInstance
  ) {}

  static async open(opts: CarrierOptions): Promise<CarrierClient> {
    if (!opts.carriers?.length) throw new Error("CarrierClient: at least one carrier URL required");
    const pillar = await loadPillar();
    const defaultClient = new pillar.CarrierClient({ keychain: opts.identity._keychain(), carriers: opts.carriers });
    return new CarrierClient(pillar, opts.identity, opts.carriers, defaultClient);
  }

  get uuaid(): string {
    return this.identity.uuaid;
  }

  /** Deliver to every configured carrier (Pillar's own seed-replication semantics). */
  async deliver(envelope: PillarEnvelope, opts: CarrierDeliverOptions = {}): Promise<PillarCarrierDeliverResult> {
    const client = opts.tierGrant
      ? new this.pillar.CarrierClient({
          keychain: this.identity._keychain(),
          carriers: this.carriers,
          tierGrant: opts.tierGrant,
        })
      : this.defaultClient;
    return client.deliver(envelope, { timeoutMs: opts.timeoutMs });
  }

  /** Poll the first configured carrier's inbox for us, signed per Pillar's `x-pillar-{pubkey,ts,sig}` scheme. */
  async fetchInbox(opts: CarrierFetchInboxOptions = {}): Promise<PillarCarrierInboxResult> {
    return this.defaultClient.fetchInbox(this.carriers[0], opts);
  }
}
