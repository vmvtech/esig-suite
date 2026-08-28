// delivery.ts
//
// `PillarDelivery` implements the `DeliveryChannel` contract (types.ts) by
// sealing each signer's signing link into a wire-kind `esig:sign-request`
// Pillar envelope and delivering it to that signer's own inbox instead of
// (or alongside) email. docs/architecture/esig-mcp.md §17 seam 2.
//
// Security notes (see also README "Security notes"):
//   - `kind` is a routing hint only, never authorization (§17 "Measured
//     corrections") — the real verb lives inside the sealed, signed
//     payload, and `open()`/`seal()` bind the transport signature to the
//     sender uuaid regardless of what `kind` claims.
//   - A link's `pillar.publicKey` MUST derive `pillar.uuaid`'s local id
//     (self-authenticating identity) AND that uuaid must be
//     `uuaid:foundation:agent:<id>` — Pillar's own `seal()` binding covers
//     only `split(":")[3]`, so the namespace/objectType check here pins
//     the FULL uuaid string (§17 seam 2: "Pillar's binding covers index 3
//     only ... so the FULL uuaid string is pinned, never the local id
//     alone").
//   - The raw signing `url` never leaves this payload for anyone but the
//     E2E-encrypted recipient; the sender-side agent still never sees it
//     (I8) — only the sealed envelope's opaque `enc.ct` crosses the
//     carrier.

import { loadPillar } from "./shim.js";
import { localIdFromEd25519Key } from "./identity.js";
import type { PillarIdentity } from "./identity.js";
import { CarrierClient } from "./carrier.js";
import type { DeliveryChannel, DeliveryEnvelopeMeta, DeliveryLink, Receipt } from "./types.js";
import type { PillarModules } from "./pillar-types.js";

const HEX64 = /^[0-9a-f]{64}$/i;

export interface PillarDeliveryOptions {
  identity: PillarIdentity;
  carriers: string[];
  timeoutMs?: number;
}

/**
 * `esig:sign-request` sealed payload shape (§17 seam 2). `expiresAt` is
 * REQUIRED (RT-2026-08-28-01 F5/G3: "expiresAt on every esig:* verb") — a
 * sign-request with no expiry could otherwise sit valid in a recipient's
 * inbox for the full 14-day carrier TTL; `deliverOne` below refuses to seal
 * one without it.
 */
export interface SignRequestPayload {
  v: 1;
  envelopeId: string;
  title: string;
  url: string;
  expiresAt: string;
  note?: string;
  sender: string;
  createdAt: string;
}

function validatePillarTarget(uuaid: string, publicKey: string): string | null {
  if (!HEX64.test(publicKey)) {
    return `pillar.publicKey must be 64 lowercase hex chars, got ${JSON.stringify(publicKey)}`;
  }
  const parts = uuaid.split(":");
  if (parts.length !== 4 || parts[0] !== "uuaid" || parts[1] !== "foundation" || parts[2] !== "agent") {
    return `pillar.uuaid must be uuaid:foundation:agent:<id>, got ${JSON.stringify(uuaid)}`;
  }
  const derived = localIdFromEd25519Key(Buffer.from(publicKey, "hex"));
  if (derived !== parts[3]) {
    return `pillar.publicKey does not derive pillar.uuaid (key owns ...${derived.slice(0, 8)}, link addressed to ...${parts[3].slice(0, 8)})`;
  }
  return null;
}

export class PillarDelivery implements DeliveryChannel {
  private constructor(
    private readonly pillar: PillarModules,
    private readonly identity: PillarIdentity,
    private readonly carrier: CarrierClient,
    private readonly timeoutMs?: number
  ) {}

  static async open(opts: PillarDeliveryOptions): Promise<PillarDelivery> {
    const pillar = await loadPillar();
    const carrier = await CarrierClient.open({ identity: opts.identity, carriers: opts.carriers });
    return new PillarDelivery(pillar, opts.identity, carrier, opts.timeoutMs);
  }

  async deliver(meta: DeliveryEnvelopeMeta, links: DeliveryLink[]): Promise<Receipt[]> {
    const receipts: Receipt[] = [];
    for (const link of links) {
      receipts.push(await this.deliverOne(meta, link));
    }
    return receipts;
  }

  private async deliverOne(meta: DeliveryEnvelopeMeta, link: DeliveryLink): Promise<Receipt> {
    if (!link.pillar) {
      return { signerId: link.signerId, channel: "pillar", ok: false, detail: "no pillar target" };
    }
    const { uuaid, publicKey } = link.pillar;
    const invalid = validatePillarTarget(uuaid, publicKey);
    if (invalid) {
      return { signerId: link.signerId, channel: "pillar", ok: false, detail: invalid };
    }
    // RT-2026-08-28-01 F5/G3: expiresAt is required on every esig:* verb —
    // refuse rather than seal an envelope with no expiry.
    if (!meta.expiresAt) {
      return {
        signerId: link.signerId,
        channel: "pillar",
        ok: false,
        detail: "meta.expiresAt is required for esig:sign-request over Pillar (RT-2026-08-28-01 G3)",
      };
    }

    const payload: SignRequestPayload = {
      v: 1,
      envelopeId: meta.id,
      title: meta.title,
      url: link.url,
      expiresAt: meta.expiresAt,
      ...(meta.message !== undefined ? { note: meta.message } : {}),
      sender: this.identity.uuaid,
      createdAt: new Date().toISOString(),
    };

    try {
      const envelope = this.pillar.envelope.seal(this.identity._keychain(), {
        recipient: uuaid,
        recipientPublicKey: publicKey,
        kind: "esig:sign-request",
        payload,
      });
      const result = await this.carrier.deliver(envelope, { timeoutMs: this.timeoutMs });
      // Never the url — the Pillar envelope id + carrier seq only.
      return { signerId: link.signerId, channel: "pillar", ok: true, messageId: `${envelope.id}#${result.seq}` };
    } catch (err) {
      return {
        signerId: link.signerId,
        channel: "pillar",
        ok: false,
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
