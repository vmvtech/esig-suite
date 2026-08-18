// tsa.ts
//
// RFC-3161 timestamp transport for @e-sig/core, plus the readiness probe that
// backs `/ready`.
//
// core performs no egress itself: `signPdf({ tsa })` hands us the DER-encoded
// TimeStampReq and expects the DER-encoded TimeStampResp back (see
// TsaTransport in core/types.ts). Everything network lives here.
//
// Failover: TSAs are tried in configured order and the first protocol-level
// success wins. `required: true` (ESIG_GATEWAY_TSA_REQUIRED=1) makes a total
// failure abort the signature rather than silently downgrading CAdES-T →
// CAdES-B — which matters because the response field dsalvus reads is a plain
// boolean `timestamped`, so a downgrade is otherwise invisible until someone
// audits a dossier a year later.

import crypto from "node:crypto";

import { buildTimeStampReq, parseTimeStampResp } from "@e-sig/core";

import type { TsaConfig } from "./config.js";

const TSQ_CONTENT_TYPE = "application/timestamp-query";
const TSR_CONTENT_TYPE = "application/timestamp-reply";

function toBinaryString(bytes: Uint8Array): string {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return s;
}

function fromBinaryString(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export interface TsaHealth {
  configured: boolean;
  healthy: boolean;
  /** The endpoint that answered (or last failed), for operator triage. */
  endpoint?: string;
  error?: string;
  checkedAt?: string;
}

export class TsaPool {
  private lastHealth: TsaHealth;
  private lastProbeAt = 0;
  private probeInflight: Promise<TsaHealth> | null = null;

  constructor(
    private readonly cfg: TsaConfig,
    private readonly fetchImpl: typeof fetch = fetch,
    /** Minimum interval between real TSA probes, ms. */
    private readonly probeIntervalMs = 60_000,
  ) {
    this.lastHealth = { configured: cfg.urls.length > 0, healthy: cfg.urls.length === 0 };
  }

  get configured(): boolean {
    return this.cfg.urls.length > 0;
  }

  /** The `tsa` value to pass to `signPdf`, or undefined when not configured. */
  transport(): { fetch: (req: Uint8Array) => Promise<Uint8Array>; required?: boolean } | undefined {
    if (!this.configured) return undefined;
    return {
      required: this.cfg.required,
      fetch: async (reqDer: Uint8Array) => {
        const errors: string[] = [];
        for (const url of this.cfg.urls) {
          try {
            const resp = await this.post(url, reqDer);
            this.record({ configured: true, healthy: true, endpoint: url, checkedAt: new Date().toISOString() });
            return resp;
          } catch (e) {
            errors.push(`${url}: ${e instanceof Error ? e.message : String(e)}`);
          }
        }
        const detail = errors.join("; ");
        this.record({
          configured: true,
          healthy: false,
          endpoint: this.cfg.urls[0],
          error: detail,
          checkedAt: new Date().toISOString(),
        });
        throw new Error(`all TSA endpoints failed — ${detail}`);
      },
    };
  }

  private async post(url: string, reqDer: Uint8Array): Promise<Uint8Array> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.cfg.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": TSQ_CONTENT_TYPE, accept: TSR_CONTENT_TYPE },
        body: reqDer,
        signal: ac.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = new Uint8Array(await res.arrayBuffer());
      if (buf.length === 0) throw new Error("empty TimeStampResp");
      return buf;
    } finally {
      clearTimeout(t);
    }
  }

  private record(h: TsaHealth): void {
    this.lastHealth = h;
    this.lastProbeAt = Date.now();
  }

  /**
   * Real protocol-level probe: build a well-formed TimeStampReq over random
   * bytes and require a parseable TimeStampResp. This is deliberately a full
   * TSP round trip rather than a TCP/HTTP reachability check — a TSA that
   * answers 200 with an error PKIStatus is not a healthy TSA, and `/ready`
   * exists precisely so that shows up before the monthly batch, not during it.
   *
   * Rate-limited to one real probe per `probeIntervalMs`; a genuine sign
   * attempt also refreshes the cached health, so a busy gateway rarely probes.
   */
  async health(now = Date.now()): Promise<TsaHealth> {
    if (!this.configured) return { configured: false, healthy: true };
    if (now - this.lastProbeAt < this.probeIntervalMs) return this.lastHealth;
    if (this.probeInflight) return this.probeInflight;

    this.probeInflight = (async () => {
      const reqDer = fromBinaryString(buildTimeStampReq(toBinaryString(crypto.randomBytes(32))));
      const errors: string[] = [];
      for (const url of this.cfg.urls) {
        try {
          const respDer = await this.post(url, reqDer);
          // Throws on a non-granted PKIStatus or a malformed response.
          parseTimeStampResp(toBinaryString(respDer));
          this.record({ configured: true, healthy: true, endpoint: url, checkedAt: new Date().toISOString() });
          return this.lastHealth;
        } catch (e) {
          errors.push(`${url}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      this.record({
        configured: true,
        healthy: false,
        error: errors.join("; "),
        checkedAt: new Date().toISOString(),
      });
      return this.lastHealth;
    })().finally(() => {
      this.probeInflight = null;
    });

    return this.probeInflight;
  }
}
