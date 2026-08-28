// events/webhook.ts
//
// §16 "Webhook delivery": signs and POSTs one event as JSON to the
// operator-configured URL (`ESIG_MCP_EVENTS_WEBHOOK_URL` — an agent can
// never set or change it, config.ts). T18 (webhook SSRF): the target is
// re-validated on EVERY send, not only at config-load time — https unless
// `allowInsecureWebhook`, and the resolved address(es) refused unless
// `allowPrivateWebhook` when they land in loopback, link-local (169.254/16
// — this covers the cloud-metadata address too — and fe80::/10), RFC1918
// (10/8, 172.16/12, 192.168/16), unique-local (fc00::/7), unspecified
// (0.0.0.0, ::), or an IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`, in either
// dotted or all-hex form) wrapping a private v4 address. A literal IP in the
// URL goes through the identical check — `dns.promises.lookup` resolves a
// literal address to itself, so there is no separate code path to bypass.
// T19 (replay/forgery): HMAC-SHA256 over `timestamp + "." + body`, secret
// env-only, receivers must reject timestamps older than 5 minutes
// (documented in the README, not enforced here — that is the receiver's
// job).
//
// RedTeam RT-2026-08-27-05 G1 (pre-publish gate): vetting the target is not
// enough on its own — a DNS answer can change between the vetting lookup and
// whatever lookup the HTTP client itself performs when it actually connects
// (a rebinding TOCTOU: resolve to a public address first, pass the vet,
// then resolve to 127.0.0.1 on the client's OWN internal lookup a moment
// later). So once an address has been resolved and vetted, `sendWebhook`
// below CONNECTS TO THAT EXACT ADDRESS — never lets `fetch` (or anything
// else) re-resolve the hostname — while still sending the original hostname
// as the `Host` header and TLS SNI (`servername`), via `node:http`/
// `node:https` directly (no dependency provides IP-pinning + SNI + a plain
// `fetch`-shaped API together without adding one). Every send re-resolves
// and re-vets fresh (never cached from a previous attempt or from
// config-load time), so a retry after a DNS answer changes is caught, not
// grandfathered in. This only applies when vetting is actually happening
// (`!allowPrivateWebhook`) — with `allowPrivateWebhook: true` the operator
// has already said "I trust this destination, don't protect it", so there is
// nothing to pin against and the request goes out by hostname exactly like
// any other configured HTTP client (also avoids a real DNS query in that
// branch for a config value like a `.example` test hostname).

import crypto from "node:crypto";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";

import type { EsigEvent } from "./types.js";

export class WebhookSsrfError extends Error {}

export interface WebhookTargetPolicy {
  allowInsecureWebhook: boolean;
  allowPrivateWebhook: boolean;
}

// ---------- IP range checks ----------

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr4(ipInt: number, base: string, bits: number): boolean {
  const baseInt = ipv4ToInt(base);
  if (baseInt === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) >>> 0 === (baseInt & mask) >>> 0;
}

function isPrivateOrLocalV4(ip: string): boolean {
  const ipInt = ipv4ToInt(ip);
  if (ipInt === null) return false;
  return (
    ipInt === 0 || // 0.0.0.0 (unspecified)
    inCidr4(ipInt, "127.0.0.0", 8) || // loopback
    inCidr4(ipInt, "169.254.0.0", 16) || // link-local, incl. cloud metadata (169.254.169.254)
    inCidr4(ipInt, "10.0.0.0", 8) || // RFC1918
    inCidr4(ipInt, "172.16.0.0", 12) || // RFC1918
    inCidr4(ipInt, "192.168.0.0", 16) // RFC1918
  );
}

/** Expand any valid textual IPv6 address to 8 hextets (handling `::` and an embedded IPv4 tail), or `null` if unparseable. */
function expandV6(ip: string): string[] | null {
  const withoutZone = ip.split("%")[0];
  const dblIdx = withoutZone.indexOf("::");
  const expandPart = (s: string): string[] | null => {
    if (s.length === 0) return [];
    const parts = s.split(":");
    const last = parts[parts.length - 1];
    if (last.includes(".")) {
      const v4 = ipv4ToInt(last);
      if (v4 === null) return null;
      parts[parts.length - 1] = ((v4 >>> 16) & 0xffff).toString(16);
      parts.push((v4 & 0xffff).toString(16));
    }
    return parts;
  };

  if (dblIdx === -1) {
    const parts = expandPart(withoutZone);
    return parts && parts.length === 8 ? parts : null;
  }
  const head = expandPart(withoutZone.slice(0, dblIdx));
  const tail = expandPart(withoutZone.slice(dblIdx + 2));
  if (!head || !tail) return null;
  const missing = 8 - (head.length + tail.length);
  if (missing < 0) return null;
  return [...head, ...Array(missing).fill("0"), ...tail];
}

function isPrivateOrLocalV6(ip: string): boolean {
  const lower = ip.toLowerCase();
  const hextets = expandV6(lower);
  if (!hextets) return false;

  // IPv4-mapped (::ffff:a.b.c.d) — check the embedded IPv4 address instead.
  if (hextets[0] === "0" && hextets[1] === "0" && hextets[2] === "0" && hextets[3] === "0" && hextets[4] === "0" && hextets[5] === "ffff") {
    const v4 = `${parseInt(hextets[6], 16) >>> 8}.${parseInt(hextets[6], 16) & 0xff}.${parseInt(hextets[7], 16) >>> 8}.${parseInt(hextets[7], 16) & 0xff}`;
    return isPrivateOrLocalV4(v4);
  }

  const h0 = parseInt(hextets[0], 16);
  if (hextets.every((h) => h === "0")) return true; // :: (unspecified)
  if (hextets.slice(0, 7).every((h) => h === "0") && hextets[7] === "1") return true; // ::1 (loopback)
  if ((h0 & 0xffc0) === 0xfe80) return true; // fe80::/10 (link-local)
  if ((h0 & 0xfe00) === 0xfc00) return true; // fc00::/7 (unique-local)
  return false;
}

/**
 * Injectable DNS lookup — the same shape `dns.promises.lookup(host, {all:
 * true})` returns. TESTS ONLY: lets a test simulate a DNS-rebinding TOCTOU
 * (a public address on the first resolve, a private one on a later retry)
 * without touching real DNS.
 */
export type LookupFn = (hostname: string, options: { all: true }) => Promise<Array<{ address: string; family: number }>>;

const defaultLookup: LookupFn = (host, options) => dns.promises.lookup(host, options);

/** The address `sendWebhook` should actually connect to, once resolved+vetted — or nothing, when vetting was skipped entirely (`allowPrivateWebhook: true`; see this module's header comment). */
interface VettedTarget {
  address?: string;
  family?: 4 | 6;
}

/**
 * Protocol check, then (unless `policy.allowPrivateWebhook`) a fresh DNS
 * resolve + private-range vet of every returned address — refusing if ANY
 * A/AAAA record is private (G1(b)). Returns the address to pin the
 * connection to (G1(c)) — the first address, once every returned address has
 * passed the vet — or `{}` when vetting was skipped.
 */
async function resolveAndVet(url: URL, policy: WebhookTargetPolicy, lookupFn: LookupFn): Promise<VettedTarget> {
  if (url.protocol !== "https:" && !policy.allowInsecureWebhook) {
    throw new WebhookSsrfError(
      `webhook URL must use https:// (got "${url.protocol}//..."); set ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1 to override for a trusted local/loopback receiver.`,
    );
  }
  if (policy.allowPrivateWebhook) return {};

  const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await lookupFn(host, { all: true });
  } catch (e) {
    throw new WebhookSsrfError(`could not resolve webhook host "${host}": ${e instanceof Error ? e.message : String(e)}`);
  }
  if (addresses.length === 0) {
    throw new WebhookSsrfError(`webhook host "${host}" did not resolve to any address.`);
  }
  for (const { address } of addresses) {
    // R4 (verifier finding): classify by parsing `address` itself
    // (`net.isIP`), never by the lookup result's own `family` label — a
    // resolver (real or, in tests, injected) can return a `family` that
    // disagrees with the address string, and trusting that label let an
    // actually-private v4 address slip past the vet whenever it carried
    // `family: 6`.
    const isPrivate = net.isIP(address) === 6 ? isPrivateOrLocalV6(address) : isPrivateOrLocalV4(address);
    if (isPrivate) {
      throw new WebhookSsrfError(
        `webhook host "${host}" resolves to a private/local address (${address}) — refusing (set ` +
          "ESIG_MCP_ALLOW_PRIVATE_WEBHOOK=1 to override for a trusted receiver).",
      );
    }
  }
  const picked = addresses[0];
  return { address: picked.address, family: picked.family === 6 ? 6 : 4 };
}

/**
 * Throws {@link WebhookSsrfError} if `url` fails the https/private-range
 * policy — the config-time/startup check (F4, bin.ts) as well as
 * `sendWebhook`'s own defense in depth below. Every field of `policy`
 * (and, when supplied, `lookupFn`'s answer) re-read fresh on every call —
 * never cached across calls. `lookupFn` is TESTS ONLY (G1(d): proves
 * re-resolution happens on every call, e.g. a DNS-rebinding TOCTOU stub).
 */
export async function assertSafeWebhookTarget(url: URL, policy: WebhookTargetPolicy, lookupFn: LookupFn = defaultLookup): Promise<void> {
  await resolveAndVet(url, policy, lookupFn);
}

// ---------- Signing ----------

/** `'sha256=' + HMAC-SHA256(secret, timestamp + "." + body)`, hex-encoded (§16, T19). */
export function signPayload(secret: string, timestamp: string, body: string): string {
  const mac = crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`, "utf8").digest("hex");
  return `sha256=${mac}`;
}

// ---------- Send ----------

export interface WebhookConfig extends WebhookTargetPolicy {
  url: string;
  secret: string;
  timeoutMs?: number;
}

export class WebhookDeliveryError extends Error {}

/**
 * The pinned (G1(c)) request implementation's shape — TESTS ONLY injectable
 * via {@link SendWebhookOptions.requestImpl}, so a test can assert what
 * address/headers/SNI a pinned send actually used without a real socket.
 * Defaults to {@link requestPinned} below, the real `node:http`/`node:https`
 * implementation.
 */
export type PinnedRequestFn = (args: {
  url: URL;
  address: string;
  family: 4 | 6;
  body: string;
  headers: Record<string, string>;
  timeoutMs: number;
}) => Promise<{ status: number }>;

/**
 * G1(c): connects directly to `address` (never lets the HTTP stack resolve
 * `url.hostname` itself) while sending the ORIGINAL hostname as the `Host`
 * header and, for https, as the TLS `servername` (SNI) — so certificate
 * validation still checks the hostname the operator configured, not the raw
 * IP. Any status outside 2xx — including a 3xx, which is never followed —
 * resolves with that status for the caller to turn into a
 * {@link WebhookDeliveryError}; the response body is drained and discarded
 * (only the status matters). `timeoutMs` bounds socket idle time so a hung
 * receiver can never stall the delivery worker loop indefinitely.
 */
const requestPinned: PinnedRequestFn = ({ url, address, family, body, headers, timeoutMs }) => {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const mod = isHttps ? https : http;
    const port = url.port ? Number(url.port) : isHttps ? 443 : 80;
    const req = mod.request(
      {
        host: address,
        family,
        port,
        path: `${url.pathname}${url.search}`,
        method: "POST",
        headers: { ...headers, host: url.host, "content-length": Buffer.byteLength(body) },
        timeout: timeoutMs,
        ...(isHttps ? { servername: url.hostname } : {}),
      },
      (res) => {
        res.resume(); // drain — the body is never used, only the status
        resolve({ status: res.statusCode ?? 0 });
      },
    );
    req.on("timeout", () => req.destroy(new Error(`webhook request to ${url.hostname} timed out after ${timeoutMs}ms`)));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
};

export interface SendWebhookOptions {
  /** Injectable fetch — used only on the `allowPrivateWebhook` (hostname-connect, nothing pinned) path. TESTS ONLY; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Injectable DNS lookup — TESTS ONLY; see {@link LookupFn}. Defaults to `dns.promises.lookup`. */
  lookupFn?: LookupFn;
  /** Injectable pinned-request implementation — TESTS ONLY; see {@link PinnedRequestFn}. Defaults to {@link requestPinned}. */
  requestImpl?: PinnedRequestFn;
}

/**
 * POST one event, signed. Throws {@link WebhookSsrfError} (target refused)
 * or {@link WebhookDeliveryError} (non-2xx, any 3xx, timeout, or network
 * failure) on anything but a 2xx response — the caller (events/queue.ts)
 * treats either as a failed delivery attempt to retry/back off.
 *
 * G1(c)+(d): re-resolves and re-vets the target FRESH on every call (never
 * cached from a previous attempt) via {@link resolveAndVet}; when vetting
 * actually applies (`!allowPrivateWebhook`) the request connects to the
 * vetted address directly ({@link requestPinned}), never by hostname —
 * closing the DNS-rebinding TOCTOU a "vet then let the HTTP client resolve
 * again" design would leave open. G1(e): on the unpinned
 * (`allowPrivateWebhook`) path, `redirect: "error"` makes `fetch` reject the
 * moment a 3xx arrives rather than follow it; the pinned path's own status
 * check treats any non-2xx, including a 3xx, identically. A hard
 * `AbortSignal.timeout`/socket timeout (default 10s either way) so a hung
 * receiver can never stall the delivery worker loop indefinitely.
 */
export async function sendWebhook(
  cfg: WebhookConfig,
  event: EsigEvent,
  packageVersion: string,
  opts: SendWebhookOptions = {},
): Promise<void> {
  const url = new URL(cfg.url);
  const lookupFn = opts.lookupFn ?? defaultLookup;
  const vetted = await resolveAndVet(url, cfg, lookupFn);

  const body = JSON.stringify(event);
  const timestamp = new Date().toISOString();
  const signature = signPayload(cfg.secret, timestamp, body);
  const headers = {
    "content-type": "application/json",
    "user-agent": `esig-mcp/${packageVersion}`,
    "x-esig-event-id": event.id,
    "x-esig-timestamp": timestamp,
    "x-esig-signature": signature,
  };
  const timeoutMs = cfg.timeoutMs ?? 10_000;

  try {
    if (vetted.address) {
      const requestImpl = opts.requestImpl ?? requestPinned;
      const { status } = await requestImpl({ url, address: vetted.address, family: vetted.family ?? 4, body, headers, timeoutMs });
      if (status < 200 || status >= 300) {
        throw new WebhookDeliveryError(`webhook POST failed: HTTP ${status}`);
      }
    } else {
      // allowPrivateWebhook: the operator has explicitly opted out of SSRF
      // protection for this URL — nothing was resolved to pin against, so
      // this connects by hostname like any other configured HTTP client.
      const fetchImpl = opts.fetchImpl ?? fetch;
      const res = await fetchImpl(cfg.url, {
        method: "POST",
        headers,
        body,
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) {
        throw new WebhookDeliveryError(`webhook POST failed: HTTP ${res.status}`);
      }
    }
  } catch (e) {
    if (e instanceof WebhookDeliveryError) throw e;
    throw new WebhookDeliveryError(`webhook request failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}
