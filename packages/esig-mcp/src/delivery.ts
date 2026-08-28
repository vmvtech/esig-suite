// delivery.ts
//
// The operator-configured link-delivery channel (design doc §5). This is the
// ONE place a raw signing link is allowed to leave the process under normal
// (H-mode, ESIG_MCP_RETURN_LINKS unset) operation — the MCP tool layer never
// sees it (I8, T1, T8).

import { promises as fs } from "node:fs";
import path from "node:path";

import type { IdentityLevel } from "./identity/types.js";

export interface DeliveryLink {
  signerId: string;
  name: string;
  email: string;
  /** `${baseUrl}/sign/<raw token>` — treat as a secret; deliver out-of-band. */
  url: string;
  /**
   * Informational only (§12) — this envelope's identity requirement, so
   * whoever relays the link to the signer's wallet/agent knows what's
   * expected. Never a verified result (that only exists once the signer has
   * actually presented a proof — see esig_envelope_status instead).
   */
  identity?: { minLevel: IdentityLevel; expectedUuaid?: string };
  /**
   * §17 seam 2: present when this signer should be reached over Pillar
   * (uuaid-to-uuaid) instead of, or alongside, `url` — a `DeliveryChannel`
   * that doesn't understand Pillar (file/console/webhook/email) simply
   * ignores this field and delivers `url` as it always has. Shape matches
   * the `@e-sig/pillar-bridge` contract byte-for-byte (packages/
   * esig-pillar-bridge/src/types.ts `DeliveryLink.pillar`).
   */
  pillar?: {
    /** The signer's `uuaid:foundation:agent:<localId>`. */
    uuaid: string;
    /** The signer's raw Ed25519 public key, 64 lowercase hex chars. */
    publicKey: string;
  };
}

export interface Receipt {
  signerId: string;
  channel: string;
  ok: boolean;
  detail?: string;
  /** email/delivery.ts's `EmailDelivery` only: the outgoing message's id (SMTP `Message-ID` / SES `MessageId`), set on success. */
  messageId?: string;
}

export interface DeliveryChannel {
  deliver(
    envelope: {
      id: string;
      title: string;
      /** §15: `esig_create_envelope`'s optional sender note (`metadata.mcp.message`) — only `EmailDelivery` reads it. */
      message?: string;
      /** ISO-8601 envelope expiry, if any — only `EmailDelivery` reads it. */
      expiresAt?: string;
    },
    links: DeliveryLink[],
  ): Promise<Receipt[]>;
}

/**
 * OPT-IN delivery channel (G3(c) FIX — no longer the default, `config.ts`):
 * prints each signing link to STDERR. In the canonical stdio MCP deployment,
 * stderr is the agent harness's own captured log — so this channel hands the
 * signing capability itself to the very principal (the untrusted agent,
 * T1/T8) this package's threat model excludes it from, UNLESS the operator
 * genuinely owns and reads this terminal themselves (local demo). `bin.ts`
 * prints a loud startup warning whenever this channel is selected.
 *
 * Deliberately STDERR, never stdout: stdout is reserved for the MCP stdio
 * JSON-RPC transport — a stray write to stdout from anywhere in this process
 * corrupts that stream for every stdio-transport client. No function in this
 * package writes to stdout; this is the one place output happens at all, and
 * it is stderr.
 */
export class ConsoleDelivery implements DeliveryChannel {
  async deliver(envelope: { id: string; title: string }, links: DeliveryLink[]): Promise<Receipt[]> {
    for (const link of links) {
      process.stderr.write(
        `[esig-mcp] signing link for ${link.name} <${link.email}> on envelope ${envelope.id} ` +
          `("${envelope.title}"): ${link.url}\n`,
      );
    }
    return links.map((l) => ({ signerId: l.signerId, channel: "console", ok: true }));
  }
}

/**
 * Writes one JSON receipt per envelope to `<dataDir>/outbox/<envelopeId>.json`
 * (G3(b) FIX — the v0.1 quickstart channel, README "60-second quickstart").
 *
 * The outbox directory and file are created 0700/0600 respectively — the
 * file contains every signer's raw signing URL, so its permissions are the
 * only thing standing between "operator-only" and "world-readable on a
 * shared host". `fs.mkdir`'s/`fs.writeFile`'s own `mode` option is masked by
 * the process umask (identical to a bare POSIX `open()`), so the mode is
 * re-asserted with an explicit `chmod` after creation — the only way to
 * guarantee the exact bits regardless of umask.
 *
 * Only the outbox PATH is ever returned in a `Receipt` (never the URL) — the
 * URL exists on disk, in the one file the operator's filesystem permissions
 * gate, never in an MCP tool result (I8).
 */
export class FileDelivery implements DeliveryChannel {
  constructor(private readonly dataDir: string) {}

  async deliver(envelope: { id: string; title: string }, links: DeliveryLink[]): Promise<Receipt[]> {
    const dir = path.join(this.dataDir, "outbox");
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    await fs.chmod(dir, 0o700);

    const file = path.join(dir, `${envelope.id}.json`);
    const payload = {
      envelopeId: envelope.id,
      title: envelope.title,
      signers: links.map((l) => ({
        signerId: l.signerId,
        name: l.name,
        email: l.email,
        url: l.url,
        ...(l.identity ? { identity: l.identity } : {}),
        ...(l.pillar ? { pillar: l.pillar } : {}),
      })),
      createdAt: new Date().toISOString(),
    };
    await fs.writeFile(file, JSON.stringify(payload, null, 2), { encoding: "utf8", mode: 0o600 });
    await fs.chmod(file, 0o600);

    return links.map((l) => ({ signerId: l.signerId, channel: "file", ok: true, detail: file }));
  }
}

/**
 * POSTs each signer's link as JSON to a fixed operator-configured URL.
 *
 * G3(d) FIX: a hung or unreachable webhook must never hang `create()`. Every
 * request carries `AbortSignal.timeout(timeoutMs)` (default 10s); a timeout
 * or any other fetch failure is caught and reported as a failed `Receipt`
 * (`ok:false`, `detail`) exactly like an HTTP error response — it never
 * throws out of `deliver()`. `timeoutMs` is constructor-injectable so tests
 * can bound a real hung-server race without a real 10s wait.
 */
export class WebhookDelivery implements DeliveryChannel {
  constructor(
    private readonly url: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs: number = 10_000,
  ) {}

  async deliver(envelope: { id: string; title: string }, links: DeliveryLink[]): Promise<Receipt[]> {
    const receipts: Receipt[] = [];
    for (const link of links) {
      try {
        const res = await this.fetchImpl(this.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            envelopeId: envelope.id,
            title: envelope.title,
            signerId: link.signerId,
            name: link.name,
            email: link.email,
            url: link.url,
          }),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        receipts.push({
          signerId: link.signerId,
          channel: "webhook",
          ok: res.ok,
          detail: res.ok ? undefined : `HTTP ${res.status}`,
        });
      } catch (e) {
        receipts.push({
          signerId: link.signerId,
          channel: "webhook",
          ok: false,
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }
    return receipts;
  }
}

// ---------- R2: outbox completion receipt ----------
//
// Verifier finding R2: the `file` outbox creation receipt above
// (`<dataDir>/outbox/<envelopeId>.json`) is left exactly as-is; this is a
// SECOND, independent receipt written once an envelope reaches a terminal
// seal outcome (`sealed` or `seal_failed`) — regardless of which delivery
// channel was configured (this is bookkeeping about the ENVELOPE, not about
// dispatching a signing link, so it is not gated behind `ESIG_MCP_DELIVERY
// =file`). Same permission discipline as the creation receipt (0700 dir /
// 0600 file) since signer identity records can carry PII (uuaid, name).

export interface CompletionReceiptSigner {
  signerId: string;
  name: string;
  email: string;
  /** ISO-8601, when this signer has signed. */
  signedAt?: string;
  /** sha256 of the drawn signature image data URL — never the full data URL itself (§13). */
  signatureImageSha256?: string;
  /** This signer's verified identity record (§12), when one exists. */
  identity?: unknown;
}

/**
 * Write `<dataDir>/outbox/<envelopeId>.completed.json`. Returns the absolute
 * file path written. Callers (envelopes.ts `seal()`) are expected to treat
 * this as best-effort auxiliary bookkeeping — see that call site's own
 * comment for why a failure here must never propagate.
 */
export async function writeOutboxCompletionReceipt(
  dataDir: string,
  envelope: { id: string; title: string },
  status: "sealed" | "seal_failed",
  signers: CompletionReceiptSigner[],
  extra: Record<string, unknown> = {},
): Promise<string> {
  const dir = path.join(dataDir, "outbox");
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.chmod(dir, 0o700);

  const file = path.join(dir, `${envelope.id}.completed.json`);
  const payload = {
    envelopeId: envelope.id,
    title: envelope.title,
    status,
    signers,
    ...extra,
    recordedAt: new Date().toISOString(),
  };
  await fs.writeFile(file, JSON.stringify(payload, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.chmod(file, 0o600);

  return file;
}

/** Test double: records every call in-memory instead of delivering anywhere. */
export class CapturingDelivery implements DeliveryChannel {
  readonly calls: Array<{ envelope: { id: string; title: string }; links: DeliveryLink[] }> = [];

  async deliver(envelope: { id: string; title: string }, links: DeliveryLink[]): Promise<Receipt[]> {
    this.calls.push({ envelope, links });
    return links.map((l) => ({ signerId: l.signerId, channel: "capture", ok: true }));
  }
}
