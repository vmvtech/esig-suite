// envelopes.ts
//
// The library-level operations the MCP tool layer calls 1:1
// (esig_create_envelope, esig_envelope_status, esig_list_envelopes,
// esig_void_envelope, and the approval-page-facing resolve/sign — design doc
// §4-§5). All cryptographic + persistence work is core's; this module adds
// only: sanitization (I9), caps + rate limiting (T6), token custody (I8),
// content-pinning (I4), and the completion→seal orchestration.
//
// Why sealing is NOT a call to core's `signDocument()`:
// `signDocument()` (sign-document.ts:90-96) hardcodes
// `renderHtmlToPdf({ html: input.html })` with no injection point for the
// render step. The ticket requires an injectable renderer so tests can seal
// WITHOUT Chrome (a fixture buffer stands in for the rendered PDF). The
// gateway package hit the identical wall and made the identical call — see
// packages/esig-gateway/src/sign.ts:6-15's own header comment, which composes
// `renderHtmlToPdf → ensureActiveCert → signPdf → PdfStorageStore →
// AuditLogStore` directly for the same reason (there: bytes-in-hand instead
// of storage-first; here: an injectable render step). `seal()` below mirrors
// that same composition, with `ensureActivePqKeys` added for the optional PQ
// seal, matching packages/esig-gateway/src/sign.ts:206-243.

import crypto from "node:crypto";

import {
  composeEnvelopeHtml,
  createEnvelope,
  ensureActiveCert,
  ensureActivePqKeys,
  recordSignature,
  renderHtmlToPdf,
  resolveSigningToken,
  signPdf,
  verifyPdfSignature,
  voidEnvelope,
  type AuditLogStore,
  type CertStore,
  type Envelope,
  type EnvelopeStore,
  type PdfStorageStore,
  type PqKeyStore,
  type TokenResolution,
} from "@e-sig/core";

import type { Config } from "./config.js";
import type { DeliveryChannel, DeliveryLink, Receipt } from "./delivery.js";
import { sanitizeEnvelopeHtml } from "./sanitize.js";
import { listEnvelopes } from "./stores.js";
import { messageOf } from "./tools/helpers.js";

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

export interface SignerInput {
  name: string;
  email: string;
  roleLabel?: string;
  /** 1-based signing order; equal values sign in parallel. Default 1 (core default, envelope.ts:134). */
  order?: number;
}

export interface CreateEnvelopeArgs {
  title: string;
  html: string;
  signers: SignerInput[];
  expiresAt?: Date;
}

export interface CreatedSigner {
  signerId: string;
  name: string;
  email: string;
  status: string;
}

export interface CreateEnvelopeResultSummary {
  envelopeId: string;
  signers: CreatedSigner[];
  htmlSha256: string;
  removedTags: string[];
  delivery: Receipt[];
  /** Present ONLY when config.returnLinks is true (I8). */
  links?: Array<{ signerId: string; name: string; email: string; url: string }>;
}

/**
 * D1: a phase derived from `envelope.status` plus this package's own seal
 * state (core has no notion of "sealed" — the MCP layer owns that). A
 * `completed` core envelope splits into three MCP phases depending on
 * whether the (retryable) seal step has run and how it landed:
 *   - `awaiting_seal` — completed, seal never attempted yet (should not be
 *     observable through `sign()`, which always attempts a seal right away,
 *     but is the correct phase for a `completed` envelope with no
 *     `metadata.mcp.seal` at all, e.g. one created by a different code path).
 *   - `seal_failed` — completed, the seal step threw (D2: commonly "no
 *     Chrome"); the signature itself is still validly recorded. Retry with
 *     `esig_reseal`.
 *   - `sealed` — completed and the sealed PDF was produced.
 */
export type EnvelopePhase =
  | "sent"
  | "partially_signed"
  | "awaiting_seal"
  | "sealed"
  | "seal_failed"
  | "voided"
  | "expired";

/** D1: the tracked, retryable state of the seal step for one envelope. */
export interface EnvelopeSealState {
  status: "sealed" | "failed";
  /** How many times `seal()` has been attempted for this envelope (auto + `esig_reseal`), including this one. */
  attempts: number;
  /** Set only when `status === "failed"`. The caught error's `.message` only — never a stack trace (I1). */
  error?: string;
  /** Set only when `status === "failed"`. ISO-8601. */
  lastAttemptAt?: string;
  /** Set only when `status === "sealed"`. Same value as `sealedPdfUrl` below. */
  sealedPdfPath?: string;
  /** Set only when `status === "sealed"`. ISO-8601. */
  sealedAt?: string;
}

export interface EnvelopeStatusSummary {
  envelopeId: string;
  title: string;
  status: string;
  /** D1(c): a finer-grained state than `status` alone — see {@link EnvelopePhase}. */
  phase: EnvelopePhase;
  signers: Array<{
    signerId: string;
    name: string;
    email: string;
    status: string;
    order: number;
    signedAt?: string;
  }>;
  createdAt: string;
  completedAt?: string;
  voidedAt?: string;
  /** Set once the envelope reaches `completed` AND the seal step has succeeded (phase `sealed`). */
  sealedPdfUrl?: string;
  /** D1(c): present once a seal attempt (success or failure) has run at least once. */
  seal?: EnvelopeSealState;
}

interface McpEnvelopeMetadata {
  htmlSha256?: string;
  removedTags?: string[];
  returnLinks?: boolean;
  sealedPdfUrl?: string;
  certFingerprint?: string;
  pqSealed?: boolean;
  pqKeyId?: string;
  pqMldsa65Fpr?: string;
  /** D1: explicit, retryable seal state — see `EnvelopeService.seal()`/`.reseal()`. */
  seal?: EnvelopeSealState;
}

function mcpMeta(envelope: Envelope): McpEnvelopeMetadata | undefined {
  return (envelope.metadata as { mcp?: McpEnvelopeMetadata } | undefined)?.mcp;
}

/** D1(c): derive {@link EnvelopePhase} from core's `status` plus this package's own seal state. */
export function derivePhase(envelope: Envelope): EnvelopePhase {
  if (envelope.status !== "completed") return envelope.status;
  const seal = mcpMeta(envelope)?.seal;
  if (seal?.status === "sealed") return "sealed";
  if (seal?.status === "failed") return "seal_failed";
  return "awaiting_seal";
}

export interface EnvelopeServiceDeps {
  config: Config;
  envelopeStore: EnvelopeStore;
  certStore: CertStore;
  pqKeyStore: PqKeyStore;
  auditStore: AuditLogStore;
  pdfStorage: PdfStorageStore;
  delivery: DeliveryChannel;
  /** Injectable HTML→PDF renderer. Defaults to core's `renderHtmlToPdf` (needs a real Chrome). */
  render?: (html: string) => Promise<Buffer>;
  /** Injectable clock, for deterministic tests. */
  now?: () => Date;
}

/**
 * Chrome launch args for the seal-time render (G1 FIX — RedTeam
 * rt-verdict-ESIGMCP-V01-20260826, MEDIUM).
 *
 * Envelope HTML is AGENT-AUTHORED and therefore untrusted (design doc §2 T9).
 * Disabling JavaScript — core's `renderHtmlToPdf` default — does NOT make the
 * render SSRF-safe: JS-off stops scripts, not resource loading, and core waits
 * on `waitUntil: "load"`, which actively waits for subresources to finish. So
 * at seal time a plain `<img>`, `<link rel=stylesheet>`, `style="…url(…)"`,
 * `<object>`, or `<meta http-equiv=refresh>` still reaches the network from
 * the operator's machine — the one holding the signing keys — and any content
 * it fetches is baked into the SIGNED PDF (read-SSRF), not merely leaked.
 *
 * `--host-resolver-rules=MAP * ~NOTFOUND` fails every hostname AND literal-IP
 * lookup inside the renderer, so no subresource of any scheme that needs the
 * network can load. `data:` URLs are unaffected, which is what the composed
 * document actually uses (the signature image is a data: URL).
 *
 * MEASURED, not assumed (local Chrome, 2026-08-26):
 *   - without the rule: 6/6 vectors fetched — literal-IP img, hostname img,
 *     stylesheet link, CSS url(), iframe, object — plus meta-refresh navigation.
 *   - with the rule: 0/6, and meta-refresh does not navigate.
 *   - data: image still renders (+1670 B over an empty page).
 *   - `file://` subresources were already blocked by Chrome from the
 *     about:blank document `setContent` produces (byte-identical to control).
 *
 * These are passed as an explicit `launchArgs` override rather than a core
 * option so the guarantee holds against `@e-sig/core@0.7.0` exactly as
 * published — it does not depend on shipping a new core first. The two
 * sandbox flags reproduce core's own non-Lambda default (render-pdf.ts), which
 * an explicit `launchArgs` replaces wholesale.
 */
export const SEAL_RENDER_LAUNCH_ARGS: readonly string[] = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--host-resolver-rules=MAP * ~NOTFOUND",
];

/** Simple in-memory sliding-window hourly rate limiter (T6). v0.1, single process — resets on restart. */
class HourlyRateLimiter {
  private readonly hits: number[] = [];

  constructor(
    private readonly limit: number,
    private readonly now: () => Date,
  ) {}

  /** `label` names what's being capped in the thrown message; default preserves the original wording for `create()`. */
  take(label = "envelope-creation"): void {
    const cutoffMs = this.now().getTime() - 60 * 60 * 1000;
    while (this.hits.length > 0 && this.hits[0] < cutoffMs) this.hits.shift();
    if (this.hits.length >= this.limit) {
      throw new EnvelopeError(`hourly ${label} cap reached (${this.limit}/hour)`);
    }
    this.hits.push(this.now().getTime());
  }
}

export class EnvelopeService {
  private readonly render: (html: string) => Promise<Buffer>;
  private readonly now: () => Date;
  private readonly rateLimiter: HourlyRateLimiter;

  constructor(private readonly deps: EnvelopeServiceDeps) {
    this.render =
      deps.render ?? ((html) => renderHtmlToPdf({ html, launchArgs: [...SEAL_RENDER_LAUNCH_ARGS] }));
    this.now = deps.now ?? (() => new Date());
    this.rateLimiter = new HourlyRateLimiter(deps.config.envelopesPerHour, this.now);
  }

  /** `esig_create_envelope`. Sanitizes, caps, rate-limits, mints tokens, delivers links, audits, and returns NO raw tokens by default (I8). */
  async create(args: CreateEnvelopeArgs): Promise<CreateEnvelopeResultSummary> {
    const { config } = this.deps;

    if (!args.signers?.length) {
      throw new EnvelopeError("at least one signer is required");
    }
    const htmlBytes = Buffer.byteLength(args.html ?? "", "utf8");
    if (htmlBytes > config.maxHtmlBytes) {
      throw new EnvelopeError(`html is ${htmlBytes} bytes, exceeds the ${config.maxHtmlBytes}-byte cap`);
    }

    this.rateLimiter.take();

    const { html: sanitized, removed } = sanitizeEnvelopeHtml(args.html);
    const htmlSha256 = crypto.createHash("sha256").update(sanitized, "utf8").digest("hex");

    const { envelope, signingTokens } = await createEnvelope({
      store: this.deps.envelopeStore,
      tenantId: config.tenant,
      title: args.title,
      html: sanitized,
      signers: args.signers,
      expiresAt: args.expiresAt,
      // I4: pin the creation-time content hash ON THE ENVELOPE ITSELF, not
      // only in the audit row. `AuditLogStore` (adapters.ts:95-98) offers
      // `insert()` only — no query/read API — so re-checking "the creation
      // audit value" at seal time (per the ticket's I4 wording) against the
      // audit STORE would require depending on a non-contractual method of
      // whatever concrete AuditLogStore is injected. Storing the same value
      // here instead makes the invariant hold for ANY injected EnvelopeStore,
      // not just the default Fs one — the audit row below still carries the
      // same value for the audit trail.
      metadata: { mcp: { htmlSha256, removedTags: removed, returnLinks: config.returnLinks } },
    });

    const links: DeliveryLink[] = signingTokens.map((t) => {
      const signer = envelope.signers.find((s) => s.id === t.signerId)!;
      return {
        signerId: t.signerId,
        name: signer.name,
        email: signer.email,
        url: `${config.baseUrl}/sign/${t.token}`,
      };
    });

    const receipts = await this.deps.delivery.deliver({ id: envelope.id, title: envelope.title }, links);

    if (config.returnLinks) {
      // I8's escape hatch — loud on purpose (design doc §4: "loudly").
      process.stderr.write(
        `[esig-mcp] WARNING: ESIG_MCP_RETURN_LINKS=1 — returning raw signing links for envelope ` +
          `${envelope.id} directly to the MCP caller. This defeats the human-in-the-loop token ` +
          `custody guarantee (T1/T8, docs/architecture/esig-mcp.md §2) and is intended for local ` +
          `demos only.\n`,
      );
    }

    // I6 / G3(c)+(d): audit row written before this call returns success.
    // `delivery` stamps the CHANNEL every envelope's links were dispatched
    // through (ticket G3(c): "All channels stamp delivery:<channel>"), and
    // `deliveryFailures` records any signer whose receipt came back
    // `ok:false` (G3(d): a hung/failed webhook must not hang create() — the
    // envelope is still created, but the failure is on the audit trail).
    const deliveryFailures = receipts
      .filter((r) => !r.ok)
      .map((r) => ({ signerId: r.signerId, detail: r.detail }));
    await this.deps.auditStore.insert({
      tenantId: config.tenant,
      action: "envelope.created",
      targetTable: "envelope",
      targetId: envelope.id,
      metadata: {
        htmlSha256,
        removedTags: removed,
        returnLinks: config.returnLinks,
        signerCount: envelope.signers.length,
        delivery: config.delivery.kind,
        deliveryFailures,
      },
    });

    return {
      envelopeId: envelope.id,
      signers: envelope.signers.map((s) => ({ signerId: s.id, name: s.name, email: s.email, status: s.status })),
      htmlSha256,
      removedTags: removed,
      delivery: receipts,
      ...(config.returnLinks ? { links } : {}),
    };
  }

  /** `esig_envelope_status`. */
  async status(envelopeId: string): Promise<EnvelopeStatusSummary> {
    const envelope = await this.deps.envelopeStore.findById(this.deps.config.tenant, envelopeId);
    if (!envelope) throw new EnvelopeError(`envelope not found: ${envelopeId}`);
    return summarize(envelope);
  }

  /** `esig_list_envelopes`. See stores.ts's `listEnvelopes` header note for the Fs-backed-only limitation. */
  async list(): Promise<EnvelopeStatusSummary[]> {
    const envelopes = await listEnvelopes(this.deps.config.dataDir, this.deps.config.tenant);
    return envelopes.map(summarize);
  }

  /** `esig_void_envelope`. Sender-side cancel; no token needed. */
  async void(envelopeId: string): Promise<EnvelopeStatusSummary> {
    const envelope = await voidEnvelope({
      store: this.deps.envelopeStore,
      tenantId: this.deps.config.tenant,
      envelopeId,
    });
    await this.deps.auditStore.insert({
      tenantId: this.deps.config.tenant,
      action: "envelope.voided",
      targetTable: "envelope",
      targetId: envelope.id,
    });
    return summarize(envelope);
  }

  /** Approval-page-facing: resolve a raw token to its gate state. Never exposed as an MCP tool itself (design doc §4). */
  async resolve(token: string): Promise<TokenResolution> {
    return resolveSigningToken({ store: this.deps.envelopeStore, token });
  }

  /** Approval-page-facing: record a drawn signature; attempts to seal the document when this was the last signer. */
  async sign(token: string, signatureImageDataUrl: string): Promise<EnvelopeStatusSummary> {
    let envelope = await recordSignature({
      store: this.deps.envelopeStore,
      token,
      signatureImageDataUrl,
      signedAt: this.now(),
    });

    await this.deps.auditStore.insert({
      tenantId: this.deps.config.tenant,
      action: "envelope.signed",
      targetTable: "envelope",
      targetId: envelope.id,
      metadata: { status: envelope.status },
    });

    // D1(a): core already persisted `status: "completed"` inside
    // `recordSignature` above — the signature is validly recorded regardless
    // of what happens next. `seal()` below NEVER throws for a seal failure
    // (only for a bad `envelopeId` in `reseal()`'s own guards, which this
    // call path never hits) — see its own header comment.
    if (envelope.status === "completed") {
      envelope = await this.seal(envelope);
    }

    return summarize(envelope);
  }

  /**
   * `esig_reseal`. Retries the seal step for an envelope every signer has
   * already signed, when the automatic attempt inside `sign()` failed
   * (phase `seal_failed`) or never ran (phase `awaiting_seal`). Refuses with
   * a clear error if the envelope is not yet `completed`, or if it is
   * already `sealed`. `composeEnvelopeHtml` works from the stored envelope
   * alone — signatures are persisted on the envelope, not held in memory —
   * so this needs nothing beyond the `envelopeId`.
   */
  async reseal(envelopeId: string): Promise<EnvelopeStatusSummary> {
    const envelope = await this.deps.envelopeStore.findById(this.deps.config.tenant, envelopeId);
    if (!envelope) throw new EnvelopeError(`envelope not found: ${envelopeId}`);
    if (envelope.status !== "completed") {
      throw new EnvelopeError(
        `envelope ${envelopeId} is not completed yet (status: ${envelope.status}) — esig_reseal only ` +
          `applies to an envelope every signer has already signed.`,
      );
    }
    const currentSeal = mcpMeta(envelope)?.seal;
    if (currentSeal?.status === "sealed") {
      throw new EnvelopeError(
        `envelope ${envelopeId} is already sealed (${currentSeal.sealedPdfPath ?? "no path recorded"}) — ` +
          "nothing to reseal.",
      );
    }

    // D1(d): reuses the same hourly limiter `create()` draws from, under a
    // distinct label, so an agent retrying esig_reseal in a loop is bounded
    // by the same per-process cap rather than an unbounded new one.
    this.rateLimiter.take("reseal");

    await this.deps.auditStore.insert({
      tenantId: this.deps.config.tenant,
      action: "envelope.reseal_requested",
      targetTable: "envelope",
      targetId: envelopeId,
      metadata: { previousAttempts: currentSeal?.attempts ?? 0 },
    });

    const updated = await this.seal(envelope);
    return summarize(updated);
  }

  /**
   * Compose → render → sign (+ optional PQ seal) → self-verify → persist →
   * audit. Called once, right after the last signer completes an envelope
   * (`sign()`), and again on demand (`reseal()`).
   *
   * D1: NEVER throws for a seal failure — the signature this envelope
   * already carries (persisted by core's `recordSignature` before this ever
   * runs) is validly recorded no matter what happens here. On failure this
   * catches, persists `metadata.mcp.seal = {status:"failed", ...}`, and
   * audits `envelope.seal_failed` instead — `esig_reseal` (or another
   * automatic seal attempt) is how the envelope reaches `sealed` later. The
   * I4 content-binding check is inside the same try/catch as the render/
   * sign/verify/upload steps for the same reason: from the caller's point of
   * view both are "sealing didn't work this time", and either one is
   * equally worth surfacing through `esig_envelope_status`'s `seal.error`
   * rather than as an uncaught throw a caller might never see.
   */
  private async seal(envelope: Envelope): Promise<Envelope> {
    const { config } = this.deps;
    const attempts = (mcpMeta(envelope)?.seal?.attempts ?? 0) + 1;

    let artifact: {
      uploadedUrl: string;
      certId: string;
      certFingerprint: string;
      pqSealed: boolean;
      pqKeyId?: string;
      pqMldsa65Fpr?: string;
      signedAt: Date;
    };
    try {
      // I4: re-check the base html at seal time against the value pinned at
      // creation. Nothing in this package ever mutates `envelope.html` after
      // `create()`, so under correct operation this can only fail if a store
      // implementation (this one or an injected one) corrupted the row — but
      // that is exactly the case the invariant exists to catch.
      const pinned = mcpMeta(envelope)?.htmlSha256;
      const actual = crypto.createHash("sha256").update(envelope.html, "utf8").digest("hex");
      if (!pinned || pinned !== actual) {
        throw new EnvelopeError(
          `content binding check failed for envelope ${envelope.id}: base html sha256 at seal time ` +
            `(${actual}) does not match the value pinned at creation (${pinned ?? "none"}).`,
        );
      }

      const composed = composeEnvelopeHtml(envelope, { platformLabel: "e-sig MCP" });
      const pdf = await this.render(composed);

      const cert = await ensureActiveCert({
        store: this.deps.certStore,
        tenantId: config.tenant,
        subjectName: config.subjectName,
        passphrase: config.passphrase,
      });

      const pq = config.pq
        ? await ensureActivePqKeys({
            store: this.deps.pqKeyStore,
            tenantId: config.tenant,
            passphrase: config.passphrase,
          })
        : undefined;

      const signedAt = this.now();
      // v0.1: no TSA (design doc §5 "Config" / §8 rollout — RFC-3161 is not in scope here).
      const result = await signPdf({
        pdf,
        keyPem: cert.keyPem,
        certPem: cert.certPem,
        reason: "Envelope completed",
        location: "",
        contactInfo: "",
        name: config.subjectName,
        signingTime: signedAt,
        pqSeal: pq ? { keys: pq.keys, signedAt } : undefined,
      });

      const verdict = verifyPdfSignature(result.signedPdf);
      if (!verdict.ok) {
        throw new EnvelopeError(
          `self-verification failed for envelope ${envelope.id}: ${verdict.failures.join("; ")}`,
        );
      }

      const upload = await this.deps.pdfStorage.upload({
        path: `${config.tenant}/${envelope.id}/sealed.pdf`,
        bytes: result.signedPdf,
        contentType: "application/pdf",
      });

      artifact = {
        uploadedUrl: upload.url,
        certId: cert.cert.id,
        certFingerprint: cert.cert.certFingerprint,
        pqSealed: result.pqSealed,
        pqKeyId: result.pqKeyId,
        pqMldsa65Fpr: result.pqMldsa65Fpr,
        signedAt,
      };
    } catch (e) {
      const errorMessage = messageOf(e); // never a stack trace (I1)
      envelope.metadata = {
        ...envelope.metadata,
        mcp: {
          ...mcpMeta(envelope),
          seal: { status: "failed", attempts, error: errorMessage, lastAttemptAt: this.now().toISOString() },
        } satisfies McpEnvelopeMetadata,
      };
      const updated = await this.deps.envelopeStore.update(envelope);

      await this.deps.auditStore.insert({
        tenantId: config.tenant,
        action: "envelope.seal_failed",
        targetTable: "envelope",
        targetId: envelope.id,
        metadata: { error: errorMessage, attempts },
      });

      return updated;
    }

    envelope.metadata = {
      ...envelope.metadata,
      mcp: {
        ...mcpMeta(envelope),
        sealedPdfUrl: artifact.uploadedUrl,
        certFingerprint: artifact.certFingerprint,
        pqSealed: artifact.pqSealed,
        pqKeyId: artifact.pqKeyId,
        pqMldsa65Fpr: artifact.pqMldsa65Fpr,
        seal: {
          status: "sealed",
          attempts,
          sealedPdfPath: artifact.uploadedUrl,
          sealedAt: artifact.signedAt.toISOString(),
        },
      } satisfies McpEnvelopeMetadata,
    };
    const updated = await this.deps.envelopeStore.update(envelope);

    // D1(b): 'envelope.completed' is audited ONLY here — a failed attempt
    // audits 'envelope.seal_failed' instead (above), never this action.
    await this.deps.auditStore.insert({
      tenantId: config.tenant,
      action: "envelope.completed",
      targetTable: "envelope",
      targetId: envelope.id,
      certId: artifact.certId,
      certFingerprint: artifact.certFingerprint,
      signedPdfUrl: artifact.uploadedUrl,
      metadata: {
        post_quantum: artifact.pqSealed
          ? {
              sealed: true,
              alg: "hybrid-ed25519-ml-dsa-65",
              key_id: artifact.pqKeyId,
              mldsa65_fpr: artifact.pqMldsa65Fpr,
            }
          : { sealed: false },
        attempts,
      },
    });

    return updated;
  }
}

function summarize(envelope: Envelope): EnvelopeStatusSummary {
  const meta = mcpMeta(envelope);
  return {
    envelopeId: envelope.id,
    title: envelope.title,
    status: envelope.status,
    phase: derivePhase(envelope),
    signers: envelope.signers.map((s) => ({
      signerId: s.id,
      name: s.name,
      email: s.email,
      status: s.status,
      order: s.order,
      signedAt: s.signedAt?.toISOString(),
    })),
    createdAt: envelope.createdAt.toISOString(),
    completedAt: envelope.completedAt?.toISOString(),
    voidedAt: envelope.voidedAt?.toISOString(),
    sealedPdfUrl: meta?.sealedPdfUrl,
    seal: meta?.seal,
  };
}
