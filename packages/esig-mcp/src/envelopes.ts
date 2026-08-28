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
  declineEnvelope,
  decryptKeyPem,
  encryptKeyPem,
  ensureActiveCert,
  ensureActivePqKeys,
  isWellFormedUuaidAssertion,
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
import type { DocumentStore } from "./documents.js";
import {
  writeOutboxCompletionReceipt,
  type CompletionReceiptSigner,
  type DeliveryChannel,
  type DeliveryLink,
  type Receipt,
} from "./delivery.js";
import { stripControlChars } from "./email/templates.js";
import { appendEvent, listEvents } from "./events/log.js";
import type { EsigEvent, EsigEventInput } from "./events/types.js";
import type { EventDeliveryStatus, EventQueue } from "./events/queue.js";
import type { EventDispatcher } from "./events/sinks.js";
import { verifyRegistryBadge, type BadgePayload } from "./identity/badge.js";
import { issueChallenge, type IdentityChallengePayload } from "./identity/challenge.js";
import type { IdentityProofEvent } from "./identity/proof-source.js";
import { RegistryClient, RegistryNotFoundError } from "./identity/registry.js";
import {
  getEnvelopeIdentityPolicy,
  getSignerIdentityState,
  IDENTITY_LEVEL_ORDER,
  IdentityError,
  maxIdentityLevel,
  setEnvelopeIdentityPolicy,
  type EnvelopeIdentityPolicy,
  type IdentityLevel,
  type IdentityProofInput,
  type SignerIdentityRecord,
} from "./identity/types.js";
import { FOUNDATION_AGENT_UUAID_RE, uuaidFromEd25519Key, verifySignerIdentity } from "./identity/verify.js";
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
  /**
   * §17 seam 2: reach this signer over Pillar instead of/alongside email.
   * Validated at `create()` (fail closed): `publicKey` must derive `uuaid`
   * (`localIdFromEd25519Key`), and — when a registry is configured — its
   * badge for `uuaid` must attest `publicKey` too (RT G2), unless
   * `ESIG_MCP_PILLAR_ALLOW_UNREGISTERED=1` opts out of that second check.
   */
  pillar?: { uuaid: string; publicKey: string };
}

/** `esig_create_envelope`'s optional `identity` input (docs/architecture/esig-mcp.md §12 "Policy"). */
export interface CreateEnvelopeIdentityArgs {
  /** May only RAISE the server's configured `ESIG_MCP_IDENTITY_MIN_LEVEL` floor, never lower it. */
  minLevel?: IdentityLevel;
  /** Per-signer expected uuaid pin (T12). Exactly one of `signerId`/`index` per entry — `index` is a 0-based position into THIS call's `signers` array (server-generated ids don't exist yet at request time). */
  signers?: Array<{ signerId?: string; index?: number; uuaid: string }>;
}

/**
 * §13: a PDF envelope's pinned document — the ingested bytes an envelope
 * signs instead of rendering HTML. `docId`/`sha256` agree by construction for
 * the shipped `FsDocumentStore` (docId IS the sha256 of the ingested bytes),
 * but `sha256` is recomputed independently at both creation and seal time
 * (I4) rather than assumed equal to `docId`, so this shape holds for any
 * `DocumentStore` implementation.
 */
export interface EnvelopeDocumentMeta {
  docId: string;
  sha256: string;
  size: number;
  kind: "pdf";
}

export interface CreateEnvelopeArgs {
  title: string;
  /** The envelope body as HTML. Exactly one of `html`/`docId` is required (§13). */
  html?: string;
  /** A docId from `esig_ingest_document` — creates a PDF envelope (§13). Exactly one of `html`/`docId` is required. */
  docId?: string;
  signers: SignerInput[];
  expiresAt?: Date;
  identity?: CreateEnvelopeIdentityArgs;
  /** §15: optional sender note, shown in the signing-notification email (email delivery only). <= 500 chars enforced by the tool schema; control chars stripped here regardless of delivery channel. */
  message?: string;
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
  /** This envelope's signer-identity requirement (§12), if any was set. */
  identityPolicy?: EnvelopeIdentityPolicy;
  /** Present only for a PDF envelope (§13, created with `docId`). */
  document?: EnvelopeDocumentMeta;
  /** §15: the sender note, if one was set — control chars stripped, escaped wherever rendered (templates.ts). */
  message?: string;
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
  /** This envelope's signer-identity requirement (§12), if any was set. */
  identityPolicy?: EnvelopeIdentityPolicy;
  /** Present only for a PDF envelope (§13, created with `docId`). */
  document?: EnvelopeDocumentMeta;
  /** §15: the sender note, if one was set. */
  message?: string;
  signers: Array<{
    signerId: string;
    name: string;
    email: string;
    status: string;
    order: number;
    signedAt?: string;
    /** §16: ISO-8601, set the first time `GET /sign/<token>` resolves `"ok"` for this signer. */
    viewedAt?: string;
    /** Present once this signer's identity has been verified (§12 "What gets recorded"). */
    identity?: SignerIdentityRecord;
  }>;
  createdAt: string;
  completedAt?: string;
  voidedAt?: string;
  /** Set once the envelope reaches `completed` AND the seal step has succeeded (phase `sealed`). */
  sealedPdfUrl?: string;
  /** D1(c): present once a seal attempt (success or failure) has run at least once. */
  seal?: EnvelopeSealState;
  /** §16: the last 10 lifecycle events, oldest first. `esig_list_events` returns the full log. */
  events: EsigEvent[];
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
  /** §12 signer-identity policy + per-signer challenge/verified state — read/written ONLY via identity/types.ts's accessors, never spread/assigned directly. */
  identity?: import("./identity/types.js").EnvelopeIdentityMetadata;
  /** §13: set at creation for a PDF envelope (created with `docId`), never for an HTML envelope. */
  document?: EnvelopeDocumentMeta;
  /** §15: the sender note (esig_create_envelope's `message`), control chars stripped, set at creation only. */
  message?: string;
  /** §15: encrypted-at-rest signing links + per-signer reminder history — present only when reminders are configured (email delivery + ESIG_MCP_REMINDERS non-empty). */
  delivery?: McpDeliveryMetadata;
  /** §16: keyed by signerId, ISO-8601 — set once, the first time `GET /sign/<token>` resolves `"ok"` for that signer (`EnvelopeService.recordViewed`). */
  viewed?: Record<string, string>;
  /** §16: the full lifecycle event log, oldest first, capped at `MAX_EVENTS` (events/log.ts) — read/written only via `appendEvent`/`listEvents` there, never spread/assigned directly. */
  events?: EsigEvent[];
  /** §16: ISO-8601, set once `envelope.expired` has been emitted for this envelope (`events/expiry.ts`'s idempotency guard) — read/written only there, never here, but declared for documentation. */
  expiredEmittedAt?: string;
  /**
   * §17 seam 2 RT G2: signerIds whose `signers[].pillar.uuaid` had no
   * registry badge at creation time — present only when
   * `ESIG_MCP_PILLAR_ALLOW_UNREGISTERED=1` let `create()` proceed anyway.
   * Surfaced on the approval page as an "unregistered signer" notice for
   * each listed signer; audited per-signer as `signer.pillar_unregistered`.
   */
  pillarUnregisteredSignerIds?: string[];
}

/** §15 "Link persistence for reminders" + "Reminders". */
interface McpDeliveryMetadata {
  /** signerId -> base64(encryptKeyPem(url, config.passphrase)) — the ONLY place a signer's raw signing link is persisted outside the delivery channel itself; decrypted ONLY inside `EnvelopeService`'s reminder-sending path. */
  links?: Record<string, string>;
  /** signerId -> this signer's reminder send history. */
  reminders?: Record<string, SignerReminderState>;
}

export interface SignerReminderState {
  /**
   * ISO-8601, one entry per SCHEDULED (automatic) reminder actually sent, in
   * order — drives `nextAt`/the schedule index (`reminders.ts`'s
   * `computeDue`). Never includes manual sends (R1 fix, verifier finding):
   * before this fix, `esig_send_reminder`/`sendReminder` appended to this
   * SAME array, so a manual nudge silently consumed a scheduled slot (e.g. a
   * manual reminder sent between the 24h and 72h scheduled reminders could
   * make the 72h one never fire).
   */
  sentAt: string[];
  /**
   * ISO-8601, one entry per MANUAL reminder actually sent
   * (`esig_send_reminder` / `EnvelopeService.sendReminder`), in order — kept
   * separate from `sentAt` so a manual send never advances or cancels the
   * automatic schedule. Both arrays count toward `ESIG_MCP_REMINDER_MAX`
   * (the overall per-signer spam bound) combined — see `sendOneReminder`.
   */
  manualSentAt: string[];
  /** ISO-8601 of the next scheduled reminder, or `null` once the schedule/max cap is exhausted. */
  nextAt: string | null;
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

/** §13: this envelope's pinned PDF document metadata, if it is a PDF envelope (created with `docId`). */
export function getEnvelopeDocument(envelope: Envelope): EnvelopeDocumentMeta | undefined {
  return mcpMeta(envelope)?.document;
}

/** §17 seam 2 RT G2: signerIds whose Pillar-asserted uuaid had no registry badge at creation (present only under `ESIG_MCP_PILLAR_ALLOW_UNREGISTERED=1`) — the approval page uses this to show an "unregistered signer" notice. */
export function getPillarUnregisteredSignerIds(envelope: Envelope): string[] | undefined {
  return mcpMeta(envelope)?.pillarUnregisteredSignerIds;
}

/** §15: this signer's reminder send history, if any reminder has been sent yet. */
export function getSignerReminderState(envelope: Envelope, signerId: string): SignerReminderState | undefined {
  return mcpMeta(envelope)?.delivery?.reminders?.[signerId];
}

/**
 * RedTeam RT-2026-08-27-05 G3: a stored signing link (§15 "Link persistence")
 * has no purpose once the state it exists to resend has passed — a signed
 * (per that signer), declined, voided, expired, or completed envelope will
 * never send another reminder for the link(s) this erases, so the ciphertext
 * must not outlive its purpose. In place; no-op if there is nothing to
 * erase. `signerId` erases just that signer's link (the "signed" terminal
 * state, which is per-signer on a multi-signer envelope); omitted erases
 * every stored link (decline/void/expire/complete, which are terminal for
 * the WHOLE envelope).
 *
 * Callers apply this INSIDE an existing `emit()`/`appendEvent` `build`
 * callback, on the freshly-read envelope that callback already receives, so
 * the erasure rides the SAME fresh-read-CAS-write-with-retry cycle as the
 * event it's paired with (events/log.ts's `appendEvent`) — never a separate,
 * independently-racing write (see F1's fix, `EnvelopeService.sendOneReminder`,
 * for why an independent write here would be exactly the wrong shape).
 */
function eraseStoredLinks(envelope: Envelope, signerId?: string): void {
  const currentMcp = mcpMeta(envelope);
  const links = currentMcp?.delivery?.links;
  if (!links || Object.keys(links).length === 0) return;
  if (signerId !== undefined && !(signerId in links)) return;

  const nextLinks = { ...links };
  if (signerId !== undefined) {
    delete nextLinks[signerId];
  } else {
    for (const key of Object.keys(nextLinks)) delete nextLinks[key];
  }
  envelope.metadata = {
    ...envelope.metadata,
    mcp: { ...currentMcp, delivery: { ...currentMcp!.delivery, links: nextLinks } } satisfies McpEnvelopeMetadata,
  };
}

export interface EnvelopeServiceDeps {
  config: Config;
  envelopeStore: EnvelopeStore;
  certStore: CertStore;
  pqKeyStore: PqKeyStore;
  auditStore: AuditLogStore;
  pdfStorage: PdfStorageStore;
  delivery: DeliveryChannel;
  /**
   * §13: content-addressed PDF store, needed only for PDF envelopes (`docId`
   * on `create()`, and the seal step that signs the ingested bytes directly).
   * Optional so existing harnesses that only ever create HTML envelopes don't
   * need to supply it; `create()`/`seal()` throw a clear error if a PDF
   * envelope is attempted without one. `bin.ts` always supplies the real one.
   */
  documents?: DocumentStore;
  /** Injectable HTML→PDF renderer. Defaults to core's `renderHtmlToPdf` (needs a real Chrome). */
  render?: (html: string) => Promise<Buffer>;
  /**
   * G4 (RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827, MED): injectable
   * identity verifier, defaulting to the real `verifySignerIdentity`
   * (identity/verify.ts). Exists so a test can prove the downgrade-path
   * invariant directly — inject one that THROWS (a plain `Error`, not an
   * `IdentityError`) and confirm `sign()` still never records a signature,
   * still writes no `envelope.signed` audit row, and the throw still
   * propagates all the way to `POST /sign` as a non-2xx response — i.e.
   * that identity verification really does sit structurally OUTSIDE the
   * `seal()` error-swallowing try/catch (see `sign()` below: the identity
   * check runs, and can throw straight out of this function, well before
   * `recordSignature`/`seal()` are ever reached).
   */
  verifySignerIdentity?: typeof verifySignerIdentity;
  /** Injectable clock, for deterministic tests. */
  now?: () => Date;
  /** §16: present only when `ESIG_MCP_EVENTS_WEBHOOK_URL`/`_SECRET` are configured (bin.ts) — every emitted event is also enqueued here for webhook delivery. Absent means events are still logged (`metadata.mcp.events[]`, `esig_list_events`) but never POSTed anywhere. */
  eventQueue?: EventQueue;
  /** §17 seam 4: present only when at least one `EventSink` is registered (e.g. the Pillar bridge's, bin.ts) — every emitted event is ALSO fanned out here, after the webhook enqueue above, with per-sink isolation (a sink failure never blocks the webhook queue or another sink). */
  eventDispatcher?: EventDispatcher;
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
  /** §12 L2: undefined whenever no registry URL is configured — `verifySignerIdentity` fails closed on that (never silently skips L2). */
  private readonly registryClient?: RegistryClient;
  /** G4: the real verifier by default; injectable so a test can prove the downgrade-path invariant with one that throws (see `EnvelopeServiceDeps.verifySignerIdentity`). */
  private readonly verifyIdentity: typeof verifySignerIdentity;

  constructor(private readonly deps: EnvelopeServiceDeps) {
    this.render =
      deps.render ?? ((html) => renderHtmlToPdf({ html, launchArgs: [...SEAL_RENDER_LAUNCH_ARGS] }));
    this.now = deps.now ?? (() => new Date());
    this.rateLimiter = new HourlyRateLimiter(deps.config.envelopesPerHour, this.now);
    this.registryClient = deps.config.uuaidRegistryUrl ? new RegistryClient(deps.config.uuaidRegistryUrl) : undefined;
    this.verifyIdentity = deps.verifySignerIdentity ?? verifySignerIdentity;
    // §15: defense in depth alongside config.ts's own loadConfig-time refusal
    // — a test harness (or a future caller) that hand-builds a `Config`
    // bypassing loadConfig must not silently end up with a reminder schedule
    // it can never act on (no stored link to decrypt outside email delivery).
    if (deps.config.reminders.durationsMs.length > 0 && deps.config.delivery.kind !== "email") {
      throw new EnvelopeError('ESIG_MCP_REMINDERS requires ESIG_MCP_DELIVERY="email" (fail closed).');
    }
  }

  /**
   * §16: the single entry point every state-change site in this class calls
   * to append a lifecycle event and (when a webhook is configured) enqueue
   * it for delivery. `build` gets the freshly-read envelope on every attempt
   * (see `events/log.ts`'s `appendEvent` header comment) and returns the
   * event to append, or `false` to skip (the idempotency guards
   * `recordViewed`/`events/expiry.ts` use).
   *
   * Deliberately best-effort — NEVER throws, mirroring `seal()`'s own
   * "recorded either way" posture: the event log and its webhook are
   * auxiliary bookkeeping, and a failure here (a disk hiccup, a queue
   * directory permission issue) must never turn an otherwise-successful
   * `create`/`sign`/`void`/`decline`/`seal`/reminder call into a failure the
   * caller sees. A failure is reported once to stderr; the audit trail each
   * call site writes separately remains the authoritative record either way.
   */
  private async emit(envelopeId: string, build: (envelope: Envelope) => EsigEventInput | false): Promise<EsigEvent | undefined> {
    try {
      const { event } = await appendEvent({
        store: this.deps.envelopeStore,
        auditStore: this.deps.auditStore,
        tenantId: this.deps.config.tenant,
        envelopeId,
        now: this.now,
        build,
      });
      if (event && this.deps.eventQueue) {
        await this.deps.eventQueue.enqueue(event);
      }
      // §17 seam 4: fanned out AFTER the webhook enqueue above — see
      // EventDispatcher.dispatch's own header comment for why a sink
      // failure can never block the webhook queue or another sink.
      if (event && this.deps.eventDispatcher) {
        await this.deps.eventDispatcher.dispatch(event);
      }
      return event;
    } catch (e) {
      process.stderr.write(
        `[esig-mcp] WARNING: could not append lifecycle event for envelope ${envelopeId}: ${messageOf(e)}\n`,
      );
      return undefined;
    }
  }

  /**
   * F1 fix (verifier finding): fresh-read-CAS-write-with-retry, the exact
   * same shape as `appendEvent` (events/log.ts) — reads `envelopeId` fresh
   * from the store on every attempt (never trusts a caller's in-hand
   * `Envelope` object across an I/O gap this class doesn't fully control:
   * a concurrent `emit()`'s own independent CAS cycle, elsewhere in this
   * same call, can bump the store's revision out from under a stale
   * reference), lets `mutate` change it in place and return `true` to
   * persist or `false` to skip (no write), and retries from a fresh read on
   * `EnvelopeConflictError` up to `MAX_ATTEMPTS` times. Returns the
   * freshly-persisted envelope, or `undefined` when `mutate` chose to skip.
   */
  private async updateWithRetry(
    envelopeId: string,
    mutate: (envelope: Envelope) => boolean,
  ): Promise<Envelope | undefined> {
    const MAX_ATTEMPTS = 5;
    let lastError: unknown;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const envelope = await this.deps.envelopeStore.findById(this.deps.config.tenant, envelopeId);
      if (!envelope) throw new EnvelopeError(`envelope not found: ${envelopeId}`);
      const shouldWrite = mutate(envelope);
      if (!shouldWrite) return undefined;
      try {
        return await this.deps.envelopeStore.update(envelope);
      } catch (e) {
        lastError = e;
        // A concurrent writer won the CAS — retry from a fresh read, same as
        // events/log.ts's appendEvent.
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error(`could not update envelope ${envelopeId} (concurrent update contention)`);
  }

  /** `esig_create_envelope`. Sanitizes, caps, rate-limits, mints tokens, delivers links, audits, and returns NO raw tokens by default (I8). */
  async create(args: CreateEnvelopeArgs): Promise<CreateEnvelopeResultSummary> {
    const { config } = this.deps;

    if (!args.signers?.length) {
      throw new EnvelopeError("at least one signer is required");
    }
    // G6 (RedTeam RT-2026-08-27-05): bounds the email/webhook fan-out one
    // esig_create_envelope call can trigger.
    if (args.signers.length > config.maxSigners) {
      throw new EnvelopeError(
        `too many signers (${args.signers.length}) — this server's cap is ${config.maxSigners} ` +
          "(ESIG_MCP_MAX_SIGNERS).",
      );
    }

    // §13: esig_create_envelope accepts exactly one of `html` or `docId` — a
    // PDF envelope (docId) signs the exact ingested bytes; an HTML envelope
    // (html) renders at seal time. Checked before touching the doc store or
    // the rate limiter (the tool layer's zod refine gives a friendlier error
    // first, but this is the invariant's single source of truth — every
    // caller of this library method, not only the MCP tool, gets it).
    const hasHtml = args.html !== undefined;
    const hasDocId = args.docId !== undefined;
    if (hasHtml === hasDocId) {
      throw new EnvelopeError("exactly one of `html` or `docId` is required");
    }

    let effectiveHtml: string;
    let documentMeta: EnvelopeDocumentMeta | undefined;
    if (hasDocId) {
      if (!this.deps.documents) {
        throw new EnvelopeError(
          "this server has no document store configured — cannot create a PDF envelope from docId",
        );
      }
      const docId = args.docId!;
      let pdfBytes: Buffer;
      try {
        pdfBytes = await this.deps.documents.get(docId);
      } catch (e) {
        throw new EnvelopeError(`could not read docId ${docId}: ${messageOf(e)}`);
      }
      if (!isPdfMagic(pdfBytes)) {
        throw new EnvelopeError("docId is not a PDF");
      }
      if (pdfBytes.byteLength > config.maxPdfBytes) {
        throw new EnvelopeError(
          `docId ${docId} is ${pdfBytes.byteLength} bytes, exceeds the ${config.maxPdfBytes}-byte cap`,
        );
      }
      const sha256 = crypto.createHash("sha256").update(pdfBytes).digest("hex");
      documentMeta = { docId, sha256, size: pdfBytes.byteLength, kind: "pdf" };
      // The cover sheet drives core's html/token/order/recordSignature flow
      // exactly like a normal HTML envelope; it embeds the document sha256,
      // so the identity challenge's htmlSha256 pin (unchanged mechanism,
      // below) binds the PDF transitively (§13 "Identity challenge format
      // unchanged").
      effectiveHtml = buildPdfCoverSheetHtml({
        title: args.title,
        docId,
        sha256,
        size: pdfBytes.byteLength,
        signers: args.signers,
      });
    } else {
      effectiveHtml = args.html!;
    }

    const htmlBytes = Buffer.byteLength(effectiveHtml, "utf8");
    if (htmlBytes > config.maxHtmlBytes) {
      throw new EnvelopeError(`html is ${htmlBytes} bytes, exceeds the ${config.maxHtmlBytes}-byte cap`);
    }

    // §15: the length cap (<= 500) is enforced by the tool schema
    // (tools/create-envelope.ts) — this is defense in depth for any other
    // caller of this library method, plus the SMTP-header-injection strip
    // every rendering of it (templates.ts) applies again anyway.
    const message = args.message !== undefined ? stripControlChars(args.message) || undefined : undefined;

    // §12 "Policy": the effective level may only RAISE the server's
    // configured floor, never lower it. Validated BEFORE any write (fail
    // closed) — an L2 request with no registry configured refuses at
    // creation, matching config.ts's identical server-wide-floor check.
    const requestedMinLevel = args.identity?.minLevel ?? "none";
    const effectiveMinLevel = maxIdentityLevel(config.identityMinLevel, requestedMinLevel);
    if (effectiveMinLevel === "L2" && !config.uuaidRegistryUrl) {
      throw new EnvelopeError(
        "identity level L2 requires ESIG_MCP_UUAID_REGISTRY_URL (https://...) to be configured on " +
          "this server — refusing to create this envelope (fail closed).",
      );
    }
    // The badge trust anchor (identity/badge.ts) is as mandatory as the URL:
    // without the pinned key no badge can be verified, so an L2 envelope
    // would be dead on arrival at sign time.
    if (effectiveMinLevel === "L2" && !config.uuaidRegistrySigningKey) {
      throw new EnvelopeError(
        "identity level L2 requires ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY (the pinned UUAID registry Ed25519 " +
          "public key, 64 hex chars) to be configured on this server — refusing to create this envelope (fail closed).",
      );
    }
    for (const s of args.identity?.signers ?? []) {
      if (!isWellFormedUuaidAssertion(s.uuaid)) {
        throw new EnvelopeError(`identity.signers[].uuaid is not a well-formed uuaid: "${s.uuaid}"`);
      }
      const hasSignerId = s.signerId !== undefined;
      const hasIndex = s.index !== undefined;
      if (hasSignerId === hasIndex) {
        throw new EnvelopeError("each identity.signers[] entry needs exactly one of signerId or index");
      }
      if (hasIndex && (s.index! < 0 || s.index! >= args.signers.length)) {
        throw new EnvelopeError(
          `identity.signers[].index ${s.index} is out of range for ${args.signers.length} signer(s)`,
        );
      }
    }

    // §17 seam 2: validate signers[].pillar BEFORE any write (fail closed).
    // Pillar's own binding covers `split(":")[3]` of the uuaid only, so the
    // FULL uuaid string is what's checked here (§17 "the FULL uuaid string
    // is pinned, never the local id alone") — a wrong/substituted key simply
    // fails to derive the asserted uuaid.
    for (const s of args.signers) {
      if (!s.pillar) continue;
      if (!FOUNDATION_AGENT_UUAID_RE.test(s.pillar.uuaid)) {
        throw new EnvelopeError(
          `signers[].pillar.uuaid "${s.pillar.uuaid}" is not a well-formed uuaid:foundation:agent uuaid.`,
        );
      }
      if (!/^[0-9a-fA-F]{64}$/.test(s.pillar.publicKey)) {
        throw new EnvelopeError(
          `signers[].pillar.publicKey must be 64 hex characters (raw Ed25519 public key), got ${s.pillar.publicKey.length}.`,
        );
      }
      const derivedUuaid = uuaidFromEd25519Key(Buffer.from(s.pillar.publicKey, "hex"));
      if (derivedUuaid !== s.pillar.uuaid) {
        throw new EnvelopeError(
          `signers[].pillar.publicKey derives uuaid "${derivedUuaid}", not the configured "${s.pillar.uuaid}" — ` +
            "refusing (a self-authenticating identity must derive by construction).",
        );
      }
    }

    // RT-2026-08-28-01 G2: derivation alone cannot stop a substituted
    // self-consistent (uuaid, key) pair — only the registry can. When one is
    // configured, cross-check each pillar signer's asserted key against the
    // registry's own attestation BEFORE creating the envelope (fail closed).
    // A badge 404 is an explicit opt-in (`config.pillarAllowUnregistered`),
    // tracked here by INDEX (real signerIds don't exist until after
    // `createEnvelope` below) and later persisted + audited per signer.
    const unregisteredPillarIndices: number[] = [];
    if (config.uuaidRegistryUrl && config.uuaidRegistrySigningKey) {
      for (let i = 0; i < args.signers.length; i++) {
        const s = args.signers[i];
        if (!s.pillar) continue;
        let badgeRaw: unknown;
        try {
          badgeRaw = await this.registryClient!.badge(s.pillar.uuaid);
        } catch (e) {
          if (e instanceof RegistryNotFoundError) {
            if (!config.pillarAllowUnregistered) {
              throw new EnvelopeError(
                `registry has no badge for pillar signer uuaid "${s.pillar.uuaid}" — refusing (set ` +
                  "ESIG_MCP_PILLAR_ALLOW_UNREGISTERED=1 to allow unregistered Pillar signers).",
              );
            }
            unregisteredPillarIndices.push(i);
            continue;
          }
          throw new EnvelopeError(
            `registry badge fetch failed for pillar signer uuaid "${s.pillar.uuaid}": ${messageOf(e)}`,
          );
        }
        let badgePayload: BadgePayload;
        try {
          badgePayload = verifyRegistryBadge(badgeRaw, { pinnedRegistryKey: config.uuaidRegistrySigningKey, now: this.now() });
        } catch (e) {
          throw new EnvelopeError(`registry badge for pillar signer uuaid "${s.pillar.uuaid}" is invalid: ${messageOf(e)}`);
        }
        const presentationKey = badgePayload.subject.presentationKey;
        if (
          badgePayload.subject.uuaid !== s.pillar.uuaid ||
          !presentationKey ||
          presentationKey.publicKey.toLowerCase() !== s.pillar.publicKey.toLowerCase()
        ) {
          throw new EnvelopeError(
            `registry badge for pillar signer uuaid "${s.pillar.uuaid}" does not attest the configured publicKey ` +
              "(fail closed — a mismatch here means the registry disagrees with the asserted identity).",
          );
        }
      }
    }

    this.rateLimiter.take();

    const { html: sanitized, removed } = sanitizeEnvelopeHtml(effectiveHtml);
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
      // §13: `document` is present only for a PDF envelope (created with
      // `docId`) — status()/list()/create() all surface it from here.
      metadata: {
        mcp: {
          htmlSha256,
          removedTags: removed,
          returnLinks: config.returnLinks,
          ...(documentMeta ? { document: documentMeta } : {}),
          ...(message ? { message } : {}),
        },
      },
    });

    // §12: per-signer pins need real signerIds, which only exist after
    // creation — `index` resolves against `envelope.signers`, which core
    // preserves in the same order as the `args.signers` this call submitted.
    // One extra write, right after insert and before this envelope's id/
    // tokens are handed to anyone — nothing else can be racing it yet.
    let identityPolicy: EnvelopeIdentityPolicy | undefined;
    const identitySigners = args.identity?.signers ?? [];
    if (effectiveMinLevel !== "none" || identitySigners.length > 0) {
      const policySigners: Record<string, { expectedUuaid?: string }> = {};
      for (const s of identitySigners) {
        const signerId = s.signerId ?? envelope.signers[s.index!].id;
        policySigners[signerId] = { expectedUuaid: s.uuaid };
      }
      identityPolicy = {
        minLevel: effectiveMinLevel,
        signers: policySigners,
        // G3: pin the registry URL this envelope commits to, ONLY when L2
        // will actually consult one (the earlier fail-closed check above
        // already guarantees config.uuaidRegistryUrl is set whenever
        // effectiveMinLevel is "L2").
        ...(effectiveMinLevel === "L2" ? { registryUrl: config.uuaidRegistryUrl } : {}),
      };
      setEnvelopeIdentityPolicy(envelope, identityPolicy);
      await this.deps.envelopeStore.update(envelope);
    }

    // §17 seam 2 RT G2: persist which signers were let through unregistered
    // (index -> real signerId, now that envelope.signers exists) and audit
    // each one — one more write, same "right after insert, nothing else can
    // be racing it yet" window the identity-policy write above uses.
    const pillarUnregisteredEntries = unregisteredPillarIndices.map((i) => ({
      signerId: envelope.signers[i].id,
      uuaid: args.signers[i].pillar!.uuaid,
    }));
    if (pillarUnregisteredEntries.length > 0) {
      const pillarUnregisteredSignerIds = pillarUnregisteredEntries.map((e) => e.signerId);
      const currentMcp = mcpMeta(envelope) ?? {};
      envelope.metadata = {
        ...envelope.metadata,
        mcp: { ...currentMcp, pillarUnregisteredSignerIds } satisfies McpEnvelopeMetadata,
      };
      await this.deps.envelopeStore.update(envelope);
      for (const { signerId, uuaid } of pillarUnregisteredEntries) {
        await this.deps.auditStore.insert({
          tenantId: config.tenant,
          action: "signer.pillar_unregistered",
          targetTable: "envelope",
          targetId: envelope.id,
          metadata: { signerId, uuaid },
        });
      }
    }

    const links: DeliveryLink[] = signingTokens.map((t) => {
      const signerIndex = envelope.signers.findIndex((s) => s.id === t.signerId);
      const signer = envelope.signers[signerIndex];
      const pillarInput = signerIndex >= 0 ? args.signers[signerIndex]?.pillar : undefined;
      return {
        signerId: t.signerId,
        name: signer.name,
        email: signer.email,
        url: `${config.baseUrl}/sign/${t.token}`,
        // Informational only (never a verified record — that only exists
        // after this signer actually presents a proof): lets the file-outbox
        // receipt (delivery.ts) tell whoever relays the link what identity
        // level/uuaid pin this signer is expected to satisfy (§12 "What gets
        // recorded" — file outbox receipt).
        ...(identityPolicy
          ? { identity: { minLevel: identityPolicy.minLevel, expectedUuaid: identityPolicy.signers[signer.id]?.expectedUuaid } }
          : {}),
        // §17 seam 2: a channel that understands Pillar (PillarDelivery)
        // routes this signer over it instead of/alongside `url` above; any
        // other channel simply ignores this field.
        ...(pillarInput ? { pillar: { uuaid: pillarInput.uuaid, publicKey: pillarInput.publicKey.toLowerCase() } } : {}),
      };
    });

    // §15 "Link persistence for reminders" — the ONE custody change: when
    // reminders are configured (which config.ts only ever allows alongside
    // email delivery — the constructor above re-checks it for hand-built
    // Configs too), core will never re-mint these tokens, so a reminder needs
    // the original link. Encrypted at rest under the operator passphrase
    // (core's AES-256-GCM encryptKeyPem/decryptKeyPem — the same helpers
    // ensureActiveCert/wrapPqKeyBundle already use for the cert/PQ key
    // bundles), decrypted ONLY inside the reminder-sending path
    // (`sendOneReminder` below), and never exposed by any tool (I8 unchanged
    // — nothing here touches what `esig_create_envelope`'s result carries).
    // Off (no write at all) when reminders are not configured.
    if (config.delivery.kind === "email" && config.reminders.durationsMs.length > 0) {
      const encryptedLinks: Record<string, string> = {};
      for (const link of links) {
        encryptedLinks[link.signerId] = Buffer.from(encryptKeyPem(link.url, config.passphrase)).toString("base64");
      }
      const currentMcp = mcpMeta(envelope) ?? {};
      envelope.metadata = {
        ...envelope.metadata,
        mcp: {
          ...currentMcp,
          delivery: { ...currentMcp.delivery, links: encryptedLinks },
        } satisfies McpEnvelopeMetadata,
      };
      await this.deps.envelopeStore.update(envelope);
    }

    const receipts = await this.deps.delivery.deliver(
      { id: envelope.id, title: envelope.title, message, expiresAt: envelope.expiresAt?.toISOString() },
      links,
    );

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
        identityMinLevel: identityPolicy?.minLevel,
        document: documentMeta,
        hasMessage: message !== undefined,
      },
    });

    // §16: emitted last, after the audit row above — see `emit()`'s own
    // header comment for why a failure here never turns a successful
    // `create()` into a failure the caller sees.
    await this.emit(envelope.id, (e) => ({
      type: "envelope.created",
      envelopeId: e.id,
      phase: derivePhase(e),
      data: { signerCount: e.signers.length, delivery: config.delivery.kind },
    }));

    return {
      envelopeId: envelope.id,
      signers: envelope.signers.map((s) => ({ signerId: s.id, name: s.name, email: s.email, status: s.status })),
      htmlSha256,
      removedTags: removed,
      delivery: receipts,
      ...(config.returnLinks ? { links } : {}),
      ...(identityPolicy ? { identityPolicy } : {}),
      ...(documentMeta ? { document: documentMeta } : {}),
      ...(message ? { message } : {}),
    };
  }

  /** `esig_envelope_status`. */
  async status(envelopeId: string): Promise<EnvelopeStatusSummary> {
    const envelope = await this.deps.envelopeStore.findById(this.deps.config.tenant, envelopeId);
    if (!envelope) throw new EnvelopeError(`envelope not found: ${envelopeId}`);
    return summarize(envelope);
  }

  /**
   * `esig_list_events(envelopeId, since?)` (§16). Read-only. `since` filters
   * to events strictly after the given ISO-8601 timestamp (pass the
   * `createdAt` of the last event you've already seen). When a webhook is
   * configured, each event also carries its current delivery status
   * (`pending`/`delivered`/`dead` + attempt count) — omitted when no webhook
   * is configured, or once a delivered receipt has aged past its 24h
   * retention.
   */
  async listEvents(envelopeId: string, since?: string): Promise<Array<EsigEvent & { delivery?: EventDeliveryStatus }>> {
    const envelope = await this.deps.envelopeStore.findById(this.deps.config.tenant, envelopeId);
    if (!envelope) throw new EnvelopeError(`envelope not found: ${envelopeId}`);
    const events = listEvents(envelope, since);
    const eventQueue = this.deps.eventQueue;
    if (!eventQueue) return events;
    return Promise.all(events.map(async (e) => ({ ...e, delivery: await eventQueue.statusOf(e.id) })));
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
    await this.emit(envelope.id, (e) => {
      // G3: void is terminal for the whole envelope — erase every stored link.
      eraseStoredLinks(e);
      return { type: "envelope.voided", envelopeId: e.id, phase: derivePhase(e), data: {} };
    });
    return summarize(envelope);
  }

  /** Approval-page-facing: resolve a raw token to its gate state. Never exposed as an MCP tool itself (design doc §4). */
  async resolve(token: string): Promise<TokenResolution> {
    return resolveSigningToken({ store: this.deps.envelopeStore, token });
  }

  /**
   * Approval-page-facing (§15/§16 "Decline"): `POST /sign/<token>/decline`
   * (http.ts) only — deliberately not an MCP tool, same reasoning as
   * signing itself (design doc §4: declining is human-side only). Core's
   * `declineEnvelope` marks the signer `declined` and voids the whole
   * envelope in one step; `reason` is control-character-stripped and capped
   * by the caller (http.ts) before it ever reaches here.
   */
  async decline(token: string, reason?: string): Promise<EnvelopeStatusSummary> {
    const envelope = await declineEnvelope({ store: this.deps.envelopeStore, token, reason });
    // declineEnvelope refuses (throws core's EnvelopeError) once the
    // envelope is already voided/expired/completed/already-signed, and it
    // flips the WHOLE envelope to voided on success — so at most one signer
    // can ever be "declined" on a given envelope.
    const signer = envelope.signers.find((s) => s.status === "declined");
    await this.deps.auditStore.insert({
      tenantId: this.deps.config.tenant,
      action: "envelope.declined",
      targetTable: "envelope",
      targetId: envelope.id,
      metadata: { signerId: signer?.id, hasReason: reason !== undefined },
    });
    await this.emit(envelope.id, (e) => {
      const declinedSigner = e.signers.find((s) => s.id === signer?.id) ?? signer;
      // G3: declineEnvelope voids the WHOLE envelope — erase every stored link.
      eraseStoredLinks(e);
      return {
        type: "envelope.declined",
        envelopeId: e.id,
        phase: derivePhase(e),
        signer: declinedSigner
          ? { signerId: declinedSigner.id, name: declinedSigner.name, email: declinedSigner.email, status: declinedSigner.status }
          : undefined,
        data: { hasReason: reason !== undefined },
      };
    });
    return summarize(envelope);
  }

  /**
   * Approval-page-facing (§16): `GET /sign/<token>` resolving `"ok"`
   * (http.ts) calls this once per request — it is idempotent PER SIGNER, so
   * repeat page loads/reloads are cheap no-ops after the first. Persists
   * `viewedAt` on the signer's mcp metadata and emits `envelope.viewed`
   * exactly once. Never throws (mirrors `seal()`'s "recorded either way"
   * posture): a viewed-tracking failure must not block the approval page
   * from rendering — `emit()` itself already swallows append/enqueue
   * failures, so the only thing this wraps is the audit insert below.
   */
  async recordViewed(envelopeId: string, signerId: string): Promise<void> {
    const event = await this.emit(envelopeId, (envelope) => {
      const signer = envelope.signers.find((s) => s.id === signerId);
      if (!signer) return false;
      const meta = mcpMeta(envelope) ?? {};
      if (meta.viewed?.[signerId] !== undefined) return false; // already recorded — no-op
      const at = this.now().toISOString();
      envelope.metadata = {
        ...envelope.metadata,
        mcp: { ...meta, viewed: { ...meta.viewed, [signerId]: at } } satisfies McpEnvelopeMetadata,
      };
      return {
        type: "envelope.viewed",
        envelopeId: envelope.id,
        phase: derivePhase(envelope),
        signer: { signerId: signer.id, name: signer.name, email: signer.email, status: signer.status },
        data: {},
      };
    });
    if (!event) return; // no-op (already viewed) or `emit()` swallowed a failure — either way, nothing new to audit
    try {
      await this.deps.auditStore.insert({
        tenantId: this.deps.config.tenant,
        action: "envelope.viewed",
        targetTable: "envelope",
        targetId: envelopeId,
        metadata: { signerId },
      });
    } catch (e) {
      process.stderr.write(
        `[esig-mcp] WARNING: could not write the envelope.viewed audit row for envelope ${envelopeId} signer ${signerId}: ${messageOf(e)}\n`,
      );
    }
  }

  /**
   * Approval-page-facing (§13): read the raw ingested PDF bytes for a docId
   * this envelope pinned at creation — `GET /sign/<token>/document.pdf`
   * (http.ts) is the only caller. Bytes only; the caller is responsible for
   * resolving the token to a `docId` first via {@link getEnvelopeDocument}.
   */
  async getDocumentBytes(docId: string): Promise<Buffer> {
    if (!this.deps.documents) {
      throw new EnvelopeError("this server has no document store configured — cannot read PDF envelope bytes");
    }
    return this.deps.documents.get(docId);
  }

  /**
   * `esig_identity_challenge` / `GET /sign/<token>/challenge` (§12
   * "Challenge"). Rate-limited under the SAME hourly limiter `create()`
   * draws from (label `"challenge"`, distinct bucket from the default
   * `"envelope-creation"` one), audited `signer.challenge_issued`.
   */
  async issueIdentityChallenge(envelopeId: string, signerId: string): Promise<IdentityChallengePayload> {
    this.rateLimiter.take("challenge");
    const payload = await issueChallenge({
      store: this.deps.envelopeStore,
      tenantId: this.deps.config.tenant,
      envelopeId,
      signerId,
      ttlSec: this.deps.config.identityChallengeTtlSec,
      now: this.now,
    });
    await this.deps.auditStore.insert({
      tenantId: this.deps.config.tenant,
      action: "signer.challenge_issued",
      targetTable: "envelope",
      targetId: envelopeId,
      metadata: { signerId, expiresAt: payload.expiresAt },
    });
    return payload;
  }

  /**
   * Approval-page-facing: record a drawn signature; attempts to seal the
   * document when this was the last signer. §12: when this envelope's
   * effective identity level is above "none", `identityProof` is verified
   * BEFORE core `recordSignature` runs — a rejection throws
   * {@link IdentityError} (http.ts maps it to 403) and NO signature is
   * recorded; success persists the signer's identity record + audits
   * `signer.identity_verified`, then (and only then) falls through to
   * `recordSignature` below.
   */
  async sign(token: string, signatureImageDataUrl: string, identityProof?: IdentityProofInput): Promise<EnvelopeStatusSummary> {
    const gate = await resolveSigningToken({ store: this.deps.envelopeStore, token });
    if (gate.status === "ok") {
      const policy = getEnvelopeIdentityPolicy(gate.envelope);
      const minLevel = policy?.minLevel ?? "none";
      if (minLevel !== "none") {
        const expectedUuaid = policy?.signers[gate.signer.id]?.expectedUuaid;

        // §17 seam 3: a record already verified out-of-band (Pillar identity
        // proof, `acceptPreVerifiedIdentity` below — SAME verification path,
        // already atomically bound to this signer's challenge nonce) that
        // satisfies THIS request's effective level is accepted without
        // requiring `identityProof` at all — even when one was also passed,
        // it is simply not needed (never re-verified: its nonce may already
        // be consumed by the very record we're accepting here).
        const existing = getSignerIdentityState(gate.envelope, gate.signer.id)?.verified;
        const preVerifiedOk =
          existing !== undefined &&
          IDENTITY_LEVEL_ORDER[existing.level] >= IDENTITY_LEVEL_ORDER[minLevel] &&
          (expectedUuaid === undefined || existing.uuaid === expectedUuaid);

        if (preVerifiedOk) {
          await this.deps.auditStore.insert({
            tenantId: this.deps.config.tenant,
            action: "signer.identity_preverified_used",
            targetTable: "envelope",
            targetId: gate.envelope.id,
            metadata: { signerId: gate.signer.id, uuaid: existing!.uuaid, level: existing!.level },
          });
        } else {
        let record: SignerIdentityRecord | undefined;
        try {
          record = await this.verifyIdentity({
            store: this.deps.envelopeStore,
            tenantId: this.deps.config.tenant,
            envelopeId: gate.envelope.id,
            signerId: gate.signer.id,
            minLevel,
            expectedUuaid,
            proof: identityProof,
            registry: this.registryClient,
            // G3: pinned at creation vs. read fresh from config right now —
            // compared inside verifySignerIdentity before any registry call.
            pinnedRegistryUrl: policy?.registryUrl,
            configuredRegistryUrl: this.deps.config.uuaidRegistryUrl,
            // The badge trust anchor, read fresh from config (never cached at
            // creation — see VerifySignerIdentityInput.registrySigningKey).
            registrySigningKey: this.deps.config.uuaidRegistrySigningKey,
            // R1: persists proof/credential/resolve-response JSON via the
            // same PdfStorageStore seam `seal()` uses for the sealed PDF.
            blobStore: this.deps.pdfStorage,
            now: this.now,
          });
        } catch (e) {
          if (e instanceof IdentityError) {
            await this.deps.auditStore.insert({
              tenantId: this.deps.config.tenant,
              action: "signer.identity_rejected",
              targetTable: "envelope",
              targetId: gate.envelope.id,
              metadata: { signerId: gate.signer.id, reason: e.reason, uuaid: e.uuaid, level: e.level },
            });
            // §16: emit-only (this ticket's own wording) — never touches the
            // verification result or ordering above; `sign()` still throws
            // `e` unconditionally right below regardless of what `emit()` does.
            await this.emit(gate.envelope.id, (env) => {
              const s = env.signers.find((x) => x.id === gate.signer.id) ?? gate.signer;
              return {
                type: "signer.identity_rejected",
                envelopeId: env.id,
                phase: derivePhase(env),
                signer: { signerId: s.id, name: s.name, email: s.email, status: s.status },
                data: { reason: e.reason, level: e.level },
              };
            });
          }
          throw e;
        }
        if (record) {
          await this.deps.auditStore.insert({
            tenantId: this.deps.config.tenant,
            action: "signer.identity_verified",
            targetTable: "envelope",
            targetId: gate.envelope.id,
            metadata: { signerId: gate.signer.id, uuaid: record.uuaid, level: record.level, keyFingerprint: record.keyFingerprint },
          });
          await this.emit(gate.envelope.id, (env) => {
            const s = env.signers.find((x) => x.id === gate.signer.id) ?? gate.signer;
            return {
              type: "signer.identity_verified",
              envelopeId: env.id,
              phase: derivePhase(env),
              signer: { signerId: s.id, name: s.name, email: s.email, status: s.status },
              data: { level: record!.level },
            };
          });
        }
        }
      }
    }

    // Captured before `recordSignature` (below) advances signer state — safe
    // even when `gate.status !== "ok"` (every non-"invalid" TokenResolution
    // variant still carries `signer`; an "invalid" token throws out of
    // `recordSignature` before this value is ever used).
    const signingSignerId = gate.status !== "invalid" ? gate.signer.id : undefined;

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
    await this.emit(envelope.id, (e) => {
      const signer = e.signers.find((s) => s.id === signingSignerId);
      // G3: "signed" is terminal PER SIGNER (a multi-signer envelope keeps
      // going) — erase only this signer's stored link.
      if (signingSignerId !== undefined) eraseStoredLinks(e, signingSignerId);
      return {
        type: "envelope.signed",
        envelopeId: e.id,
        phase: derivePhase(e),
        signer: signer ? { signerId: signer.id, name: signer.name, email: signer.email, status: signer.status } : undefined,
        data: {},
      };
    });
    if (envelope.status === "completed") {
      await this.emit(envelope.id, (e) => {
        // G3: belt-and-suspenders — every signer's own "signed" emit above
        // already erased its own link, but completion is independently a
        // terminal state for the whole envelope (the ticket's own wording
        // lists it separately from "signed").
        eraseStoredLinks(e);
        return { type: "envelope.completed", envelopeId: e.id, phase: derivePhase(e), data: {} };
      });
    }

    // Each `emit()` call above performs its OWN fresh read-CAS-write cycle
    // (events/log.ts's `appendEvent`, I3 class) against a SEPARATE envelope
    // object — unlike `EnvelopeStore.update()` (stores.ts's
    // `ConcurrencySafeEnvelopeStore`), which mutates and returns the SAME
    // object it was given, so sequential writes on one in-hand reference
    // normally chain safely. `envelope` here is that original
    // `recordSignature` result, now stale (its `__mcpRev` no longer matches
    // what's on disk once either emit above ran) — `seal()`'s own
    // `envelopeStore.update()` next would throw `EnvelopeConflictError` on
    // it. Re-reading once, fresh, fixes both `seal()` below and
    // `summarize()`'s own "last 10 events" freshness.
    const refreshed = await this.deps.envelopeStore.findById(this.deps.config.tenant, envelope.id);
    if (refreshed) envelope = refreshed;

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
   * §17 seam 3: accept an out-of-band identity proof relayed by an
   * `IdentityProofSource` (e.g. the Pillar bridge's inbox poller). Runs the
   * SAME verification path `POST /sign`'s `identityProof` uses — challenge
   * nonce binding, L0/L1/L1p/L2, atomic consumption via `finalizeChallenge`
   * — against whatever identity challenge is CURRENTLY live for this signer
   * (`verifySignerIdentity` itself refuses with `L1_NO_CHALLENGE` if none
   * has been issued yet; the sender-side agent must relay/issue one first,
   * exactly like the human-facing flow). On success `finalizeChallenge`
   * already persists the record under
   * `metadata.mcp.identity.signers[signerId].verified` — `sign()`'s own
   * `preVerifiedOk` check above is what later reads it back, so the human
   * just signs, no pasting.
   *
   * Deliberately never throws for a VERIFICATION failure (a stale, forged,
   * or mismatched proof is audited as `signer.identity_rejected` and
   * swallowed) — an out-of-band relay is best-effort, unlike `POST /sign`'s
   * own live `identityProof`, which must surface a real error to the human
   * waiting on it. It still throws for a genuinely unexpected failure (e.g.
   * the envelope store itself erroring).
   */
  async acceptPreVerifiedIdentity(evt: IdentityProofEvent): Promise<SignerIdentityRecord | undefined> {
    const envelope = await this.deps.envelopeStore.findById(this.deps.config.tenant, evt.envelopeId);
    if (!envelope) {
      process.stderr.write(
        `[esig-mcp] WARNING: acceptPreVerifiedIdentity: envelope not found: ${evt.envelopeId} (signer ${evt.signerId})\n`,
      );
      return undefined;
    }
    const policy = getEnvelopeIdentityPolicy(envelope);
    const minLevel = policy?.minLevel ?? "none";
    if (minLevel === "none") return undefined; // nothing this envelope requires verifying
    const expectedUuaid = policy?.signers[evt.signerId]?.expectedUuaid;

    try {
      const record = await this.verifyIdentity({
        store: this.deps.envelopeStore,
        tenantId: this.deps.config.tenant,
        envelopeId: evt.envelopeId,
        signerId: evt.signerId,
        minLevel,
        expectedUuaid,
        proof: { uuaid: evt.uuaid, proof: evt.proof, credential: evt.credential as IdentityProofInput["credential"] },
        registry: this.registryClient,
        pinnedRegistryUrl: policy?.registryUrl,
        configuredRegistryUrl: this.deps.config.uuaidRegistryUrl,
        registrySigningKey: this.deps.config.uuaidRegistrySigningKey,
        blobStore: this.deps.pdfStorage,
        now: this.now,
      });
      if (record) {
        await this.deps.auditStore.insert({
          tenantId: this.deps.config.tenant,
          action: "signer.identity_verified",
          targetTable: "envelope",
          targetId: evt.envelopeId,
          metadata: {
            signerId: evt.signerId,
            uuaid: record.uuaid,
            level: record.level,
            keyFingerprint: record.keyFingerprint,
            viaPillarEnvelopeId: evt.pillarEnvelopeId,
          },
        });
        await this.emit(evt.envelopeId, (env) => {
          const s = env.signers.find((x) => x.id === evt.signerId);
          return {
            type: "signer.identity_verified",
            envelopeId: env.id,
            phase: derivePhase(env),
            signer: s ? { signerId: s.id, name: s.name, email: s.email, status: s.status } : undefined,
            data: { level: record.level },
          };
        });
      }
      return record;
    } catch (e) {
      if (e instanceof IdentityError) {
        await this.deps.auditStore.insert({
          tenantId: this.deps.config.tenant,
          action: "signer.identity_rejected",
          targetTable: "envelope",
          targetId: evt.envelopeId,
          metadata: { signerId: evt.signerId, reason: e.reason, uuaid: e.uuaid, level: e.level, viaPillarEnvelopeId: evt.pillarEnvelopeId },
        });
        return undefined;
      }
      throw e;
    }
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
   * `esig_send_reminder(envelopeId, signerId?)` (§15 "Reminders", manual
   * path). Rate-limited under the SAME hourly limiter `create()`/`reseal()`
   * draw from (label `"reminder"`, its own bucket). Omit `signerId` to remind
   * every currently-pending signer; a specific `signerId` that is not
   * pending is reported (not thrown) as a per-signer failure so a batch call
   * doesn't die on one already-signed signer.
   *
   * Requires reminders to be configured (`ESIG_MCP_REMINDERS` non-empty) —
   * that is the only thing that causes a signing link to have been
   * persisted at creation (see `create()`'s "Link persistence" block above);
   * with no stored link there is nothing to resend.
   */
  async sendReminder(
    envelopeId: string,
    signerId?: string,
  ): Promise<{ sent: Array<{ signerId: string; ok: boolean; messageId?: string; error?: string }> }> {
    const { config } = this.deps;
    if (config.reminders.durationsMs.length === 0) {
      throw new EnvelopeError(
        "reminders are not configured (ESIG_MCP_REMINDERS is unset) — no signing links were stored to resend.",
      );
    }
    if (config.delivery.kind !== "email") {
      throw new EnvelopeError('reminders require ESIG_MCP_DELIVERY="email".');
    }

    const envelope = await this.deps.envelopeStore.findById(config.tenant, envelopeId);
    if (!envelope) throw new EnvelopeError(`envelope not found: ${envelopeId}`);

    const targets = signerId ? envelope.signers.filter((s) => s.id === signerId) : envelope.signers;
    if (signerId && targets.length === 0) {
      throw new EnvelopeError(`signer not found on envelope ${envelopeId}: ${signerId}`);
    }

    this.rateLimiter.take("reminder");

    const sent: Array<{ signerId: string; ok: boolean; messageId?: string; error?: string }> = [];
    for (const signer of targets) {
      if (signer.status !== "pending") {
        sent.push({ signerId: signer.id, ok: false, error: `signer status is "${signer.status}", not pending` });
        continue;
      }
      try {
        const receipt = await this.sendOneReminder(envelope, signer.id, "manual");
        sent.push({
          signerId: signer.id,
          ok: receipt.ok,
          messageId: receipt.messageId,
          error: receipt.ok ? undefined : receipt.detail,
        });
      } catch (e) {
        sent.push({ signerId: signer.id, ok: false, error: messageOf(e) });
      }
    }
    return { sent };
  }

  /**
   * reminders.ts's `Scheduler` — send one automatically-due reminder for a
   * specific signer, given the envelope object already in hand (from
   * `stores.ts`'s `listEnvelopes`, which is how the scheduler finds due
   * envelopes in the first place). Deliberately NOT rate-limited: the
   * schedule + `ESIG_MCP_REMINDER_MAX` cap (`reminders.ts` `computeDue`) are
   * the throttle for the automatic path — `sendReminder`'s hourly "reminder"
   * bucket above is for the agent-facing MANUAL tool only, so an agent
   * retrying `esig_send_reminder` in a loop can never starve the scheduled
   * reminders a human is actually waiting on (and vice versa).
   */
  async sendScheduledReminder(envelope: Envelope, signerId: string): Promise<Receipt> {
    return this.sendOneReminder(envelope, signerId, "scheduled");
  }

  /**
   * `nextAt` for a signer given how many SCHEDULED reminders they have had
   * (manual sends never affect this — R1 fix). Shared by the forward path
   * and the R3 rollback path below so both compute it identically.
   */
  private reminderNextAt(createdAt: Date, scheduledCount: number): string | null {
    const scheduleMs = this.deps.config.reminders.durationsMs;
    const cap = Math.min(this.deps.config.reminders.max, scheduleMs.length);
    return scheduledCount < cap ? new Date(createdAt.getTime() + scheduleMs[scheduledCount]).toISOString() : null;
  }

  /**
   * Shared by `sendReminder()` (manual) and `sendScheduledReminder()`
   * (automatic): decrypt the stored link, send it through the configured
   * (email) delivery channel, persist this signer's reminder history, and
   * audit the outcome. Never THROWS for a delivery failure — mirrors
   * `seal()`'s own "this is recorded either way" shape: the receipt's
   * `ok:false` is the signal, not an exception, so a batch `sendReminder()`
   * call can report per-signer results instead of aborting on the first
   * failed send.
   *
   * `kind` distinguishes a scheduler-driven send from an agent-driven
   * `esig_send_reminder` call (R1 fix, verifier finding): before this fix
   * both appended to the SAME `sentAt[]` that `reminders.ts`'s `computeDue`
   * reads to decide the next scheduled index, so a manual nudge silently
   * consumed a scheduled slot (schedule 24h/72h: a manual reminder sent
   * between them could make the 72h one never fire). Now only a `"scheduled"`
   * send appends to `sentAt[]`/advances `nextAt`; a `"manual"` send appends
   * only to `manualSentAt[]`. Both arrays still count toward
   * `ESIG_MCP_REMINDER_MAX` combined (the spam bound) — see the limit check
   * below.
   *
   * F1 fix (verifier finding): both `sendReminder()`'s own per-signer loop
   * and `reminders.ts`'s `Scheduler.tick()` can call this method several
   * times in a row for the SAME envelope, handing it the exact same in-hand
   * `Envelope` object each time (`envelopeIn` below) — but `emit()` below
   * (via `appendEvent`) does its OWN independent fresh-read-CAS-write cycle
   * against a SEPARATE envelope object on every call, silently bumping the
   * store's revision out from under any other in-hand reference. Reusing
   * `envelopeIn` across signers therefore made the SECOND signer's own
   * `envelopeStore.update()` call fail with `EnvelopeConflictError` — AFTER
   * this method had already sent that signer's email — reporting a bogus
   * failure and leaving the schedule/audit state unwritten, so the next tick
   * re-sent the same reminder. The fix: `envelopeIn` is used for nothing but
   * its `.id` — every attempt re-reads fresh from the store
   * (`updateWithRetry`) and persists the "this reminder was sent" state
   * BEFORE actually sending, with retry, so a CAS conflict can only ever
   * delay a send (retried against a fresh read) and never cause a duplicate
   * one.
   *
   * R3 fix (verifier finding): persisting BEFORE sending means a transport
   * failure would otherwise leave the slot permanently consumed (recorded
   * `ok:false`, `nextAt` already advanced/nulled) with no code path left to
   * retry it. On a failed `receipt`, the exact entry this attempt appended is
   * rolled back (removed from `sentAt`/`manualSentAt`, `nextAt` recomputed as
   * if this attempt never happened) so `computeDue` sees the signer as still
   * due and the next tick (or the next manual call) retries. The audit row
   * for a failure is `envelope.reminder_failed`, not `envelope.reminder_sent`
   * — nothing was actually, durably sent.
   */
  private async sendOneReminder(envelopeIn: Envelope, signerId: string, kind: "scheduled" | "manual"): Promise<Receipt> {
    const { config } = this.deps;

    let link!: DeliveryLink;
    let title = "";
    let message: string | undefined;
    let expiresAt: string | undefined;
    let sentTimestamp = "";
    // LOW carry-over fix: the position THIS attempt appended its entry at,
    // captured fresh on every `updateWithRetry` attempt (a retry re-derives
    // `nextScheduledSentAt`/`nextManualSentAt` from a fresh read, so the
    // index can legitimately differ between attempts) — the rollback below
    // removes exactly this position, never by matching the timestamp VALUE
    // (two entries can share an identical timestamp under a frozen/coarse
    // clock, and removing by value would then delete the wrong one, or both).
    let appendedScheduledIndex: number | undefined;
    let appendedManualIndex: number | undefined;

    const persisted = await this.updateWithRetry(envelopeIn.id, (envelope) => {
      const signer = envelope.signers.find((s) => s.id === signerId);
      if (!signer) throw new EnvelopeError(`signer not found on envelope ${envelope.id}: ${signerId}`);

      const encryptedLink = mcpMeta(envelope)?.delivery?.links?.[signerId];
      if (!encryptedLink) {
        throw new EnvelopeError(
          `no stored signing link for signer ${signerId} on envelope ${envelope.id} — reminders must be ` +
            "configured (ESIG_MCP_REMINDERS) at the time this envelope was created.",
        );
      }
      const url = decryptKeyPem(Buffer.from(encryptedLink, "base64"), config.passphrase);
      link = { signerId, name: signer.name, email: signer.email, url };
      title = envelope.title;
      message = mcpMeta(envelope)?.message;
      expiresAt = envelope.expiresAt?.toISOString();

      const currentMcp = mcpMeta(envelope) ?? {};
      const currentState = currentMcp.delivery?.reminders?.[signerId];
      const scheduledSentAt = currentState?.sentAt ?? [];
      const manualSentAt = currentState?.manualSentAt ?? [];

      // R1: both kinds count toward the overall per-signer spam bound.
      if (scheduledSentAt.length + manualSentAt.length >= config.reminders.max) {
        throw new EnvelopeError(
          `reminder limit reached for signer ${signerId} on envelope ${envelope.id} ` +
            `(${config.reminders.max} sent, scheduled + manual combined) — no further reminders (scheduled or ` +
            "manual) will be sent.",
        );
      }

      sentTimestamp = this.now().toISOString();
      const nextScheduledSentAt = kind === "scheduled" ? [...scheduledSentAt, sentTimestamp] : scheduledSentAt;
      const nextManualSentAt = kind === "manual" ? [...manualSentAt, sentTimestamp] : manualSentAt;
      // Recorded on EVERY attempt (including retries) — see this method's
      // header comment above.
      appendedScheduledIndex = kind === "scheduled" ? nextScheduledSentAt.length - 1 : undefined;
      appendedManualIndex = kind === "manual" ? nextManualSentAt.length - 1 : undefined;

      envelope.metadata = {
        ...envelope.metadata,
        mcp: {
          ...currentMcp,
          delivery: {
            ...currentMcp.delivery,
            reminders: {
              ...currentMcp.delivery?.reminders,
              [signerId]: {
                sentAt: nextScheduledSentAt,
                manualSentAt: nextManualSentAt,
                nextAt: this.reminderNextAt(envelope.createdAt, nextScheduledSentAt.length),
              },
            },
          },
        } satisfies McpEnvelopeMetadata,
      };
      return true;
    });
    // `mutate` above always returns `true` or throws — `updateWithRetry`
    // only returns `undefined` when `mutate` chose to skip, which never
    // happens here.
    const envelope = persisted!;

    const [receipt] = await this.deps.delivery.deliver({ id: envelope.id, title, message, expiresAt }, [link]);

    if (!receipt.ok) {
      // LOW carry-over fix (index-based, not timestamp-equality): roll back
      // exactly the ENTRY this attempt appended — identified by the POSITION
      // it landed at (captured above, on the attempt that actually
      // persisted), never by matching `sentTimestamp`'s VALUE. A frozen (or
      // just coarse) clock can produce two reminders with an IDENTICAL
      // timestamp string; `.filter((t) => t !== sentTimestamp)` would then
      // remove every entry sharing that value (or, if only one happens to
      // match by luck, still the wrong one) instead of exactly the one this
      // call appended. Removing by index is correct regardless of whether
      // any other entry's timestamp collides with this one's.
      await this.updateWithRetry(envelope.id, (e) => {
        const currentMcp = mcpMeta(e) ?? {};
        const currentState = currentMcp.delivery?.reminders?.[signerId];
        if (!currentState) return false; // nothing to roll back (shouldn't happen — defensive)
        const rolledBackSentAt =
          kind === "scheduled" && appendedScheduledIndex !== undefined
            ? currentState.sentAt.filter((_, i) => i !== appendedScheduledIndex)
            : currentState.sentAt;
        const rolledBackManualSentAt =
          kind === "manual" && appendedManualIndex !== undefined
            ? (currentState.manualSentAt ?? []).filter((_, i) => i !== appendedManualIndex)
            : (currentState.manualSentAt ?? []);
        e.metadata = {
          ...e.metadata,
          mcp: {
            ...currentMcp,
            delivery: {
              ...currentMcp.delivery,
              reminders: {
                ...currentMcp.delivery?.reminders,
                [signerId]: {
                  sentAt: rolledBackSentAt,
                  manualSentAt: rolledBackManualSentAt,
                  nextAt: this.reminderNextAt(e.createdAt, rolledBackSentAt.length),
                },
              },
            },
          } satisfies McpEnvelopeMetadata,
        };
        return true;
      });

      await this.deps.auditStore.insert({
        tenantId: config.tenant,
        action: "envelope.reminder_failed",
        targetTable: "envelope",
        targetId: envelope.id,
        metadata: { signerId, detail: receipt.detail },
      });

      return receipt;
    }

    await this.deps.auditStore.insert({
      tenantId: config.tenant,
      action: "envelope.reminder_sent",
      targetTable: "envelope",
      targetId: envelope.id,
      metadata: { signerId, ok: receipt.ok, messageId: receipt.messageId, detail: receipt.ok ? undefined : receipt.detail },
    });
    // data deliberately omits `messageId` — while not a signing link, it is
    // an email-provider-internal identifier with no reason to leave this
    // process; `ok` is the only outcome a webhook receiver needs.
    await this.emit(envelope.id, (e) => {
      const s = e.signers.find((x) => x.id === signerId);
      return {
        type: "envelope.reminder_sent",
        envelopeId: e.id,
        phase: derivePhase(e),
        signer: s ? { signerId: s.id, name: s.name, email: s.email, status: s.status } : undefined,
        data: { ok: receipt.ok },
      };
    });

    return receipt;
  }

  /**
   * RedTeam RT-2026-08-27-05 G3: "also when reminders are not configured at
   * startup, purge any stored links on first tick." A prior run may have
   * persisted encrypted signing links (§15 "Link persistence") while
   * `ESIG_MCP_REMINDERS` WAS set; if this run's config has since dropped the
   * schedule, `create()` no longer writes new ones and `sendReminder()`/
   * `sendScheduledReminder()` both refuse outright — so that ciphertext has
   * no code path left to ever be read again. Called once, by
   * `reminders.ts`'s `Scheduler`, on its first tick, only when
   * `config.reminders.durationsMs` is empty. A single envelope's purge
   * failure is logged to stderr and never aborts the rest of the sweep.
   */
  async purgeStaleReminderLinks(): Promise<void> {
    const envelopes = await listEnvelopes(this.deps.config.dataDir, this.deps.config.tenant);
    for (const envelope of envelopes) {
      const links = mcpMeta(envelope)?.delivery?.links;
      if (!links || Object.keys(links).length === 0) continue;
      try {
        await this.updateWithRetry(envelope.id, (e) => {
          const currentLinks = mcpMeta(e)?.delivery?.links;
          if (!currentLinks || Object.keys(currentLinks).length === 0) return false;
          eraseStoredLinks(e);
          return true;
        });
      } catch (err) {
        process.stderr.write(
          `[esig-mcp] WARNING: could not purge stale reminder links for envelope ${envelope.id}: ${messageOf(err)}\n`,
        );
      }
    }
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
      const doc = getEnvelopeDocument(envelope);
      let pdf: Buffer;
      let reason: string;
      let signerName: string;
      if (doc) {
        // §13: PDF envelope — sign the EXACT ingested bytes directly. NO
        // rendering, so no Chrome anywhere on this path (this.render is
        // never called in this branch — a test can inject a `render` that
        // throws and confirm sealing still succeeds). I4: re-verify the
        // document sha256 pinned at creation against what the doc store
        // returns right now, mirroring the base-html check in the `else`
        // branch below for the same reason.
        if (!this.deps.documents) {
          throw new EnvelopeError(`no document store configured — cannot seal PDF envelope ${envelope.id}`);
        }
        pdf = await this.deps.documents.get(doc.docId);
        const actualDocSha256 = crypto.createHash("sha256").update(pdf).digest("hex");
        if (actualDocSha256 !== doc.sha256) {
          throw new EnvelopeError(
            `content binding check failed for envelope ${envelope.id}: document sha256 at seal time ` +
              `(${actualDocSha256}) does not match the value pinned at creation (${doc.sha256}).`,
          );
        }
        reason = `Signed via e-sig envelope ${envelope.id} by ${envelope.signers.length} signer(s)`;
        signerName = envelope.signers.map((s) => s.name).join(", ");
      } else {
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

        // §12 MUST DO item 3: an "Identity attestations" block, one line per
        // signer whose identity was verified, appended BEFORE rendering — so
        // it is part of the sealed PDF the signature covers. Every value is
        // agent/signer-influenced (name, uuaid) and is escaped.
        const composed = composeEnvelopeHtml(envelope, { platformLabel: "e-sig MCP" }) + identityAttestationsHtml(envelope);
        pdf = await this.render(composed);
        reason = "Envelope completed";
        signerName = config.subjectName;
      }

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
        reason,
        location: "",
        contactInfo: "",
        name: signerName,
        signingTime: signedAt,
        // §12 MUST DO item 3: "Do NOT put signer uuaids into the operator PQ
        // seal" — `pqSeal` here carries only the OPERATOR's own keys, never a
        // `uuaid` field (mode A/C, not implemented in this package, is the
        // only caller that would ever set one — see design doc §5 T4). Signer
        // identities live in `identityAttestationsHtml` above instead (HTML
        // envelopes only — a PDF envelope's `reason`/`name` above already name
        // the envelope + its signers directly).
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
      // §16: distinct event TYPE from the pre-existing audit ACTION name
      // above (also "envelope.seal_failed", coincidentally identical here) —
      // never confuse this with "envelope.completed" (sign()'s own event,
      // emitted separately when core's status first flips to "completed",
      // well before any seal attempt runs).
      await this.emit(envelope.id, (e) => ({ type: "envelope.seal_failed", envelopeId: e.id, phase: derivePhase(e), data: { attempts } }));

      await this.writeCompletionReceiptBestEffort(updated, "seal_failed", { error: errorMessage, attempts });

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
    // §16: this ticket's "envelope.sealed" event type — NOT the same thing
    // as the "envelope.completed" AUDIT action name reused above (a
    // pre-existing naming quirk, D1(b)'s own comment); "envelope.completed"
    // the EVENT already fired inside `sign()` when core's status first
    // flipped to "completed", independent of whether sealing then succeeds.
    // data deliberately omits the sealed PDF's storage URL/path — §16
    // "Payloads never contain links, tokens, proofs, or document bytes";
    // some `PdfStorageStore` implementations return a pre-signed/readable
    // URL there, which is exactly the class of capability this rule exists
    // to keep out of a third-party webhook payload. `esig_envelope_status`/
    // `esig_list_events`'s own `delivery`/`sealedPdfUrl` fields (MCP-only,
    // never webhook-delivered) are the place to read it from.
    await this.emit(envelope.id, (e) => ({
      type: "envelope.sealed",
      envelopeId: e.id,
      phase: derivePhase(e),
      data: { pqSealed: artifact.pqSealed },
    }));

    await this.writeCompletionReceiptBestEffort(updated, "sealed", { sealedPdfUrl: artifact.uploadedUrl, attempts });

    return updated;
  }

  /**
   * R2 (verifier finding): a COMPLETION receipt at
   * `<dataDir>/outbox/<envelopeId>.completed.json`, distinct from and
   * additional to the `file`-channel CREATION receipt (delivery.ts,
   * unchanged) — written on every terminal seal outcome regardless of which
   * delivery channel is configured (this is bookkeeping about the envelope
   * completing, not about dispatching a signing link).
   *
   * Deliberately best-effort: `seal()` NEVER throws for a seal failure (its
   * own header comment), and it must not start doing so here either — a
   * disk hiccup writing this SECONDARY artifact must never make an
   * otherwise-successful (or already-recorded-failed) seal outcome look
   * like a `sign()` failure to the caller. A write failure is reported once
   * to stderr and otherwise swallowed; the audit trail above remains the
   * authoritative record either way.
   */
  private async writeCompletionReceiptBestEffort(
    envelope: Envelope,
    status: "sealed" | "seal_failed",
    extra: Record<string, unknown>,
  ): Promise<void> {
    try {
      // §13 MUST DO item 4: signatures evidence per signer — name, signedAt,
      // and a sha256 of the drawn signature image (never the full data URL,
      // which can be tens of KB of pixel data and is PII-adjacent).
      const signers: CompletionReceiptSigner[] = envelope.signers.map((s) => ({
        signerId: s.id,
        name: s.name,
        email: s.email,
        signedAt: s.signedAt?.toISOString(),
        signatureImageSha256: s.signatureImageDataUrl
          ? crypto.createHash("sha256").update(s.signatureImageDataUrl, "utf8").digest("hex")
          : undefined,
        identity: getSignerIdentityState(envelope, s.id)?.verified,
      }));
      // §13: `document` is present only for a PDF envelope.
      const document = getEnvelopeDocument(envelope);
      await writeOutboxCompletionReceipt(this.deps.config.dataDir, envelope, status, signers, {
        ...(document ? { document } : {}),
        ...extra,
      });
    } catch (e) {
      process.stderr.write(
        `[esig-mcp] WARNING: could not write the outbox completion receipt for envelope ${envelope.id}: ` +
          `${messageOf(e)} (the audit trail — envelope.completed/envelope.seal_failed — is unaffected).\n`,
      );
    }
  }
}

function summarize(envelope: Envelope): EnvelopeStatusSummary {
  const meta = mcpMeta(envelope);
  return {
    envelopeId: envelope.id,
    title: envelope.title,
    status: envelope.status,
    phase: derivePhase(envelope),
    identityPolicy: getEnvelopeIdentityPolicy(envelope),
    signers: envelope.signers.map((s) => ({
      signerId: s.id,
      name: s.name,
      email: s.email,
      status: s.status,
      order: s.order,
      signedAt: s.signedAt?.toISOString(),
      viewedAt: meta?.viewed?.[s.id],
      identity: getSignerIdentityState(envelope, s.id)?.verified,
    })),
    createdAt: envelope.createdAt.toISOString(),
    completedAt: envelope.completedAt?.toISOString(),
    voidedAt: envelope.voidedAt?.toISOString(),
    sealedPdfUrl: meta?.sealedPdfUrl,
    seal: meta?.seal,
    document: meta?.document,
    message: meta?.message,
    // §16: last 10, oldest first — `esig_list_events` returns the full log.
    events: listEvents(envelope).slice(-10),
  };
}

// ---------- §13: PDF envelopes ----------

const PDF_MAGIC = Buffer.from("%PDF-", "ascii");

/** True iff `bytes` starts with the PDF magic bytes (`%PDF-`). */
function isPdfMagic(bytes: Buffer): boolean {
  return bytes.length >= PDF_MAGIC.length && bytes.subarray(0, PDF_MAGIC.length).equals(PDF_MAGIC);
}

/**
 * The cover-sheet HTML a PDF envelope drives core's html/token/order/
 * recordSignature flow with (§13 "Core stays unchanged"). Every value is
 * escaped; the sentence naming the document sha256 is what lets the identity
 * challenge (§12, unchanged mechanism — its `htmlSha256` pins THIS html) bind
 * the PDF transitively.
 */
function buildPdfCoverSheetHtml(input: {
  title: string;
  docId: string;
  sha256: string;
  size: number;
  signers: SignerInput[];
}): string {
  const ordered = [...input.signers].sort((a, b) => (a.order ?? 1) - (b.order ?? 1));
  const signerItems = ordered
    .map(
      (s) =>
        `<li>${escapeHtml(s.name)} (${escapeHtml(s.email)})` +
        (s.roleLabel ? ` — ${escapeHtml(s.roleLabel)}` : "") +
        `</li>`,
    )
    .join("\n");
  return (
    `<h1>${escapeHtml(input.title)}</h1>\n` +
    `<p>This envelope covers the PDF document <code>${escapeHtml(input.docId)}</code>, ${input.size} byte(s).</p>\n` +
    `<p>This envelope signs the PDF document with sha256 ${escapeHtml(input.sha256)}.</p>\n` +
    `<p>Signers, in order:</p>\n<ol>\n${signerItems}\n</ol>`
  );
}

// ---------- §12: "Identity attestations" block appended before rendering ----------

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * One line per signer whose identity was verified (§12 MUST DO item 3): name,
 * uuaid, level, key fingerprint (when there is one — absent at L0), verified
 * at. Returns `""` when no signer on this envelope has a verified identity
 * (nothing to append — most envelopes, v0.1 behavior unchanged).
 */
function identityAttestationsHtml(envelope: Envelope): string {
  const rows: string[] = [];
  for (const signer of envelope.signers) {
    const record = getSignerIdentityState(envelope, signer.id)?.verified;
    if (!record) continue;
    rows.push(
      `<div>${escapeHtml(signer.name)} — uuaid ${escapeHtml(record.uuaid)}, level ${escapeHtml(record.level)}` +
        (record.keyFingerprint ? `, key fingerprint ${escapeHtml(record.keyFingerprint)}` : "") +
        `, verified at ${escapeHtml(record.verifiedAt)}</div>`,
    );
  }
  if (rows.length === 0) return "";
  return `\n<section class="identity-attestations"><h3>Identity attestations</h3>\n${rows.join("\n")}\n</section>`;
}
