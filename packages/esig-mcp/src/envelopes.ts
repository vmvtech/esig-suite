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
import {
  writeOutboxCompletionReceipt,
  type CompletionReceiptSigner,
  type DeliveryChannel,
  type DeliveryLink,
  type Receipt,
} from "./delivery.js";
import { issueChallenge, type IdentityChallengePayload } from "./identity/challenge.js";
import { RegistryClient } from "./identity/registry.js";
import {
  getEnvelopeIdentityPolicy,
  getSignerIdentityState,
  IdentityError,
  maxIdentityLevel,
  setEnvelopeIdentityPolicy,
  type EnvelopeIdentityPolicy,
  type IdentityLevel,
  type IdentityProofInput,
  type SignerIdentityRecord,
} from "./identity/types.js";
import { verifySignerIdentity } from "./identity/verify.js";
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

/** `esig_create_envelope`'s optional `identity` input (docs/architecture/esig-mcp.md §12 "Policy"). */
export interface CreateEnvelopeIdentityArgs {
  /** May only RAISE the server's configured `ESIG_MCP_IDENTITY_MIN_LEVEL` floor, never lower it. */
  minLevel?: IdentityLevel;
  /** Per-signer expected uuaid pin (T12). Exactly one of `signerId`/`index` per entry — `index` is a 0-based position into THIS call's `signers` array (server-generated ids don't exist yet at request time). */
  signers?: Array<{ signerId?: string; index?: number; uuaid: string }>;
}

export interface CreateEnvelopeArgs {
  title: string;
  html: string;
  signers: SignerInput[];
  expiresAt?: Date;
  identity?: CreateEnvelopeIdentityArgs;
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
  signers: Array<{
    signerId: string;
    name: string;
    email: string;
    status: string;
    order: number;
    signedAt?: string;
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

    const links: DeliveryLink[] = signingTokens.map((t) => {
      const signer = envelope.signers.find((s) => s.id === t.signerId)!;
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
        identityMinLevel: identityPolicy?.minLevel,
      },
    });

    return {
      envelopeId: envelope.id,
      signers: envelope.signers.map((s) => ({ signerId: s.id, name: s.name, email: s.email, status: s.status })),
      htmlSha256,
      removedTags: removed,
      delivery: receipts,
      ...(config.returnLinks ? { links } : {}),
      ...(identityPolicy ? { identityPolicy } : {}),
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
        }
      }
    }

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

      // §12 MUST DO item 3: an "Identity attestations" block, one line per
      // signer whose identity was verified, appended BEFORE rendering — so
      // it is part of the sealed PDF the signature covers. Every value is
      // agent/signer-influenced (name, uuaid) and is escaped.
      const composed = composeEnvelopeHtml(envelope, { platformLabel: "e-sig MCP" }) + identityAttestationsHtml(envelope);
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
        // §12 MUST DO item 3: "Do NOT put signer uuaids into the operator PQ
        // seal" — `pqSeal` here carries only the OPERATOR's own keys, never a
        // `uuaid` field (mode A/C, not implemented in this package, is the
        // only caller that would ever set one — see design doc §5 T4). Signer
        // identities live in `identityAttestationsHtml` above instead.
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
      const signers: CompletionReceiptSigner[] = envelope.signers.map((s) => ({
        signerId: s.id,
        name: s.name,
        email: s.email,
        identity: getSignerIdentityState(envelope, s.id)?.verified,
      }));
      await writeOutboxCompletionReceipt(this.deps.config.dataDir, envelope, status, signers, extra);
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
      identity: getSignerIdentityState(envelope, s.id)?.verified,
    })),
    createdAt: envelope.createdAt.toISOString(),
    completedAt: envelope.completedAt?.toISOString(),
    voidedAt: envelope.voidedAt?.toISOString(),
    sealedPdfUrl: meta?.sealedPdfUrl,
    seal: meta?.seal,
  };
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
