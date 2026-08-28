// tools/create-envelope.ts — esig_create_envelope (design doc §4, "Prepare
// tools (allowed, audited)"). State-changing; `EnvelopeService.create()`
// already writes its own audit row (I6) and already withholds raw tokens/
// links unless `config.returnLinks` (I8) — this tool is a thin, validating
// pass-through and must not weaken either guarantee.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

const pillarSignerSchema = z.object({
  uuaid: z
    .string()
    .min(1)
    .describe("The signer's uuaid:foundation:agent:<localId> — must be derivable from `publicKey` (localIdFromEd25519Key), or this call is refused."),
  publicKey: z
    .string()
    .length(64)
    .describe("The signer's raw Ed25519 public key, 64 lowercase hex characters."),
});

const signerSchema = z.object({
  name: z.string().min(1).describe("Signer's display name."),
  email: z.string().min(1).describe("Signer's email address (used for display and delivery only)."),
  roleLabel: z.string().optional().describe('Optional role label, e.g. "Landlord" or "Tenant".'),
  order: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe("1-based signing order; equal values sign in parallel. Default 1 (all sign in any order)."),
  pillar: pillarSignerSchema
    .optional()
    .describe(
      "Reach this signer over Pillar (uuaid-to-uuaid, docs/architecture/esig-mcp.md §17) instead of/alongside " +
        "email — requires the optional @e-sig/pillar-bridge to be configured. `publicKey` must derive `uuaid`; " +
        "when a UUAID registry is configured, its badge for `uuaid` must also attest `publicKey` (or the server " +
        "must have opted in with ESIG_MCP_PILLAR_ALLOW_UNREGISTERED=1).",
    ),
});

const identitySignerSchema = z
  .object({
    signerId: z.string().optional().describe("A signerId from THIS call's own `signers` list (rarely known in advance — prefer `index`)."),
    index: z.number().int().min(0).optional().describe("0-based position into THIS call's `signers` array."),
    uuaid: z.string().min(1).describe("The uuaid this signer is expected to present a proof for (uuaid:<subjectClass>:<jurisdiction>:<authority>:<localId>, or the foundation form)."),
  })
  .refine((v) => (v.signerId !== undefined) !== (v.index !== undefined), {
    message: "exactly one of signerId or index is required",
  });

// §13: `html` and `docId` are both individually optional (below) so the JSON
// schema exposed via tools/list stays a plain object shape — a top-level
// `.refine()` passed as `registerTool`'s own `inputSchema` would make the
// MCP SDK's `normalizeObjectSchema` unable to find a `.shape` on the result
// (verified against the installed SDK: a ZodEffects has none) and fall back
// to an EMPTY input schema for this tool's `tools/list` entry. This small,
// separate schema is parsed by hand in the handler instead — still a real
// zod `.refine()`, just not the one wired to `registerTool`.
const exactlyOneOfHtmlOrDocId = z
  .object({ html: z.string().optional(), docId: z.string().optional() })
  .refine((v) => (v.html !== undefined) !== (v.docId !== undefined), {
    message: "exactly one of `html` or `docId` must be provided.",
  });

const identitySchema = z.object({
  minLevel: z
    .enum(["none", "L0", "L1", "L1p", "L2"])
    .optional()
    .describe(
      "This envelope's signer-identity floor (docs/architecture/esig-mcp.md §12, §17). May only RAISE this " +
        "server's configured ESIG_MCP_IDENTITY_MIN_LEVEL, never lower it. none: no identity check (v0.1 " +
        "behavior). L0: signer's uuaid must be well-formed (and match the pin below, if set) — asserted, " +
        "no cryptographic proof. L1: the signer's wallet/agent must sign a server-issued sole-control " +
        "challenge — obtain it via esig_identity_challenge or GET /sign/<token>/challenge, then present " +
        "the resulting DataIntegrityProof as `identityProof` on POST /sign. L1p: like L1, but the signer's " +
        "uuaid must be a uuaid:foundation:agent:<localId> whose local id is itself derived from the proof's " +
        "Ed25519 key (self-authenticating — no registry needed; a foundation:agent uuaid that does NOT " +
        "derive from its own proof key is refused, never silently accepted at L1). L2: L1 plus the registry " +
        "(ESIG_MCP_UUAID_REGISTRY_URL) must attest the proof's key<->uuaid binding via its signed badge — " +
        "requires that env var AND ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY (the registry's pinned Ed25519 public key).",
    ),
  signers: z
    .array(identitySignerSchema)
    .optional()
    .describe("Per-signer expected uuaid pins (T12: rejects a proof for any other uuaid). Optional even when minLevel is set."),
});

export function registerCreateEnvelopeTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_create_envelope",
    {
      title: "Create a signing envelope",
      description:
        "Create a new envelope and dispatch each signer's tokenized signing link through this " +
        "server's configured delivery channel (file outbox, console, or webhook — never back to " +
        "the calling agent). Pass EXACTLY ONE of `html` (an HTML document, rendered to PDF at seal " +
        "time) or `docId` (a docId from esig_ingest_document): to sign an existing PDF, ingest it " +
        "then create an envelope with docId — no Chrome needed, and the signer reviews and signs " +
        "the exact ingested bytes (WYSIWYS). `<script>` tags, event-handler attributes, " +
        "`javascript:` URLs, and `<iframe>`/`<object>`/`<embed>`/`<form>` are stripped from `html` " +
        "before storage (defense in depth; the human-facing approval page also renders the " +
        "envelope inside a fully sandboxed iframe). By design (invariants I8/T1/T8), the result " +
        "NEVER contains a raw signing token or `/sign/` URL unless this server was started with " +
        "ESIG_MCP_RETURN_LINKS=1 (local demos only) — an agent that needs a human to sign should " +
        "tell that human to check their configured delivery channel, not ask this tool for a link.",
      inputSchema: {
        title: z.string().min(1).describe("Envelope title, shown to signers on the approval page."),
        html: z
          .string()
          .min(1)
          .optional()
          .describe(
            "The envelope body as HTML, rendered to PDF at seal time. Exactly one of `html`/`docId` " +
              "is required — use `docId` instead to sign an existing PDF with no Chrome needed.",
          ),
        docId: z
          .string()
          .min(1)
          .optional()
          .describe(
            "A docId returned by esig_ingest_document (sha256 hex of previously-ingested PDF bytes). " +
              "Creates a PDF envelope: the signer reviews and signs the EXACT ingested bytes (WYSIWYS) " +
              "via a generated cover sheet that drives the same signer/order/token flow as an HTML " +
              "envelope — no Chrome/rendering involved anywhere on this path. Exactly one of " +
              "`html`/`docId` is required.",
          ),
        signers: z.array(signerSchema).min(1).describe("One or more signers. At least one is required."),
        expiresAt: z
          .string()
          .optional()
          .describe("ISO-8601 timestamp after which the envelope expires. Omit for no expiry."),
        identity: identitySchema
          .optional()
          .describe(
            "Require signer identity (UUAID + IAASO, docs/architecture/esig-mcp.md §12) before a " +
              "signature is recorded for this envelope. Omit entirely for v0.1 behavior (no identity " +
              "check) unless this server's own ESIG_MCP_IDENTITY_MIN_LEVEL floor already requires one.",
          ),
        message: z
          .string()
          .max(500)
          .optional()
          .describe(
            "Optional note shown to signers in the signing-notification email (ESIG_MCP_DELIVERY=email " +
              "only; ignored by other channels). <= 500 chars; control characters are stripped and it is " +
              "HTML-escaped wherever rendered. Never the document body, never other signers' details.",
          ),
      },
    },
    async ({ title, html, docId, signers, expiresAt, identity, message }) => {
      const oneOf = exactlyOneOfHtmlOrDocId.safeParse({ html, docId });
      if (!oneOf.success) {
        return toolError(oneOf.error.issues[0]?.message ?? "exactly one of `html` or `docId` must be provided.");
      }

      let expiresAtDate: Date | undefined;
      if (expiresAt !== undefined) {
        expiresAtDate = new Date(expiresAt);
        if (Number.isNaN(expiresAtDate.getTime())) {
          return toolError(`expiresAt is not a valid ISO-8601 timestamp: "${expiresAt}"`);
        }
      }

      let result;
      try {
        result = await deps.envelopes.create({
          title,
          html,
          docId,
          signers,
          expiresAt: expiresAtDate,
          identity,
          message,
        });
      } catch (e) {
        return toolError(messageOf(e));
      }

      // G3(d): a webhook delivery failure (timeout, refused connection, non-2xx)
      // never throws out of `create()` — the envelope IS created — but the
      // agent needs to be told plainly, not just via the structured `delivery`
      // receipts array, since the summary line is what an agent reads first.
      const failedDeliveries = result.delivery.filter((r) => !r.ok);

      // D2: `undefined` (a harness that didn't supply it) reads as ready —
      // see tools/types.ts's own comment; `bin.ts` always supplies the real,
      // probed value. §13: a PDF envelope's seal step never renders via
      // Chrome (it signs the ingested bytes directly), so the server-wide
      // Chrome preflight does not apply to THIS envelope — report it ready
      // regardless of `deps.sealReady`.
      const sealReady = (deps.sealReady ?? true) || result.document !== undefined;

      const summary =
        `envelope ${result.envelopeId} created with ${result.signers.length} signer(s); ` +
        `signing links delivered via "${deps.config.delivery.kind}"` +
        (deps.config.returnLinks
          ? " (ESIG_MCP_RETURN_LINKS=1: raw links are included in this result — local demo only)"
          : " (raw links are withheld from this result by design, invariants I8/T1/T8)") +
        (result.removedTags.length > 0 ? `; stripped from html: ${result.removedTags.join(", ")}` : "") +
        (result.document
          ? `; signs the ingested PDF docId ${result.document.docId} (sha256 ${result.document.sha256}, ` +
            `${result.document.size} byte(s)) — no Chrome needed`
          : "") +
        (result.identityPolicy
          ? `; requires signer identity level ${result.identityPolicy.minLevel} (esig_identity_challenge issues the sole-control challenge)`
          : "") +
        (failedDeliveries.length > 0
          ? `; WARNING: delivery failed for ${failedDeliveries.length} signer(s): ` +
            failedDeliveries.map((r) => r.detail ?? "unknown error").join("; ")
          : "") +
        (sealReady
          ? ""
          : `; WARNING: no Chrome/Chromium available on this server (${deps.sealReadyReason}) — ` +
            "this envelope can be created and signed, but the sealed PDF cannot be produced until " +
            "sealing works (see esig_reseal)");

      return toolResult(summary, {
        ...result,
        sealReady,
        ...(sealReady
          ? {}
          : {
              warning:
                `No Chrome/Chromium is available on this server (${deps.sealReadyReason}). Signers can ` +
                "still sign this envelope, but the sealed PDF will not be produced until sealing works " +
                "— the envelope will land in phase seal_failed after the last signature, and the " +
                "operator (or an agent, once resolved) can retry with esig_reseal.",
            }),
      });
    },
  );
}
