// tools/create-envelope.ts — esig_create_envelope (design doc §4, "Prepare
// tools (allowed, audited)"). State-changing; `EnvelopeService.create()`
// already writes its own audit row (I6) and already withholds raw tokens/
// links unless `config.returnLinks` (I8) — this tool is a thin, validating
// pass-through and must not weaken either guarantee.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

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

const identitySchema = z.object({
  minLevel: z
    .enum(["none", "L0", "L1", "L2"])
    .optional()
    .describe(
      "This envelope's signer-identity floor (docs/architecture/esig-mcp.md §12). May only RAISE this " +
        "server's configured ESIG_MCP_IDENTITY_MIN_LEVEL, never lower it. none: no identity check (v0.1 " +
        "behavior). L0: signer's uuaid must be well-formed (and match the pin below, if set) — asserted, " +
        "no cryptographic proof. L1: the signer's wallet/agent must sign a server-issued sole-control " +
        "challenge — obtain it via esig_identity_challenge or GET /sign/<token>/challenge, then present " +
        "the resulting DataIntegrityProof as `identityProof` on POST /sign. L2: L1 plus the proof's key " +
        "must resolve on ESIG_MCP_UUAID_REGISTRY_URL (requires that env var to be configured).",
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
        "Create a new envelope from HTML content and a signer list, and dispatch each signer's " +
        "tokenized signing link through this server's configured delivery channel (file outbox, " +
        "console, or webhook — never back to the calling agent). `<script>` tags, event-handler attributes, " +
        "`javascript:` URLs, and `<iframe>`/`<object>`/`<embed>`/`<form>` are stripped from `html` " +
        "before storage (defense in depth; the human-facing approval page also renders the " +
        "envelope inside a fully sandboxed iframe). By design (invariants I8/T1/T8), the result " +
        "NEVER contains a raw signing token or `/sign/` URL unless this server was started with " +
        "ESIG_MCP_RETURN_LINKS=1 (local demos only) — an agent that needs a human to sign should " +
        "tell that human to check their configured delivery channel, not ask this tool for a link.",
      inputSchema: {
        title: z.string().min(1).describe("Envelope title, shown to signers on the approval page."),
        html: z.string().min(1).describe("The envelope body as HTML."),
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
      },
    },
    async ({ title, html, signers, expiresAt, identity }) => {
      let expiresAtDate: Date | undefined;
      if (expiresAt !== undefined) {
        expiresAtDate = new Date(expiresAt);
        if (Number.isNaN(expiresAtDate.getTime())) {
          return toolError(`expiresAt is not a valid ISO-8601 timestamp: "${expiresAt}"`);
        }
      }

      let result;
      try {
        result = await deps.envelopes.create({ title, html, signers, expiresAt: expiresAtDate, identity });
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
      // probed value.
      const sealReady = deps.sealReady ?? true;

      const summary =
        `envelope ${result.envelopeId} created with ${result.signers.length} signer(s); ` +
        `signing links delivered via "${deps.config.delivery.kind}"` +
        (deps.config.returnLinks
          ? " (ESIG_MCP_RETURN_LINKS=1: raw links are included in this result — local demo only)"
          : " (raw links are withheld from this result by design, invariants I8/T1/T8)") +
        (result.removedTags.length > 0 ? `; stripped from html: ${result.removedTags.join(", ")}` : "") +
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
