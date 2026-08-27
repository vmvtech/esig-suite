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
      },
    },
    async ({ title, html, signers, expiresAt }) => {
      let expiresAtDate: Date | undefined;
      if (expiresAt !== undefined) {
        expiresAtDate = new Date(expiresAt);
        if (Number.isNaN(expiresAtDate.getTime())) {
          return toolError(`expiresAt is not a valid ISO-8601 timestamp: "${expiresAt}"`);
        }
      }

      let result;
      try {
        result = await deps.envelopes.create({ title, html, signers, expiresAt: expiresAtDate });
      } catch (e) {
        return toolError(messageOf(e));
      }

      // G3(d): a webhook delivery failure (timeout, refused connection, non-2xx)
      // never throws out of `create()` — the envelope IS created — but the
      // agent needs to be told plainly, not just via the structured `delivery`
      // receipts array, since the summary line is what an agent reads first.
      const failedDeliveries = result.delivery.filter((r) => !r.ok);

      const summary =
        `envelope ${result.envelopeId} created with ${result.signers.length} signer(s); ` +
        `signing links delivered via "${deps.config.delivery.kind}"` +
        (deps.config.returnLinks
          ? " (ESIG_MCP_RETURN_LINKS=1: raw links are included in this result — local demo only)"
          : " (raw links are withheld from this result by design, invariants I8/T1/T8)") +
        (result.removedTags.length > 0 ? `; stripped from html: ${result.removedTags.join(", ")}` : "") +
        (failedDeliveries.length > 0
          ? `; WARNING: delivery failed for ${failedDeliveries.length} signer(s): ` +
            failedDeliveries.map((r) => r.detail ?? "unknown error").join("; ")
          : "");

      return toolResult(summary, result);
    },
  );
}
