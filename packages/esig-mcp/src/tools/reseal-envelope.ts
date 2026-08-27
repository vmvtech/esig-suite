// tools/reseal-envelope.ts — esig_reseal (D1(d), design doc §4-class "prepare
// tools (allowed, audited)"). State-changing; `EnvelopeService.reseal()`
// already writes its own audit rows (envelope.reseal_requested, and
// envelope.completed only on success) and is gated by the same hourly rate
// limiter `esig_create_envelope` draws from — this tool is a thin,
// validating pass-through, same shape as `tools/void-envelope.ts`.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerResealEnvelopeTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_reseal",
    {
      title: "Retry sealing a signed envelope",
      description:
        "Retry producing the sealed PDF for an envelope every signer has already signed, when the " +
        "automatic seal step failed (phase `seal_failed` — e.g. no Chrome/Chromium was available, " +
        "see esig_whoami's sealReady) or never ran (phase `awaiting_seal`). The signature itself was " +
        "already validly recorded when each signer signed — this only retries rendering, " +
        "cryptographically signing, and storing the final PDF, from the envelope as stored. Fails " +
        "with a clear error if the envelope is not yet completed, or if it is already sealed.",
      inputSchema: {
        envelopeId: z.string().min(1).describe("The envelopeId returned by esig_create_envelope."),
      },
    },
    async ({ envelopeId }) => {
      try {
        const status = await deps.envelopes.reseal(envelopeId);
        return toolResult(
          `envelope ${status.envelopeId}: ${status.phase}` +
            (status.sealedPdfUrl ? `, sealed at ${status.sealedPdfUrl}` : "") +
            (status.seal?.status === "failed" ? `, seal error: ${status.seal.error}` : ""),
          status,
        );
      } catch (e) {
        // This package's own `EnvelopeError` (envelopes.ts) — the guard
        // conditions (not completed yet / already sealed) — and core's
        // `EnvelopeError` are both plain `Error` subclasses with an
        // actionable `.message`; `messageOf` handles either uniformly.
        return toolError(messageOf(e));
      }
    },
  );
}
