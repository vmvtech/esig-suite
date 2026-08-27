// tools/envelope-status.ts — esig_envelope_status (design doc §4). Read-only.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerEnvelopeStatusTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_envelope_status",
    {
      title: "Get envelope status",
      description:
        "Look up one envelope's current status (sent -> partially_signed -> completed, or voided / " +
        "expired), each signer's own status and signing order, and the sealed PDF's storage path " +
        "once the envelope reaches completed. Read-only.",
      inputSchema: {
        envelopeId: z.string().min(1).describe("The envelopeId returned by esig_create_envelope."),
      },
    },
    async ({ envelopeId }) => {
      try {
        const status = await deps.envelopes.status(envelopeId);
        return toolResult(
          `envelope ${status.envelopeId} ("${status.title}"): ${status.status}` +
            (status.sealedPdfUrl ? `, sealed at ${status.sealedPdfUrl}` : ""),
          status,
        );
      } catch (e) {
        // Both this package's own `EnvelopeError` (envelopes.ts) and core's
        // `EnvelopeError` (envelope.ts) are plain `Error` subclasses with an
        // actionable `.message` — `messageOf` handles either uniformly.
        return toolError(messageOf(e));
      }
    },
  );
}
