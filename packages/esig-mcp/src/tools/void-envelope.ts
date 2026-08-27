// tools/void-envelope.ts — esig_void_envelope (design doc §4, "Prepare tools
// (allowed, audited)"). State-changing; `EnvelopeService.void()` already
// writes its own audit row (I6) via core's `voidEnvelope`. Sender-side cancel
// — no token needed; declining is human-side only and deliberately not an
// MCP tool (design doc §4).

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerVoidEnvelopeTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_void_envelope",
    {
      title: "Void an envelope",
      description:
        "Cancel a pending or partially-signed envelope so no further signatures can be recorded " +
        "against it. Fails if the envelope is already completed (a fully-signed, sealed envelope " +
        "cannot be voided).",
      inputSchema: {
        envelopeId: z.string().min(1).describe("The envelopeId returned by esig_create_envelope."),
      },
    },
    async ({ envelopeId }) => {
      try {
        const status = await deps.envelopes.void(envelopeId);
        return toolResult(`envelope ${status.envelopeId} voided`, status);
      } catch (e) {
        return toolError(messageOf(e));
      }
    },
  );
}
