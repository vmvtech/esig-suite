// tools/list-events.ts — esig_list_events (docs/architecture/esig-mcp.md
// §16). Read-only. Each event also carries its webhook delivery status
// (`pending`/`delivered`/`dead` + attempt count) when a webhook is
// configured — see `EnvelopeService.listEvents`.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerListEventsTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_list_events",
    {
      title: "List an envelope's lifecycle events",
      description:
        "List every lifecycle event recorded for an envelope (created, viewed, signed, declined, " +
        "completed, sealed/seal_failed, voided, expired, reminder_sent, identity_verified/rejected), " +
        "oldest first. Pass `since` (an event's `createdAt`) to see only events after it. When this " +
        "server has ESIG_MCP_EVENTS_WEBHOOK_URL configured, each event also carries its delivery " +
        "status (pending/delivered/dead + attempt count) — an event's `data` never contains links, " +
        "tokens, proofs, or document bytes, the same rule the webhook payload itself follows.",
      inputSchema: {
        envelopeId: z.string().min(1).describe("The envelopeId returned by esig_create_envelope."),
        since: z.string().optional().describe("An event's `createdAt` (ISO-8601) — return only events strictly after it."),
      },
    },
    async ({ envelopeId, since }) => {
      try {
        const events = await deps.envelopes.listEvents(envelopeId, since);
        return toolResult(`envelope ${envelopeId}: ${events.length} event(s)`, { envelopeId, events });
      } catch (e) {
        return toolError(messageOf(e));
      }
    },
  );
}
