// tools/list-envelopes.ts — esig_list_envelopes (design doc §4). Read-only.
//
// `EnvelopeService.list()` (envelopes.ts) takes no filter argument — it is
// the library layer this server was handed (out of this ticket's write set;
// see docs/architecture/esig-mcp.md §7 "lib worker -> server worker"), and
// core's `EnvelopeStore` deliberately has no query API for the same reason
// `listEnvelopes` reads the Fs layout directly (stores.ts's own header
// note). The design doc's "input: filter" is implemented here instead, as a
// tool-layer post-filter over the full list — correct for v0.1's single
// filesystem-backed tenant dataset, and it keeps `EnvelopeService` itself
// filter-agnostic for whatever future backing store list() gains one.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

const STATUS_VALUES = ["sent", "partially_signed", "completed", "voided", "expired"] as const;

export function registerListEnvelopesTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_list_envelopes",
    {
      title: "List envelopes",
      description:
        "List envelopes for this server's configured tenant. Pass `status` to only return " +
        "envelopes currently in that state; omit it to return all. Read-only.",
      inputSchema: {
        status: z
          .enum(STATUS_VALUES)
          .optional()
          .describe("Only return envelopes with this status. Omit to return every envelope."),
      },
    },
    async ({ status }) => {
      let envelopes;
      try {
        envelopes = await deps.envelopes.list();
      } catch (e) {
        return toolError(messageOf(e));
      }
      const filtered = status ? envelopes.filter((e) => e.status === status) : envelopes;
      return toolResult(
        `${filtered.length} envelope(s)${status ? ` with status "${status}"` : ""}`,
        { envelopes: filtered },
      );
    },
  );
}
