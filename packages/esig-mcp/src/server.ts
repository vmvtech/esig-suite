// server.ts
//
// Builds the v0.1 MCP tool surface (design doc §4, §5, §7) on top of the
// library layer (config/stores/documents/delivery/envelopes/verify/sanitize)
// a previous worker built. Registers exactly the read + prepare tools —
// esig_sign_as_agent / esig_cosign_start are v0.2 (mode A/C) and are never
// registered here; `loadConfig` (config.ts) already refuses to build a
// `Config` at all for a mode other than H, so there is no reachable code
// path in this package that could serve those tools anyway (I2).
//
// SDK types verified against the installed package (node_modules/
// @modelcontextprotocol/sdk@1.30, dist/esm/server/mcp.d.ts): `McpServer`'s
// constructor takes only `(serverInfo, options?)` — `registerTool` derives
// and merges the `tools` server capability itself on first registration
// (mcp.js:56-65's `setToolRequestHandlers` calls `registerCapabilities`), so
// no capabilities need to be declared here.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./tools/types.js";
import { registerVerifyDocumentTool } from "./tools/verify-document.js";
import { registerEnvelopeStatusTool } from "./tools/envelope-status.js";
import { registerListEnvelopesTool } from "./tools/list-envelopes.js";
import { registerWhoamiTool } from "./tools/whoami.js";
import { registerIngestDocumentTool } from "./tools/ingest-document.js";
import { registerCreateEnvelopeTool } from "./tools/create-envelope.js";
import { registerVoidEnvelopeTool } from "./tools/void-envelope.js";
import { registerResealEnvelopeTool } from "./tools/reseal-envelope.js";
import { registerIdentityChallengeTool } from "./tools/identity-challenge.js";
import { registerSendReminderTool } from "./tools/send-reminder.js";
import { registerListEventsTool } from "./tools/list-events.js";

export type { McpServerDeps } from "./tools/types.js";

/**
 * The exact tool surface, in the order registered. Kept as one list so tests
 * can assert against it directly. `esig_identity_challenge` (§12, v0.2) is
 * always registered — unlike modes A/C, it is read/write only against the
 * mode-H envelope/challenge state this package already owns, gated purely by
 * whether an envelope's identity policy is above "none" (loadConfig's I2
 * fail-closed gate does not apply to it the way it does to modes A/C).
 */
export const V0_1_TOOL_NAMES = [
  "esig_create_envelope",
  "esig_envelope_status",
  "esig_identity_challenge",
  "esig_ingest_document",
  "esig_list_envelopes",
  "esig_list_events",
  "esig_reseal",
  "esig_send_reminder",
  "esig_verify_document",
  "esig_void_envelope",
  "esig_whoami",
] as const;

/**
 * Build a v0.1 `@e-sig/mcp` server: read tools (verify/status/list/whoami)
 * plus prepare tools (ingest/create/void/reseal). No sign-as-agent, no
 * co-sign — those are v0.2 and gated by `loadConfig` before this function is
 * ever reached with a mode other than H.
 */
export function createMcpServer(deps: McpServerDeps): McpServer {
  const server = new McpServer({ name: "esig-mcp", version: "0.1.0" });

  registerVerifyDocumentTool(server, deps);
  registerEnvelopeStatusTool(server, deps);
  registerListEnvelopesTool(server, deps);
  registerWhoamiTool(server, deps);
  registerIngestDocumentTool(server, deps);
  registerCreateEnvelopeTool(server, deps);
  registerVoidEnvelopeTool(server, deps);
  registerResealEnvelopeTool(server, deps);
  registerIdentityChallengeTool(server, deps);
  registerSendReminderTool(server, deps);
  registerListEventsTool(server, deps);

  return server;
}
