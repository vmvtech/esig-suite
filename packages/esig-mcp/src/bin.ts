#!/usr/bin/env node
// bin.ts — the real MCP server entrypoint (design doc §5 "Architecture",
// MUST DO item 3). Loads config, builds the library-layer stores/services,
// starts the built-in HTTP approval server, then connects the MCP server
// over stdio.
//
// stdout is reserved ENTIRELY for the MCP stdio JSON-RPC transport
// (StdioServerTransport reads/writes it directly) — this file, and every
// module it calls into, writes only to stderr. No exception for --help.

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { loadConfig, ConfigError } from "./config.js";
import { buildStores } from "./stores.js";
import { FsDocumentStore } from "./documents.js";
import { ConsoleDelivery, FileDelivery, WebhookDelivery, type DeliveryChannel } from "./delivery.js";
import { EnvelopeService } from "./envelopes.js";
import { createMcpServer } from "./server.js";
import { createApprovalServer } from "./http.js";

function usage(): string {
  return [
    "esig-mcp — MCP server for agent-driven e-signature workflows (mode H: human signs by default).",
    "",
    "Usage: esig-mcp [--help]",
    "",
    "All configuration is via environment variables (see README.md's env var table).",
    "ESIG_MCP_PASSPHRASE (>= 24 chars) is required; everything else has a default.",
    "",
    "On start this process:",
    "  1. builds the filesystem-backed cert/audit/pdf/pq-key/envelope stores under ESIG_MCP_DATA_DIR,",
    "  2. starts the built-in human approval page on ESIG_MCP_HTTP_HOST:ESIG_MCP_HTTP_PORT,",
    "  3. serves the MCP tool surface over stdio.",
  ].join("\n");
}

function addressPort(server: ReturnType<typeof createApprovalServer>, fallback: number): number {
  const addr = server.address();
  return addr && typeof addr === "object" ? addr.port : fallback;
}

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stderr.write(usage() + "\n");
    process.exit(0);
    return;
  }

  let config;
  try {
    config = loadConfig(process.env);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(`esig-mcp: configuration error: ${e.message}\n`);
      process.exit(1);
      return;
    }
    throw e;
  }

  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery: DeliveryChannel =
    config.delivery.kind === "webhook"
      ? new WebhookDelivery(config.delivery.url)
      : config.delivery.kind === "file"
        ? new FileDelivery(config.dataDir)
        : new ConsoleDelivery();

  // G3(c): 'console' is opt-in (config.ts refuses to default to it) precisely
  // because it hands signing links to whatever is capturing this process's
  // stderr — in the canonical stdio MCP deployment, that's the agent
  // harness's own log. Loud on purpose, every time this channel is selected,
  // matching the ESIG_MCP_RETURN_LINKS warning's own precedent (envelopes.ts).
  if (config.delivery.kind === "console") {
    process.stderr.write(
      "[esig-mcp] WARNING: ESIG_MCP_DELIVERY=console — signing links will be printed to stderr. " +
        "Only use this where the operator owns this terminal (e.g. a local demo you are running " +
        "yourself): in a stdio MCP deployment, stderr is typically captured into the connecting " +
        "agent harness's own log, and the signing link IS the signing capability.\n",
    );
  }

  const envelopes = new EnvelopeService({ config, ...stores, delivery });

  const httpServer = createApprovalServer({ config, envelopes });
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(config.httpPort, config.httpHost, resolve);
  });
  const actualPort = addressPort(httpServer, config.httpPort);

  const mcpServer = createMcpServer({
    config,
    envelopes,
    documents,
    certStore: stores.certStore,
    pqKeyStore: stores.pqKeyStore,
    auditStore: stores.auditStore,
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stderr.write(`[esig-mcp] received ${signal}, shutting down...\n`);
    void Promise.allSettled([
      mcpServer.close(),
      new Promise<void>((resolve) => httpServer.close(() => resolve())),
    ]).then(() => process.exit(0));
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // D5: an MCP host that only closes the pipe (stdin EOF), without ever
  // sending SIGTERM, must still shut this process down gracefully —
  // otherwise the HTTP approval server is orphaned, still holding its port,
  // with nothing left to stop it. `StdioServerTransport` only invokes
  // `onclose` when something calls `.close()` on it explicitly; it never
  // listens for stdin EOF itself, so both hooks are wired to the same
  // `shutdown` path used for SIGTERM/SIGINT. `onclose` must be assigned
  // BEFORE `connect()` — the SDK reads and wraps whatever handler is already
  // set at connect time.
  const transport = new StdioServerTransport();
  transport.onclose = () => shutdown("stdio transport closed");
  process.stdin.on("end", () => shutdown("stdin EOF"));

  await mcpServer.connect(transport);

  process.stderr.write(
    `[esig-mcp] ready — tenant "${config.tenant}", modes [${config.modes.join(",")}], ` +
      `approval page http://${config.httpHost}:${actualPort}, mcp transport stdio, ` +
      `delivery "${config.delivery.kind}", pq ${config.pq ? "on" : "off"}\n`,
  );
}

main().catch((e) => {
  process.stderr.write(`esig-mcp: fatal: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
