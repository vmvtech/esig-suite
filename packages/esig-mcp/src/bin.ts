#!/usr/bin/env node
// bin.ts — the real MCP server entrypoint (design doc §5 "Architecture",
// MUST DO item 3). Loads config, builds the library-layer stores/services,
// starts the built-in HTTP approval server, then connects the MCP server
// over stdio.
//
// stdout is reserved ENTIRELY for the MCP stdio JSON-RPC transport
// (StdioServerTransport reads/writes it directly) once the server actually
// starts — this file, and every module it calls into, writes only to
// stderr from that point on. The ONE exception (D3) is `--help`/`--version`:
// both `process.exit(0)` before `StdioServerTransport` is ever constructed,
// so nothing has claimed stdout yet — printing there (not stderr) is what
// lets `esig-mcp --help` behave like a normal CLI when piped or captured.

import { readFileSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { loadConfig, ConfigError } from "./config.js";
import { buildStores } from "./stores.js";
import { FsDocumentStore } from "./documents.js";
import { ConsoleDelivery, FileDelivery, WebhookDelivery, type DeliveryChannel } from "./delivery.js";
import { EnvelopeService } from "./envelopes.js";
import { createMcpServer } from "./server.js";
import { createApprovalServer } from "./http.js";
import { checkSealReadiness } from "./chrome-preflight.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// D3: read the version from the installed/monorepo package.json at runtime
// rather than hardcoding it — `dist/bin.js`'s `..` is `packages/esig-mcp`
// both in this monorepo (tsconfig.build.json: rootDir "./src", outDir
// "./dist") and in an npm install (npm always packs package.json at the
// package root regardless of the "files" allowlist).
const PACKAGE_VERSION: string = JSON.parse(readFileSync(path.join(here, "..", "package.json"), "utf8")).version;

const REQUIRED_ENV_VARS: ReadonlyArray<[name: string, note: string]> = [
  ["ESIG_MCP_PASSPHRASE", "Encrypts the tenant's signing cert + PQ key bundle at rest. >= 24 characters."],
  [
    "ESIG_MCP_DELIVERY",
    '"file" (writes <ESIG_MCP_DATA_DIR>/outbox/<envelopeId>.json — the quickstart channel), ' +
      '"console" (prints links to stderr, opt-in only), or "webhook". No default: an operator must ' +
      "pick where signing links go.",
  ],
];

const OPTIONAL_ENV_VARS: ReadonlyArray<[name: string, defaultValue: string, note: string]> = [
  ["ESIG_MCP_MODES", "H", "Comma-separated. Only H is implemented in v0.1 — A or C refuses to start."],
  ["ESIG_MCP_DATA_DIR", "./.esig-mcp", "Root for the filesystem-backed stores. Created at startup."],
  [
    "ESIG_MCP_DOCS_ROOT",
    "<ESIG_MCP_DATA_DIR>/inbox",
    "Confines the `path` input on esig_verify_document / esig_ingest_document. Created at startup.",
  ],
  ["ESIG_MCP_TENANT", "default", "Partition key for certs/keys/envelopes."],
  ["ESIG_MCP_SUBJECT_NAME", "e-sig MCP", "Signing cert subject CN."],
  ["ESIG_MCP_HTTP_HOST", "127.0.0.1", "Approval-page bind host."],
  ["ESIG_MCP_HTTP_PORT", "7433", "Approval-page bind port."],
  ["ESIG_MCP_BASE_URL", "derived from host:port", "Base URL signing links are built from."],
  ["ESIG_MCP_RETURN_LINKS", "off", 'Set to exactly "1" to include raw signing links in esig_create_envelope. Local demos only.'],
  ["ESIG_MCP_DELIVERY_WEBHOOK_URL", "—", "Required when ESIG_MCP_DELIVERY=webhook. Must be https:// unless ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1."],
  ["ESIG_MCP_ALLOW_INSECURE_WEBHOOK", "off", 'Set to exactly "1" to allow a plain http:// webhook URL.'],
  ["ESIG_MCP_PQ", "on", 'Set to "0" to disable the hybrid Ed25519 + ML-DSA-65 post-quantum seal.'],
  ["ESIG_MCP_MAX_HTML_BYTES", "524288", "Envelope HTML size cap (512 KiB)."],
  ["ESIG_MCP_MAX_PDF_BYTES", "26214400", "Ingested/sealed PDF size cap (25 MiB)."],
  ["ESIG_MCP_ENVELOPES_PER_HOUR", "60", "Per-process rate limit on envelope creation (and esig_reseal)."],
  [
    "ESIG_MCP_IDENTITY_MIN_LEVEL",
    "none",
    "Signer-identity floor: none | L0 | L1 | L2 (docs/architecture/esig-mcp.md §12). esig_create_envelope may only RAISE this per envelope.",
  ],
  [
    "ESIG_MCP_UUAID_REGISTRY_URL",
    "—",
    "https:// UUAID registry base URL. Required when ESIG_MCP_IDENTITY_MIN_LEVEL=L2 (or any envelope requests L2).",
  ],
  [
    "ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC",
    "900",
    "Sole-control challenge lifetime in seconds. Max 3600.",
  ],
  [
    "ESIG_CHROME_PATH / PUPPETEER_EXECUTABLE_PATH / CHROME_PATH",
    "unset",
    "Chrome/Chromium executable override, checked in this order. Only needed for sealing — envelopes " +
      "can be created and signed without it; see esig_whoami's sealReady.",
  ],
];

function envTable(rows: ReadonlyArray<readonly string[]>): string {
  const nameWidth = Math.max(...rows.map((r) => r[0].length));
  return rows.map((r) => `  ${r[0].padEnd(nameWidth)}  ${r.slice(1).join("  ")}`).join("\n");
}

function usage(): string {
  return [
    "esig-mcp — MCP server for agent-driven e-signature workflows (mode H: human signs by default).",
    "",
    "Usage: esig-mcp [--help] [--version]",
    "",
    "All configuration is via environment variables.",
    "",
    "Required:",
    envTable(REQUIRED_ENV_VARS),
    "",
    "Optional (default):",
    envTable(OPTIONAL_ENV_VARS.map(([name, def, note]) => [name, `(${def})`, note])),
    "",
    "On start this process:",
    "  1. creates ESIG_MCP_DATA_DIR and its inbox/, outbox/, blobs/ subdirectories,",
    "  2. builds the filesystem-backed cert/audit/pdf/pq-key/envelope stores under ESIG_MCP_DATA_DIR,",
    "  3. runs a Chrome/Chromium preflight (a filesystem check only — never launches a browser) and",
    "     warns if sealing won't work yet; envelopes can still be created and signed either way,",
    "  4. starts the built-in human approval page on ESIG_MCP_HTTP_HOST:ESIG_MCP_HTTP_PORT,",
    "  5. serves the MCP tool surface over stdio.",
    "",
    "60-second quickstart:",
    '  ESIG_MCP_PASSPHRASE="a passphrase at least 24 characters long" \\',
    "  ESIG_MCP_DELIVERY=file \\",
    "  npx @e-sig/mcp",
    "",
    "Full reference: https://github.com/vmvtech/esig-suite/blob/main/packages/esig-mcp/README.md",
  ].join("\n");
}

function addressPort(server: ReturnType<typeof createApprovalServer>, fallback: number): number {
  const addr = server.address();
  return addr && typeof addr === "object" ? addr.port : fallback;
}

async function main(): Promise<void> {
  // D3: both flags exit before StdioServerTransport is ever constructed, so
  // stdout is still free to use (see this file's header comment) — printed
  // there, not stderr, so `esig-mcp --help` / `--version` behave like a
  // normal CLI when piped or captured.
  if (process.argv.includes("--version")) {
    process.stdout.write(`${PACKAGE_VERSION}\n`);
    process.exit(0);
    return;
  }
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(usage() + "\n");
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

  // D6: create the data dir and its inbox/outbox/blobs subdirectories up
  // front, rather than letting each of them get created lazily by whichever
  // store/channel/tool happens to touch them first (FsDocumentStore's own
  // "documents/" subdirectory is separate — it's created lazily by
  // FsDocumentStore itself on first ingest, same as before; it isn't one of
  // the three the ticket names). Absolute paths are printed in the "ready"
  // line below so an operator can find them without re-deriving from
  // ESIG_MCP_DATA_DIR.
  const absoluteDataDir = path.resolve(config.dataDir);
  const absoluteInbox = config.docsRoot; // already absolute (config.ts resolves it)
  const absoluteOutbox = path.join(absoluteDataDir, "outbox");
  const absoluteBlobs = path.join(absoluteDataDir, "blobs");
  await fs.mkdir(absoluteDataDir, { recursive: true });
  await fs.mkdir(absoluteInbox, { recursive: true });
  await fs.mkdir(absoluteOutbox, { recursive: true });
  await fs.mkdir(absoluteBlobs, { recursive: true });

  // D2: filesystem-only preflight — never launches Chrome (chrome-preflight.ts).
  const { sealReady, sealReadyReason } = await checkSealReadiness(process.env);
  if (!sealReady) {
    process.stderr.write(
      "[esig-mcp] WARNING: no Chrome/Chromium found — envelopes can be created and signed but NOT " +
        `sealed; set ESIG_CHROME_PATH (${sealReadyReason}).\n`,
    );
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
    sealReady,
    sealReadyReason,
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
      `delivery "${config.delivery.kind}", pq ${config.pq ? "on" : "off"}, ` +
      `sealReady ${sealReady}, data dir ${absoluteDataDir}, inbox ${absoluteInbox}, ` +
      `outbox ${absoluteOutbox}, blobs ${absoluteBlobs}\n`,
  );
}

main().catch((e) => {
  process.stderr.write(`esig-mcp: fatal: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
