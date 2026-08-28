// cli-init.ts
//
// `esig-mcp init` (design doc §14, MUST DO item 2): sets up a local data
// directory + `.esig-mcp.env`, prints an `.mcp.json` snippet, and runs the
// Chrome preflight — everything a first-time operator needs before wiring
// `esig-mcp` into an MCP client. Dispatched from bin.ts's `main()` on
// `argv[2] === "init"`, exiting well before `StdioServerTransport` is ever
// constructed — stdout is exactly as free to use here as for `--help`/
// `--version` (bin.ts's own header comment).

import { promises as fs } from "node:fs";
import path from "node:path";

import { checkSealReadiness } from "./chrome-preflight.js";
import { fileExists, flagValue, randomPassphrase } from "./cli-shared.js";

export async function runInit(argv: string[]): Promise<void> {
  const dir = path.resolve(flagValue(argv, "--dir") ?? process.cwd());
  const force = argv.includes("--force");

  // Checked FIRST, before touching the filesystem at all: a refused run must
  // create nothing and change nothing (the data dirs below are created
  // unconditionally by `fs.mkdir(..., { recursive: true })`, which is a
  // harmless no-op when they already exist — so this guard is the only
  // thing standing between a re-run and a silently-regenerated passphrase).
  const envFile = path.join(dir, ".esig-mcp.env");
  if (!force && (await fileExists(envFile))) {
    process.stderr.write(
      `esig-mcp init: ${envFile} already exists — refusing to overwrite it (pass --force to overwrite).\n`,
    );
    process.exit(1);
    return;
  }

  const dataDir = path.join(dir, "esig-data");
  const inbox = path.join(dataDir, "inbox");
  const outbox = path.join(dataDir, "outbox");
  const blobs = path.join(dataDir, "blobs");
  await fs.mkdir(inbox, { recursive: true });
  await fs.mkdir(outbox, { recursive: true });
  await fs.mkdir(blobs, { recursive: true });

  const passphrase = randomPassphrase();
  const envLines = [
    `ESIG_MCP_PASSPHRASE=${passphrase}`,
    "ESIG_MCP_DELIVERY=file",
    `ESIG_MCP_DATA_DIR=${dataDir}`,
    `ESIG_MCP_DOCS_ROOT=${inbox}`,
    "",
    "# Email delivery + reminders (docs/architecture/esig-mcp.md §15) — commented",
    "# out; the `file` outbox above is the quickstart channel. Uncomment and fill",
    "# these in (switching ESIG_MCP_DELIVERY=email above) to send signing links by",
    "# email instead, and/or to enable reminders.",
    "# ESIG_MCP_DELIVERY=email",
    "# ESIG_MCP_EMAIL_TRANSPORT=smtp",
    "# ESIG_MCP_EMAIL_FROM=Your Name <you@example.com>",
    "# ESIG_MCP_EMAIL_REPLY_TO=",
    "# ESIG_MCP_SMTP_HOST=smtp.example.com",
    "# ESIG_MCP_SMTP_PORT=587",
    "# ESIG_MCP_SMTP_USER=",
    "# ESIG_MCP_SMTP_PASS=",
    "# ESIG_MCP_EMAIL_TRANSPORT=ses",
    "# ESIG_MCP_SES_REGION=us-east-1",
    "# Reminders require ESIG_MCP_DELIVERY=email:",
    "# ESIG_MCP_REMINDERS=24h,72h",
    "# ESIG_MCP_REMINDER_MAX=3",
    "",
    "# Lifecycle event webhooks (docs/architecture/esig-mcp.md §16) — commented",
    "# out. Uncomment to POST every envelope/signer lifecycle event (created,",
    "# viewed, signed, declined, completed, sealed, voided, expired, ...) to",
    "# your own receiver, HMAC-signed. Both required together; the secret must",
    "# be at least 32 characters.",
    "# ESIG_MCP_EVENTS_WEBHOOK_URL=https://your-app.example.com/esig-events",
    "# ESIG_MCP_EVENTS_WEBHOOK_SECRET=",
    "",
  ];
  // `fs.writeFile`'s own `mode` option is masked by the process umask
  // (delivery.ts's `FileDelivery` follows the identical pattern) — re-assert
  // with an explicit `chmod` so the bits are exact regardless of umask; this
  // file contains a signing passphrase.
  await fs.writeFile(envFile, envLines.join("\n"), { encoding: "utf8", mode: 0o600 });
  await fs.chmod(envFile, 0o600);

  // Never the passphrase value itself (MUST DO item 2) — an operator wiring
  // this snippet into an MCP client's config should paste it from the env
  // file (or reference the file directly), never copy it out of a terminal
  // scrollback.
  const mcpJsonSnippet = {
    mcpServers: {
      esig: {
        command: "esig-mcp",
        env: {
          ESIG_MCP_PASSPHRASE: "<see .esig-mcp.env>",
          ESIG_MCP_DELIVERY: "file",
          ESIG_MCP_DATA_DIR: dataDir,
          ESIG_MCP_DOCS_ROOT: inbox,
        },
      },
    },
  };

  process.stdout.write(`Created ${dataDir} (inbox/, outbox/, blobs/)\n`);
  process.stdout.write(`Wrote ${envFile} (mode 0600)\n`);
  process.stdout.write("\nAdd this to your MCP client's config (Claude Desktop, or a project .mcp.json):\n\n");
  process.stdout.write(`${JSON.stringify(mcpJsonSnippet, null, 2)}\n\n`);

  const { sealReady, sealReadyReason } = await checkSealReadiness(process.env);
  process.stdout.write(`Chrome preflight: sealReady=${sealReady} (${sealReadyReason})\n`);
  process.stdout.write(
    "PDF envelopes (esig_create_envelope with docId) seal without Chrome — only HTML envelopes need " +
      "it, for the HTML→PDF render at seal time.\n",
  );

  process.stdout.write("\nNext steps:\n");
  process.stdout.write("  1. Wire the snippet above into your MCP client.\n");
  process.stdout.write("  2. Or run the server directly:\n");
  process.stdout.write(`       set -a; source ${envFile}; set +a\n`);
  process.stdout.write("       npx @e-sig/mcp\n");
  process.stdout.write("  3. See the whole flow end to end, no setup needed: npx @e-sig/mcp demo --auto\n");

  process.exit(0);
}
