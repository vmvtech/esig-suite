// cli-demo.ts
//
// `esig-mcp demo` (design doc §14, MUST DO item 3): an end-to-end,
// Chrome-free PDF-envelope signing demo in a temp data dir — ingest the
// bundled `assets/sample.pdf`, create a one-signer envelope, and either
// print the signing URL and wait for a human (default) or sign it
// in-process (`--auto`). Chrome-free by construction, not by injection: a
// PDF envelope's seal step never calls the HTML renderer at all (§13,
// envelopes.ts `seal()`), and this command only ever creates PDF envelopes.
//
// Dispatched from bin.ts's `main()` on `argv[2] === "demo"`, exiting (or, in
// the non-`--auto` case, blocking on Ctrl-C/stdin EOF) well before
// `StdioServerTransport` is ever constructed — stdout is exactly as free to
// use here as for `--help`/`--version`/`init` (bin.ts's own header comment):
// this is not the MCP wire.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig } from "./config.js";
import { buildStores } from "./stores.js";
import { FsDocumentStore } from "./documents.js";
import { FileDelivery } from "./delivery.js";
import { EnvelopeService } from "./envelopes.js";
import { createApprovalServer } from "./http.js";
import { verifyDocumentBytes } from "./verify.js";
import { randomPassphrase, sleep, TINY_PNG_DATA_URL } from "./cli-shared.js";
import { messageOf } from "./tools/helpers.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// dist/cli-demo.js's `..` is packages/esig-mcp, both in this monorepo and in
// an npm install — same rationale as bin.ts's own `PACKAGE_VERSION` comment.
// `assets/` ships alongside `dist/` (package.json's `files`), never inside
// `dist/` itself (tsconfig.build.json only compiles `src/**/*`).
const SAMPLE_PDF_PATH = path.join(here, "..", "assets", "sample.pdf");

function addressPort(server: { address(): unknown }, fallback: number): number {
  const addr = server.address();
  return addr && typeof addr === "object" ? (addr as { port: number }).port : fallback;
}

export async function runDemo(argv: string[]): Promise<void> {
  const start = Date.now();
  const auto = argv.includes("--auto");
  const keep = argv.includes("--keep");

  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-mcp-demo-"));
  let cleanedUp = false;
  const cleanup = async (): Promise<void> => {
    if (cleanedUp || keep) return;
    cleanedUp = true;
    await fs.rm(dataDir, { recursive: true, force: true }).catch(() => {});
  };

  // ESIG_MCP_RETURN_LINKS=1: MUST DO item 3 — "print the existing loud
  // warning" is `create()`'s own (envelopes.ts), fired automatically below
  // the moment `config.returnLinks` is true; nothing here suppresses it.
  const config = loadConfig({
    ESIG_MCP_PASSPHRASE: randomPassphrase(),
    ESIG_MCP_DELIVERY: "file",
    ESIG_MCP_DATA_DIR: dataDir,
    ESIG_MCP_RETURN_LINKS: "1",
  });

  await fs.mkdir(config.docsRoot, { recursive: true });
  await fs.mkdir(path.join(dataDir, "outbox"), { recursive: true });
  await fs.mkdir(path.join(dataDir, "blobs"), { recursive: true });

  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new FileDelivery(config.dataDir);
  const envelopes = new EnvelopeService({ config, ...stores, documents, delivery });

  const httpServer = createApprovalServer({ config, envelopes });
  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(0, config.httpHost, resolve);
  });
  // The real listening port is only known after `listen()` resolves — patch
  // up the placeholder `baseUrl`/`httpPort` `loadConfig` derived from the
  // (unset) configured port, BEFORE creating the envelope below, so the
  // signing link this command prints/POSTs to is actually reachable. Nothing
  // else reads `config.httpPort` after the `.listen()` call above, and
  // `EnvelopeService` reads only `config.baseUrl` to build signing links
  // (envelopes.ts `create()`) — so this is the only fix-up needed.
  const actualPort = addressPort(httpServer, config.httpPort);
  config.httpPort = actualPort;
  config.baseUrl = `http://${config.httpHost}:${actualPort}`;

  const closeServer = (): Promise<void> => new Promise((resolve) => httpServer.close(() => resolve()));

  let sampleBytes: Buffer;
  try {
    sampleBytes = await fs.readFile(SAMPLE_PDF_PATH);
  } catch (e) {
    process.stderr.write(`esig-mcp demo: could not read bundled sample.pdf: ${messageOf(e)}\n`);
    await closeServer();
    await cleanup();
    process.exit(1);
    return;
  }
  const { docId } = await documents.ingest(sampleBytes);

  const created = await envelopes.create({
    title: "e-sig demo — sample.pdf",
    docId,
    signers: [{ name: "Demo Signer", email: "demo@example.com" }],
  });
  const link = created.links?.[0];
  const outboxPath = created.delivery.find((r) => r.channel === "file")?.detail;
  if (!link || !outboxPath) {
    // Unreachable in practice: ESIG_MCP_RETURN_LINKS=1 and delivery=file are
    // both fixed above, so create() always returns exactly this shape.
    process.stderr.write("esig-mcp demo: internal error — no signing link or outbox path was returned.\n");
    await closeServer();
    await cleanup();
    process.exit(1);
    return;
  }

  const curlBody = JSON.stringify({ signatureImageDataUrl: TINY_PNG_DATA_URL, consent: true });
  const curl = `curl -s -X POST '${link.url}' -H 'content-type: application/json' -d '${curlBody}'`;

  process.stdout.write(`Signing URL:  ${link.url}\n`);
  process.stdout.write(`Outbox file:  ${outboxPath}\n`);
  process.stdout.write(`Try it:       ${curl}\n`);

  if (!auto) {
    process.stdout.write("\nwaiting for the signature… (Ctrl-C, or close stdin, to stop)\n");
    await new Promise<void>((resolve) => {
      const done = (): void => resolve();
      process.once("SIGINT", done);
      process.once("SIGTERM", done);
      process.stdin.once("end", done);
      process.stdin.resume();
    });
    process.stdout.write("\nshutting down…\n");
    await closeServer();
    await cleanup();
    process.exit(0);
    return;
  }

  let signRes: Response;
  try {
    signRes = await fetch(link.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: curlBody,
    });
  } catch (e) {
    process.stderr.write(`esig-mcp demo: --auto signing POST failed: ${messageOf(e)}\n`);
    await closeServer();
    await cleanup();
    process.exit(1);
    return;
  }
  if (!signRes.ok) {
    const body = await signRes.text().catch(() => "");
    process.stderr.write(`esig-mcp demo: --auto signing POST returned HTTP ${signRes.status}: ${body}\n`);
    await closeServer();
    await cleanup();
    process.exit(1);
    return;
  }

  // `sign()` (envelopes.ts) already `await`s the seal step before the POST
  // above ever resolves, and a PDF envelope's seal never calls the HTML
  // renderer — so this is normally already `sealed` by the time we get
  // here. Poll briefly anyway rather than assume, mirroring this package's
  // own retry precedent (`esig_reseal`) for the one case a seal attempt is
  // still settling.
  let status = await envelopes.status(created.envelopeId);
  const deadline = Date.now() + 10_000;
  while (status.phase !== "sealed" && status.phase !== "seal_failed" && Date.now() < deadline) {
    await sleep(100);
    status = await envelopes.status(created.envelopeId);
  }

  await closeServer();

  if (status.phase !== "sealed" || !status.sealedPdfUrl) {
    process.stderr.write(
      `esig-mcp demo: envelope did not seal (phase=${status.phase}` +
        `${status.seal?.error ? `: ${status.seal.error}` : ""}).\n`,
    );
    await cleanup();
    process.exit(1);
    return;
  }

  const sealedBytes = await fs.readFile(status.sealedPdfUrl);
  const verdict = verifyDocumentBytes(sealedBytes, { requirePq: config.pq });

  process.stdout.write(`Sealed PDF: ${status.sealedPdfUrl}\n`);
  process.stdout.write(
    `Verify verdict: ok=${verdict.ok} classical.digestValid=${verdict.classical.digestValid} ` +
      `postQuantum.ok=${verdict.postQuantum.ok}\n`,
  );
  process.stdout.write(`Demo completed in ${Date.now() - start}ms.\n`);

  await cleanup();
  process.exit(0);
}
