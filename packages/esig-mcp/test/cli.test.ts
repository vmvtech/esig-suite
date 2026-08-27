// cli.test.ts — `esig-mcp init` and `esig-mcp demo` (design doc §14, MUST
// DO item 4). Spawns the REAL compiled dist/bin.js — same consumer-path
// rationale as bin-cli.test.ts — rather than calling cli-init.ts/cli-demo.ts
// directly.

import { spawnSync, type SpawnSyncOptions } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

import { verifyDocumentBytes } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const BIN = join(here, "..", "dist", "bin.js");

function run(args: string[], opts: SpawnSyncOptions = {}) {
  return spawnSync("node", [BIN, ...args], { encoding: "utf8", timeout: 20_000, ...opts });
}

describe("esig-mcp init", () => {
  it("creates the data dirs + a 0600 env file, refuses a second run, --force overwrites with a new passphrase", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-init-"));

    const first = run(["init", "--dir", dir]);
    expect(first.status).toBe(0);
    expect(first.stderr).toBe("");

    const dataDir = path.join(dir, "esig-data");
    expect(existsSync(path.join(dataDir, "inbox"))).toBe(true);
    expect(existsSync(path.join(dataDir, "outbox"))).toBe(true);
    expect(existsSync(path.join(dataDir, "blobs"))).toBe(true);

    const envFile = path.join(dir, ".esig-mcp.env");
    expect(existsSync(envFile)).toBe(true);
    const mode = (await stat(envFile)).mode & 0o777;
    expect(mode).toBe(0o600);

    const envContents = await readFile(envFile, "utf8");
    const passphraseMatch = envContents.match(/^ESIG_MCP_PASSPHRASE=(\S+)$/m);
    expect(passphraseMatch).toBeTruthy();
    expect(passphraseMatch![1].length).toBeGreaterThanOrEqual(24);
    expect(envContents).toContain("ESIG_MCP_DELIVERY=file");
    expect(envContents).toContain(`ESIG_MCP_DATA_DIR=${dataDir}`);
    expect(envContents).toContain(`ESIG_MCP_DOCS_ROOT=${path.join(dataDir, "inbox")}`);

    // The passphrase VALUE never appears on stdout — only the placeholder.
    expect(first.stdout).toContain("<see .esig-mcp.env>");
    expect(first.stdout).not.toContain(passphraseMatch![1]);
    expect(first.stdout).toContain('"mcpServers"');
    expect(first.stdout).toMatch(/sealReady/);

    // Refuses to overwrite without --force — file untouched.
    const second = run(["init", "--dir", dir]);
    expect(second.status).toBe(1);
    expect(second.stderr).toMatch(/already exists/);
    expect(await readFile(envFile, "utf8")).toBe(envContents);

    // --force overwrites, with a freshly generated passphrase.
    const third = run(["init", "--dir", dir, "--force"]);
    expect(third.status).toBe(0);
    const envContentsAfterForce = await readFile(envFile, "utf8");
    expect(envContentsAfterForce).not.toBe(envContents);
  });
});

describe("esig-mcp demo --auto", () => {
  it(
    "exit 0; stdout has the signing URL/outbox path/curl one-liner, 'sealed', a verdict with ok true, " +
      "and the wall time; the sealed PDF exists on disk and verifies via core verifyDocument",
    async () => {
      const t0 = Date.now();
      // --keep: the child process cleans its own temp dir on exit unless
      // told to keep it — this test needs the sealed PDF to still be on
      // disk AFTER the process exits, to verify it independently below.
      const res = run(["demo", "--auto", "--keep"], { timeout: 30_000 });
      const wallMs = Date.now() - t0;
      // "total demo wall time reported" (MUST DO item 4) — visible in the
      // test's own output, alongside the CLI's own reported figure below.
      // eslint-disable-next-line no-console
      console.log(`[cli.test] esig-mcp demo --auto --keep: spawn-to-exit ${wallMs}ms`);

      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/^Signing URL:\s+http:\/\/127\.0\.0\.1:\d+\/sign\/\S+$/m);
      expect(res.stdout).toMatch(/^Outbox file:\s+\S+\.json$/m);
      expect(res.stdout).toMatch(/^Try it:\s+curl .*\/sign\/\S+/m);
      expect(res.stdout).toContain("sealed");
      expect(res.stdout).toMatch(/ok=true/);
      expect(res.stdout).toMatch(/classical\.digestValid=true/);
      expect(res.stdout).toMatch(/postQuantum\.ok=true/);
      expect(res.stdout).toMatch(/Demo completed in \d+ms\./);

      const sealedMatch = res.stdout.match(/^Sealed PDF: (.+)$/m);
      expect(sealedMatch).toBeTruthy();
      const sealedPath = sealedMatch![1].trim();
      expect(existsSync(sealedPath)).toBe(true);

      const sealedBytes = await readFile(sealedPath);
      const verdict = verifyDocumentBytes(sealedBytes, { requirePq: true });
      expect(verdict.ok).toBe(true);
      expect(verdict.classical.digestValid).toBe(true);
      expect(verdict.postQuantum.ok).toBe(true);

      // --keep leaves the demo's temp data dir behind by design; remove it
      // here so repeated test runs don't accumulate esig-mcp-demo-* dirs.
      const keptRoot = sealedPath.match(/^(.*[\\/]esig-mcp-demo-[^\\/]+)/)?.[1];
      if (keptRoot) rmSync(keptRoot, { recursive: true, force: true });
    },
    30_000,
  );

  it("without --keep, the temp data dir is removed on exit", () => {
    const res = run(["demo", "--auto"], { timeout: 30_000 });
    expect(res.status).toBe(0);
    const sealedPath = res.stdout.match(/^Sealed PDF: (.+)$/m)![1].trim();
    expect(existsSync(sealedPath)).toBe(false);
  });
});
