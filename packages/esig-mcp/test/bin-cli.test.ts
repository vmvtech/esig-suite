// bin-cli.test.ts — D3 (bin.ts --help/--version), plus D2 (startup WARNING
// when no Chrome is found) and D6 (data dir / inbox / outbox / blobs created
// at startup, printed in the ready line). Spawns the REAL compiled
// dist/bin.js — the actual thing an operator or MCP host runs — rather than
// calling library functions directly (design doc §7: "the consumer path").

import { spawnSync } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const BIN = join(here, "..", "dist", "bin.js");
const PACKAGE_VERSION: string = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")).version;
const PASSPHRASE = "a".repeat(24);

describe("dist/bin.js --help / --version (D3)", () => {
  it("--help: exit 0, stdout has the required + optional env-var table and the quickstart, stderr empty", () => {
    const res = spawnSync("node", [BIN, "--help"], { encoding: "utf8", input: "", timeout: 10_000 });
    expect(res.status).toBe(0);
    expect(res.stderr).toBe("");
    expect(res.stdout).toMatch(/ESIG_MCP_PASSPHRASE/);
    expect(res.stdout).toMatch(/ESIG_MCP_DELIVERY/);
    // Optional-with-defaults table:
    expect(res.stdout).toMatch(/ESIG_MCP_DATA_DIR/);
    expect(res.stdout).toMatch(/ESIG_MCP_ENVELOPES_PER_HOUR/);
    expect(res.stdout).toMatch(/ESIG_CHROME_PATH/);
    expect(res.stdout.toLowerCase()).toMatch(/quickstart/);
    expect(res.stdout).toMatch(/npx @e-sig\/mcp/);
  });

  it("--version: exit 0, stdout has the package.json version, stderr empty", () => {
    const res = spawnSync("node", [BIN, "--version"], { encoding: "utf8", input: "", timeout: 10_000 });
    expect(res.status).toBe(0);
    expect(res.stderr).toBe("");
    expect(res.stdout.trim()).toBe(PACKAGE_VERSION);
  });
});

describe("dist/bin.js startup (D2, D6)", () => {
  it(
    "no Chrome found: still starts (exit 0 on stdin EOF), prints a WARNING naming ESIG_CHROME_PATH, " +
      "creates data dir / inbox / outbox / blobs, and writes nothing to stdout",
    async () => {
      const dataDir = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-bin-smoke-"));

      // `input: ""` closes the child's stdin immediately after writing zero
      // bytes — the same EOF signal `</dev/null` sends — which drives
      // bin.ts's own `process.stdin.on("end", ...)` graceful-shutdown path
      // (see bin.ts's D5-labeled comment), so the process exits on its own
      // rather than needing a signal.
      const res = spawnSync("node", [BIN], {
        env: {
          ...process.env,
          ESIG_CHROME_PATH: "/nonexistent/chrome-binary",
          ESIG_MCP_PASSPHRASE: PASSPHRASE,
          ESIG_MCP_DELIVERY: "file",
          ESIG_MCP_DATA_DIR: dataDir,
          // Avoid colliding with the 7433 default (or anything else on the
          // test machine) — the port itself isn't what this test is about.
          ESIG_MCP_HTTP_PORT: "18933",
        },
        encoding: "utf8",
        input: "",
        timeout: 10_000,
      });

      expect(res.status).toBe(0);
      expect(res.stdout).toBe("");
      expect(res.stderr).toMatch(/WARNING: no Chrome\/Chromium found/);
      expect(res.stderr).toMatch(/ESIG_CHROME_PATH/);
      expect(res.stderr).toMatch(/ready/);
      expect(res.stderr).toContain(dataDir);

      expect(existsSync(path.join(dataDir, "inbox"))).toBe(true);
      expect(existsSync(path.join(dataDir, "outbox"))).toBe(true);
      expect(existsSync(path.join(dataDir, "blobs"))).toBe(true);
    },
    15_000,
  );
});
