import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function runDemo() {
  const isolatedTmp = mkdtempSync(join(tmpdir(), "esig-envelope-demo-test-"));
  try {
    const result = spawnSync(process.execPath, ["demos/envelope.mjs"], {
      cwd: repoRoot,
      encoding: "utf8",
      env: { ...process.env, TMPDIR: isolatedTmp },
      timeout: 30_000,
    });
    return { result, leftovers: readdirSync(isolatedTmp) };
  } finally {
    rmSync(isolatedTmp, { recursive: true, force: true });
  }
}

function assertTranscript(stdout) {
  expect(stdout).toMatch(/alice link\s+https:\/\/example\.com\/sign\/[A-Za-z0-9_-]{8}… \(masked\)/);
  expect(stdout).toMatch(/bob link\s+https:\/\/example\.com\/sign\/[A-Za-z0-9_-]{8}… \(masked\)/);
  expect(stdout).toContain(
    "signing gates    alice=pending bob=not_your_turn (not yet your turn)",
  );
  expect(stdout).toContain("alice signed     status=partially_signed");
  expect(stdout).toContain("bob signed       status=completed");
  expect(stdout.trimEnd().split("\n").at(-1)).toMatch(
    /^7\. completed \+ verified  status=completed ok=true digestValid=true signatureValid=true$/,
  );
}

describe("multi-signer envelope demo", () => {
  let result;
  let leftovers;

  beforeAll(() => {
    ({ result, leftovers } = runDemo());
  });

  it("runs the ordered signing flow and verifies the sealed PDF", () => {
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(leftovers).toEqual([]);
    assertTranscript(result.stdout);
  });

  it("rejects a transcript whose final verification verdict is false", () => {
    const mutant = result.stdout.replace("status=completed ok=true", "status=completed ok=false");

    expect(result.status, result.stderr).toBe(0);
    expect(() => assertTranscript(mutant)).toThrow();
  });
});
