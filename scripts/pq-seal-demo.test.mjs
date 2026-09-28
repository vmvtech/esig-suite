import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const pqDigestFailure = "post-quantum digest does not match the document — content altered";

function runDemo() {
  const isolatedTmp = mkdtempSync(join(tmpdir(), "esig-pq-seal-demo-test-"));
  try {
    const result = spawnSync(process.execPath, ["demos/pq-seal.mjs"], {
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
  expect(stdout).toContain("pqSealed=true");
  expect(stdout).toMatch(/ML-DSA-65 fingerprint=[0-9a-f]{64}/);
  expect(stdout).toMatch(/out\.pdf: OK/);
  expect(stdout).toMatch(/post-quantum:\s+present, ok/);
  expect(stdout).toContain("✓ classical + post-quantum verification passed");
  expect(stdout).toMatch(/tampered\.pdf: FAIL/);
  expect(stdout).toMatch(/digest valid:\s+no/);
  expect(stdout).toMatch(/post-quantum:\s+present, FAIL/);
  expect(stdout).toContain(pqDigestFailure);
  expect(stdout.trimEnd().split("\n").at(-1)).toBe("post-quantum seal demo passed ✓");
}

describe("post-quantum seal demo", () => {
  let result;
  let leftovers;

  beforeAll(() => {
    ({ result, leftovers } = runDemo());
  });

  it("verifies the sealed PDF and rejects one-byte tampering in both layers", () => {
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(leftovers).toEqual([]);
    assertTranscript(result.stdout);
  });

  it("rejects a transcript missing the exact post-quantum digest failure", () => {
    const mutant = result.stdout.replace(pqDigestFailure, "post-quantum verification failed");

    expect(result.status, result.stderr).toBe(0);
    expect(() => assertTranscript(mutant)).toThrow();
  });
});
