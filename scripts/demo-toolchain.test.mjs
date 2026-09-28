import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

const repoRoot = new URL("..", import.meta.url);

function run(script, args = []) {
  return spawnSync("bash", [script, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

describe("terminal demo toolchain guards", () => {
  it("requires record.sh arguments in NAME -- CMD form", () => {
    const result = run("demos/record.sh", ["smoke", "node"]);

    expect(result.status).toBe(64);
    expect(result.stderr).toContain("Usage: record.sh NAME -- CMD...");
  });

  it("rejects demo names that can escape the casts directory", () => {
    const result = run("demos/record.sh", ["../escape", "--", "true"]);

    expect(result.status).toBe(64);
    expect(result.stderr).toContain("Demo name must use only");
  });

  it("reports a missing cast before rendering", () => {
    const result = run("demos/render.sh", ["vitest-missing-cast"]);

    expect(result.status).toBe(66);
    expect(result.stderr).toContain("Cast not found:");
  });
});
