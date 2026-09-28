import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const repoRoot = new URL("..", import.meta.url);

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

describe("published demo assets", () => {
  it("keeps the two quickstart GIFs byte-identical", () => {
    const exampleGif = new URL("examples/quickstart/demo.gif", repoRoot);
    const siteGif = new URL("site/assets/quickstart-demo.gif", repoRoot);

    expect(sha256(exampleGif)).toBe(sha256(siteGif));
  });

  it("keeps the quickstart cast as the recording source", () => {
    const cast = new URL("demos/casts/quickstart.cast", repoRoot);

    expect(existsSync(cast)).toBe(true);
  });
});
