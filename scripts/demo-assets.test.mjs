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

  it("keeps the two MCP demo GIFs byte-identical", () => {
    const packageGif = new URL("packages/esig-mcp/demo.gif", repoRoot);
    const siteGif = new URL("site/assets/mcp-demo.gif", repoRoot);

    expect(sha256(packageGif)).toBe(sha256(siteGif));
  });

  it("keeps the MCP demo cast as the recording source", () => {
    const cast = new URL("demos/casts/mcp-demo.cast", repoRoot);

    expect(existsSync(cast)).toBe(true);

    const [header, ...events] = readFileSync(cast, "utf8")
      .trimEnd()
      .split("\n")
      .map(JSON.parse);
    const output = events.filter((event) => event[1] === "o").at(-1);

    expect(header.command).toBe("node packages/esig-mcp/dist/bin.js demo --auto");
    expect(output?.[2]).toMatch(/^Demo completed in \d+ms\.\r\n$/);
    expect(events.at(-1)?.slice(1)).toEqual(["x", "0"]);
  });

  it("keeps the two envelope demo GIFs byte-identical", () => {
    const packageGif = new URL("packages/esig-core/demo-envelope.gif", repoRoot);
    const siteGif = new URL("site/assets/envelope-demo.gif", repoRoot);

    expect(sha256(packageGif)).toBe(sha256(siteGif));
  });

  it("keeps a successful envelope cast as the recording source", () => {
    const cast = new URL("demos/casts/envelope.cast", repoRoot);

    expect(existsSync(cast)).toBe(true);

    const [header, ...events] = readFileSync(cast, "utf8")
      .trimEnd()
      .split("\n")
      .map(JSON.parse);
    const output = events.filter((event) => event[1] === "o").at(-1);

    expect(header.command).toBe("node demos/envelope.mjs");
    expect(output?.[2]).toBe(
      "7. completed + verified  status=completed ok=true digestValid=true signatureValid=true\r\n",
    );
    expect(events.at(-1)?.slice(1)).toEqual(["x", "0"]);
  });
});
