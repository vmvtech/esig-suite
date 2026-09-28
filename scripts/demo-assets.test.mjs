import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const repoRoot = new URL("..", import.meta.url);

const demos = [
  ["quickstart", "quickstart-demo"],
  ["mcp-demo", "mcp-demo"],
  ["envelope", "envelope-demo"],
  ["pq-seal", "pq-seal-demo"],
];

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

describe("published demo assets", () => {
  it("publishes every demo as valid GIF and MP4 assets", () => {
    for (const [, assetName] of demos) {
      for (const extension of ["gif", "mp4"]) {
        const published = new URL(`site/assets/${assetName}.${extension}`, repoRoot);

        expect(existsSync(published), `${assetName}.${extension} exists`).toBe(true);
        if (existsSync(published)) {
          const bytes = readFileSync(published);
          const signature = extension === "gif"
            ? bytes.subarray(0, 6).toString("ascii")
            : bytes.subarray(4, 8).toString("ascii");
          expect(signature, `${assetName}.${extension} has the expected format`).toBe(
            extension === "gif" ? "GIF89a" : "ftyp",
          );
        }
      }
    }
  });

  it("wires demo recordings into docs, the agent guide, and the press kit", () => {
    const docs = readFileSync(new URL("docs/index.html", repoRoot), "utf8");
    const agents = readFileSync(new URL("site/agents/index.html", repoRoot), "utf8");
    const press = readFileSync(new URL("site/press/index.html", repoRoot), "utf8");

    expect(docs).toContain('src="https://e-sig.org/assets/mcp-demo.gif"');
    expect(docs).toContain('src="https://e-sig.org/assets/envelope-demo.gif"');
    expect(agents).toContain('src="/assets/mcp-demo.gif"');
    for (const [, assetName] of demos) {
      expect(press).toContain(`href="/assets/${assetName}.gif"`);
      expect(press).toContain(`href="/assets/${assetName}.mp4"`);
    }
  });

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

  it("keeps the successful post-quantum cast and published site asset", () => {
    const cast = new URL("demos/casts/pq-seal.cast", repoRoot);
    const siteGif = new URL("site/assets/pq-seal-demo.gif", repoRoot);
    const siteHtml = new URL("site/index.html", repoRoot);

    expect(existsSync(cast)).toBe(true);
    expect(existsSync(siteGif)).toBe(true);
    expect(readFileSync(siteGif).subarray(0, 6).toString("ascii")).toBe("GIF89a");

    const [header, ...events] = readFileSync(cast, "utf8")
      .trimEnd()
      .split("\n")
      .map(JSON.parse);
    const output = events
      .filter((event) => event[1] === "o")
      .map((event) => event[2])
      .join("");

    expect(header.command).toBe("npm run demo:pq --silent");
    expect(output).toContain("pqSealed=true");
    expect(output).toContain("out.pdf: OK");
    expect(output).toContain("tampered.pdf: FAIL");
    expect(output).toContain("post-quantum digest does not match the document — content altered");
    expect(output).toContain("post-quantum seal demo passed ✓");
    expect(events.at(-1)?.slice(1)).toEqual(["x", "0"]);

    const html = readFileSync(siteHtml, "utf8");
    expect(html).toContain('src="/assets/pq-seal-demo.gif"');
    expect(html).toContain("recorded from <code>npm run demo:pq</code>");
  });
});
