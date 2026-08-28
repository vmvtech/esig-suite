import { access } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { buildDigest, htmlToText, PAGES } from "./gen-llms-full.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");

describe("llms-full.txt digest", () => {
  it("strips markup, scripts, and styles but keeps real text", () => {
    const text = htmlToText(
      "<html><head><style>p{color:red}</style></head><body>" +
        "<script>evil()</script><h2>Head</h2><p>Copy &amp; more &rarr; done</p>" +
        "<ul><li>one</li><li>two</li></ul></body></html>",
    );
    expect(text).toContain("## Head");
    expect(text).toContain("Copy & more → done");
    expect(text).toContain("- one");
    expect(text).toContain("- two");
    expect(text).not.toContain("evil");
    expect(text).not.toContain("color:red");
    expect(text).not.toContain("<");
  });

  it("decodes numeric entities", () => {
    expect(htmlToText("<body>&#65;&#x42;</body>")).toBe("AB");
  });

  it("covers every page file it claims to digest", async () => {
    for (const [, , file] of PAGES) {
      await expect(access(join(ROOT, file))).resolves.toBeUndefined();
    }
  });

  it("renders the full digest from the live pages", async () => {
    const digest = await buildDigest();
    expect(digest).toContain("e-sig — full site digest");
    for (const [, url] of PAGES) {
      expect(digest).toContain(url);
    }
    expect(digest).toContain("signDocument");
  });
});
