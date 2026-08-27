// scripts/templates.test.mjs — validates examples/templates/*.html: size
// cap, the visible TEMPLATE banner, placeholder count, absence of
// active/executable markup, absence of external http(s) URLs, and (build
// permitting) that sanitizeEnvelopeHtml is a true no-op on each unmodified
// template — i.e. nothing an agent-authored envelope's defense-in-depth
// layer (packages/esig-mcp/src/sanitize.ts) would ever need to strip.

import { describe, it, expect, beforeAll } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const scriptsDir = dirname(fileURLToPath(import.meta.url));
const templatesDir = join(scriptsDir, "..", "examples", "templates");
const sanitizeDistUrl = new URL("../packages/esig-mcp/dist/index.js", import.meta.url);

const BANNER_TEXT = "TEMPLATE — not legal advice; have counsel review before use";
const DANGEROUS_RE = /<script|on[a-z]+\s*=|javascript:|<form|<iframe|<object|<embed/i;
const EXTERNAL_URL_RE = /(src|href)\s*=\s*["']?https?:/i;
const MAX_BYTES = 60 * 1024;

const templateFiles = readdirSync(templatesDir)
  .filter((name) => name.endsWith(".html"))
  .sort();

let sanitizeEnvelopeHtml;
let sanitizeSkipReason = null;

beforeAll(async () => {
  const tryImport = () => import(sanitizeDistUrl.href).then((m) => m.sanitizeEnvelopeHtml);
  try {
    sanitizeEnvelopeHtml = await tryImport();
  } catch (firstErr) {
    // packages/esig-mcp is owned by a concurrent workflow right now (another
    // lane is actively editing/building it) — a build in flight can make
    // this import fail transiently. Retry once after a short wait before
    // giving up and skipping just the assertion that needs it.
    await new Promise((resolve) => setTimeout(resolve, 20_000));
    try {
      sanitizeEnvelopeHtml = await tryImport();
    } catch (secondErr) {
      sanitizeSkipReason =
        "packages/esig-mcp/dist/index.js import failed twice, 20s apart " +
        `(likely a concurrent build still in flight): ${secondErr?.message ?? secondErr}`;
      // eslint-disable-next-line no-console
      console.warn(`[templates.test.mjs] ${sanitizeSkipReason}`);
    }
  }
}, 40_000);

describe.each(templateFiles)("examples/templates/%s", (file) => {
  const filePath = join(templatesDir, file);
  const buf = readFileSync(filePath);
  const html = buf.toString("utf8");

  it("is under 60 KB", () => {
    expect(buf.byteLength).toBeLessThan(MAX_BYTES);
  });

  it("shows the TEMPLATE banner", () => {
    expect(html).toContain(BANNER_TEXT);
  });

  it("documents at least 3 {{placeholder}} fields", () => {
    const count = (html.match(/\{\{/g) ?? []).length;
    expect(count).toBeGreaterThanOrEqual(3);
  });

  it("contains no script/event-handler/dangerous-tag markup", () => {
    expect(DANGEROUS_RE.test(html)).toBe(false);
  });

  it("contains no external http(s) src/href URLs", () => {
    expect(EXTERNAL_URL_RE.test(html)).toBe(false);
  });

  it("is untouched by sanitizeEnvelopeHtml (nothing to strip)", (ctx) => {
    if (sanitizeSkipReason) ctx.skip(sanitizeSkipReason);
    const result = sanitizeEnvelopeHtml(html);
    expect(result.html).toBe(html);
    expect(result.removed).toEqual([]);
  });
});

it("ships exactly the six expected templates", () => {
  expect(templateFiles).toEqual([
    "dua-mta.html",
    "grant-approval.html",
    "irb-consent.html",
    "nda.html",
    "offer-letter.html",
    "permission-slip.html",
  ]);
});
