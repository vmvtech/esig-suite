// g1-launch-args.test.ts — G1 regression (RedTeam rt-verdict-ESIGMCP-V01-20260826,
// MEDIUM): the seal-time Chrome launch must ALWAYS carry the host-resolver
// deny rule + both sandbox flags (docs/architecture/esig-mcp.md §6 I10), on
// the DEFAULT render path, not merely as an unused exported constant.
//
// OBSERVABILITY NOTE: `EnvelopeService`'s default renderer (envelopes.ts,
// unmodified by this ticket — see the file's own header comment on why it is
// not touched) closes over core's `renderHtmlToPdf`, imported directly from
// "@e-sig/core", with NO constructor-level seam for the no-`render`-override
// path. Rather than adding an injectable seam to envelopes.ts (out of this
// ticket's write set except for a G1 seam, and unnecessary here), this test
// partially mocks the "@e-sig/core" module — replacing ONLY
// `renderHtmlToPdf` with a spy while keeping every other export (including
// `signPdf`/`ensureActiveCert`/`composeEnvelopeHtml`/`verifyPdfSignature`,
// all of which the real seal() path still needs) real. `vi.mock` intercepts
// by module specifier across this file's whole module graph, including the
// transitively-imported `dist/envelopes.js` — so the DEFAULT render path
// (no `render` passed into `EnvelopeServiceDeps`) is genuinely exercised and
// observed, with zero production-code seam added. Confirmed empirically:
// this test fails (`renderSpy` never called) if `EnvelopeService` is
// constructed WITH a `render` override, and passes only when the default
// path itself calls the mocked `renderHtmlToPdf`.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { vi, describe, it, expect } from "vitest";

const { renderSpy } = vi.hoisted(() => ({ renderSpy: vi.fn() }));

vi.mock("@e-sig/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@e-sig/core")>();
  return { ...actual, renderHtmlToPdf: renderSpy };
});

import { EnvelopeService, buildStores, CapturingDelivery, SEAL_RENDER_LAUNCH_ARGS } from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
// Real, Chrome-free fixture PDF the mocked renderer returns, so the REST of
// seal() (signPdf, verifyPdfSignature, pdfStorage.upload — all real) still
// succeeds on realistic bytes, same fixture e2e.test.ts/mcp.test.ts use.
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

describe("SEAL_RENDER_LAUNCH_ARGS (G1 regression, I10)", () => {
  it("contains the host-resolver deny rule and both sandbox flags", () => {
    expect(SEAL_RENDER_LAUNCH_ARGS).toContain("--host-resolver-rules=MAP * ~NOTFOUND");
    expect(SEAL_RENDER_LAUNCH_ARGS).toContain("--no-sandbox");
    expect(SEAL_RENDER_LAUNCH_ARGS).toContain("--disable-setuid-sandbox");
  });

  it("the DEFAULT render path (no `render` override injected) calls core's renderHtmlToPdf with exactly these launchArgs", async () => {
    renderSpy.mockReset();
    renderSpy.mockImplementation(async () => SAMPLE_PDF);

    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    // Deliberately NO `render:` key — exercises `this.render = deps.render ??
    // (...)` default branch (envelopes.ts) which is what production (bin.ts)
    // actually runs.
    const service = new EnvelopeService({ config, ...stores, delivery });

    const created = await service.create({
      title: "G1 regression",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    expect(renderSpy).not.toHaveBeenCalled(); // render only happens at seal time, on last signature

    const signed = await service.sign(token, PNG_DATA_URL);
    expect(signed.status).toBe("completed");

    expect(renderSpy).toHaveBeenCalledTimes(1);
    const callArgs = renderSpy.mock.calls[0][0] as { html: string; launchArgs?: string[] };
    expect(callArgs.launchArgs).toEqual([...SEAL_RENDER_LAUNCH_ARGS]);
    expect(callArgs.launchArgs).toContain("--host-resolver-rules=MAP * ~NOTFOUND");
    expect(callArgs.launchArgs).toContain("--no-sandbox");
    expect(callArgs.launchArgs).toContain("--disable-setuid-sandbox");

    expect(created.envelopeId).toBe(signed.envelopeId);
  });
});
