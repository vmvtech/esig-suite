// config.test.ts — I2 (fail closed).

import path from "node:path";

import { describe, it, expect } from "vitest";
import { loadConfig, ConfigError } from "../dist/index.js";

// G3(a): ESIG_MCP_DELIVERY has no default any more, so every test below that
// expects `loadConfig` to SUCCEED needs an explicit channel. "file" is the
// quickstart channel (README) and does no I/O at loadConfig time, so it's
// the natural minimal-valid-env choice here — mirroring how BASE already
// carries the minimum valid ESIG_MCP_PASSPHRASE.
const BASE = { ESIG_MCP_PASSPHRASE: "a".repeat(24), ESIG_MCP_DELIVERY: "file" };

describe("loadConfig — fail-closed (I2)", () => {
  it("refuses to start when ESIG_MCP_MODES includes A", () => {
    expect(() => loadConfig({ ...BASE, ESIG_MCP_MODES: "H,A" })).toThrow(ConfigError);
    expect(() => loadConfig({ ...BASE, ESIG_MCP_MODES: "H,A" })).toThrow(/not implemented/i);
  });

  it("refuses to start when ESIG_MCP_MODES includes C", () => {
    expect(() => loadConfig({ ...BASE, ESIG_MCP_MODES: "C" })).toThrow(ConfigError);
  });

  it("refuses on an unknown mode letter", () => {
    expect(() => loadConfig({ ...BASE, ESIG_MCP_MODES: "Z" })).toThrow(ConfigError);
  });

  it("defaults to mode H only, and that succeeds", () => {
    const cfg = loadConfig(BASE);
    expect(cfg.modes).toEqual(["H"]);
  });

  it("accepts an explicit ESIG_MCP_MODES=H", () => {
    const cfg = loadConfig({ ...BASE, ESIG_MCP_MODES: "H" });
    expect(cfg.modes).toEqual(["H"]);
  });

  it("refuses to start without a passphrase", () => {
    expect(() => loadConfig({})).toThrow(ConfigError);
    expect(() => loadConfig({})).toThrow(/PASSPHRASE/);
  });

  it("refuses a too-short passphrase", () => {
    expect(() => loadConfig({ ESIG_MCP_PASSPHRASE: "short" })).toThrow(ConfigError);
  });

  // D3: this package's floor must match core's (cert-issuer.ts:24,
  // MIN_PASSPHRASE_LEN = 24) — a passphrase between the old 16-char floor and
  // the real 24-char one used to pass loadConfig here and then throw later,
  // at first seal, from inside ensureActiveCert/ensureActivePqKeys.
  it("refuses a 20-char passphrase (below core's 24-char floor)", () => {
    expect(() => loadConfig({ ESIG_MCP_PASSPHRASE: "a".repeat(20) })).toThrow(ConfigError);
  });

  it("accepts exactly the 24-char floor", () => {
    const cfg = loadConfig({ ESIG_MCP_PASSPHRASE: "a".repeat(24), ESIG_MCP_DELIVERY: "file" });
    expect(cfg.passphrase.length).toBeGreaterThanOrEqual(24);
  });

  it("applies defaults for everything else", () => {
    const cfg = loadConfig(BASE);
    expect(cfg.dataDir).toBe("./.esig-mcp");
    expect(cfg.tenant).toBe("default");
    expect(cfg.subjectName).toBe("e-sig MCP");
    expect(cfg.httpHost).toBe("127.0.0.1");
    expect(cfg.httpPort).toBe(7433);
    expect(cfg.baseUrl).toBe("http://127.0.0.1:7433");
    expect(cfg.returnLinks).toBe(false);
    expect(cfg.delivery).toEqual({ kind: "file" }); // BASE sets ESIG_MCP_DELIVERY=file explicitly (G3(a): no real default)
    expect(cfg.pq).toBe(true);
    expect(cfg.maxHtmlBytes).toBe(512 * 1024);
    expect(cfg.maxPdfBytes).toBe(25 * 1024 * 1024);
    expect(cfg.envelopesPerHour).toBe(60);
  });

  it("derives baseUrl from host/port when ESIG_MCP_BASE_URL is unset", () => {
    const cfg = loadConfig({ ...BASE, ESIG_MCP_HTTP_HOST: "0.0.0.0", ESIG_MCP_HTTP_PORT: "9999" });
    expect(cfg.baseUrl).toBe("http://0.0.0.0:9999");
  });

  it("ESIG_MCP_RETURN_LINKS is on only for the exact string '1'", () => {
    expect(loadConfig({ ...BASE, ESIG_MCP_RETURN_LINKS: "1" }).returnLinks).toBe(true);
    expect(loadConfig({ ...BASE, ESIG_MCP_RETURN_LINKS: "true" }).returnLinks).toBe(false);
    expect(loadConfig(BASE).returnLinks).toBe(false);
  });

  it("ESIG_MCP_PQ='0' disables PQ; default is enabled", () => {
    expect(loadConfig(BASE).pq).toBe(true);
    expect(loadConfig({ ...BASE, ESIG_MCP_PQ: "0" }).pq).toBe(false);
  });

  it("requires ESIG_MCP_DELIVERY_WEBHOOK_URL when delivery=webhook", () => {
    expect(() => loadConfig({ ...BASE, ESIG_MCP_DELIVERY: "webhook" })).toThrow(ConfigError);
    const cfg = loadConfig({
      ...BASE,
      ESIG_MCP_DELIVERY: "webhook",
      ESIG_MCP_DELIVERY_WEBHOOK_URL: "https://example.com/hook",
    });
    expect(cfg.delivery).toEqual({ kind: "webhook", url: "https://example.com/hook" });
  });

  it("rejects an unparseable webhook URL", () => {
    expect(() =>
      loadConfig({ ...BASE, ESIG_MCP_DELIVERY: "webhook", ESIG_MCP_DELIVERY_WEBHOOK_URL: "not a url" }),
    ).toThrow(ConfigError);
  });

  // G3(a) — I11: ESIG_MCP_DELIVERY has NO default any more. The old default
  // ("console") prints the signing link — the signing capability itself — to
  // stderr, which in the canonical stdio MCP deployment is the agent
  // harness's own captured log.
  describe("ESIG_MCP_DELIVERY is required (G3(a), no default)", () => {
    it("refuses to start when ESIG_MCP_DELIVERY is unset", () => {
      expect(() => loadConfig({ ESIG_MCP_PASSPHRASE: "a".repeat(24) })).toThrow(ConfigError);
    });

    it("refuses to start when ESIG_MCP_DELIVERY is an empty string", () => {
      expect(() => loadConfig({ ESIG_MCP_PASSPHRASE: "a".repeat(24), ESIG_MCP_DELIVERY: "  " })).toThrow(
        ConfigError,
      );
    });

    it("the error message lists all three channels", () => {
      try {
        loadConfig({ ESIG_MCP_PASSPHRASE: "a".repeat(24) });
        throw new Error("loadConfig should have thrown");
      } catch (e) {
        expect(e).toBeInstanceOf(ConfigError);
        const message = (e as ConfigError).message;
        expect(message).toMatch(/"file"/);
        expect(message).toMatch(/"console"/);
        expect(message).toMatch(/"webhook"/);
      }
    });

    it("rejects an unknown delivery kind", () => {
      expect(() => loadConfig({ ...BASE, ESIG_MCP_DELIVERY: "carrier-pigeon" })).toThrow(ConfigError);
    });
  });

  it('accepts ESIG_MCP_DELIVERY="file" (the quickstart channel)', () => {
    const cfg = loadConfig({ ...BASE, ESIG_MCP_DELIVERY: "file" });
    expect(cfg.delivery).toEqual({ kind: "file" });
  });

  // G3(d): a plaintext webhook leaks the signing link on the wire; require
  // https:// unless the operator explicitly opts out.
  describe("webhook delivery requires https:// (G3(d))", () => {
    it("refuses an http:// webhook URL by default", () => {
      expect(() =>
        loadConfig({
          ...BASE,
          ESIG_MCP_DELIVERY: "webhook",
          ESIG_MCP_DELIVERY_WEBHOOK_URL: "http://example.com/hook",
        }),
      ).toThrow(ConfigError);
    });

    it("allows http:// only with ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1", () => {
      const cfg = loadConfig({
        ...BASE,
        ESIG_MCP_DELIVERY: "webhook",
        ESIG_MCP_DELIVERY_WEBHOOK_URL: "http://example.com/hook",
        ESIG_MCP_ALLOW_INSECURE_WEBHOOK: "1",
      });
      expect(cfg.delivery).toEqual({ kind: "webhook", url: "http://example.com/hook" });
    });

    it("https:// always works without the escape hatch", () => {
      const cfg = loadConfig({
        ...BASE,
        ESIG_MCP_DELIVERY: "webhook",
        ESIG_MCP_DELIVERY_WEBHOOK_URL: "https://example.com/hook",
      });
      expect(cfg.delivery).toEqual({ kind: "webhook", url: "https://example.com/hook" });
    });
  });

  // D6: ESIG_MCP_DOCS_ROOT defaults to "<dataDir>/inbox" and is resolved to
  // an absolute path either way.
  it("defaults docsRoot to <dataDir>/inbox, resolved absolute", () => {
    const cfg = loadConfig({ ...BASE, ESIG_MCP_DATA_DIR: "./some-data" });
    expect(cfg.docsRoot.endsWith(path.join("some-data", "inbox"))).toBe(true);
    expect(path.isAbsolute(cfg.docsRoot)).toBe(true);
  });

  it("honors an explicit ESIG_MCP_DOCS_ROOT override", () => {
    const cfg = loadConfig({ ...BASE, ESIG_MCP_DOCS_ROOT: "./my-inbox" });
    expect(cfg.docsRoot.endsWith("my-inbox")).toBe(true);
    expect(path.isAbsolute(cfg.docsRoot)).toBe(true);
  });

  it("rejects a non-integer cap", () => {
    expect(() => loadConfig({ ...BASE, ESIG_MCP_MAX_HTML_BYTES: "not-a-number" })).toThrow(ConfigError);
    expect(() => loadConfig({ ...BASE, ESIG_MCP_ENVELOPES_PER_HOUR: "0" })).toThrow(ConfigError);
  });
});
