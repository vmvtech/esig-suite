// http.test.ts — approval-page gate states served directly over HTTP,
// bypassing MCP entirely (design doc §7 e2e list: "human simulated via HTTP
// against the real approval endpoint").

import { describe, it, expect } from "vitest";
import type { Server } from "node:http";

import { buildStores, EnvelopeService, CapturingDelivery, createApprovalServer } from "../dist/index.js";
import { makeConfig, tokenFromLink } from "./helpers.js";

async function startServer(envelopes: EnvelopeService, config: Awaited<ReturnType<typeof makeConfig>>) {
  const server = createApprovalServer({ config, envelopes });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, base: `http://127.0.0.1:${port}` };
}

describe("GET /sign/<token> — gate states", () => {
  let server: Server;
  let base: string;
  let envelopes: EnvelopeService;

  it("invalid token -> 404-ish page, no envelope content", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
    ({ server, base } = await startServer(envelopes, config));

    const res = await fetch(`${base}/sign/not-a-real-token`);
    expect(res.status).toBe(404);
    expect(res.headers.get("content-security-policy")).toMatch(/default-src 'none'/);

    const html = await res.text();
    expect(html).not.toContain("<iframe");
    expect(html.toLowerCase()).toContain("invalid");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("wrong-order signer -> not_your_turn, no signature form, envelope still viewable", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    envelopes = new EnvelopeService({ config, ...stores, delivery });
    ({ server, base } = await startServer(envelopes, config));

    const created = await envelopes.create({
      title: "Two-signer order test",
      html: "<p>body</p>",
      signers: [
        { name: "Alice", email: "alice@example.com", order: 1 },
        { name: "Bob", email: "bob@example.com", order: 2 },
      ],
    });
    const bobToken = tokenFromLink(delivery.calls[0].links.find((l) => l.name === "Bob")!.url);

    const res = await fetch(`${base}/sign/${bobToken}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html.toLowerCase()).toContain("waiting");
    // Envelope is shown for context, but not the pad — it isn't Bob's turn.
    expect(html).toContain("<iframe");
    expect(html).not.toContain('id="submit"');
    expect(html).not.toContain('id="consent"');

    expect(created.envelopeId).toBeTruthy();

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("ok -> 200, shows the signature form", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    envelopes = new EnvelopeService({ config, ...stores, delivery });
    ({ server, base } = await startServer(envelopes, config));

    await envelopes.create({
      title: "Single signer",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const aliceToken = tokenFromLink(delivery.calls[0].links[0].url);

    const res = await fetch(`${base}/sign/${aliceToken}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('id="submit"');
    expect(html).toContain('id="consent"');
    expect(html).toContain('id="pad"');

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("POST /sign/<token> — validation", () => {
  it("rejects a missing consent flag and a non-JSON content-type", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    await envelopes.create({
      title: "Validation test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const noConsent = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signatureImageDataUrl: "data:image/png;base64,AAAA" }),
    });
    expect(noConsent.status).toBe(400);

    const badContentType = await fetch(`${base}/sign/${token}`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "not json",
    });
    expect(badContentType.status).toBe(415);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("CSP nonce (LOW-1)", () => {
  it("script-src uses a per-response nonce, not 'unsafe-inline'; nonce matches the inline <script>; two requests differ", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    await envelopes.create({
      title: "CSP nonce test",
      html: "<p>body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const res1 = await fetch(`${base}/sign/${token}`);
    const csp1 = res1.headers.get("content-security-policy") ?? "";
    expect(csp1).toContain("nonce-");
    expect(csp1).not.toContain("script-src 'unsafe-inline'");
    const nonceMatch1 = /script-src 'nonce-([^']+)'/.exec(csp1);
    expect(nonceMatch1).toBeTruthy();
    const headerNonce1 = nonceMatch1![1];

    const html1 = await res1.text();
    const attrMatch1 = /<script nonce="([^"]+)">/.exec(html1);
    expect(attrMatch1).toBeTruthy();
    expect(attrMatch1![1]).toBe(headerNonce1);

    // A second, independent request gets a DIFFERENT nonce.
    const res2 = await fetch(`${base}/sign/${token}`);
    const csp2 = res2.headers.get("content-security-policy") ?? "";
    const nonceMatch2 = /script-src 'nonce-([^']+)'/.exec(csp2);
    expect(nonceMatch2).toBeTruthy();
    expect(nonceMatch2![1]).not.toBe(headerNonce1);

    // Every other CSP directive is unchanged.
    expect(csp1).toMatch(/default-src 'none'/);
    expect(csp1).toMatch(/img-src data:/);
    expect(csp1).toMatch(/style-src 'unsafe-inline'/);
    expect(csp1).toMatch(/connect-src 'self'/);
    expect(csp1).toMatch(/frame-src data: blob: 'self'/);
    expect(csp1).toMatch(/form-action 'self'/);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("a non-'ok' gate state (no signature form) still carries a nonce-based CSP with no inline script", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
    const { server, base } = await startServer(envelopes, config);

    const res = await fetch(`${base}/sign/not-a-real-token`);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("nonce-");
    // style-src is untouched by LOW-1 (this page's own <style>, no agent
    // content); only script-src moved off 'unsafe-inline'.
    expect(csp).not.toContain("script-src 'unsafe-inline'");
    expect(csp).toMatch(/script-src 'nonce-[^']+'/);
    const html = await res.text();
    expect(html).not.toContain("<script");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

describe("GET /healthz", () => {
  it("returns 200 ok with security headers", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const envelopes = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });
    const { server, base } = await startServer(envelopes, config);

    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect((await res.json()).status).toBe("ok");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
