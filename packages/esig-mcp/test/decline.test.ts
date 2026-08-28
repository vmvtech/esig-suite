// decline.test.ts — §16 "Decline": POST /sign/<token>/decline {reason?} ->
// core declineEnvelope -> audit 'envelope.declined' + event; approval page
// gets a Decline button + optional reason; after decline the page shows the
// declined state.

import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, it, expect } from "vitest";

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

describe("POST /sign/<token>/decline", () => {
  it("declines with a reason: envelope voided, signer declined, audit row + event, page shows declined state", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    const created = await envelopes.create({
      title: "Decline test",
      html: "<p>please sign</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    // The approval page shows a Decline control while it's this signer's turn.
    const page = await fetch(`${base}/sign/${token}`);
    const html = await page.text();
    expect(html).toContain('id="decline"');
    expect(html).toContain('id="declineReason"');

    const decline = await fetch(`${base}/sign/${token}/decline`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "Not the right document" }),
    });
    expect(decline.status).toBe(200);
    const declineBody = (await decline.json()) as { status: string; declined: boolean };
    expect(declineBody.status).toBe("voided");
    expect(declineBody.declined).toBe(true);

    const status = await envelopes.status(created.envelopeId);
    expect(status.status).toBe("voided");
    expect(status.signers[0].status).toBe("declined");

    // The audit row.
    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const declinedRow = auditRows.find((r) => r.action === "envelope.declined");
    expect(declinedRow).toBeTruthy();
    expect(declinedRow.metadata.signerId).toBe(status.signers[0].signerId);
    expect(declinedRow.metadata.hasReason).toBe(true);
    // The audit metadata never stores the raw reason text (PII minimization,
    // same pattern as `hasMessage` on envelope.created).
    expect(JSON.stringify(declinedRow)).not.toContain("Not the right document");

    // The event.
    const events = await envelopes.listEvents(created.envelopeId);
    const declinedEvent = events.find((e) => e.type === "envelope.declined");
    expect(declinedEvent).toBeTruthy();
    expect(declinedEvent!.signer?.signerId).toBe(status.signers[0].signerId);
    expect(declinedEvent!.data.hasReason).toBe(true);
    expect(JSON.stringify(declinedEvent)).not.toContain("Not the right document");

    // The approval page now shows the declined state, not the generic
    // "voided by the sender" sentence.
    const pageAfter = await fetch(`${base}/sign/${token}`);
    const htmlAfter = await pageAfter.text();
    expect(htmlAfter.toLowerCase()).toContain("declined");
    expect(htmlAfter).not.toContain('id="decline"');
    expect(htmlAfter).not.toContain('id="submit"');

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("declines with no reason (empty body {})", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    await envelopes.create({
      title: "No reason",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const decline = await fetch(`${base}/sign/${token}/decline`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(decline.status).toBe(200);

    const auditRows = (await readFile(path.join(config.dataDir, "audit-log.ndjson"), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const declinedRow = auditRows.find((r) => r.action === "envelope.declined");
    expect(declinedRow.metadata.hasReason).toBe(false);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("strips control characters from the reason and caps it at 500 characters", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    await envelopes.create({ title: "Cap test", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const tooLong = await fetch(`${base}/sign/${token}/decline`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "x".repeat(501) }),
    });
    expect(tooLong.status).toBe(400);

    const withControlChars = await fetch(`${base}/sign/${token}/decline`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "line one\r\nline two\x00\x01" }),
    });
    expect(withControlChars.status).toBe(200);

    // The stored (core) signer.declineReason has the control characters
    // stripped — http.ts's own stripControlChars, applied before the reason
    // ever reaches EnvelopeService.decline().
    const envelopeId = (await envelopes.list())[0].envelopeId;
    const envelope = await stores.envelopeStore.findById(config.tenant, envelopeId);
    const declinedSigner = envelope!.signers.find((s) => s.status === "declined")!;
    expect(declinedSigner.declineReason).toBe("line oneline two");
    expect(declinedSigner.declineReason).not.toMatch(/[\r\n\x00\x01]/);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("rejects a non-JSON content-type and a wrong-typed reason", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    await envelopes.create({ title: "Validation", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const badType = await fetch(`${base}/sign/${token}/decline`, { method: "POST", headers: { "content-type": "text/plain" }, body: "nope" });
    expect(badType.status).toBe(415);

    const badReason = await fetch(`${base}/sign/${token}/decline`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: 123 }),
    });
    expect(badReason.status).toBe(400);

    const wrongMethod = await fetch(`${base}/sign/${token}/decline`, { method: "GET" });
    expect(wrongMethod.status).toBe(405);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("refuses to decline an already-signed or already-declined envelope", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    await envelopes.create({ title: "Double decline", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] });
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const first = await fetch(`${base}/sign/${token}/decline`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(first.status).toBe(200);

    const second = await fetch(`${base}/sign/${token}/decline`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(second.status).toBeGreaterThanOrEqual(400);

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("esig_void_envelope's own audit/event path is unaffected — a sender-voided (not declined) envelope shows the generic voided sentence", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const envelopes = new EnvelopeService({ config, ...stores, delivery });
    const { server, base } = await startServer(envelopes, config);

    const created = await envelopes.create({ title: "Sender voided", html: "<p>hi</p>", signers: [{ name: "Alice", email: "alice@example.com" }] });
    await envelopes.void(created.envelopeId);
    const token = tokenFromLink(delivery.calls[0].links[0].url);

    const page = await fetch(`${base}/sign/${token}`);
    const html = await page.text();
    expect(html.toLowerCase()).toContain("voided by the sender");
    expect(html.toLowerCase()).not.toContain("declined");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
