// e2e.test.ts — full library end-to-end with an injected fixture renderer
// (no Chrome): create -> capture links -> resolve -> sign all signers ->
// completed -> sealed PDF -> verifyDocumentBytes ok:true -> flip one byte ->
// ok:false.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";

import { EnvelopeService, buildStores, CapturingDelivery, verifyDocumentBytes } from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
// Same Chrome-free fixture core's own tests and the gateway's own tests use —
// packages/esig-core/test/pq-pdf.test.ts:27, packages/esig-gateway/test/harness.ts:14.
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

describe("EnvelopeService — full library e2e (fixture renderer, no Chrome)", () => {
  it("create -> resolve -> sign (order-gated) -> completed -> sealed -> verify ok, then tamper breaks it", async () => {
    const config = await makeConfig({ pq: true });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const service = new EnvelopeService({
      config,
      ...stores,
      delivery,
      render: async () => SAMPLE_PDF,
    });

    const created = await service.create({
      title: "Consulting Agreement",
      html: "<p>Terms of the consulting agreement...</p>",
      signers: [
        { name: "Alice", email: "alice@example.com", order: 1 },
        { name: "Bob", email: "bob@example.com", order: 2 },
      ],
    });
    expect(created.links).toBeUndefined(); // returnLinks defaults to false

    expect(delivery.calls).toHaveLength(1);
    const links = delivery.calls[0].links;
    expect(links).toHaveLength(2);

    const aliceToken = tokenFromLink(links.find((l) => l.name === "Alice")!.url);
    const bobToken = tokenFromLink(links.find((l) => l.name === "Bob")!.url);

    // Bob is order 2 — cannot go first.
    const bobEarly = await service.resolve(bobToken);
    expect(bobEarly.status).toBe("not_your_turn");

    const afterAlice = await service.sign(aliceToken, PNG_DATA_URL);
    expect(afterAlice.status).toBe("partially_signed");
    expect(afterAlice.sealedPdfUrl).toBeUndefined();

    const afterBob = await service.sign(bobToken, PNG_DATA_URL);
    expect(afterBob.status).toBe("completed");
    expect(afterBob.sealedPdfUrl).toBeTruthy();

    const sealedBytes = readFileSync(afterBob.sealedPdfUrl!);
    const verification = verifyDocumentBytes(sealedBytes, { requirePq: true });
    expect(verification.ok).toBe(true);
    expect(verification.classical.ok).toBe(true);
    expect(verification.postQuantum.present).toBe(true);
    expect(verification.postQuantum.ok).toBe(true);
    expect(verification.summary).toMatch(/^OK/);

    // Tamper: flip a byte in the middle of the document (safely inside the
    // classically-signed region — same pattern core's own tamper tests use,
    // packages/esig-core/test/pq-pdf.test.ts:162-169).
    const tampered = Buffer.from(sealedBytes);
    const at = Math.floor(tampered.length / 2);
    tampered[at] ^= 0xff;
    const tamperedVerification = verifyDocumentBytes(tampered, { requirePq: true });
    expect(tamperedVerification.ok).toBe(false);
    expect(tamperedVerification.summary).toMatch(/^FAILED/);

    // status()/list() reflect the same completed, sealed envelope.
    const status = await service.status(created.envelopeId);
    expect(status.status).toBe("completed");
    expect(status.sealedPdfUrl).toBe(afterBob.sealedPdfUrl);

    const list = await service.list();
    expect(list.find((e) => e.envelopeId === created.envelopeId)?.status).toBe("completed");

    // A completed envelope can no longer be voided (core enforces this; void() just surfaces it).
    await expect(service.void(created.envelopeId)).rejects.toThrow();
  });

  it("void() cancels a pending envelope and is reflected in status()", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const service = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    const created = await service.create({
      title: "To cancel",
      html: "<p>draft</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const voided = await service.void(created.envelopeId);
    expect(voided.status).toBe("voided");
    expect(voided.voidedAt).toBeTruthy();

    const status = await service.status(created.envelopeId);
    expect(status.status).toBe("voided");
  });
});
