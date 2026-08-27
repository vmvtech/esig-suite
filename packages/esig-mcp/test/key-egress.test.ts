// key-egress.test.ts — I1: no tool/service result ever contains private-key
// bytes, seeds, or PEM. Exercises the fullest reachable path (create, resolve,
// sign to completion/seal with PQ on, status, list, verify) and JSON-serializes
// every result produced along the way, then sweeps the combined text.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";

import { EnvelopeService, buildStores, CapturingDelivery, verifyDocumentBytes } from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

describe("I1 — no key egress", () => {
  it("no service result across create/resolve/sign/status/list/verify contains key material", async () => {
    const config = await makeConfig({ pq: true });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const service = new EnvelopeService({ config, ...stores, delivery, render: async () => SAMPLE_PDF });

    const results: unknown[] = [];

    const created = await service.create({
      title: "Key egress sweep",
      html: "<p>Body</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    results.push(created);

    const statusBefore = await service.status(created.envelopeId);
    results.push(statusBefore);

    const link = delivery.calls[0].links[0];
    const token = tokenFromLink(link.url);

    const resolved = await service.resolve(token);
    results.push(resolved);

    const signed = await service.sign(token, PNG_DATA_URL);
    results.push(signed);

    const list = await service.list();
    results.push(list);

    const sealedBytes = readFileSync(signed.sealedPdfUrl!);
    const verification = verifyDocumentBytes(sealedBytes, {});
    results.push(verification);

    // Also record the delivery receipts and captured links (the ONE place a
    // raw token is expected to appear — the delivery channel itself, not a
    // "service result" returned to an MCP caller) so the sweep below can
    // demonstrate it is actually looking at everything, not a vacuous check.
    const deliveryLog = delivery.calls;

    const serialized = JSON.stringify(results, (_key, value) => {
      if (value instanceof Uint8Array) return `<bytes:${value.length}>`;
      return value;
    });

    expect(serialized).not.toMatch(/PRIVATE KEY/);
    expect(serialized).not.toMatch(/BEGIN CERTIFICATE/); // no raw cert PEM body anywhere
    // PQ key-bundle field names — defense-in-depth: these should never appear
    // in a service result at all (only certFingerprint/keyId/mldsa65Fpr, all
    // public identifiers, are ever exposed).
    expect(serialized).not.toMatch(/mldsa65SecretKey|ed25519Pkcs8|mldsa65Seed|keyBundleEncrypted/);

    // Sanity check that the sweep corpus is non-trivial and that raw tokens
    // really do exist SOMEWHERE in this test run (in the delivery log) —
    // otherwise "no PRIVATE KEY found" could be trivially true of an empty
    // sweep. Confirms the test isn't vacuous.
    expect(serialized.length).toBeGreaterThan(100);
    expect(JSON.stringify(deliveryLog)).toContain("/sign/");
    // ...but the raw link is NOT present in the results actually returned by
    // the service to its caller.
    expect(serialized).not.toContain(token);
  });
});
