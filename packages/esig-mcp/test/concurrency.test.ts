// concurrency.test.ts — I3: two concurrent recordSignature calls on ONE token
// must yield exactly one success. Exercises core's createEnvelope/
// recordSignature directly against ConcurrencySafeEnvelopeStore (via
// buildStores) — this is the exact race the ticket's stores.ts FINDING
// documents (FsEnvelopeStore.update, fs-adapters.ts:247-254, has no
// version/precondition check).

import crypto from "node:crypto";

import { describe, it, expect } from "vitest";
import { createEnvelope, recordSignature } from "@e-sig/core";

import { buildStores, EnvelopeConflictError } from "../dist/index.js";
import { makeConfig, PNG_DATA_URL } from "./helpers.js";

describe("ConcurrencySafeEnvelopeStore (I3)", () => {
  it("two concurrent recordSignature calls on the same token yield exactly one success", async () => {
    const config = await makeConfig();
    const { envelopeStore } = buildStores(config);

    const { signingTokens } = await createEnvelope({
      store: envelopeStore,
      tenantId: config.tenant,
      title: "Race",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const token = signingTokens[0].token;

    const results = await Promise.allSettled([
      recordSignature({ store: envelopeStore, token, signatureImageDataUrl: PNG_DATA_URL }),
      recordSignature({ store: envelopeStore, token, signatureImageDataUrl: PNG_DATA_URL }),
    ]);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    if (rejected[0].status === "rejected") {
      expect(rejected[0].reason).toBeInstanceOf(EnvelopeConflictError);
    }

    // The envelope itself ends up correctly completed (exactly one write won),
    // not corrupted by the loser's blind overwrite.
    const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
    const final = await envelopeStore.findByTokenHash(tokenHash);
    expect(final?.status).toBe("completed");
    expect(final?.signers[0].status).toBe("signed");
  });
});

describe("ConcurrencySafeEnvelopeStore (D1)", () => {
  it("3 concurrent createEnvelope calls all persist and are status()-able", async () => {
    const config = await makeConfig();
    const { envelopeStore } = buildStores(config);

    const results = await Promise.all(
      [0, 1, 2].map((i) =>
        createEnvelope({
          store: envelopeStore,
          tenantId: config.tenant,
          title: `Race ${i}`,
          html: "<p>hi</p>",
          signers: [{ name: "Alice", email: "alice@example.com" }],
        }),
      ),
    );

    expect(new Set(results.map((r) => r.envelope.id)).size).toBe(3);
    for (const { envelope } of results) {
      const found = await envelopeStore.findById(config.tenant, envelope.id);
      expect(found).not.toBeNull();
      expect(found?.id).toBe(envelope.id);
    }
  });

  it("an insert racing an update (on a DIFFERENT envelope) — both land", async () => {
    const config = await makeConfig();
    const { envelopeStore } = buildStores(config);

    // Pre-existing envelope this test's update() call will mutate.
    const existing = await createEnvelope({
      store: envelopeStore,
      tenantId: config.tenant,
      title: "Existing",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    const existingToken = existing.signingTokens[0].token;

    const [inserted] = await Promise.all([
      createEnvelope({
        store: envelopeStore,
        tenantId: config.tenant,
        title: "New",
        html: "<p>hi</p>",
        signers: [{ name: "Bob", email: "bob@example.com" }],
      }),
      recordSignature({ store: envelopeStore, token: existingToken, signatureImageDataUrl: PNG_DATA_URL }),
    ]);

    const foundNew = await envelopeStore.findById(config.tenant, inserted.envelope.id);
    expect(foundNew).not.toBeNull();

    const foundExisting = await envelopeStore.findById(config.tenant, existing.envelope.id);
    expect(foundExisting?.status).toBe("completed");
    expect(foundExisting?.signers[0].status).toBe("signed");
  });
});
