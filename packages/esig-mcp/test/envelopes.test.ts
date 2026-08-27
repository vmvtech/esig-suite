// envelopes.test.ts — I8 (token custody) + I4 (content pinning, creation half).

import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, it, expect } from "vitest";

import { EnvelopeService, buildStores, CapturingDelivery } from "../dist/index.js";
import { makeConfig } from "./helpers.js";

describe("EnvelopeService.create — token custody (I8) + content pinning (I4)", () => {
  it("never returns a raw token/link by default, and the audit row carries htmlSha256", async () => {
    const config = await makeConfig({ returnLinks: false });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const service = new EnvelopeService({ config, ...stores, delivery });

    const html = "<p>Please sign this consulting agreement.</p>";
    const expectedSha = crypto.createHash("sha256").update(html, "utf8").digest("hex");

    const result = await service.create({
      title: "NDA",
      html,
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });

    // I8: no raw token/link anywhere in the returned result.
    expect(result.links).toBeUndefined();
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/\/sign\//);

    expect(result.htmlSha256).toBe(expectedSha);
    expect(result.signers).toEqual([
      { signerId: result.signers[0].signerId, name: "Alice", email: "alice@example.com", status: "pending" },
    ]);

    // The delivery channel (operator-side custody, not the caller) DID get the real link.
    expect(delivery.calls).toHaveLength(1);
    expect(delivery.calls[0].links[0].url).toContain("/sign/");

    // I4: the value pinned at creation is recorded in the audit trail too.
    const auditFile = path.join(config.dataDir, "audit-log.ndjson");
    const rows = (await readFile(auditFile, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const createdRow = rows.find((r) => r.action === "envelope.created");
    expect(createdRow).toBeTruthy();
    expect(createdRow.metadata.htmlSha256).toBe(expectedSha);
    expect(createdRow.metadata.returnLinks).toBe(false);
    expect(createdRow.targetId).toBe(result.envelopeId);
  });

  it("returns links only when ESIG_MCP_RETURN_LINKS=1 (returnLinks:true in config)", async () => {
    const config = await makeConfig({ returnLinks: true });
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const service = new EnvelopeService({ config, ...stores, delivery });

    const result = await service.create({
      title: "Demo",
      html: "<p>hi</p>",
      signers: [{ name: "Bob", email: "bob@example.com" }],
    });
    expect(result.links).toBeDefined();
    expect(result.links?.[0].url).toContain("/sign/");
  });

  it("sanitizes html and reports removed tags", async () => {
    const config = await makeConfig();
    const stores = buildStores(config);
    const delivery = new CapturingDelivery();
    const service = new EnvelopeService({ config, ...stores, delivery });

    const result = await service.create({
      title: "With script",
      html: '<p>hi</p><script>alert(1)</script>',
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });
    expect(result.removedTags).toContain("script");
  });

  it("enforces the html size cap", async () => {
    const config = await makeConfig({ maxHtmlBytes: 10 });
    const stores = buildStores(config);
    const service = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    await expect(
      service.create({
        title: "Too big",
        html: "<p>this html body is definitely longer than ten bytes</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
      }),
    ).rejects.toThrow(/exceeds/);
  });

  it("enforces the hourly envelope cap", async () => {
    const config = await makeConfig({ envelopesPerHour: 1 });
    const stores = buildStores(config);
    const service = new EnvelopeService({ config, ...stores, delivery: new CapturingDelivery() });

    await service.create({ title: "One", html: "<p>1</p>", signers: [{ name: "A", email: "a@example.com" }] });
    await expect(
      service.create({ title: "Two", html: "<p>2</p>", signers: [{ name: "A", email: "a@example.com" }] }),
    ).rejects.toThrow(/hourly/);
  });
});
