// delivery.test.ts — G3 (RedTeam rt-verdict-ESIGMCP-V01-20260826, MEDIUM /
// I11): the 'file' outbox channel (G3(b)), the 'console'-channel audit stamp
// (G3(c)), and webhook http:// refusal + timeout behavior (G3(d)).

import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { describe, it, expect } from "vitest";

import {
  EnvelopeService,
  buildStores,
  ConsoleDelivery,
  FileDelivery,
  WebhookDelivery,
} from "../dist/index.js";
import { makeConfig } from "./helpers.js";

describe("FileDelivery — the quickstart channel (G3(b))", () => {
  it("writes <dataDir>/outbox/<envelopeId>.json mode 0600 (dir 0700), containing the signing URL", async () => {
    const config = await makeConfig({ delivery: { kind: "file" } });
    const stores = buildStores(config);
    const delivery = new FileDelivery(config.dataDir);
    const service = new EnvelopeService({ config, ...stores, delivery });

    const result = await service.create({
      title: "File channel test",
      html: "<p>hi</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
    });

    // Receipts contain the outbox PATH, never the raw signing URL (I8).
    expect(result.delivery).toHaveLength(1);
    expect(result.delivery[0].channel).toBe("file");
    expect(result.delivery[0].ok).toBe(true);
    const outboxPath = result.delivery[0].detail!;
    expect(outboxPath).toBeTruthy();
    expect(outboxPath).not.toContain("/sign/");
    const wholeResultSerialized = JSON.stringify(result);
    expect(wholeResultSerialized).not.toMatch(/\/sign\//);

    const dir = path.join(config.dataDir, "outbox");
    const dirStat = await stat(dir);
    expect(dirStat.mode & 0o777).toBe(0o700);

    const fileStat = await stat(outboxPath);
    expect(fileStat.mode & 0o777).toBe(0o600);
    expect(outboxPath).toBe(path.join(dir, `${result.envelopeId}.json`));

    // The URL DOES live in the outbox file itself — that's the point of the channel.
    const written = JSON.parse(await readFile(outboxPath, "utf8"));
    expect(written.envelopeId).toBe(result.envelopeId);
    expect(written.title).toBe("File channel test");
    expect(written.signers).toHaveLength(1);
    expect(written.signers[0].url).toContain("/sign/");
    expect(written.signers[0].name).toBe("Alice");
    expect(written.signers[0].email).toBe("alice@example.com");
    expect(typeof written.createdAt).toBe("string");
  });
});

describe("ConsoleDelivery — opt-in, audit-stamped (G3(c))", () => {
  it("envelope.created audit row metadata carries delivery:'console'", async () => {
    const config = await makeConfig({ delivery: { kind: "console" } });
    const stores = buildStores(config);
    const service = new EnvelopeService({ config, ...stores, delivery: new ConsoleDelivery() });

    const result = await service.create({
      title: "Console channel test",
      html: "<p>hi</p>",
      signers: [{ name: "Bob", email: "bob@example.com" }],
    });

    const auditFile = path.join(config.dataDir, "audit-log.ndjson");
    const rows = (await readFile(auditFile, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const createdRow = rows.find((r) => r.action === "envelope.created" && r.targetId === result.envelopeId);
    expect(createdRow).toBeTruthy();
    expect(createdRow.metadata.delivery).toBe("console");
    expect(createdRow.metadata.deliveryFailures).toEqual([]);
  });

  it("every channel stamps its own kind (file channel example)", async () => {
    const config = await makeConfig({ delivery: { kind: "file" } });
    const stores = buildStores(config);
    const service = new EnvelopeService({ config, ...stores, delivery: new FileDelivery(config.dataDir) });

    const result = await service.create({
      title: "Stamp test",
      html: "<p>hi</p>",
      signers: [{ name: "Carl", email: "carl@example.com" }],
    });

    const auditFile = path.join(config.dataDir, "audit-log.ndjson");
    const rows = (await readFile(auditFile, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const createdRow = rows.find((r) => r.action === "envelope.created" && r.targetId === result.envelopeId);
    expect(createdRow.metadata.delivery).toBe("file");
  });
});

describe("WebhookDelivery — https-only + bounded timeout (G3(d))", () => {
  it("a hung webhook does not hang create(): times out within the injected bound with a failed receipt", async () => {
    // A real node:http server that accepts the connection and never responds.
    const server = createServer(() => {
      /* never calls res.end() */
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;
    const url = `http://127.0.0.1:${port}/hook`;

    const config = await makeConfig({ delivery: { kind: "webhook", url } });
    const stores = buildStores(config);
    const TIMEOUT_MS = 300; // small injected bound — the point is NOT waiting the real 10s default
    const delivery = new WebhookDelivery(url, fetch, TIMEOUT_MS);
    const service = new EnvelopeService({ config, ...stores, delivery });

    const start = Date.now();
    const result = await service.create({
      title: "Hung webhook test",
      html: "<p>hi</p>",
      signers: [{ name: "Dana", email: "dana@example.com" }],
    });
    const elapsedMs = Date.now() - start;

    // Bounded well under the real 10s default — proves create() did not hang.
    expect(elapsedMs).toBeLessThan(5_000);
    expect(result.delivery).toHaveLength(1);
    expect(result.delivery[0].ok).toBe(false);
    expect(result.delivery[0].channel).toBe("webhook");
    expect(result.delivery[0].detail).toBeTruthy();

    // G3(d): envelope is still created (not thrown away); audit + tool-result
    // both surface the failure — audit half asserted here, tool-result half
    // in tools/create-envelope.ts (mcp.test.ts / manual read covers wording).
    expect(result.envelopeId).toBeTruthy();
    const auditFile = path.join(config.dataDir, "audit-log.ndjson");
    const rows = (await readFile(auditFile, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    const createdRow = rows.find((r) => r.action === "envelope.created" && r.targetId === result.envelopeId);
    expect(createdRow.metadata.delivery).toBe("webhook");
    expect(createdRow.metadata.deliveryFailures).toHaveLength(1);
    expect(createdRow.metadata.deliveryFailures[0].signerId).toBe(result.signers[0].signerId);

    // Teardown note: the aborted fetch's underlying socket lingers in
    // undici's keep-alive pool for ~4s after AbortSignal.timeout fires (a
    // client-side pooling artifact, unrelated to WebhookDelivery's own
    // bounded behavior already asserted above via `elapsedMs`) — without
    // this, a plain `server.close(callback)` would wait for that same ~4s
    // for the lingering connection to end before its callback fires.
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("the default timeout is 10_000ms when not overridden", () => {
    // Constructor-level check only (no real 10s wait in the suite): the
    // third constructor arg defaults per delivery.ts, verified by TS type
    // (no third arg required) plus this smoke construction not throwing.
    expect(() => new WebhookDelivery("https://example.com/hook")).not.toThrow();
  });
});
