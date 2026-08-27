// reseal.test.ts — D1: sealing as an explicit, retryable, tracked step. A
// seal failure (e.g. no Chrome) must never strand a validly-recorded
// signature: `sign()` must not throw, phase must read `seal_failed`, the
// audit trail must show `envelope.seal_failed` (never `envelope.completed`),
// POST /sign must respond 202 (not 500), and `esig_reseal` must retry and
// reach `sealed` — writing `envelope.completed` exactly once — through a
// real MCP client session (design doc §7: "the consumer path, not internal
// calls").

import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import {
  createMcpServer,
  createApprovalServer,
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

async function connectedClient(mcpServer: McpServer): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

describe("D1 — sealing as an explicit, retryable, tracked step", () => {
  it(
    "a seal failure does not strand the signature (POST /sign -> 202, phase seal_failed, audit " +
      "seal_failed row); esig_reseal retries to sealed with exactly one envelope.completed audit " +
      "row; esig_reseal on a sealed envelope is refused",
    async () => {
      const config = await makeConfig({ pq: false });
      const stores = buildStores(config);
      const delivery = new CapturingDelivery();

      // Injectable renderer that fails first (simulating "no Chrome") and
      // can be flipped to succeed later, WITHOUT rebuilding the service —
      // `seal()` reads `this.render` fresh on every call.
      let renderShouldFail = true;
      const render = async (): Promise<Buffer> => {
        if (renderShouldFail) throw new Error("no Chrome/Chromium found (injected test failure)");
        return SAMPLE_PDF;
      };
      const envelopes = new EnvelopeService({ config, ...stores, delivery, render });
      const deps: McpServerDeps = {
        config,
        envelopes,
        documents: new FsDocumentStore(config.dataDir, config.maxPdfBytes),
        certStore: stores.certStore,
        pqKeyStore: stores.pqKeyStore,
        auditStore: stores.auditStore,
      };
      const mcpServer = createMcpServer(deps);
      const client = await connectedClient(mcpServer);

      const httpServer = createApprovalServer({ config, envelopes });
      await new Promise<void>((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(0, "127.0.0.1", () => resolve());
      });
      const address = httpServer.address();
      const port = typeof address === "object" && address ? address.port : 0;
      const base = `http://127.0.0.1:${port}`;

      const created = await client.callTool({
        name: "esig_create_envelope",
        arguments: {
          title: "D1 seal failure",
          html: "<p>terms</p>",
          signers: [{ name: "Alice", email: "alice@example.com" }],
        },
      });
      expect(created.isError).not.toBe(true);
      const envelopeId = (created.structuredContent as Record<string, any>).envelopeId as string;
      const token = tokenFromLink(delivery.calls[0].links[0].url);

      // The only signer signs -> core marks the envelope completed -> the
      // automatic seal attempt (inside sign()) fails on the injected
      // renderer. sign() must NOT throw / POST /sign must NOT 500.
      const signRes = await fetch(`${base}/sign/${token}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ signatureImageDataUrl: PNG_DATA_URL, consent: true }),
      });
      expect(signRes.status).toBe(202);
      const signBody = (await signRes.json()) as { status: string; sealed: boolean; message: string };
      expect(signBody.status).toBe("signed");
      expect(signBody.sealed).toBe(false);
      expect(signBody.message).toMatch(/operator will produce the sealed PDF/i);

      // The signature IS validly recorded on the core envelope even though
      // sealing failed.
      const afterFail = await client.callTool({ name: "esig_envelope_status", arguments: { envelopeId } });
      const infoAfterFail = afterFail.structuredContent as Record<string, any>;
      expect(infoAfterFail.status).toBe("completed");
      expect(infoAfterFail.phase).toBe("seal_failed");
      expect(infoAfterFail.seal.status).toBe("failed");
      expect(infoAfterFail.seal.attempts).toBe(1);
      expect(infoAfterFail.seal.error).toMatch(/no Chrome/);
      expect(infoAfterFail.sealedPdfUrl).toBeUndefined();

      // GET /sign for a signed-but-unsealed envelope shows the same sentence.
      const getPage = await fetch(`${base}/sign/${token}`);
      expect(getPage.status).toBe(200);
      const html = await getPage.text();
      expect(html).toMatch(/operator will produce the sealed PDF/i);
      expect(html).not.toMatch(/every signer has signed/i);

      const auditFile = join(config.dataDir, "audit-log.ndjson");
      const readAudit = async () =>
        (await readFile(auditFile, "utf8"))
          .trim()
          .split("\n")
          .map((l) => JSON.parse(l));

      const rowsAfterFail = await readAudit();
      expect(rowsAfterFail.filter((r: any) => r.action === "envelope.seal_failed")).toHaveLength(1);
      expect(rowsAfterFail.filter((r: any) => r.action === "envelope.completed")).toHaveLength(0);

      // Fix "Chrome" and retry via esig_reseal, through the real MCP client.
      renderShouldFail = false;
      const resealed = await client.callTool({ name: "esig_reseal", arguments: { envelopeId } });
      expect(resealed.isError).not.toBe(true);
      const infoResealed = resealed.structuredContent as Record<string, any>;
      expect(infoResealed.phase).toBe("sealed");
      expect(infoResealed.seal.status).toBe("sealed");
      expect(infoResealed.seal.attempts).toBe(2);
      expect(infoResealed.sealedPdfUrl).toBeTruthy();

      const rowsAfterReseal = await readAudit();
      expect(rowsAfterReseal.filter((r: any) => r.action === "envelope.reseal_requested")).toHaveLength(1);
      expect(rowsAfterReseal.filter((r: any) => r.action === "envelope.completed")).toHaveLength(1);
      expect(rowsAfterReseal.filter((r: any) => r.action === "envelope.seal_failed")).toHaveLength(1);

      // esig_reseal on an already-sealed envelope is refused with a clear message.
      const resealAgain = await client.callTool({ name: "esig_reseal", arguments: { envelopeId } });
      expect(resealAgain.isError).toBe(true);
      expect((resealAgain.content as any[])[0]?.text).toMatch(/already sealed/i);

      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      await client.close();
    },
    30_000,
  );
});
