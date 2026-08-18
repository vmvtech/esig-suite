// Shared test harness: a real gateway on an ephemeral port, with the HTML→PDF
// renderer replaced by the repo's sample unsigned PDF fixture so CI needs no
// Chromium (same trick core's own pq-pdf tests use).

import { promises as fs, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createGateway, parseTenantRegistry, type GatewayConfig } from "../dist/index.js";
import { FsAuditLogStore, FsPdfStorageStore } from "@e-sig/core/fs";

const here = path.dirname(fileURLToPath(import.meta.url));
export const SAMPLE_PDF = readFileSync(path.join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

export const TEST_PASSPHRASE = "test-passphrase-at-least-24-chars-long";
export const TEST_API_KEY_ID = "dsalvus-pilot";
export const TEST_API_SECRET = "s".repeat(48);
export const TEST_CALLER = `apikey:${TEST_API_KEY_ID}`;

export const REGISTRY = [
  {
    tenant: "acme-health",
    aliases: ["assurance-signer", "assurance-signer-next"],
    subjectName: "Acme Health Inc",
    callers: [TEST_CALLER, "spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance"],
    location: "vmv-internal",
  },
  {
    tenant: "other-tenant",
    aliases: ["assurance-signer"],
    subjectName: "Other Tenant LLC",
    // Deliberately NOT callable by the test credential — proves the caller
    // binding is enforced per tenant, not just per gateway.
    callers: ["spiffe://vmvtech.io/ns/somewhere/sa/else"],
  },
];

export async function makeConfig(overrides: Partial<GatewayConfig> = {}): Promise<GatewayConfig> {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "esig-gw-"));
  return {
    host: "127.0.0.1",
    port: 0,
    stateDir,
    passphrase: TEST_PASSPHRASE,
    tenants: parseTenantRegistry(REGISTRY),
    auth: {
      mode: "api-key",
      apiKeys: new Map([[TEST_API_KEY_ID, TEST_API_SECRET]]),
    },
    tsa: { urls: [], required: false, timeoutMs: 8000 },
    maxBodyBytes: 1024 * 1024,
    maxConcurrentSigns: 2,
    signDeadlineMs: 25_000,
    maxClientSkewSec: 900,
    ...overrides,
  };
}

export interface Harness {
  base: string;
  stateDir: string;
  auditRows(): Promise<Array<Record<string, unknown>>>;
  close(): Promise<void>;
}

export async function startHarness(
  config?: GatewayConfig,
  render: (html: string) => Promise<Buffer> = async () => SAMPLE_PDF,
  archive?: FsPdfStorageStore,
): Promise<Harness> {
  const cfg = config ?? (await makeConfig());
  const gw = await createGateway(cfg, {
    render,
    archive,
    // Silence per-request logs in test output.
    log: () => undefined,
  });
  const addr = await gw.listen();
  const auditStore = new FsAuditLogStore(cfg.stateDir);
  return {
    base: `http://127.0.0.1:${addr.port}`,
    stateDir: cfg.stateDir,
    auditRows: async () => (await auditStore.readAll()) as unknown as Array<Record<string, unknown>>,
    close: () => gw.close(),
  };
}

export function signBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tenant: "acme-health",
    cert_alias: "assurance-signer",
    html_base64: Buffer.from("<html><body><h1>Assurance dossier</h1></body></html>").toString("base64"),
    purpose: "dsalvus-assurance-package",
    timestamp: new Date().toISOString(),
    ...over,
  };
}

export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "content-type": "application/json",
    authorization: `Bearer ${TEST_API_KEY_ID}.${TEST_API_SECRET}`,
    ...extra,
  };
}
