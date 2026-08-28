// Shared test setup, mirrors packages/esig-gateway/test/harness.ts's pattern
// (ephemeral tmp dataDir per test, a fixed test passphrase/signature image).

import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { Config } from "../dist/index.js";

export const TEST_PASSPHRASE = "test-passphrase-at-least-24-chars-long!!";

// A syntactically valid (but not necessarily decodable) base64 image data URL —
// core's `assertImageDataUrl` (signature-block.ts) only regex-validates the
// shape, never decodes the pixels, so this is sufficient everywhere a "drawn
// signature" is needed.
export const PNG_DATA_URL =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

export async function makeConfig(overrides: Partial<Config> = {}): Promise<Config> {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "esig-mcp-test-"));
  return {
    modes: ["H"],
    passphrase: TEST_PASSPHRASE,
    dataDir,
    docsRoot: path.join(dataDir, "inbox"),
    tenant: "test-tenant",
    subjectName: "Test Co",
    httpHost: "127.0.0.1",
    httpPort: 0,
    baseUrl: "http://127.0.0.1:7433",
    returnLinks: false,
    delivery: { kind: "console" },
    pq: true,
    maxHtmlBytes: 1_000_000,
    maxPdfBytes: 25_000_000,
    envelopesPerHour: 1000,
    maxSigners: 25,
    identityMinLevel: "none",
    uuaidRegistryUrl: undefined,
    identityChallengeTtlSec: 900,
    reminders: { durationsMs: [], max: 3 },
    events: { webhook: undefined },
    allowInsecureWebhook: false,
    allowInsecureEventsWebhook: false,
    allowPrivateWebhook: false,
    pillarAllowUnregistered: false,
    pillar: undefined,
    ...overrides,
  };
}

export function tokenFromLink(url: string): string {
  const parts = new URL(url).pathname.split("/");
  return parts[parts.length - 1];
}
