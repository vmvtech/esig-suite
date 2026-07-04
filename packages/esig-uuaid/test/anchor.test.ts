// esig-uuaid anchoring test suite.
//
// Tests run against the BUILT package (../dist) — the exact artifact
// consumers receive — so `npm run build` must precede `vitest run` (the
// package `test` script enforces this via pretest).
//
// No live calls: the REAL @uuaid/sdk UuaidClient runs over a mocked
// fetchImpl, so the genuine client-side encryption path (@uuaid/vault
// AES-256-GCM, slot-binding AAD) is exercised end-to-end and the test can
// assert that ONLY ciphertext — never the chain-head hash — appears in the
// outbound request.

import { describe, it, expect } from "vitest";
import { UuaidClient } from "@uuaid/sdk";
import { decryptItemText, generateVaultKey, isVaultEnvelope } from "@uuaid/vault";

import { anchorChainHead } from "../dist/index.js";

const AGENT = "uuaid:agent:0f5b2c9d";
const TENANT = "6b1e2f3a-4c5d-4e6f-8a9b-0c1d2e3f4a5b";
const HEAD = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const VAULT_SLOT = `esig/chain-head/${TENANT}`;

interface CapturedRequest {
  url?: string;
  method?: string;
  body?: string;
}

/** fetch stub that records the request and answers like PUT /agents/:uuaid/vault/:key. */
function fakeFetch(capture: CapturedRequest, contentHash = "a".repeat(64)): typeof fetch {
  return (async (url: unknown, init?: RequestInit) => {
    capture.url = String(url);
    capture.method = init?.method;
    capture.body = String(init?.body);
    return new Response(
      JSON.stringify({
        agent: AGENT,
        key: VAULT_SLOT,
        content_hash: contentHash,
        size_bytes: 512,
        replaced: false,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
}

describe("anchorChainHead", () => {
  it("PUTs an encrypted envelope to the tenant's chain-head vault slot and returns its content hash", async () => {
    const capture: CapturedRequest = {};
    const vaultKey = generateVaultKey();
    const client = new UuaidClient({ apiKey: "uuaid_test_fake_key", fetchImpl: fakeFetch(capture) });

    const result = await anchorChainHead({
      client,
      agentUuaid: AGENT,
      vaultKey,
      tenantId: TENANT,
      chainHeadHash: HEAD,
    });

    expect(result).toEqual({ contentHash: "a".repeat(64) });
    expect(capture.method).toBe("PUT");
    expect(capture.url).toBe(
      `https://api.uuaid.org/agents/${encodeURIComponent(AGENT)}/vault/${VAULT_SLOT}`,
    );

    // Only ciphertext leaves the process: the chain-head hash must not
    // appear anywhere in the outbound request body.
    expect(capture.body).not.toContain(HEAD);

    const sent = JSON.parse(capture.body!) as { envelope: unknown };
    expect(isVaultEnvelope(sent.envelope)).toBe(true);

    // The envelope decrypts (with the slot-binding AAD saveMemory uses) back
    // to the versioned anchor record.
    const plaintext = JSON.parse(
      decryptItemText(vaultKey, sent.envelope as never, { aad: `${AGENT}/${VAULT_SLOT}` }),
    ) as Record<string, unknown>;
    expect(plaintext.v).toBe(1);
    expect(plaintext.tenantId).toBe(TENANT);
    expect(plaintext.chainHeadHash).toBe(HEAD);
    expect(typeof plaintext.anchoredAt).toBe("string");
  });

  it("rejects blank options before any network call", async () => {
    let calls = 0;
    const client = new UuaidClient({
      fetchImpl: (async () => {
        calls++;
        return new Response("{}");
      }) as typeof fetch,
    });
    const base = { client, agentUuaid: AGENT, vaultKey: "uvk_x", tenantId: TENANT, chainHeadHash: HEAD };
    await expect(anchorChainHead({ ...base, agentUuaid: "" })).rejects.toThrow("agentUuaid");
    await expect(anchorChainHead({ ...base, vaultKey: "" })).rejects.toThrow("vaultKey");
    await expect(anchorChainHead({ ...base, tenantId: "" })).rejects.toThrow("tenantId");
    await expect(anchorChainHead({ ...base, chainHeadHash: "" })).rejects.toThrow("chainHeadHash");
    expect(calls).toBe(0);
  });

  it("propagates API failures (UuaidError carries the status)", async () => {
    const client = new UuaidClient({
      apiKey: "uuaid_test_fake_key",
      fetchImpl: (async () =>
        new Response(JSON.stringify({ error: "vault quota exceeded" }), { status: 402 })) as typeof fetch,
    });
    await expect(
      anchorChainHead({
        client,
        agentUuaid: AGENT,
        vaultKey: generateVaultKey(),
        tenantId: TENANT,
        chainHeadHash: HEAD,
      }),
    ).rejects.toThrow("402");
  });
});
