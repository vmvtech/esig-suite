import { describe, it, expect } from "vitest";
import {
  createExchange,
  jcs,
  jcsBytes,
  uuidv7,
  UaidNetworkClient,
  exchangeInputFromEsigEnvelope,
  type AgentSigner,
  type IssuerSigner,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// JCS (RFC 8785) canonicalization
// ---------------------------------------------------------------------------

describe("jcs", () => {
  it("sorts object keys lexicographically", () => {
    expect(jcs({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("emits arrays in order without whitespace", () => {
    expect(jcs([3, 1, 2])).toBe("[3,1,2]");
  });

  it("escapes control characters and quotes", () => {
    expect(jcs("hi\nworld")).toBe('"hi\\nworld"');
    expect(jcs('a"b')).toBe('"a\\"b"');
  });

  it("rejects non-finite numbers", () => {
    expect(() => jcs(Number.NaN)).toThrow();
    expect(() => jcs(Number.POSITIVE_INFINITY)).toThrow();
  });

  it("omits undefined object properties", () => {
    expect(jcs({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it("produces byte-stable output", () => {
    const a = jcsBytes({ x: 1, y: [true, null, "z"] });
    const b = jcsBytes({ y: [true, null, "z"], x: 1 });
    expect(Buffer.from(a).toString("hex")).toEqual(Buffer.from(b).toString("hex"));
  });
});

// ---------------------------------------------------------------------------
// UUIDv7
// ---------------------------------------------------------------------------

describe("uuidv7", () => {
  it("returns a canonical uuid string", () => {
    const id = uuidv7();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("is monotonically-ish increasing", () => {
    const a = uuidv7();
    const b = uuidv7();
    // The first 12 hex chars encode the ms timestamp. Since we sleep 0ms
    // between calls, they can equal; they must never be a<b false.
    expect(a.slice(0, 13) <= b.slice(0, 13)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// createExchange
// ---------------------------------------------------------------------------

function mockSigner(handle: string): AgentSigner & IssuerSigner {
  return {
    agentUuaid: handle,
    issuerDid: handle,
    verificationMethod: `${handle}#k1`,
    async sign(bytes: Uint8Array) {
      // Deterministic pseudo-signature: base32-ish hash of length + first byte
      return `z${bytes.length.toString(16)}${(bytes[0] ?? 0).toString(16)}`;
    },
  };
}

describe("createExchange", () => {
  it("returns two proofs (authentication + assertionMethod)", async () => {
    const agent = mockSigner("uuaid:foundation:agent:018f7abc");
    const issuer = mockSigner("uuaid:foundation:certifier:018f7aaa");
    const now = new Date("2026-07-04T18:12:33.412Z");
    const ex = await createExchange(
      {
        signingCredentialId: "uuaid:foundation:signing-credential:018f7ac8",
        principal: "did:web:acme.com",
        action: "sign.contract",
        counterparty: "did:web:customer.com",
        resource: {
          type: "application/pdf",
          sha256: "sha256:abc123",
          size: 184321,
        },
        purpose: "MSA Q3 renewal",
        soleControl: {
          challenge_type: "webauthn-prf",
          challenge_at: "2026-07-04T18:12:31.804Z",
          challenge_evidence_hash: "sha256:def456",
        },
        now: () => now,
        idFactory: () => "018f7ad5-4d3d-7ac8-8e11-4e6c9e2c6b3a",
      },
      agent,
      issuer
    );
    expect(ex.id).toBe(
      "uuaid:foundation:exchange:018f7ad5-4d3d-7ac8-8e11-4e6c9e2c6b3a"
    );
    expect(ex.issuer).toBe(agent.agentUuaid);
    expect(ex.proof).toHaveLength(2);
    const [a, b] = ex.proof;
    expect(a.proofPurpose).toBe("authentication");
    expect(b.proofPurpose).toBe("assertionMethod");
    expect(a.cryptosuite).toBe("eddsa-jcs-2022");
  });

  it("exchangeInputFromEsigEnvelope shapes a sign.contract action", () => {
    const input = exchangeInputFromEsigEnvelope({
      envelopeId: "018f7000",
      signingCredentialId: "uuaid:foundation:signing-credential:018f7ac8",
      principal: "did:web:acme.com",
      counterparty: "did:web:customer.com",
      pdfSha256: "sha256:aaa",
      pdfSize: 100,
      purpose: "test",
      soleControl: {
        challenge_type: "email-otp",
        challenge_at: "2026-07-04T18:00:00Z",
        challenge_evidence_hash: "sha256:xyz",
      },
    });
    expect(input.action).toBe("sign.contract");
    expect(input.resource.type).toBe("application/pdf");
    expect(input.external_refs?.esign_envelope).toBe("esig:envelope:018f7000");
  });
});

// ---------------------------------------------------------------------------
// UaidNetworkClient
// ---------------------------------------------------------------------------

describe("UaidNetworkClient", () => {
  it("submit requires an apiKey", async () => {
    const c = new UaidNetworkClient({ baseUrl: "http://x" });
    await expect(c.submit({} as never)).rejects.toThrow(/apiKey/);
  });

  it("txBrowserUrl builds the public url", () => {
    const c = new UaidNetworkClient({ baseUrl: "http://x" });
    expect(c.txBrowserUrl("2026-07-04.acme.ax9k4z")).toBe(
      "https://tx.uuaid.org/2026-07-04.acme.ax9k4z"
    );
  });

  it("resolverUrl escapes the exchange id", () => {
    const c = new UaidNetworkClient({ baseUrl: "http://x" });
    expect(c.resolverUrl("uuaid:foundation:exchange:018f")).toBe(
      "https://registry.uuaid.org/exchange/uuaid%3Afoundation%3Aexchange%3A018f"
    );
  });

  it("submit POSTs and parses success", async () => {
    const fetchImpl: typeof fetch = (async () =>
      new Response(
        JSON.stringify({
          exchange_id: "uuaid:foundation:exchange:1",
          status: "verified",
          receipt_pending_anchor: true,
          estimated_anchor_at: "2026-07-04T18:22:00Z",
        }),
        { status: 201, headers: { "content-type": "application/json" } }
      )) as unknown as typeof fetch;
    const c = new UaidNetworkClient({
      baseUrl: "http://x",
      apiKey: "test",
      fetchImpl,
    });
    const r = await c.submit({ id: "test" } as never);
    expect(r.exchange_id).toBe("uuaid:foundation:exchange:1");
    expect(r.status).toBe("verified");
  });
});
