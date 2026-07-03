// Envelope + tokenized-signing-link test suite. Runs against the BUILT package
// (../dist) like crypto.test.ts — `npm run build` precedes `vitest run`.

import { describe, it, expect } from "vitest";

import {
  createEnvelope,
  resolveSigningToken,
  recordSignature,
  declineEnvelope,
  voidEnvelope,
  composeEnvelopeHtml,
  EnvelopeError,
  type Envelope,
  type EnvelopeStore,
} from "../dist/index.js";

const PNG_1PX =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

/** In-memory EnvelopeStore (the reference shape adapters must implement). */
function memoryStore(): EnvelopeStore & { rows: Envelope[] } {
  const rows: Envelope[] = [];
  const clone = (e: Envelope) => structuredClone(e);
  return {
    rows,
    async insert(e) {
      rows.push(clone(e));
      return clone(e);
    },
    async update(e) {
      const i = rows.findIndex((r) => r.id === e.id);
      if (i === -1) throw new Error("not found");
      rows[i] = clone(e);
      return clone(e);
    },
    async findById(tenantId, id) {
      const r = rows.find((x) => x.tenantId === tenantId && x.id === id);
      return r ? clone(r) : null;
    },
    async findByTokenHash(tokenHash) {
      const r = rows.find((x) => x.signers.some((s) => s.tokenHash === tokenHash));
      return r ? clone(r) : null;
    },
  };
}

async function twoSignerEnvelope(store = memoryStore(), extra: Record<string, unknown> = {}) {
  const created = await createEnvelope({
    store,
    tenantId: "t1",
    title: "MSA",
    html: "<h1>Master Service Agreement</h1>",
    signers: [
      { name: "Ada Lovelace", email: "ada@acme.example", roleLabel: "CEO", order: 1 },
      { name: "Grace Hopper", email: "grace@acme.example", roleLabel: "Witness", order: 2 },
    ],
    ...extra,
  });
  return { store, ...created };
}

describe("createEnvelope", () => {
  it("mints one single-use token per signer and persists only hashes", async () => {
    const { envelope, signingTokens } = await twoSignerEnvelope();
    expect(signingTokens).toHaveLength(2);
    for (const t of signingTokens) {
      expect(t.token).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes base64url
      const persisted = JSON.stringify(envelope);
      expect(persisted).not.toContain(t.token); // raw token never stored
    }
    expect(envelope.status).toBe("sent");
    expect(new Set(envelope.signers.map((s) => s.tokenHash)).size).toBe(2);
  });

  it("rejects empty html, no signers, bad emails, bad order, past expiry", async () => {
    const store = memoryStore();
    const base = { store, tenantId: "t1", title: "x", html: "<p>x</p>" };
    const signer = { name: "A", email: "a@b.c" };
    await expect(createEnvelope({ ...base, html: " ", signers: [signer] })).rejects.toThrow(EnvelopeError);
    await expect(createEnvelope({ ...base, signers: [] })).rejects.toThrow(/at least one/);
    await expect(
      createEnvelope({ ...base, signers: [{ name: "A", email: "nope" }] }),
    ).rejects.toThrow(/email/);
    await expect(
      createEnvelope({ ...base, signers: [{ ...signer, order: 0 }] }),
    ).rejects.toThrow(/order/);
    await expect(
      createEnvelope({ ...base, signers: [signer], expiresAt: new Date(Date.now() - 1000) }),
    ).rejects.toThrow(/future/);
  });
});

describe("resolveSigningToken", () => {
  it("resolves a valid token to its signer", async () => {
    const { store, signingTokens, envelope } = await twoSignerEnvelope();
    const res = await resolveSigningToken({ store, token: signingTokens[0].token });
    expect(res.status).toBe("ok");
    if (res.status === "ok") {
      expect(res.signer.id).toBe(signingTokens[0].signerId);
      expect(res.envelope.id).toBe(envelope.id);
    }
  });

  it("returns invalid for garbage and near-miss tokens", async () => {
    const { store, signingTokens } = await twoSignerEnvelope();
    expect((await resolveSigningToken({ store, token: "nope" })).status).toBe("invalid");
    const t = signingTokens[0].token;
    const flipped = (t[0] === "A" ? "B" : "A") + t.slice(1);
    expect((await resolveSigningToken({ store, token: flipped })).status).toBe("invalid");
  });

  it("gates on signing order (not_your_turn lists blockers)", async () => {
    const { store, signingTokens } = await twoSignerEnvelope();
    const res = await resolveSigningToken({ store, token: signingTokens[1].token });
    expect(res.status).toBe("not_your_turn");
    if (res.status === "not_your_turn") {
      expect(res.waitingOn.map((s) => s.name)).toEqual(["Ada Lovelace"]);
    }
  });

  it("expires lazily and persists the flip", async () => {
    const store = memoryStore();
    const { signingTokens } = await twoSignerEnvelope(store, {
      expiresAt: new Date(Date.now() + 50),
    });
    await new Promise((r) => setTimeout(r, 80));
    const res = await resolveSigningToken({ store, token: signingTokens[0].token });
    expect(res.status).toBe("expired");
    expect(store.rows[0].status).toBe("expired");
  });
});

describe("recordSignature", () => {
  it("walks sent → partially_signed → completed in order", async () => {
    const { store, signingTokens } = await twoSignerEnvelope();
    const afterFirst = await recordSignature({
      store,
      token: signingTokens[0].token,
      signatureImageDataUrl: PNG_1PX,
    });
    expect(afterFirst.status).toBe("partially_signed");

    const afterSecond = await recordSignature({
      store,
      token: signingTokens[1].token,
      signatureImageDataUrl: PNG_1PX,
    });
    expect(afterSecond.status).toBe("completed");
    expect(afterSecond.completedAt).toBeTruthy();
    expect(afterSecond.signers.every((s) => s.status === "signed")).toBe(true);
  });

  it("parallel signers (equal order) can sign in any order", async () => {
    const store = memoryStore();
    const { signingTokens } = await createEnvelope({
      store,
      tenantId: "t1",
      title: "NDA",
      html: "<p>nda</p>",
      signers: [
        { name: "A", email: "a@x.y", order: 1 },
        { name: "B", email: "b@x.y", order: 1 },
      ],
    });
    const first = await recordSignature({
      store,
      token: signingTokens[1].token, // "second" listed signer goes first
      signatureImageDataUrl: PNG_1PX,
    });
    expect(first.status).toBe("partially_signed");
  });

  it("rejects out-of-turn, reused, and malformed-image signatures", async () => {
    const { store, signingTokens } = await twoSignerEnvelope();
    await expect(
      recordSignature({ store, token: signingTokens[1].token, signatureImageDataUrl: PNG_1PX }),
    ).rejects.toMatchObject({ code: "not_your_turn" });

    await expect(
      recordSignature({
        store,
        token: signingTokens[0].token,
        signatureImageDataUrl: 'data:text/html,<script>alert(1)</script>',
      }),
    ).rejects.toMatchObject({ code: "invalid_input" });

    await recordSignature({ store, token: signingTokens[0].token, signatureImageDataUrl: PNG_1PX });
    await expect(
      recordSignature({ store, token: signingTokens[0].token, signatureImageDataUrl: PNG_1PX }),
    ).rejects.toMatchObject({ code: "already_signed" });
  });
});

describe("decline + void", () => {
  it("a decline voids the envelope and kills the other tokens", async () => {
    const { store, signingTokens } = await twoSignerEnvelope();
    const voided = await declineEnvelope({
      store,
      token: signingTokens[0].token,
      reason: "wrong terms",
    });
    expect(voided.status).toBe("voided");
    expect(voided.signers[0].status).toBe("declined");
    expect(voided.signers[0].declineReason).toBe("wrong terms");

    const other = await resolveSigningToken({ store, token: signingTokens[1].token });
    expect(other.status).toBe("voided");
  });

  it("sender void blocks signing; completed envelopes cannot be voided", async () => {
    const { store, envelope, signingTokens } = await twoSignerEnvelope();
    await voidEnvelope({ store, tenantId: "t1", envelopeId: envelope.id });
    await expect(
      recordSignature({ store, token: signingTokens[0].token, signatureImageDataUrl: PNG_1PX }),
    ).rejects.toMatchObject({ code: "not_signable" });

    const s2 = memoryStore();
    const e2 = await createEnvelope({
      store: s2,
      tenantId: "t1",
      title: "x",
      html: "<p>x</p>",
      signers: [{ name: "A", email: "a@x.y" }],
    });
    await recordSignature({ store: s2, token: e2.signingTokens[0].token, signatureImageDataUrl: PNG_1PX });
    await expect(
      voidEnvelope({ store: s2, tenantId: "t1", envelopeId: e2.envelope.id }),
    ).rejects.toMatchObject({ code: "not_signable" });
  });
});

describe("composeEnvelopeHtml", () => {
  it("appends every signer's block to the base document", async () => {
    const { store, signingTokens } = await twoSignerEnvelope();
    await recordSignature({ store, token: signingTokens[0].token, signatureImageDataUrl: PNG_1PX });
    const completed = await recordSignature({
      store,
      token: signingTokens[1].token,
      signatureImageDataUrl: PNG_1PX,
    });
    const html = composeEnvelopeHtml(completed, { platformLabel: "e-sig pipeline" });
    expect(html).toContain("Master Service Agreement");
    expect(html).toContain("Ada Lovelace");
    expect(html).toContain("Grace Hopper");
    expect(html).toContain("CEO");
    expect(html).toContain("Witness");
    expect(html).toContain("e-sig pipeline");
  });

  it("refuses incomplete envelopes", async () => {
    const { envelope } = await twoSignerEnvelope();
    expect(() => composeEnvelopeHtml(envelope)).toThrow(/not completed/);
  });
});
