// l1p.test.ts — L1p: self-authenticating identity (docs/architecture/esig-mcp.md
// §17 seam 1, build ticket item 1). Pure-helper vectors first, then the
// verification-path behaviors through direct `verifySignerIdentity`/
// `EnvelopeService` calls (the same code POST /sign uses).

import { createHash, generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import http from "node:http";

import { describe, it, expect } from "vitest";

import { encodeMultibase, jcsBytes, type DataIntegrityProof } from "@e-sig/uaid-exch";

import {
  buildStores,
  EnvelopeService,
  FsDocumentStore,
  CapturingDelivery,
  IdentityError,
  RegistryClient,
  verifySignerIdentity,
  localIdFromEd25519Key,
  uuaidFromEd25519Key,
  FOUNDATION_AGENT_UUAID_PREFIX,
  FOUNDATION_AGENT_UUAID_RE,
} from "../dist/index.js";
import { makeConfig, PNG_DATA_URL, tokenFromLink } from "./helpers.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

// ---------- test wallet: a real Ed25519 keypair + eddsa-jcs-2022 signer, uuaid SELF-DERIVED ----------

function makeSelfAuthenticatingWallet() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const rawPublic = spki.subarray(spki.length - 32);
  const multicodecPrefixed = Buffer.concat([Buffer.from([0xed, 0x01]), rawPublic]);
  const did = `did:key:${encodeMultibase(multicodecPrefixed, "z")}`;
  const verificationMethod = `${did}#${did.slice("did:key:".length)}`;
  const uuaid = uuaidFromEd25519Key(rawPublic);

  function sign(document: object, proofPurpose: DataIntegrityProof["proofPurpose"] = "authentication"): DataIntegrityProof {
    const signature = ed25519Sign(null, jcsBytes(document), privateKey);
    return {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      created: new Date().toISOString(),
      verificationMethod,
      proofPurpose,
      proofValue: encodeMultibase(signature, "z"),
    };
  }

  return { uuaid, rawPublic, sign };
}

async function buildHarness(overrides: Parameters<typeof makeConfig>[0] = {}) {
  const config = await makeConfig(overrides);
  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new CapturingDelivery();
  const envelopes = new EnvelopeService({ config, ...stores, documents, delivery, render: async () => SAMPLE_PDF });
  return { config, stores, envelopes, delivery };
}

// ---------- test registry stub + badge sealer (same wire format as identity.test.ts) ----------

function startRegistryStub(opts: { badgeBody?: unknown; badgeStatus?: number }): Promise<{ server: http.Server; base: string }> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url?.startsWith("/iaaso/v1/badge/")) {
        res.writeHead(opts.badgeStatus ?? 200);
        res.end(JSON.stringify(opts.badgeBody ?? {}));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({ server, base: `http://127.0.0.1:${port}` });
    });
  });
}

async function closeStub(stub: { server: http.Server }): Promise<void> {
  await new Promise<void>((resolve) => stub.server.close(() => resolve()));
}

const REGISTRY_KEY = (() => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return { publicKeyHex: Buffer.from(spki.subarray(spki.length - 32)).toString("hex"), privateKey };
})();
const PINNED_KEY_HEX = REGISTRY_KEY.publicKeyHex;

function sealBadgeEnvelope(payload: object) {
  const payloadHash = "0x" + createHash("sha256").update(jcsBytes(payload)).digest("hex");
  const signature = ed25519Sign(null, jcsBytes(payload), REGISTRY_KEY.privateKey).toString("hex");
  return {
    payload,
    payloadHash,
    signatures: [{ alg: "ed25519", keyId: "uuaid-registry-1", publicKey: REGISTRY_KEY.publicKeyHex, signature, created: new Date().toISOString() }],
  };
}

function makeBadgeEnvelope(uuaid: string, presentationKey: unknown) {
  return sealBadgeEnvelope({
    "@type": "UUAIDVerifiableBadge",
    spec: "IAASO-0003",
    v: "1.0",
    subject: { uuaid, nameVerified: false, presentationKey },
    status: "active",
    credentials: [],
    issuer: { id: "uuaid-registry", name: "UUAID Registry", keyId: "uuaid-registry-1" },
    issuedAt: new Date().toISOString(),
    freshUntil: new Date(Date.now() + 60_000).toISOString(),
    resolve: `https://registry.example/iaaso/v1/resolve/${uuaid}`,
  });
}

// =====================================================================
// (a) Pure helpers: localIdFromEd25519Key / uuaidFromEd25519Key
// =====================================================================

describe("(a) L1p pure helpers", () => {
  it("one FIXED vector, computed independently here with node:crypto (not the implementation under test)", () => {
    // A fixed 32-byte key (not a real Ed25519 point — the derivation is pure
    // hashing over raw bytes, so any 32 bytes exercise it identically).
    const fixedKey = Buffer.from(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "hex",
    );
    expect(fixedKey).toHaveLength(32);
    const digestHex = createHash("sha256").update(fixedKey).digest("hex");
    const first16BytesHex = digestHex.slice(0, 32);
    const expectedLocalId = [
      first16BytesHex.slice(0, 8),
      first16BytesHex.slice(8, 12),
      first16BytesHex.slice(12, 16),
      first16BytesHex.slice(16, 20),
      first16BytesHex.slice(20, 32),
    ].join("-");

    expect(localIdFromEd25519Key(fixedKey)).toBe(expectedLocalId);
    expect(uuaidFromEd25519Key(fixedKey)).toBe(`${FOUNDATION_AGENT_UUAID_PREFIX}${expectedLocalId}`);
    expect(FOUNDATION_AGENT_UUAID_RE.test(uuaidFromEd25519Key(fixedKey))).toBe(true);
  });

  it("hashes the RAW key bytes, never the hex string (a plausible-looking but WRONG id)", () => {
    const fixedKey = Buffer.from(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "hex",
    );
    const hexOfHexDigest = createHash("sha256").update(Buffer.from(fixedKey.toString("hex"), "utf8")).digest("hex").slice(0, 32);
    expect(localIdFromEd25519Key(fixedKey)).not.toBe(
      `${hexOfHexDigest.slice(0, 8)}-${hexOfHexDigest.slice(8, 12)}-${hexOfHexDigest.slice(12, 16)}-${hexOfHexDigest.slice(16, 20)}-${hexOfHexDigest.slice(20, 32)}`,
    );
  });

  it("rejects a key that is not exactly 32 bytes", () => {
    expect(() => localIdFromEd25519Key(Buffer.alloc(31))).toThrow();
    expect(() => localIdFromEd25519Key(Buffer.alloc(33))).toThrow();
  });

  // 20 random real Ed25519 public keys, cross-checked against BOTH this
  // package's own implementation and (when the sibling package's build
  // artifact is present in this checkout) the bridge's OWN
  // `localIdFromEd25519Key` — a one-time, read-only cross-check of a pure
  // math function against an independent implementation, not a runtime
  // dependency: this file never imports the "@e-sig/pillar-bridge" package
  // specifier, only reads its already-built dist/index.js by relative path,
  // and every other seam test in this suite (pillar-seams.test.ts,
  // preverified.test.ts) injects a fake bridge instead.
  const bridgeDistPath = join(here, "..", "..", "esig-pillar-bridge", "dist", "index.js");
  const bridgeDistExists = existsSync(bridgeDistPath);

  it.skipIf(!bridgeDistExists)(
    "20 random Ed25519 keys: localIdFromEd25519Key matches the bridge's own implementation byte-for-byte",
    async () => {
      const bridge = (await import(bridgeDistPath)) as { localIdFromEd25519Key: (raw: Uint8Array) => string };
      for (let i = 0; i < 20; i++) {
        const { publicKey } = generateKeyPairSync("ed25519");
        const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
        const raw = spki.subarray(spki.length - 32);
        expect(localIdFromEd25519Key(raw)).toBe(bridge.localIdFromEd25519Key(raw));
      }
    },
  );

  it("20 random Ed25519 keys: well-formed per FOUNDATION_AGENT_UUAID_RE, round-trips through uuaidFromEd25519Key", () => {
    for (let i = 0; i < 20; i++) {
      const { publicKey } = generateKeyPairSync("ed25519");
      const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;
      const raw = spki.subarray(spki.length - 32);
      const uuaid = uuaidFromEd25519Key(raw);
      expect(FOUNDATION_AGENT_UUAID_RE.test(uuaid)).toBe(true);
      expect(uuaid.slice(FOUNDATION_AGENT_UUAID_PREFIX.length)).toBe(localIdFromEd25519Key(raw));
    }
  });
});

// =====================================================================
// (b)/(c) verifySignerIdentity: derivation, mismatch refusal, minLevel L1p
// =====================================================================

describe("(b) verifySignerIdentity: L1p derivation and mismatch", () => {
  it("a foundation:agent uuaid whose key DOES derive it -> level L1p, even when minLevel is only L1", async () => {
    const { envelopes, delivery } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();

    const created = await envelopes.create({
      title: "L1p opportunistic upgrade",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    const status = await envelopes.sign(tokenFromLink(link.url), PNG_DATA_URL, { uuaid: wallet.uuaid, proof });
    expect(status.signers[0].identity?.level).toBe("L1p");
    expect(status.signers[0].identity?.uuaid).toBe(wallet.uuaid);
  });

  it("a foundation:agent uuaid whose key does NOT derive it -> refused L1P_KEY_UUAID_MISMATCH, never silently accepted as L1", async () => {
    const { envelopes, delivery } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();
    const wrongUuaid = `${FOUNDATION_AGENT_UUAID_PREFIX}00000000-0000-0000-0000-000000000000`;
    expect(wrongUuaid).not.toBe(wallet.uuaid);

    const created = await envelopes.create({
      title: "L1p mismatch",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    await expect(envelopes.sign(tokenFromLink(link.url), PNG_DATA_URL, { uuaid: wrongUuaid, proof })).rejects.toMatchObject({
      reason: "L1P_KEY_UUAID_MISMATCH",
    });
    const status = await envelopes.status(created.envelopeId);
    expect(status.signers[0].identity).toBeUndefined();
    expect(status.signers[0].status).toBe("pending"); // no signature recorded either — the throw happens before recordSignature
  });

  it("minLevel L1p is enforced: a non-foundation:agent uuaid with an otherwise-valid L1 proof is refused L1P_REQUIRED", async () => {
    const { envelopes, delivery } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();
    const notSelfAuthenticating = "uuaid:person:us:ca:11111111-1111-1111-1111-111111111111";

    const created = await envelopes.create({
      title: "L1p required",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    await expect(
      envelopes.sign(tokenFromLink(link.url), PNG_DATA_URL, { uuaid: notSelfAuthenticating, proof }),
    ).rejects.toMatchObject({ reason: "L1P_REQUIRED" });
  });

  it("minLevel L1p is enforced: a self-authenticating uuaid + matching key -> succeeds at level L1p", async () => {
    const { envelopes, delivery } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();

    const created = await envelopes.create({
      title: "L1p required, satisfied",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    const status = await envelopes.sign(tokenFromLink(link.url), PNG_DATA_URL, { uuaid: wallet.uuaid, proof });
    expect(status.signers[0].identity?.level).toBe("L1p");
  });

  it("Config.identityMinLevel accepts L1p (config.ts's own IDENTITY_LEVELS list)", async () => {
    const config = await makeConfig({ identityMinLevel: "L1p" });
    expect(config.identityMinLevel).toBe("L1p");
  });
});

// =====================================================================
// (d) G5 — L1p vs. an available L2 badge disagreeing -> refused
// =====================================================================

describe("(d) G5 — L1p/L2 ladder composition disagreement", () => {
  it("an L2 badge for the SAME uuaid attesting a DIFFERENT key -> refused L2_L1P_DISAGREEMENT, even at minLevel L1p (not L2)", async () => {
    const { envelopes, delivery, stores, config } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();
    const stub = await startRegistryStub({
      badgeBody: makeBadgeEnvelope(wallet.uuaid, { alg: "ed25519", publicKey: PINNED_KEY_HEX, keyId: "someone-else" }),
    });

    const created = await envelopes.create({
      title: "G5 disagreement",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    await expect(
      verifySignerIdentity({
        store: stores.envelopeStore,
        tenantId: config.tenant,
        envelopeId: created.envelopeId,
        signerId: link.signerId,
        minLevel: "L1p",
        proof: { uuaid: wallet.uuaid, proof },
        registry: new RegistryClient(stub.base),
        registrySigningKey: PINNED_KEY_HEX,
      }),
    ).rejects.toMatchObject({ reason: "L2_L1P_DISAGREEMENT" });

    await closeStub(stub);
  });

  it("an L2 badge for the SAME uuaid attesting the SAME key -> L1p still succeeds (agreement, not a requirement)", async () => {
    const { envelopes, delivery, stores, config } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();
    const stub = await startRegistryStub({
      badgeBody: makeBadgeEnvelope(wallet.uuaid, { alg: "ed25519", publicKey: wallet.rawPublic.toString("hex"), keyId: "wallet" }),
    });

    const created = await envelopes.create({
      title: "G5 agreement",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    const record = await verifySignerIdentity({
      store: stores.envelopeStore,
      tenantId: config.tenant,
      envelopeId: created.envelopeId,
      signerId: link.signerId,
      minLevel: "L1p",
      proof: { uuaid: wallet.uuaid, proof },
      registry: new RegistryClient(stub.base),
      registrySigningKey: PINNED_KEY_HEX,
    });
    expect(record?.level).toBe("L1p");

    await closeStub(stub);
  });

  it("no registry configured at all -> L1p still succeeds fully locally (never requires the registry)", async () => {
    const { envelopes, delivery } = await buildHarness();
    const wallet = makeSelfAuthenticatingWallet();

    const created = await envelopes.create({
      title: "L1p, no registry",
      html: "<p>terms</p>",
      signers: [{ name: "Alice", email: "alice@example.com" }],
      identity: { minLevel: "L1p" },
    });
    const link = delivery.calls[0].links[0];
    const challenge = await envelopes.issueIdentityChallenge(created.envelopeId, link.signerId);
    const proof = wallet.sign(challenge);

    const status = await envelopes.sign(tokenFromLink(link.url), PNG_DATA_URL, { uuaid: wallet.uuaid, proof });
    expect(status.signers[0].identity?.level).toBe("L1p");
  });
});
