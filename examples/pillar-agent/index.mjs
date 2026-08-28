#!/usr/bin/env node
// examples/pillar-agent — reference recipient.
//
// A minimal agent that holds its own Pillar identity, polls its own inbox
// for `esig:sign-request` envelopes (docs/architecture/esig-mcp.md §17 seam
// 2), prints the title + link, and — when the sign-request's payload carries
// a `challenge` — produces an `eddsa-jcs-2022` DataIntegrityProof over it and
// replies `esig:identity-proof` (seam 3): machine-to-machine identity, human
// still holds the pen (a human opens `url` to actually sign; this agent only
// proves it controls the key behind its uuaid).
//
// Run standalone against the real network:
//   PILLAR_CARRIER_URL=https://pillar.uuaid.org node index.mjs
// Run the full offline walkthrough (no network): `node demo.mjs` — see README.md.

import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { loadPillar, PillarIdentity, CarrierClient } from "@e-sig/pillar-bridge";
import { jcsBytes, encodeMultibase } from "@e-sig/uaid-exch";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const DEFAULT_HOME = path.join(__dirname, ".pillar-agent-home");
export const DEFAULT_CARRIER = process.env.PILLAR_CARRIER_URL || "https://pillar.uuaid.org";

// multicodec varint for "ed25519-pub" (table code 0xed) — see
// packages/esig-uaid-exch/src/verify.ts for the same constant + derivation.
const ED25519_MULTICODEC_PREFIX = Uint8Array.from([0xed, 0x01]);

/** Load this agent's identity from `home`, generating one on first run. */
export async function loadOrCreateIdentity({ home = DEFAULT_HOME, passphrase } = {}) {
  try {
    return await PillarIdentity.load({ home, passphrase });
  } catch {
    const identity = await PillarIdentity.generate({ home, passphrase });
    console.log(`[pillar-agent] generated a fresh identity: ${identity.uuaid}`);
    return identity;
  }
}

function didKeyFor(identity) {
  const rawPub = Buffer.from(identity.publicKeyHex, "hex");
  const multicodec = Buffer.concat([Buffer.from(ED25519_MULTICODEC_PREFIX), rawPub]);
  return `did:key:${encodeMultibase(multicodec, "z")}`;
}

/**
 * Build an `eddsa-jcs-2022` DataIntegrityProof over `challenge`, signed by
 * `identity` — mirrors `@e-sig/uaid-exch`'s `createExchange` construction
 * exactly (packages/esig-uaid-exch/src/index.ts:266-280): sign
 * `jcsBytes(document)` directly (no W3C proofConfig-hash), multibase-encode
 * the raw signature, and use a `did:key:` verificationMethod — so
 * `verifyChallengeProof`/`verifyDataIntegrityProof` accept it unmodified.
 */
export function proveChallenge(identity, challenge) {
  const canonicalBytes = jcsBytes(challenge);
  const signature = identity.sign(canonicalBytes);
  return {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: new Date().toISOString(),
    verificationMethod: didKeyFor(identity),
    proofPurpose: "authentication",
    proofValue: encodeMultibase(signature, "z"),
  };
}

/**
 * Handle one already-`open()`-verified `esig:sign-request` envelope.
 * RT-2026-08-28-01 F5/G3 (f): only proceeds when the DECRYPTED payload's own
 * `sender` matches the ENVELOPE's transport-verified `sender` — `open()`
 * only proves who sealed the envelope, not that the plaintext payload isn't
 * lying about who it claims to be from, so this cross-check is what
 * actually binds the two. (e): also requires a present, unexpired
 * `expiresAt` — a sign-request with no expiry, or a stale one, is dropped
 * rather than acted on.
 */
export async function handleSignRequest({ pillar, identity, carrier, envelope }) {
  const payload = pillar.envelope.decrypt(identity._keychain(), envelope);

  if (payload.sender !== envelope.sender) {
    console.log(
      `[pillar-agent] dropped sign-request: payload.sender (${payload.sender}) does not match the verified envelope sender (${envelope.sender})`
    );
    return null;
  }
  if (!payload.expiresAt) {
    console.log("[pillar-agent] dropped sign-request: missing expiresAt");
    return null;
  }
  if (Date.parse(payload.expiresAt) <= Date.now()) {
    console.log(`[pillar-agent] dropped sign-request: expired at ${payload.expiresAt}`);
    return null;
  }

  console.log(`[pillar-agent] esig:sign-request "${payload.title}" -> ${payload.url}`);
  if (payload.note) console.log(`[pillar-agent]   note: ${payload.note}`);

  if (!payload.challenge) {
    console.log("[pillar-agent] no challenge in this sign-request — nothing to prove; a human still opens the url to sign.");
    return null;
  }

  const proof = proveChallenge(identity, payload.challenge);
  // envelope.open() (already run by the caller) bound this key to
  // envelope.sender — safe to address the reply to it directly.
  const senderPublicKeyHex = envelope.transportSignature.publicKey;
  const replyPayload = {
    v: 1,
    envelopeId: payload.envelopeId,
    signerId: payload.signerId ?? "signer-1",
    uuaid: identity.uuaid,
    proof,
  };
  const reply = pillar.envelope.seal(identity._keychain(), {
    recipient: envelope.sender,
    recipientPublicKey: senderPublicKeyHex,
    kind: "esig:identity-proof",
    payload: replyPayload,
  });
  const result = await carrier.deliver(reply);
  console.log(`[pillar-agent] replied esig:identity-proof (envelope ${reply.id}, seq ${result.seq})`);
  return reply;
}

/**
 * One fetch+handle pass. Returns the highest seq seen (the next `since`).
 * RT-2026-08-28-01 F5/G3 (f): only considers envelopes addressed to this
 * agent's OWN uuaid — the carrier's inbox endpoint already filters by
 * recipient, but this is defense-in-depth against a carrier bug or a
 * differently-behaved carrier, not a check this agent should rely on the
 * server for.
 */
export async function pollOnce({ pillar, identity, carrier, since = 0, waitS = 5 }) {
  const inbox = await carrier.fetchInbox({ since, waitS });
  let lastSeq = since;
  for (const { seq, envelope } of inbox.envelopes) {
    lastSeq = Math.max(lastSeq, seq);
    if (envelope.recipient !== identity.uuaid) {
      console.log(`[pillar-agent] ignoring an envelope not addressed to us (recipient ${envelope.recipient})`);
      continue;
    }
    const verdict = pillar.envelope.open(envelope);
    if (!verdict.ok) {
      console.log(`[pillar-agent] dropped an envelope that failed open(): ${verdict.reason}`);
      continue;
    }
    if (envelope.kind !== "esig:sign-request") {
      console.log(`[pillar-agent] ignoring kind "${envelope.kind}"`);
      continue;
    }
    await handleSignRequest({ pillar, identity, carrier, envelope });
  }
  return lastSeq;
}

/** Long-running entry point: load/generate identity, poll forever (or `maxIterations` times). */
export async function run({ home = DEFAULT_HOME, carrierUrl = DEFAULT_CARRIER, passphrase, waitS = 25, maxIterations = Infinity } = {}) {
  const pillar = await loadPillar();
  const identity = await loadOrCreateIdentity({ home, passphrase });
  console.log(`[pillar-agent] identity: ${identity.uuaid}`);
  console.log(`[pillar-agent] carrier:  ${carrierUrl}`);
  const carrier = await CarrierClient.open({ identity, carriers: [carrierUrl] });
  let since = 0;
  for (let i = 0; i < maxIterations; i++) {
    since = await pollOnce({ pillar, identity, carrier, since, waitS });
  }
  return { identity, since };
}

const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  run().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
