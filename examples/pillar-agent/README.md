# pillar-agent — a reference Pillar recipient

A minimal agent built on [`@e-sig/pillar-bridge`](../../packages/esig-pillar-bridge):
it holds its own [Pillar](https://www.npmjs.com/package/@uuaid/pillar) identity,
polls its own inbox for `esig:sign-request` envelopes, prints the title +
signing link, and — when the sign-request carries a `challenge` — replies with
a signed `eddsa-jcs-2022` `DataIntegrityProof`. This is the other half of
`docs/architecture/esig-mcp.md` §17: machine-to-machine identity, a human
still holds the pen (this agent never signs the document itself — it only
proves it controls the key behind its own `uuaid`, so whoever opens `url`
signs with a pre-verified identity attached).

## Install

This directory is deliberately **not** an npm workspace member (it
exercises `@e-sig/pillar-bridge` the same way an outside consumer would —
as a normal package dependency, not a sibling workspace package). Get its
two dependencies (`@e-sig/pillar-bridge`, `@e-sig/uaid-exch`) one of two
ways:

- **From inside an `esig-suite` checkout (this repo).** Nothing extra to
  do: `npm install` at the repo root already builds and symlinks both
  packages into the repo's root `node_modules/`, and Node's module
  resolution walks up from `examples/pillar-agent/` to find them there — no
  separate install step for this directory.
- **Standalone** (this directory copied out on its own, or as a template
  for a new project). `cd examples/pillar-agent && npm install` —
  `package.json`'s `@e-sig/pillar-bridge` dependency is
  `file:../../packages/esig-pillar-bridge`, so keep that relative path
  pointing at a *built* copy of the bridge package (run `npm run build -w
  @e-sig/pillar-bridge` first, or `npm run build` in that package's own
  directory), and `@e-sig/uaid-exch` installs from the npm registry.

Either way, `node demo.mjs` and `node test.mjs` (below) run fully offline —
no network dependency, no `@uuaid/pillar` carrier account needed.

## 5-step walkthrough (offline, no network)

This example ships its own carrier stub (`stub-carrier.mjs`) so the whole
loop runs with no dependency on `https://pillar.uuaid.org`. The automated
version of the five steps below is `node demo.mjs`; here they are spelled
out:

1. **Start a carrier.** `stub-carrier.mjs`'s `startStubCarrier()` spins up a
   local `node:http` server implementing `POST /v1/envelopes` and
   `GET /v1/inbox/<uuaid>` — verified with the SAME `@e-sig/pillar-bridge`
   shim this example depends on (no separate crypto to trust).
2. **Two identities.** A *sender* (standing in for the `esig-mcp` operator)
   and a *recipient* (this agent, `loadOrCreateIdentity` from `index.mjs`) —
   each `PillarIdentity.generate({ home, passphrase })`.
3. **Sender delivers a sign-request with a challenge.** Sealed directly with
   the loaded Pillar primitives (`pillar.envelope.seal`, wire kind
   `esig:sign-request`) — `{v:1, envelopeId, title, url, expiresAt, note,
   sender, createdAt, challenge}`. `expiresAt` is REQUIRED — `index.mjs`
   drops any sign-request missing it, or already past it
   (RT-2026-08-28-01 G3). A real `esig-mcp` sender would relay the challenge
   from `esig_identity_challenge` (`docs/architecture/esig-mcp.md` §12);
   `PillarDelivery`'s own payload shape has no `challenge` field, so the demo
   goes one level below it, straight to the shim's `envelope.seal`, to
   exercise this branch.
4. **The recipient polls once and replies.** `index.mjs`'s `pollOnce` fetches
   the inbox, confirms the envelope is addressed to its own uuaid,
   `envelope.open()`-verifies + decrypts, confirms the decrypted
   `payload.sender` matches the verified `envelope.sender` and the
   `expiresAt` check passes (RT-2026-08-28-01 G3 — see `test.mjs` for the
   negative cases), prints the title/link, and — seeing `payload.challenge`
   — builds a proof (`proveChallenge`) and seals it back as
   `esig:identity-proof`.
5. **The sender sees the proof.** Polls its own inbox, finds the
   `esig:identity-proof` envelope, decrypts it, and reads `uuaid` +
   `proof.cryptosuite` + `proof.verificationMethod` off it.

```
node demo.mjs
```

## Running against the real network

```
PILLAR_CARRIER_URL=https://pillar.uuaid.org \
ESIG_PILLAR_PASSPHRASE=<a passphrase, at least 24 characters> \
node index.mjs
```

(`PILLAR_PASSPHRASE` also works — see `@e-sig/pillar-bridge`'s own README;
`ESIG_PILLAR_PASSPHRASE`/`PILLAR_PASSPHRASE` is what `PillarIdentity.load`/
`.generate` actually read. Below 24 characters, or empty, is refused.)

First run generates a fresh identity under `.pillar-agent-home/keychain.json`
(0600) and prints its `uuaid` — hand that (plus the public key) to whoever
will address `esig_create_envelope`'s `signers[].pillar` at you. Subsequent
runs load the same identity. `index.mjs` polls forever
(`waitS: 25`, the carrier's long-poll cap); `Ctrl-C` to stop.

## How `proveChallenge` matches `@e-sig/uaid-exch`'s verifier

`verifyChallengeProof`/`verifyDataIntegrityProof`
(`packages/esig-uaid-exch/src/verify.ts`) sign/verify `jcsBytes(document)`
directly — the exact bytes `createExchange` signs
(`packages/esig-uaid-exch/src/index.ts:266`), NOT the W3C `eddsa-jcs-2022`
proofConfig-hash construction. `proveChallenge` in `index.mjs` mirrors that:

- `jcsBytes(challenge)` — the challenge object itself, JCS-canonicalized, no
  `proof` field mixed in.
- Raw Ed25519 signature over those bytes (`identity.sign`), multibase-encoded
  (`encodeMultibase(sig, "z")`) into `proof.proofValue` — matching
  `AgentSigner.sign`'s documented return shape.
- `verificationMethod` is a `did:key:z...` URI built the same way
  `packages/esig-uaid-exch/src/verify.ts`'s `publicKeyFromDidKey` decodes one:
  Ed25519 multicodec prefix `0xed 0x01` + the raw 32-byte public key,
  multibase (`z`, base58btc).

A caller with the real `@e-sig/uaid-exch`'s `verifyChallengeProof(challenge,
proof)` accepts this proof unmodified.

## Files

| File | What |
|---|---|
| `index.mjs` | The reference recipient — identity load/generate, inbox poll loop, reply-gating (recipient/sender/expiresAt checks), challenge proof, `esig:identity-proof` reply. Exports its pieces (`loadOrCreateIdentity`, `proveChallenge`, `pollOnce`, `handleSignRequest`, `run`) for reuse — see `demo.mjs`/`test.mjs`. |
| `stub-carrier.mjs` | The offline carrier stub — ships standalone so this walkthrough never needs the real network. |
| `demo.mjs` | Runs all 5 steps above in one process (`npm run demo` / `node demo.mjs`). |
| `test.mjs` | Plain `node:assert` checks for the RT-2026-08-28-01 F5/G3 reply-gating: an envelope not addressed to us is ignored, a payload whose `sender` doesn't match the verified envelope sender is dropped, and a sign-request with no `expiresAt` is dropped (`npm test` / `node test.mjs`). |
