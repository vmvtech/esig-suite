# @e-sig/mcp

An MCP (Model Context Protocol) server for agent-driven e-signature workflows: agents draft, send, and track envelopes over `@e-sig/core`; a human holds the pen. Cryptographic control of signing stays with the human by default — no tool in v0.1 can produce a signature, and no tool can return a raw signing link, unless an operator explicitly opts in.

Full design: [`docs/architecture/esig-mcp.md`](https://github.com/vmvtech/esig-suite/blob/main/docs/architecture/esig-mcp.md).

## Requirements

- **Node.js >= 20** (ESM).
- **Chrome or Chromium is needed ONLY to produce the sealed PDF** — the HTML→PDF render at envelope completion. Point at a binary with `ESIG_CHROME_PATH` (or `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH`, checked in that order), or install a system Chrome/Chromium/Edge/Brave and this server finds it automatically. On AWS Lambda or Vercel it uses `@sparticuz/chromium` (an `@e-sig/core` peer dependency) instead — nothing to configure.
- **Everything else works without Chrome.** Creating envelopes, delivering signing links, a human signing from the approval page, `esig_envelope_status`/`esig_list_envelopes`, `esig_verify_document`, `esig_whoami`, `esig_ingest_document`, and `esig_void_envelope` all work with no Chrome installed at all. Only the seal step needs it: if it's unavailable, the server still starts (with a startup warning) and a completed envelope lands in phase `seal_failed` instead of `sealed` — retry once Chrome is available with `esig_reseal`. See ["Sealing, phases, and `esig_reseal`"](#sealing-phases-and-esig_reseal) below.

## 60-second quickstart

See the whole flow work with zero setup — no passphrase to pick, no data directory, no Chrome:

```bash
npx @e-sig/mcp demo --auto
```

That ingests a bundled sample PDF, creates a one-signer envelope in a temp data dir, signs it in-process, and prints the sealed PDF's path plus an `esig_verify_document`-style verdict (`ok`, `classical.digestValid`, `postQuantum.ok`). Drop `--auto` and it prints a real signing URL instead, then waits for you to open it and sign from a browser yourself.

When you're ready to wire this into an agent for real, set up a local data directory:

```bash
npx @e-sig/mcp init
```

`init` creates `./esig-data/{inbox,outbox,blobs}`, writes a `.esig-mcp.env` file (mode `0600`) with a generated `ESIG_MCP_PASSPHRASE` and `ESIG_MCP_DELIVERY=file`, prints an `.mcp.json` snippet with the absolute paths already filled in (see below), and runs the Chrome preflight (`esig-mcp` starts without Chrome either way — see "Requirements" above).

`ESIG_MCP_DELIVERY` has no default (see "Security model" below for why) — `file` (what `init` picks) is the quickstart channel: it writes one JSON file per envelope, containing that envelope's signing link(s), to `<ESIG_MCP_DATA_DIR>/outbox/<envelopeId>.json` (mode `0600`, in a `0700` directory). Open that file to get the link a human signs from.

Prefer to configure it by hand instead of running `init`?

```bash
ESIG_MCP_PASSPHRASE="a passphrase at least 24 characters long" \
ESIG_MCP_DELIVERY=file \
ESIG_MCP_DATA_DIR=./esig-data \
npx @e-sig/mcp
```

Either way, that starts an MCP server over stdio plus a small HTTP approval page.

### Wire it into an MCP client

Claude Desktop (`claude_desktop_config.json`) or a project's `.mcp.json` — this is exactly what `esig-mcp init` prints above, with your own paths already filled in:

```json
{
  "mcpServers": {
    "esig": {
      "command": "esig-mcp",
      "env": {
        "ESIG_MCP_PASSPHRASE": "a passphrase at least 24 characters long",
        "ESIG_MCP_DELIVERY": "file",
        "ESIG_MCP_DATA_DIR": "/absolute/path/to/esig-data"
      }
    }
  }
}
```

### Install in Claude Code / Cursor / VS Code

The one-liners below use `npx -y @e-sig/mcp` so nothing needs a prior global install; swap in `esig-mcp` (the package's own bin) once you've `npm install -g @e-sig/mcp` or run `esig-mcp init` as above. All three need the same three environment variables as the snippet above: `ESIG_MCP_PASSPHRASE`, `ESIG_MCP_DELIVERY`, `ESIG_MCP_DATA_DIR`.

**Claude Code:**

```bash
claude mcp add esig \
  -e ESIG_MCP_PASSPHRASE="a passphrase at least 24 characters long" \
  -e ESIG_MCP_DELIVERY=file \
  -e ESIG_MCP_DATA_DIR=/absolute/path/to/esig-data \
  -- npx -y @e-sig/mcp
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "esig": {
      "command": "npx",
      "args": ["-y", "@e-sig/mcp"],
      "env": {
        "ESIG_MCP_PASSPHRASE": "a passphrase at least 24 characters long",
        "ESIG_MCP_DELIVERY": "file",
        "ESIG_MCP_DATA_DIR": "/absolute/path/to/esig-data"
      }
    }
  }
}
```

**VS Code** (`.vscode/mcp.json` — note the root key is `servers`, not `mcpServers`, and each entry needs its own `type`):

```json
{
  "servers": {
    "esig": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@e-sig/mcp"],
      "env": {
        "ESIG_MCP_PASSPHRASE": "a passphrase at least 24 characters long",
        "ESIG_MCP_DELIVERY": "file",
        "ESIG_MCP_DATA_DIR": "/absolute/path/to/esig-data"
      }
    }
  }
}
```

The demo flow: an agent drafts an NDA with `esig_create_envelope`, a human opens the signing link from your configured delivery channel (the `file` outbox JSON in the quickstart above) and signs from their phone, the agent polls `esig_envelope_status` and files the sealed PDF, and anyone — agent or human — can later confirm it with `esig_verify_document`.

## Tools

There is no tool that signs — `esig_sign_as_agent` and `esig_cosign_start` (modes A/C) are v0.2, gated behind a RedTeam review, and this server refuses to even start if `ESIG_MCP_MODES` asks for them.

### Sign an existing PDF (no Chrome needed)

`esig_create_envelope` accepts **exactly one of `html` or `docId`**. Pass `docId` — a docId returned by `esig_ingest_document` — to create a **PDF envelope**: the signer reviews and signs the *exact ingested bytes* (WYSIWYS — What You See Is What You Sign), served from `GET /sign/<token>/document.pdf` and shown in a plain same-origin iframe on the approval page (the sandboxed `srcdoc` iframe an HTML envelope uses cannot host a PDF viewer). At seal time this server signs those same bytes directly — **no HTML rendering, so no Chrome anywhere on this path**.

```js
const ingested = await client.callTool({ name: "esig_ingest_document", arguments: { path: "./contract.pdf" } });
const { docId } = JSON.parse(ingested.content[0].text);

await client.callTool({
  name: "esig_create_envelope",
  arguments: { title: "Contract", docId, signers: [{ name: "Alice", email: "alice@example.com" }] },
});
```

`esig_create_envelope`/`esig_envelope_status`/`esig_list_envelopes` all expose a `document: {docId, sha256, size, kind:"pdf"}` field for a PDF envelope (absent for an HTML envelope). Everything else — signer order, tokenized links, the drawn-signature approval flow, `esig_reseal`, signer identity (below) — works identically to an HTML envelope; core itself is unchanged, since a PDF envelope's underlying `html` is a generated cover sheet (title, docId, sha256, byte size, signer list) that drives the same token/order/`recordSignature` flow.

| Tool | Kind | What it does |
|---|---|---|
| `esig_verify_document` | read | Verify a PDF's classical signature and, if present, its post-quantum seal. Accepts `path` (confined to `ESIG_MCP_DOCS_ROOT`), `base64`, or a prior `docId`. |
| `esig_envelope_status` | read | Look up one envelope's status, phase, per-signer state (including verified identity, if any — see below), seal state, and sealed PDF path once sealed. |
| `esig_list_envelopes` | read | List envelopes for this server's tenant, optionally filtered by status. |
| `esig_whoami` | read | This server's tenant, enabled modes, caps, seal readiness, and public cert/PQ fingerprints. Never key material. |
| `esig_ingest_document` | prepare (audited) | Store PDF bytes in a content-addressed workdir; returns a `docId`, usable as `esig_create_envelope`'s `docId` to sign this exact PDF (no Chrome needed) or as `esig_verify_document`'s `docId`. `path` input is confined to `ESIG_MCP_DOCS_ROOT`. |
| `esig_create_envelope` | prepare (audited) | Create an envelope from exactly one of `html` or `docId` (a PDF, see below) + a signer list; dispatches signing links through the configured delivery channel. Never returns a raw link unless `ESIG_MCP_RETURN_LINKS=1`. Optionally requires signer identity — see below. |
| `esig_void_envelope` | prepare (audited) | Cancel a pending or partially-signed envelope. |
| `esig_reseal` | prepare (audited) | Retry producing the sealed PDF for a completed envelope whose seal step failed or never ran (phase `seal_failed` / `awaiting_seal`). Refused if the envelope isn't completed yet, or is already sealed. |
| `esig_identity_challenge` | prepare (audited) | Issue (or re-issue) the sole-control challenge a signer's wallet/agent signs to satisfy an envelope's identity requirement — see "Signer identity" below. |

Every tool's own `description` (visible to any connected agent) documents its exact input/output contract in more detail than this table.

## Sealing, phases, and `esig_reseal`

An envelope's `phase` (returned by `esig_envelope_status` and `esig_list_envelopes`) is a finer-grained view than `status` alone:

| Phase | Meaning |
|---|---|
| `sent` | Created; no signer has signed yet. |
| `partially_signed` | At least one signer has signed; not everyone yet. |
| `awaiting_seal` | Every signer has signed; the seal step hasn't run yet. |
| `sealed` | Every signer has signed and the sealed PDF was produced — `sealedPdfUrl` is set. |
| `seal_failed` | Every signer has signed, but the seal step failed (most commonly: no Chrome/Chromium available). The signature itself is still validly recorded — nothing is lost. |
| `voided` | Cancelled via `esig_void_envelope`. |
| `expired` | Past its `expiresAt` with signatures still outstanding. |

**A seal failure never strands a signature.** The moment every signer has signed, this server attempts to render, cryptographically sign, and store the final PDF. If that attempt fails — no Chrome, a transient render crash, anything — the failure is caught, recorded on the envelope (`esig_envelope_status`'s `seal` field: `{status:"failed", error, attempts, lastAttemptAt}`), and audited as `envelope.seal_failed`. It is **not** treated as a signing error: the signature each signer drew was already durably recorded before the seal step ever runs, so `POST /sign` on the approval page still responds `202` (not `500`) with:

```json
{ "status": "signed", "envelopeId": "...", "sealed": false, "message": "Your signature is recorded. The operator will produce the sealed PDF." }
```

and a human re-visiting `GET /sign/<token>` afterwards sees that same sentence instead of "every signer has signed."

Once the underlying problem is fixed (Chrome installed, `ESIG_CHROME_PATH` pointed at a working binary, etc.), call `esig_reseal(envelopeId)` to retry. It re-composes the envelope from what's stored (nothing needs to be re-signed), re-renders, re-signs, and re-verifies; on success the envelope reaches phase `sealed` and `envelope.completed` is audited exactly once, for that successful attempt. Calling it on an already-`sealed` envelope is refused with a clear error.

## Signing over HTTP (the approval page)

`GET /sign/<token>` renders the human-facing approval page: the envelope HTML inside a fully sandboxed iframe, the signer's gate state (whose turn it is, or why not), and — only when it's that signer's turn — a signature pad.

`POST /sign/<token>` records a drawn signature. Request body:

```json
{ "signatureImageDataUrl": "data:image/png;base64,...", "consent": true, "identityProof": { "uuaid": "...", "proof": { ... } } }
```

`identityProof` is required only when the envelope's identity policy is above `none` (see "Signer identity" below) — omit it entirely otherwise.

Responses:

- **`200`** — signed; `{status, envelopeId, completed, sealedPdf}`. `sealedPdf` is set once the envelope reaches phase `sealed` (immediately, if this was the last signer and sealing succeeded).
- **`202`** — signed, but not yet sealed (phase `seal_failed` or `awaiting_seal` — see above); `{status:"signed", envelopeId, sealed:false, message}`. Not an error — the signature is recorded; an operator retries with `esig_reseal`.
- **`403`** — `identityProof` was required and missing, malformed, or failed verification; `{error, reason}` (`reason` is a short machine-checkable code, e.g. `L1_PROOF_INVALID`).
- **`4xx`** (other) — the token is invalid, expired, already used, out of turn, or the request body failed validation.

## Signer identity (UUAID + IAASO)

Bind *who signed* to a verifiable identity, without inventing a new identity system: [UUAID](https://uuaid.org) identifiers and IAASO TAE assurance levels (ADR-006). Off by default (v0.1 behavior, unchanged) — set it per envelope, per server floor, or both. Full design: [`docs/architecture/esig-mcp.md` §12](https://github.com/vmvtech/esig-suite/blob/main/docs/architecture/esig-mcp.md#12-signer-identity-via-uuaid--iaaso-v02-design-2026-08-27).

**Read this plainly (docs honesty):** `L0` and `L1` bind a `uuaid` to a
signer only by **self-assertion** — the signer says "this uuaid is mine,"
and at `L1` proves they control a specific key, but nothing checks that
claim against anything outside this request. Only `L2` actually verifies
the key↔`uuaid` binding, against the UUAID registry. Treat `L1` as "sole
control of a key, self-asserted identity," not as "verified identity."

| Level | What's checked | Cryptographic proof? | Key↔uuaid binding verified? | Network call? |
|---|---|---|---|---|
| `none` | Nothing (default). | No | — | No |
| `L0` | The signer's `uuaid` is well-formed, and — if this envelope pinned an expected `uuaid` for this signer at creation — matches it. | No | No (self-asserted) | No |
| `L1` | The signer presents an `eddsa-jcs-2022` `DataIntegrityProof` over a server-issued, single-use, 15-minute sole-control challenge, verified locally against the key in `proof.verificationMethod`. | Yes (Ed25519) | **No (self-asserted)** — proves the signer controls *a* key, not that the key belongs to the claimed `uuaid` | No |
| `L2` | L1, plus: the registry's SIGNED badge (`GET /iaaso/v1/badge/{uuaid}` — `GET /resolve/{uuaid}` carries no key material at all) must verify against the pinned `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` (the registry's Ed25519 public key, 64 hex chars — hash binding + Ed25519 signature + freshness), its `subject.presentationKey` (64 hex chars) must equal the proof's key, and its `subject.uuaid` must equal the uuaid being proven (`L2_BADGE_SUBJECT_MISMATCH` otherwise — a badge signed for a *different* subject that happens to share the presentation key does not pass); a tombstoned/absent uuaid (badge `404`) refuses (`L2_UUAID_NOT_FOUND`). If a `credential` is presented, its `credentialSubject.key.publicKey` must equal the proof's key, and `GET /verify/{credentialId}` must say `valid && active && notExpired` with `agent_uuaid` equal to the proving uuaid. A down/unreachable/malformed registry response is a hard failure — this never silently drops to L1. The registry URL is pinned per envelope at creation; a server later reconfigured to a different `ESIG_MCP_UUAID_REGISTRY_URL` refuses (`L2_REGISTRY_URL_CHANGED`) rather than verifying against a different registry than the one the envelope committed to. | Yes | **Yes** — via the registry | Yes |

**Requiring it.** Pass `identity` to `esig_create_envelope`:

```json
{
  "title": "NDA",
  "html": "<p>...</p>",
  "signers": [{ "name": "Alice", "email": "alice@example.com" }],
  "identity": { "minLevel": "L1", "signers": [{ "index": 0, "uuaid": "uuaid:foundation:agent:<uuid>" }] }
}
```

`minLevel` may only **raise** this server's `ESIG_MCP_IDENTITY_MIN_LEVEL` floor for that one envelope, never lower it. The per-signer `uuaid` pin is optional even when `minLevel` is set.

**Obtaining a challenge.** Two equivalent paths — a sender-side agent uses the MCP tool to relay the challenge to the signer's own wallet/agent (the IAASO agent-to-agent exchange path); the signer's own browser session uses the HTTP endpoint directly:

- MCP: `esig_identity_challenge(envelopeId, signerId)`
- HTTP: `GET /sign/<token>/challenge` (same gate states as `GET /sign/<token>` — `409` if it isn't this signer's turn yet, `404` for an unknown token)

Both return the same shape, and — issued within TTL, before a valid proof consumes the nonce — **the same live challenge, byte-identical, on repeat calls** (idempotent re-issue): a fresh nonce is only ever minted when the prior one is missing, consumed, or expired, so reloading the approval page or racing a sender-side relay against the signer's own page load never silently invalidates a challenge someone already started signing:

```json
{ "type": "esig-signer-challenge/v1", "envelopeId": "...", "signerId": "...", "htmlSha256": "...", "nonce": "...", "issuedAt": "...", "expiresAt": "..." }
```

The challenge is **not secret** — it's bound to this envelope, signer, and content digest, and single-use once a valid proof consumes its nonce; what matters is the proof over it.

**Producing a proof.** Any Ed25519 keypair + `did:key` verification method works — no SDK required (`@e-sig/uaid-exch`'s helpers, or plain `node:crypto`):

```js
import { createPublicKey, createPrivateKey, sign as ed25519Sign, generateKeyPairSync } from "node:crypto";
import { encodeMultibase, jcsBytes } from "@e-sig/uaid-exch";

// Generate once, keep the private key; publish/register the did:key.
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPublic = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
const did = `did:key:${encodeMultibase(Buffer.concat([Buffer.from([0xed, 0x01]), rawPublic]), "z")}`;

// challenge = the exact JSON GET /sign/<token>/challenge (or esig_identity_challenge) returned.
function proveIdentity(challenge) {
  const signature = ed25519Sign(null, jcsBytes(challenge), privateKey);
  return {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: new Date().toISOString(),
    verificationMethod: `${did}#${did.slice("did:key:".length)}`,
    proofPurpose: "authentication",
    proofValue: encodeMultibase(signature, "z"),
  };
}

// POST /sign/<token>:
// { signatureImageDataUrl, consent: true, identityProof: { uuaid: "uuaid:...", proof: proveIdentity(challenge) } }
```

**Proof options aren't signed bytes.** `proof.created` (and `verificationMethod`/`proofPurpose`) live in the proof envelope, not in what's cryptographically signed: verification here signs `jcsBytes(challenge)` directly, diverging by construction from the W3C `eddsa-jcs-2022` double-hash cryptosuite, which would additionally hash the proof options in (see `@e-sig/uaid-exch`'s `verify.ts` module header for the full rationale). So `created` is convenience metadata a relay could alter without touching anything that gets checked. `proofDigest` (below) still covers the *entire* `proof.proof` object — `created` included — but as a `jcsBytes(proof.proof)` checksum of what was presented, not a re-derivation of the signed bytes; it's an audit anchor, not proof that `created` itself was signed.

**What gets recorded.** Per signer, once verified: `{level, uuaid, keyFingerprint, proofDigest, credentialDigest?, verifiedAt, registry?: {resolvedAt, credentialId?, credentialValid?, registrySnapshotDigest?}}` — surfaced in `esig_envelope_status`/`esig_list_envelopes`'s `signers[].identity`, audited as `signer.identity_verified` (a rejection audits `signer.identity_rejected` with `{reason, uuaid?, level}` instead), included in both the `file` outbox creation receipt and the completion receipt (`<envelopeId>.completed.json`, written on `sealed`/`seal_failed` regardless of delivery channel), and appended as an escaped "Identity attestations" line per verified signer to the composed HTML **before** it is sealed — so it's part of the signed PDF. The digests (`proofDigest`, `credentialDigest`, `registrySnapshotDigest`) name the exact content-addressed blob (`blobs/identity/<digest>.json`) the corresponding raw artifact — proof JSON, the presented credential JSON, the registry's signed badge response — is persisted to; only the digests/identifiers ever reach audit metadata (PII minimization), never the raw artifacts. The operator's own post-quantum seal never carries a signer's `uuaid` — that assertion is the operator's, not theirs.

**L2 registry trust (G8, corrected — pinned-key, not TOFU, for the attestation itself).** `ESIG_MCP_UUAID_REGISTRY_URL` must be `https://` (no exception — unlike the webhook delivery channel, this URL is queried by the server itself on every L2 check, not a one-time operator-chosen receiver). The registry's badge is verified against `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` — the registry's pinned Ed25519 public key (64 hex chars, from its `/.well-known/uuaid-registry.json`) — via hash binding, an Ed25519 signature, and freshness, so trust in the badge itself rests on that pin, not on TLS alone. What's still trust-on-first-use (TOFU) is *which* registry an envelope trusts at all, beyond the per-envelope URL pin at creation (G3, above: a later reconfiguration to a different registry URL is refused, but the FIRST registry an envelope's identity policy commits to is trusted as given). Every badge response is snapshotted verbatim into a content-addressed blob (`blobs/identity/<sha256>.json`) with the verification record's `registry.registrySnapshotDigest` referencing it, so the URL's TOFU decision is at least auditable after the fact even though it isn't pinned in advance.

## Data directory layout

Everything this server persists lives under `ESIG_MCP_DATA_DIR` (default `./.esig-mcp`), created at startup along with three subdirectories:

| Path | What lives there |
|---|---|
| `certs.json` | The tenant's signing cert(s), private key AES-256-GCM-encrypted at rest under `ESIG_MCP_PASSPHRASE`. |
| `envelopes.json` | Every envelope, its signers, and their signature images. |
| `audit-log.ndjson` | Append-only audit trail — one JSON row per line. |
| `pq-keys.json` | The tenant's post-quantum key bundle, encrypted at rest (present when `ESIG_MCP_PQ` is on). |
| `inbox/` (`ESIG_MCP_DOCS_ROOT`) | Where a caller-supplied `path` input to `esig_verify_document` / `esig_ingest_document` is confined — never an absolute path outside it, a `..` segment, or a symlink escaping it. |
| `outbox/` | `<envelopeId>.json` — the CREATION receipt (signing links), written only when `ESIG_MCP_DELIVERY=file`. `<envelopeId>.completed.json` — a COMPLETION receipt (R2), written on every terminal seal outcome (`sealed`/`seal_failed`) **regardless of delivery channel**, containing each signer's identity record if any. Both mode `0600`, in a `0700` directory. |
| `blobs/` | Sealed PDFs (`<tenant>/<envelopeId>/sealed.pdf`, stored by `esig_reseal`/the automatic seal step), and — under `identity/` — content-addressed signer-identity artifacts (proof JSON, presented credential JSON, registry signed-badge snapshots), named `<sha256-digest>.json`, the same digest recorded in `signers[].identity`. |
| `documents/` | Content-addressed workdir for `esig_ingest_document` (docId = sha256 of the bytes) — separate from `inbox/`: this is where *this server* stores bytes it accepted, not where a caller's `path` input is confined. |

`inbox/`, `outbox/`, and `blobs/` are all created empty at startup, before any tool is ever called — the "ready" line on stderr prints their absolute paths.

## Security model

Full threat model: design doc §2. In plain words, the three invariants this package is built around:

- **T1 — an agent can't sign something no human saw.** `esig_create_envelope` mints signing tokens and hands them straight to your configured delivery channel (`file` outbox, `console`, or `webhook` — there is no default); the MCP result the agent gets back contains signer names and delivery receipts, never the token or the `/sign/<token>` link. Set `ESIG_MCP_RETURN_LINKS=1` only for a local demo where you are both the agent and the signer — it is loud on purpose (a warning is written every time it fires) and every affected audit row records that it was on.
- **T2 — the document a human signs is the document that gets sealed.** An envelope's HTML is fixed at creation; no tool can edit it afterwards. Its sha256 is pinned at creation and re-checked immediately before every seal attempt (initial or `esig_reseal`), so a corrupted store (this package's own, or a future one) fails loudly instead of silently sealing something else.
- **T9 — agent-authored HTML can't attack the signer's browser.** Two independent layers: `<script>` tags, `on*=` event handlers, `javascript:` URLs, and `<iframe>/<object>/<embed>/<form>` are stripped from envelope HTML before it is ever stored; and the approval page only ever renders that HTML inside a fully sandboxed `<iframe sandbox srcdoc="…">` — no `allow-scripts`, no `allow-same-origin`, no forms — behind a `Content-Security-Policy: default-src 'none'` baseline whose own inline `<script>` (the signature pad) runs under a fresh, per-response nonce rather than `'unsafe-inline'`.
- **G1 — the seal render can't be turned into SSRF.** JavaScript-off (core's default for the HTML→PDF render) stops scripts, not resource loading: a plain `<img>`, `<link rel=stylesheet>`, CSS `url()`, `<object>`, or `<meta http-equiv=refresh>` in agent-authored envelope HTML would otherwise still reach the network from the *operator's own machine* — the one holding the signing keys — at the moment the document is sealed, and whatever it fetches gets baked into the *signed* PDF. The seal-time Chrome launch always carries `--host-resolver-rules=MAP * ~NOTFOUND` (`SEAL_RENDER_LAUNCH_ARGS`), which fails every hostname/IP lookup the renderer could make while leaving `data:` URLs (the signature image) untouched — measured 6/6 SSRF vectors blocked with the rule, 0/6 without it.
- **G3 — the default delivery channel can't hand the signing capability to the agent.** `ESIG_MCP_DELIVERY` has **no default** — you must pick one. The channel this package used to default to, `console`, prints signing links to stderr; in the canonical stdio MCP deployment, stderr is captured straight into the connecting agent harness's own log. Since a signing link IS the signing capability (`POST /sign/<token>` needs no browser), a silent console default would have handed T1/T8's exact threat — the untrusted agent signing something no human reviewed — a working bypass. `console` still exists, but it's opt-in only, prints a loud startup warning every time it's selected, and every `envelope.created` audit row records which channel was actually used (and any per-signer delivery failure) regardless of channel.

Link custody, end to end: a raw signing token exists in exactly one place outside the envelope store — the delivery channel you configured (the `file` outbox, console output, or your webhook). No MCP tool ever returns it, no HTTP response ever logs it, and the approval page's own JavaScript reads it only from the URL the browser already has (it does not need to be told).

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `ESIG_MCP_PASSPHRASE` | *(required)* | Encrypts the tenant's signing cert + PQ key bundle at rest. Must be at least 24 characters — matching `@e-sig/core`'s own encryption floor exactly, so a passphrase that passes this check never later throws at first seal. |
| `ESIG_MCP_DELIVERY` | *(required)* | `file` (writes `<ESIG_MCP_DATA_DIR>/outbox/<envelopeId>.json`, mode `0600` — the quickstart channel), `console` (prints links to stderr — opt-in only, loud startup warning; see "Security model" above), or `webhook`. No default: an operator must pick where signing links go. |
| `ESIG_MCP_MODES` | `H` | Comma-separated. Only `H` is implemented in v0.1 — anything containing `A` or `C` refuses to start. |
| `ESIG_MCP_DATA_DIR` | `./.esig-mcp` | Root for the filesystem-backed stores — see "Data directory layout" above. Created at startup. |
| `ESIG_MCP_DOCS_ROOT` | `<ESIG_MCP_DATA_DIR>/inbox` | Confines the `path` input on `esig_verify_document` / `esig_ingest_document` — a connected agent is untrusted by default, so a caller-supplied filesystem path may only resolve inside this directory (never an absolute path outside it, a `..` segment, or a symlink escaping it). Created at startup. |
| `ESIG_MCP_TENANT` | `default` | Partition key for certs/keys/envelopes. |
| `ESIG_MCP_SUBJECT_NAME` | `e-sig MCP` | Signing cert subject CN. |
| `ESIG_MCP_HTTP_HOST` | `127.0.0.1` | Approval-page bind host. |
| `ESIG_MCP_HTTP_PORT` | `7433` | Approval-page bind port. |
| `ESIG_MCP_BASE_URL` | derived from host:port | Base URL signing links are built from. Set this to a real, reachable URL for anything beyond `localhost`. |
| `ESIG_MCP_RETURN_LINKS` | off | Set to exactly `1` to include raw signing links in `esig_create_envelope`'s result. Local demos only — see T1 above. |
| `ESIG_MCP_DELIVERY_WEBHOOK_URL` | — | Required when `ESIG_MCP_DELIVERY=webhook`. Must be `https://` unless `ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1`. |
| `ESIG_MCP_ALLOW_INSECURE_WEBHOOK` | off | Set to exactly `1` to allow a plain `http://` `ESIG_MCP_DELIVERY_WEBHOOK_URL` (e.g. a trusted loopback receiver). Leave unset for anything reachable over a real network — the signing link is the signing capability. |
| `ESIG_MCP_PQ` | on | Set to `0` to disable the hybrid Ed25519 + ML-DSA-65 post-quantum seal at completion. |
| `ESIG_MCP_MAX_HTML_BYTES` | `524288` (512 KiB) | Envelope HTML size cap. |
| `ESIG_MCP_MAX_PDF_BYTES` | `26214400` (25 MiB) | Ingested/sealed PDF size cap. |
| `ESIG_MCP_ENVELOPES_PER_HOUR` | `60` | Per-process rate limit on envelope creation, `esig_reseal`, and `esig_identity_challenge` (each under its own bucket). |
| `ESIG_MCP_IDENTITY_MIN_LEVEL` | `none` | Signer-identity floor: `none` \| `L0` \| `L1` \| `L2` — see "Signer identity" above. `esig_create_envelope` may only *raise* this per envelope. |
| `ESIG_MCP_UUAID_REGISTRY_URL` | — | `https://` UUAID registry base URL. Required when `ESIG_MCP_IDENTITY_MIN_LEVEL=L2`, or when any envelope itself requests `L2`. |
| `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` | — | The registry's pinned Ed25519 public key — 64 lowercase hex chars, `keys[].publicKey` (`uuaid-registry-1`) from the registry's `GET /.well-known/uuaid-registry.json`. Every registry-signed badge (`GET /iaaso/v1/badge/{uuaid}`) is verified against this pin before anything in it is trusted. Required when `ESIG_MCP_IDENTITY_MIN_LEVEL=L2`, or when any envelope itself requests `L2`. |
| `ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC` | `900` | Sole-control challenge lifetime, in seconds. Max `3600`. |
| `ESIG_CHROME_PATH` / `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH` | unset (auto-detect) | Override the Chrome/Chromium executable used to seal envelopes, checked in that order; falls back to a platform scan (or `@sparticuz/chromium` on Lambda/Vercel) when unset. Only needed for sealing — see "Requirements" above and `esig_whoami`'s `sealReady`. |

## v0.2 roadmap

- **Mode A** — the server signs as a dedicated agent identity (never the operator's primary cert), for low-stakes or machine-to-machine documents. Gated by policy (allowlist, size cap, hourly cap) and a RedTeam review before it ships.
- **Mode C** — dual-key co-sign: an envelope with both an agent signer and a human signer, completing only once both have signed.
- Supabase-backed audit chain, envelope-completion webhooks, and anchoring the tenant audit chain head to UUAID's Polygon-anchored ledger.
- **Signer identity L2 exchange submission + receipt** (phase 2): submit the verified exchange to the UUAID Network and store the anchored receipt; staple the signer-identity manifest into the sealed PDF itself as an append-only incremental update, so `esig_verify_document` can surface it offline.

Signer identity (UUAID + IAASO, levels `none`/`L0`/`L1`/`L2`) already shipped — see above; only L2's exchange-submission/receipt leg and PDF-native stapling remain.

See design doc §8 and §12 for the full rollout plan.
