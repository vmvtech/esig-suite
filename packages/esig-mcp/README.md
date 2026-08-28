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
| `esig_send_reminder` | prepare (audited) | Resend a signing reminder to a pending signer (or every pending signer) — see "Email delivery and reminders" below. |
| `esig_list_events` | read | List an envelope's lifecycle events, oldest first (`since` filters to events after a given timestamp) — see "Lifecycle events and webhooks" below. |

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
| `L1p` | Like `L1`, plus: when the signer's `uuaid` is `uuaid:foundation:agent:<localId>` ([Pillar](https://uuaid.org)'s self-authenticating identity form — see "Pillar (agent-to-agent) delivery" below), `localId` must equal `localIdFromEd25519Key(proof key)` — the uuaid derives from the key **by construction**, no registry needed. A `foundation:agent`-shaped `uuaid` whose local id does NOT derive from the proof key is refused (`L1P_KEY_UUAID_MISMATCH`) — never silently accepted as plain `L1`. When a UUAID registry happens to be configured and carries a badge for the same `uuaid`, a disagreeing `presentationKey` is refused too (`L2_L1P_DISAGREEMENT`) — L1p never *requires* the registry, but never silently ignores it either. | Yes (Ed25519) | **Yes, by construction** — the key derives the uuaid; no third party attests it | No |
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

## Email delivery and reminders

Set `ESIG_MCP_DELIVERY=email` to dispatch each signer's tokenized link as an email instead of the `file` outbox, `console`, or `webhook` channels above.

```bash
ESIG_MCP_DELIVERY=email
ESIG_MCP_EMAIL_TRANSPORT=smtp   # or "ses"
ESIG_MCP_EMAIL_FROM="Acme <noreply@acme.com>"

# smtp:
ESIG_MCP_SMTP_HOST=smtp.example.com
ESIG_MCP_SMTP_PORT=587          # 465 implies implicit TLS even without ESIG_MCP_SMTP_SECURE=1
ESIG_MCP_SMTP_USER=...
ESIG_MCP_SMTP_PASS=...

# ses (needs the optional peer dependency @aws-sdk/client-sesv2 installed):
ESIG_MCP_SES_REGION=us-east-1
```

| Variable | Default | Notes |
|---|---|---|
| `ESIG_MCP_EMAIL_TRANSPORT` | — | Required: `smtp` or `ses`. |
| `ESIG_MCP_EMAIL_FROM` | — | Required. `"Name <addr>"` or a bare address — also the envelope's SMTP sender. |
| `ESIG_MCP_EMAIL_REPLY_TO` | — | Optional `Reply-To`. |
| `ESIG_MCP_EMAIL_SUBJECT_PREFIX` | — | Optional: subjects become `"[prefix] Please sign: <title>"`. |
| `ESIG_MCP_SMTP_HOST` / `ESIG_MCP_SMTP_PORT` | — / `587` | `smtp` transport only. |
| `ESIG_MCP_SMTP_USER` / `ESIG_MCP_SMTP_PASS` | — | Both set or both unset. Never logged, never in a tool result or audit row. |
| `ESIG_MCP_SMTP_SECURE` | off | `1` for implicit TLS from connect (also implied automatically by port `465`). |
| `ESIG_MCP_SMTP_ALLOW_PLAINTEXT` | off | `1` to skip STARTTLS entirely. STARTTLS is required by default — TLS certificate verification is always on. |
| `ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS` | off | `1` to skip SMTP server certificate verification against the system CA (`rejectUnauthorized:false`). Leave unset — verification is on by default; a startup WARNING is printed whenever this is set. |
| `ESIG_MCP_SES_REGION` | — | `ses` transport only. |

**Transports.** `smtp` is dependency-free (`node:net`/`node:tls` only — EHLO, STARTTLS, AUTH PLAIN with AUTH LOGIN fallback, `MAIL FROM`/`RCPT TO`/`DATA` with CRLF normalization and RFC 5321 dot-stuffing). `ses` calls SESv2 `SendEmail` through `@aws-sdk/client-sesv2`, loaded with a dynamic `import()` — it is an **optional peer dependency this package never installs**; without it, `ESIG_MCP_EMAIL_TRANSPORT=ses` fails at first send with a clear `npm install @aws-sdk/client-sesv2` error, not a silent no-op.

**What the email contains.** Plain text + minimal HTML: the envelope title, the configured from-address (shown in the body, separately from the SMTP `From:` header itself), an optional sender note (`esig_create_envelope`'s `message`, ≤ 500 chars), the signing link, and the expiry if one was set. It never contains the document body or any other signer's details — those never reach `templates.ts` in the first place. Title/note are stripped of control characters (SMTP header injection) and HTML-escaped; subjects are `"[prefix] Please sign: <title>"`.

**Reminders (`ESIG_MCP_REMINDERS`).** Requires `ESIG_MCP_DELIVERY=email` — refused at startup otherwise, since there is no other channel to resend the original link through.

```bash
ESIG_MCP_REMINDERS=24h,72h   # durations after the envelope was created; default off (none)
ESIG_MCP_REMINDER_MAX=3      # hard cap per signer, independent of how many durations are configured
```

An in-process 60-second tick sends a reminder to each still-`pending` signer whose next scheduled reminder is due, skipping voided/expired/completed envelopes entirely; the send history is persisted per signer so a restart resumes rather than re-sends. `esig_send_reminder(envelopeId, signerId?)` sends one on demand (a specific signer, or every pending signer when `signerId` is omitted) — audited (`envelope.reminder_sent`) and rate-limited under its own `"reminder"` bucket, separate from the scheduler's own send (which is throttled by the schedule + `ESIG_MCP_REMINDER_MAX` instead, so an agent retrying the manual tool can never starve — or be starved by — the automatic reminders a human is waiting on).

**Link persistence — the one custody change.** Core mints each signing token once and never re-mints it, so a reminder needs the *original* link. When reminders are configured, every signer's link is stored **encrypted at rest** (AES-256-GCM, the same `encryptKeyPem`/`decryptKeyPem` helpers `@e-sig/core` already uses for the cert/PQ key bundles, under `ESIG_MCP_PASSPHRASE`) in `envelopes.json`, decrypted **only** inside the reminder-sending path, and never returned by any tool (I8 unchanged — `esig_create_envelope`'s result and `esig_envelope_status` are exactly as link-free as before). This is off entirely — no ciphertext written at all — unless `ESIG_MCP_REMINDERS` is set; a `file`/`console`/`webhook`-delivered envelope with no reminders configured behaves exactly as before.

**Erased once it can never be used again.** A stored link is deleted the moment the state it exists to resend has passed: per-signer the moment that signer signs, and for the whole envelope on decline/void/expiry/completion — the ciphertext never outlives its purpose. If a prior run had reminders configured and this run doesn't, any links that run left behind are purged once, on the scheduler's first tick.

## Lifecycle events and webhooks

Every state change on an envelope appends an event to its log (`metadata.mcp.events[]`, capped at 200 — oldest trimmed off, their ids recorded in an `events.trimmed` audit row). `esig_envelope_status` returns the last 10; `esig_list_events(envelopeId, since?)` returns them all, oldest first, each carrying its webhook delivery status when a webhook is configured.

| Event | Fires when |
|---|---|
| `envelope.created` | `esig_create_envelope` succeeds. |
| `envelope.viewed` | `GET /sign/<token>` first resolves `"ok"` for a given signer (once per signer). |
| `envelope.signed` | A signer's signature is recorded. |
| `envelope.declined` | A signer declines (see "Decline" below). |
| `envelope.completed` | Every signer has signed (core's own status transition — independent of whether sealing then succeeds). |
| `envelope.sealed` / `envelope.seal_failed` | The seal step (automatic, or `esig_reseal`) succeeds or fails. |
| `envelope.voided` | `esig_void_envelope`. |
| `envelope.expired` | Emitted once, by a lazy 60-second tick — core itself expires an envelope lazily on token resolution, but never touches the event log; the tick catches every envelope nobody happened to poll. |
| `envelope.reminder_sent` | A reminder (automatic or `esig_send_reminder`) is sent. |
| `signer.identity_verified` / `signer.identity_rejected` | A signer identity check (§ "Signer identity" above) passes or fails. |

Every event is `{id, type, createdAt, envelopeId, phase, signer?: {signerId, name, email, status}, data}`. `data` — and every other field — **never contains a signing link, token, proof, or document byte**; that rule applies identically to the webhook payload below.

**Decline.** The approval page gains a "Decline to sign" control (reason optional, ≤ 500 characters, control characters stripped) — `POST /sign/<token>/decline {reason?}` calls core's `declineEnvelope`, which marks the signer `declined` and voids the whole envelope in one step, exactly like a sender-side void except attributable to a specific signer. Deliberately **not** an MCP tool — same reasoning as signing itself (human-side only).

**Webhook delivery.** Set `ESIG_MCP_EVENTS_WEBHOOK_URL` + `ESIG_MCP_EVENTS_WEBHOOK_SECRET` (both required together, secret ≥ 32 characters; operator config only — no tool can ever set or change it) to POST every event as JSON to your receiver:

```bash
ESIG_MCP_EVENTS_WEBHOOK_URL=https://your-app.example.com/esig-events
ESIG_MCP_EVENTS_WEBHOOK_SECRET="a random secret, at least 32 characters"
```

```json
{
  "id": "5c8e2b3e-...",
  "type": "envelope.signed",
  "createdAt": "2026-08-28T12:00:00.000Z",
  "envelopeId": "e1a9...",
  "phase": "partially_signed",
  "signer": { "signerId": "s1...", "name": "Alice", "email": "alice@example.com", "status": "signed" },
  "data": {}
}
```

Every request carries `Content-Type: application/json`, `User-Agent: esig-mcp/<version>`, `X-Esig-Event-Id`, `X-Esig-Timestamp` (ISO-8601), and `X-Esig-Signature: sha256=<hex>` — an HMAC-SHA256 over `timestamp + "." + body`, keyed by `ESIG_MCP_EVENTS_WEBHOOK_SECRET`. Verify it (Node, `node:crypto`), reject anything older than 5 minutes, and **dedupe by `X-Esig-Event-Id`** within that same replay window — at-least-once delivery (below) means a retried event can legitimately arrive twice with an identical id and signature:

```js
import crypto from "node:crypto";

// Swap for a real store (Redis, a DB row with a TTL, ...) in production —
// this Map is a same-process example only.
const seenEventIds = new Map(); // eventId -> firstSeenAtMs
const REPLAY_WINDOW_MS = 5 * 60_000;

function verifyEsigWebhook(req, rawBody, secret) {
  const timestamp = req.headers["x-esig-timestamp"];
  const signature = req.headers["x-esig-signature"];
  const eventId = req.headers["x-esig-event-id"];
  const expected = "sha256=" + crypto.createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");
  const ok = signature.length === expected.length && crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  if (!ok) throw new Error("bad signature");
  if (Math.abs(Date.now() - Date.parse(timestamp)) > REPLAY_WINDOW_MS) throw new Error("stale timestamp");

  for (const [id, seenAt] of seenEventIds) if (Date.now() - seenAt > REPLAY_WINDOW_MS) seenEventIds.delete(id);
  if (seenEventIds.has(eventId)) return { duplicate: true }; // already processed — ack, don't re-apply side effects
  seenEventIds.set(eventId, Date.now());
  return { duplicate: false };
}
```

**At-least-once, with backoff.** Every event is persisted to `<ESIG_MCP_DATA_DIR>/events/queue/<eventId>.json` **before** any delivery attempt — enqueuing never blocks or delays the signer-facing HTTP handlers; a separate loop delivers in order, per envelope. A non-2xx response, a timeout (10s), or **any 3xx redirect** (redirects are never followed — `redirect: "error"`) counts as a failure and is retried with exponential backoff (1m → 2m → 4m → 8m → 16m → 32m, up to 6 attempts), after which the event is parked `dead` (audited `webhook.dead_lettered`, visible via `esig_list_events`) — delivery is restart-safe (the queue directory is re-scanned from scratch on every pass, so nothing is lost across a restart).

**SSRF / private-range policy (T18).** `ESIG_MCP_EVENTS_WEBHOOK_URL` must be `https://` unless `ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK=1` — its **own** flag, deliberately separate from `ESIG_MCP_ALLOW_INSECURE_WEBHOOK` (the `webhook` *delivery* channel's own flag, above): relaxing one can never silently relax the other. Both `ESIG_MCP_EVENTS_WEBHOOK_URL` and `ESIG_MCP_DELIVERY_WEBHOOK_URL` are refused **at startup** (not only at send time) if they resolve to a private/local address, unless `ESIG_MCP_ALLOW_PRIVATE_WEBHOOK=1`. Before **every** send, the target host is resolved fresh (`dns.promises.lookup`, all addresses) and refused if any address is loopback, link-local (`169.254.0.0/16` — this covers the cloud-metadata address too — and `fe80::/10`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), unique-local (`fc00::/7`), unspecified (`0.0.0.0`, `::`), or an IPv4-mapped IPv6 literal wrapping any of the above — unless `ESIG_MCP_ALLOW_PRIVATE_WEBHOOK=1` (e.g. for a trusted local receiver in dev). A literal IP in the URL goes through the identical check; there is no separate code path to bypass it. The request then **connects to that exact vetted address**, never letting the HTTP stack re-resolve the hostname itself (a DNS answer that changes between the vetting lookup and the actual connection — DNS rebinding — would otherwise bypass the check entirely); the `Host` header and TLS SNI stay on the original hostname, so certificate validation is unaffected.

## Pillar (agent-to-agent) delivery

Reach a signer that is itself an agent — no inbound HTTP, no email — over [Pillar](https://uuaid.org) (IAASO-3050), UUAID's agent-to-agent communication substrate: signed, end-to-end encrypted envelopes over a store-and-forward carrier. Full design: [`docs/architecture/esig-mcp.md` §17](https://github.com/vmvtech/esig-suite/blob/main/docs/architecture/esig-mcp.md#17-pillar-integration--agent-to-agent-signing-over-uuaids-communication-substrate-design-2026-08-28).

**Requires the optional peer dependency `@e-sig/pillar-bridge`** (`npm install @e-sig/pillar-bridge`) — `@e-sig/mcp` never depends on it, never installs it, and loads it only with a dynamic `import()` the moment it's actually needed (`ESIG_MCP_DELIVERY=pillar` or `ESIG_PILLAR_SUBSCRIBERS` set). A missing install fails startup with one clear error naming the install command — never a silent fallback to a different channel.

**L1p — self-authenticating identity, no bridge needed.** Pillar's own identity is a UUAID in this suite's grammar: `uuaid:foundation:agent:<localId>`, where `localId` derives from the agent's raw Ed25519 public key by construction (`localIdFromEd25519Key`, exported by this package — pure crypto, zero Pillar dependency). Identity level `L1p` (see the ladder table above) checks that derivation during ordinary `L1` verification, whenever a signer's `uuaid` is in that form — so any agent with a Pillar identity gets a *stronger* identity guarantee than plain `L1` for free, whether or not the Pillar bridge is even installed.

**Delivery (`ESIG_MCP_DELIVERY=pillar`).** Pass `signers[].pillar = {uuaid, publicKey}` to `esig_create_envelope` for any signer reachable over Pillar instead of (or alongside) email:

```json
{
  "title": "Vendor agreement",
  "html": "<p>...</p>",
  "signers": [{ "name": "Acquiring Agent", "email": "agent@example.com", "pillar": { "uuaid": "uuaid:foundation:agent:<localId>", "publicKey": "<64 hex>" } }]
}
```

`publicKey` must derive `uuaid` (`localIdFromEd25519Key` — refused otherwise, fail closed); when a UUAID registry is configured (`ESIG_MCP_UUAID_REGISTRY_URL`), its badge for `uuaid` must also attest `publicKey` — a mismatch refuses, and a badge `404` (unregistered) refuses unless `ESIG_MCP_PILLAR_ALLOW_UNREGISTERED=1` opts in (audited `signer.pillar_unregistered`; the approval page shows an "unregistered signer" notice to whoever ends up viewing it). The signing link and sole-control challenge travel as an E2E-encrypted `esig:m` envelope to that signer's own inbox — the sender-side agent still never sees the raw link (I8).

**Identity proof over Pillar (seam 3) — the human just signs.** The recipient agent can reply with a sealed identity proof instead of the human ever pasting JSON: esig-mcp polls its own inbox, runs the SAME verification path `POST /sign`'s `identityProof` uses (challenge nonce binding, `L0`–`L2`, atomic consumption), and stores the result bound to that signer's challenge. When a human later opens the signing link, the approval page shows "Identity verified" instead of a paste panel, and `POST /sign` accepts the signature without `identityProof` at all — audited `signer.identity_preverified_used`. Pasting a proof explicitly still works exactly as before.

**Events over Pillar (seam 4, `ESIG_PILLAR_SUBSCRIBERS`).** Every lifecycle event (§ "Lifecycle events and webhooks" above) is ALSO sealed to configured subscriber agents — independent of which delivery channel is selected:

```json
[{ "uuaid": "uuaid:foundation:agent:<localId>", "publicKey": "<64 hex>" }]
```

A subscriber whose `publicKey` doesn't derive its `uuaid` is refused at startup. A failing subscriber send is isolated (audited `events.sink_failed`) and never blocks another subscriber or the existing webhook queue — both fire independently for the same event.

| Variable | Default | Notes |
|---|---|---|
| `ESIG_PILLAR_HOME` | `<ESIG_MCP_DATA_DIR>/pillar` | Directory for this server's Pillar keychain. |
| `ESIG_PILLAR_PASSPHRASE` | *(required with pillar)* | Encrypts the Pillar keychain at rest. Same `>= 24` character floor as `ESIG_MCP_PASSPHRASE` (RT G4). |
| `ESIG_PILLAR_CARRIERS` | *(required with pillar)* | Comma-separated `https://` store-and-forward carrier URLs. |
| `ESIG_PILLAR_SUBSCRIBERS` | — | Optional JSON array of `{uuaid, publicKey}` — lifecycle-event subscribers (seam 4). Independent of `ESIG_MCP_DELIVERY`. |
| `ESIG_PILLAR_PROOF_POLL` | `1` | Seconds between inbox long-polls for out-of-band identity proofs (seam 3). |
| `ESIG_MCP_PILLAR_ALLOW_UNREGISTERED` | off | Set to exactly `1` to let `esig_create_envelope` proceed when a `signers[].pillar` uuaid has no UUAID registry badge — audited `signer.pillar_unregistered`, surfaced on the approval page. Only meaningful when a registry is configured. |

`ESIG_PILLAR_HOME`/`_PASSPHRASE`/`_CARRIERS` are only actually required when `ESIG_MCP_DELIVERY=pillar` or `ESIG_PILLAR_SUBSCRIBERS` is set — otherwise this whole section, and the `@e-sig/pillar-bridge` dynamic `import()`, is never touched.

## Data directory layout

Everything this server persists lives under `ESIG_MCP_DATA_DIR` (default `./.esig-mcp`), created at startup along with three subdirectories:

| Path | What lives there |
|---|---|
| `certs.json` | The tenant's signing cert(s), private key AES-256-GCM-encrypted at rest under `ESIG_MCP_PASSPHRASE`. |
| `envelopes.json` | Every envelope, its signers, their signature images, and its lifecycle event log (`metadata.mcp.events[]`, capped at 200 — see "Lifecycle events and webhooks" above). When reminders are configured, also each pending signer's signing link, AES-256-GCM-encrypted under `ESIG_MCP_PASSPHRASE` (see "Email delivery and reminders" above) — never in plaintext. |
| `audit-log.ndjson` | Append-only audit trail — one JSON row per line. |
| `pq-keys.json` | The tenant's post-quantum key bundle, encrypted at rest (present when `ESIG_MCP_PQ` is on). |
| `inbox/` (`ESIG_MCP_DOCS_ROOT`) | Where a caller-supplied `path` input to `esig_verify_document` / `esig_ingest_document` is confined — never an absolute path outside it, a `..` segment, or a symlink escaping it. |
| `outbox/` | `<envelopeId>.json` — the CREATION receipt (signing links), written only when `ESIG_MCP_DELIVERY=file`. `<envelopeId>.completed.json` — a COMPLETION receipt (R2), written on every terminal seal outcome (`sealed`/`seal_failed`) **regardless of delivery channel**, containing each signer's identity record if any. Both mode `0600`, in a `0700` directory. |
| `blobs/` | Sealed PDFs (`<tenant>/<envelopeId>/sealed.pdf`, stored by `esig_reseal`/the automatic seal step), and — under `identity/` — content-addressed signer-identity artifacts (proof JSON, presented credential JSON, registry signed-badge snapshots), named `<sha256-digest>.json`, the same digest recorded in `signers[].identity`. |
| `documents/` | Content-addressed workdir for `esig_ingest_document` (docId = sha256 of the bytes) — separate from `inbox/`: this is where *this server* stores bytes it accepted, not where a caller's `path` input is confined. |
| `events/queue/` | One `<eventId>.json` per not-yet-delivered lifecycle event, written **before** any webhook delivery attempt — present only when `ESIG_MCP_EVENTS_WEBHOOK_URL` is configured. `events/delivered/` holds successfully-delivered receipts for 24h (pruned after). |

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
| `ESIG_MCP_DELIVERY` | *(required)* | `file` (writes `<ESIG_MCP_DATA_DIR>/outbox/<envelopeId>.json`, mode `0600` — the quickstart channel), `console` (prints links to stderr — opt-in only, loud startup warning; see "Security model" above), `webhook`, `email` (see "Email delivery and reminders" above), or `pillar` (see "Pillar (agent-to-agent) delivery" above; requires the optional peer dependency `@e-sig/pillar-bridge`). No default: an operator must pick where signing links go. |
| `ESIG_MCP_MODES` | `H` | Comma-separated. Only `H` is implemented in v0.1 — anything containing `A` or `C` refuses to start. |
| `ESIG_MCP_DATA_DIR` | `./.esig-mcp` | Root for the filesystem-backed stores — see "Data directory layout" above. Created at startup. |
| `ESIG_MCP_DOCS_ROOT` | `<ESIG_MCP_DATA_DIR>/inbox` | Confines the `path` input on `esig_verify_document` / `esig_ingest_document` — a connected agent is untrusted by default, so a caller-supplied filesystem path may only resolve inside this directory (never an absolute path outside it, a `..` segment, or a symlink escaping it). Created at startup. |
| `ESIG_MCP_TENANT` | `default` | Partition key for certs/keys/envelopes. |
| `ESIG_MCP_SUBJECT_NAME` | `e-sig MCP` | Signing cert subject CN. |
| `ESIG_MCP_HTTP_HOST` | `127.0.0.1` | Approval-page bind host. |
| `ESIG_MCP_HTTP_PORT` | `7433` | Approval-page bind port. |
| `ESIG_MCP_BASE_URL` | derived from host:port | Base URL signing links are built from. Set this to a real, reachable URL for anything beyond `localhost`. |
| `ESIG_MCP_RETURN_LINKS` | off | Set to exactly `1` to include raw signing links in `esig_create_envelope`'s result. Local demos only — see T1 above. |
| `ESIG_MCP_DELIVERY_WEBHOOK_URL` | — | Required when `ESIG_MCP_DELIVERY=webhook`. Must be `https://` unless `ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1`. Refused **at startup** (not only at send time) if it resolves to a private/local address, unless `ESIG_MCP_ALLOW_PRIVATE_WEBHOOK=1`. |
| `ESIG_MCP_ALLOW_INSECURE_WEBHOOK` | off | Set to exactly `1` to allow a plain `http://` `ESIG_MCP_DELIVERY_WEBHOOK_URL` (e.g. a trusted loopback receiver). Leave unset for anything reachable over a real network — the signing link is the signing capability. The `ESIG_MCP_DELIVERY=webhook` channel's own flag — see `ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK` below for the events webhook. |
| `ESIG_MCP_PQ` | on | Set to `0` to disable the hybrid Ed25519 + ML-DSA-65 post-quantum seal at completion. |
| `ESIG_MCP_MAX_HTML_BYTES` | `524288` (512 KiB) | Envelope HTML size cap. |
| `ESIG_MCP_MAX_PDF_BYTES` | `26214400` (25 MiB) | Ingested/sealed PDF size cap. |
| `ESIG_MCP_ENVELOPES_PER_HOUR` | `60` | Per-process rate limit on envelope creation, `esig_reseal`, and `esig_identity_challenge` (each under its own bucket). |
| `ESIG_MCP_MAX_SIGNERS` | `25` | Per-envelope cap on `esig_create_envelope`'s `signers[]` — `esig_create_envelope` refuses with a clear error above this, bounding the email/webhook fan-out one call can trigger. |
| `ESIG_MCP_IDENTITY_MIN_LEVEL` | `none` | Signer-identity floor: `none` \| `L0` \| `L1` \| `L1p` \| `L2` — see "Signer identity" above. `esig_create_envelope` may only *raise* this per envelope. |
| `ESIG_MCP_UUAID_REGISTRY_URL` | — | `https://` UUAID registry base URL. Required when `ESIG_MCP_IDENTITY_MIN_LEVEL=L2`, or when any envelope itself requests `L2`. |
| `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` | — | The registry's pinned Ed25519 public key — 64 lowercase hex chars, `keys[].publicKey` (`uuaid-registry-1`) from the registry's `GET /.well-known/uuaid-registry.json`. Every registry-signed badge (`GET /iaaso/v1/badge/{uuaid}`) is verified against this pin before anything in it is trusted. Required when `ESIG_MCP_IDENTITY_MIN_LEVEL=L2`, or when any envelope itself requests `L2`. |
| `ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC` | `900` | Sole-control challenge lifetime, in seconds. Max `3600`. |
| `ESIG_MCP_EMAIL_TRANSPORT` | — | Required when `ESIG_MCP_DELIVERY=email`: `smtp` or `ses` — see "Email delivery and reminders" above. |
| `ESIG_MCP_EMAIL_FROM` | — | Required when `ESIG_MCP_DELIVERY=email`: `"Name <addr>"` or a bare address. |
| `ESIG_MCP_EMAIL_REPLY_TO` | — | Optional `Reply-To` for signing-notification emails. |
| `ESIG_MCP_EMAIL_SUBJECT_PREFIX` | — | Optional: subjects become `"[prefix] Please sign: <title>"`. |
| `ESIG_MCP_SMTP_HOST` / `ESIG_MCP_SMTP_PORT` | — / `587` | Required (host) when `ESIG_MCP_EMAIL_TRANSPORT=smtp`. Port `465` implies implicit TLS even without `ESIG_MCP_SMTP_SECURE=1`. |
| `ESIG_MCP_SMTP_USER` / `ESIG_MCP_SMTP_PASS` | — | SMTP AUTH — both set or both unset. Never logged, never in a tool result or audit row. |
| `ESIG_MCP_SMTP_SECURE` | off | Set to exactly `1` for implicit TLS from connect. |
| `ESIG_MCP_SMTP_ALLOW_PLAINTEXT` | off | Set to exactly `1` to skip STARTTLS entirely. Leave unset — STARTTLS is required by default. |
| `ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS` | off | Set to exactly `1` to skip SMTP server certificate verification against the system CA. Leave unset — verification is on by default; a startup WARNING is printed whenever this is set. |
| `ESIG_MCP_SES_REGION` | — | Required when `ESIG_MCP_EMAIL_TRANSPORT=ses`. Needs the optional peer dependency `@aws-sdk/client-sesv2` installed. |
| `ESIG_MCP_REMINDERS` | off (none) | Comma-separated durations after send, e.g. `"24h,72h,30m"`. Requires `ESIG_MCP_DELIVERY=email`. |
| `ESIG_MCP_REMINDER_MAX` | `3` | Hard cap on reminders sent per signer. |
| `ESIG_MCP_EVENTS_WEBHOOK_URL` | — | Operator config only — no tool can ever set or change it. Both this and `ESIG_MCP_EVENTS_WEBHOOK_SECRET`, or neither. Must be `https://` unless `ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK=1`. Refused **at startup** (not only at send time) if it resolves to a private/local address, unless `ESIG_MCP_ALLOW_PRIVATE_WEBHOOK=1`. See "Lifecycle events and webhooks" above. |
| `ESIG_MCP_EVENTS_WEBHOOK_SECRET` | — | Required with `ESIG_MCP_EVENTS_WEBHOOK_URL`. At least 32 characters. Signs every event's `X-Esig-Signature` header. |
| `ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK` | off | Set to exactly `1` to allow a plain `http://` `ESIG_MCP_EVENTS_WEBHOOK_URL`. The events webhook's **own** flag — separate from `ESIG_MCP_ALLOW_INSECURE_WEBHOOK` above (the `ESIG_MCP_DELIVERY=webhook` link-delivery channel's own flag); relaxing one never relaxes the other. |
| `ESIG_MCP_ALLOW_PRIVATE_WEBHOOK` | off | Set to exactly `1` to allow `ESIG_MCP_EVENTS_WEBHOOK_URL` (and, at startup, `ESIG_MCP_DELIVERY_WEBHOOK_URL`) to resolve to a loopback/link-local/RFC1918/unique-local address (e.g. a trusted local receiver). Checked on every send (T18). |
| `ESIG_CHROME_PATH` / `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH` | unset (auto-detect) | Override the Chrome/Chromium executable used to seal envelopes, checked in that order; falls back to a platform scan (or `@sparticuz/chromium` on Lambda/Vercel) when unset. Only needed for sealing — see "Requirements" above and `esig_whoami`'s `sealReady`. |

## v0.2 roadmap

- **Mode A** — the server signs as a dedicated agent identity (never the operator's primary cert), for low-stakes or machine-to-machine documents. Gated by policy (allowlist, size cap, hourly cap) and a RedTeam review before it ships.
- **Mode C** — dual-key co-sign: an envelope with both an agent signer and a human signer, completing only once both have signed.
- Supabase-backed audit chain, envelope-completion webhooks, and anchoring the tenant audit chain head to UUAID's Polygon-anchored ledger.
- **Signer identity L2 exchange submission + receipt** (phase 2): submit the verified exchange to the UUAID Network and store the anchored receipt; staple the signer-identity manifest into the sealed PDF itself as an append-only incremental update, so `esig_verify_document` can surface it offline.

Signer identity (UUAID + IAASO, levels `none`/`L0`/`L1`/`L1p`/`L2`) already shipped — see above; only L2's exchange-submission/receipt leg and PDF-native stapling remain.

See design doc §8 and §12 for the full rollout plan.
