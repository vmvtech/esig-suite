# @e-sig/mcp

An MCP (Model Context Protocol) server for agent-driven e-signature workflows: agents draft, send, and track envelopes over `@e-sig/core`; a human holds the pen. Cryptographic control of signing stays with the human by default — no tool in v0.1 can produce a signature, and no tool can return a raw signing link, unless an operator explicitly opts in.

Full design: [`docs/architecture/esig-mcp.md`](https://github.com/vmvtech/esig-suite/blob/main/docs/architecture/esig-mcp.md).

## Requirements

- **Node.js >= 20** (ESM).
- **Chrome or Chromium is needed ONLY to produce the sealed PDF** — the HTML→PDF render at envelope completion. Point at a binary with `ESIG_CHROME_PATH` (or `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH`, checked in that order), or install a system Chrome/Chromium/Edge/Brave and this server finds it automatically. On AWS Lambda or Vercel it uses `@sparticuz/chromium` (an `@e-sig/core` peer dependency) instead — nothing to configure.
- **Everything else works without Chrome.** Creating envelopes, delivering signing links, a human signing from the approval page, `esig_envelope_status`/`esig_list_envelopes`, `esig_verify_document`, `esig_whoami`, `esig_ingest_document`, and `esig_void_envelope` all work with no Chrome installed at all. Only the seal step needs it: if it's unavailable, the server still starts (with a startup warning) and a completed envelope lands in phase `seal_failed` instead of `sealed` — retry once Chrome is available with `esig_reseal`. See ["Sealing, phases, and `esig_reseal`"](#sealing-phases-and-esig_reseal) below.

## 60-second quickstart

```bash
ESIG_MCP_PASSPHRASE="a passphrase at least 24 characters long" \
ESIG_MCP_DELIVERY=file \
npx @e-sig/mcp
```

`ESIG_MCP_DELIVERY` has no default (see "Security model" below for why) — `file` is the quickstart channel: it writes one JSON file per envelope, containing that envelope's signing link(s), to `<ESIG_MCP_DATA_DIR>/outbox/<envelopeId>.json` (mode `0600`, in a `0700` directory). Open that file to get the link a human signs from. For anything beyond a one-off try, also set a data directory:

```bash
ESIG_MCP_PASSPHRASE="a passphrase at least 24 characters long" \
ESIG_MCP_DELIVERY=file \
ESIG_MCP_DATA_DIR=./esig-data \
npx @e-sig/mcp
```

That starts an MCP server over stdio plus a small HTTP approval page, using a temporary filesystem-backed store when `ESIG_MCP_DATA_DIR` is left at its default.

### Wire it into an MCP client

Claude Desktop (`claude_desktop_config.json`) or a project's `.mcp.json`:

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

The demo flow: an agent drafts an NDA with `esig_create_envelope`, a human opens the signing link from your configured delivery channel (the `file` outbox JSON in the quickstart above) and signs from their phone, the agent polls `esig_envelope_status` and files the sealed PDF, and anyone — agent or human — can later confirm it with `esig_verify_document`.

## Tools (v0.1)

v0.1 ships **read + prepare** tools only. There is no tool that signs — `esig_sign_as_agent` and `esig_cosign_start` (modes A/C) are v0.2, gated behind a RedTeam review, and this server refuses to even start if `ESIG_MCP_MODES` asks for them.

| Tool | Kind | What it does |
|---|---|---|
| `esig_verify_document` | read | Verify a PDF's classical signature and, if present, its post-quantum seal. Accepts `path` (confined to `ESIG_MCP_DOCS_ROOT`), `base64`, or a prior `docId`. |
| `esig_envelope_status` | read | Look up one envelope's status, phase, per-signer state, seal state, and sealed PDF path once sealed. |
| `esig_list_envelopes` | read | List envelopes for this server's tenant, optionally filtered by status. |
| `esig_whoami` | read | This server's tenant, enabled modes, caps, seal readiness, and public cert/PQ fingerprints. Never key material. |
| `esig_ingest_document` | prepare (audited) | Store PDF bytes in a content-addressed workdir; returns a `docId`. `path` input is confined to `ESIG_MCP_DOCS_ROOT`. |
| `esig_create_envelope` | prepare (audited) | Create an envelope from HTML + a signer list; dispatches signing links through the configured delivery channel. Never returns a raw link unless `ESIG_MCP_RETURN_LINKS=1`. |
| `esig_void_envelope` | prepare (audited) | Cancel a pending or partially-signed envelope. |
| `esig_reseal` | prepare (audited) | Retry producing the sealed PDF for a completed envelope whose seal step failed or never ran (phase `seal_failed` / `awaiting_seal`). Refused if the envelope isn't completed yet, or is already sealed. |

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
{ "signatureImageDataUrl": "data:image/png;base64,...", "consent": true }
```

Responses:

- **`200`** — signed; `{status, envelopeId, completed, sealedPdf}`. `sealedPdf` is set once the envelope reaches phase `sealed` (immediately, if this was the last signer and sealing succeeded).
- **`202`** — signed, but not yet sealed (phase `seal_failed` or `awaiting_seal` — see above); `{status:"signed", envelopeId, sealed:false, message}`. Not an error — the signature is recorded; an operator retries with `esig_reseal`.
- **`4xx`** — the token is invalid, expired, already used, out of turn, or the request body failed validation.

## Data directory layout

Everything this server persists lives under `ESIG_MCP_DATA_DIR` (default `./.esig-mcp`), created at startup along with three subdirectories:

| Path | What lives there |
|---|---|
| `certs.json` | The tenant's signing cert(s), private key AES-256-GCM-encrypted at rest under `ESIG_MCP_PASSPHRASE`. |
| `envelopes.json` | Every envelope, its signers, and their signature images. |
| `audit-log.ndjson` | Append-only audit trail — one JSON row per line. |
| `pq-keys.json` | The tenant's post-quantum key bundle, encrypted at rest (present when `ESIG_MCP_PQ` is on). |
| `inbox/` (`ESIG_MCP_DOCS_ROOT`) | Where a caller-supplied `path` input to `esig_verify_document` / `esig_ingest_document` is confined — never an absolute path outside it, a `..` segment, or a symlink escaping it. |
| `outbox/` | One JSON receipt per envelope (mode `0600`, in a `0700` directory), written only when `ESIG_MCP_DELIVERY=file`. |
| `blobs/` | Sealed PDFs, stored by `esig_reseal`/the automatic seal step. |
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
| `ESIG_MCP_ENVELOPES_PER_HOUR` | `60` | Per-process rate limit on envelope creation, and separately on `esig_reseal`. |
| `ESIG_CHROME_PATH` / `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH` | unset (auto-detect) | Override the Chrome/Chromium executable used to seal envelopes, checked in that order; falls back to a platform scan (or `@sparticuz/chromium` on Lambda/Vercel) when unset. Only needed for sealing — see "Requirements" above and `esig_whoami`'s `sealReady`. |

## v0.2 roadmap

- **Mode A** — the server signs as a dedicated agent identity (never the operator's primary cert), for low-stakes or machine-to-machine documents. Gated by policy (allowlist, size cap, hourly cap) and a RedTeam review before it ships.
- **Mode C** — dual-key co-sign: an envelope with both an agent signer and a human signer, completing only once both have signed.
- Supabase-backed audit chain, envelope-completion webhooks, and anchoring the tenant audit chain head to UUAID's Polygon-anchored ledger.

See design doc §8 for the full rollout plan.
