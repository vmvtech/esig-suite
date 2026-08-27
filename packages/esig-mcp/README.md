# @e-sig/mcp

An MCP (Model Context Protocol) server for agent-driven e-signature workflows: agents draft, send, and track envelopes over `@e-sig/core`; a human holds the pen. Cryptographic control of signing stays with the human by default — no tool in v0.1 can produce a signature, and no tool can return a raw signing link, unless an operator explicitly opts in.

Full design: [`docs/architecture/esig-mcp.md`](../../docs/architecture/esig-mcp.md).

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
| `esig_envelope_status` | read | Look up one envelope's status, per-signer state, and sealed PDF path once completed. |
| `esig_list_envelopes` | read | List envelopes for this server's tenant, optionally filtered by status. |
| `esig_whoami` | read | This server's tenant, enabled modes, caps, and public cert/PQ fingerprints. Never key material. |
| `esig_ingest_document` | prepare (audited) | Store PDF bytes in a content-addressed workdir; returns a `docId`. `path` input is confined to `ESIG_MCP_DOCS_ROOT`. |
| `esig_create_envelope` | prepare (audited) | Create an envelope from HTML + a signer list; dispatches signing links through the configured delivery channel. Never returns a raw link unless `ESIG_MCP_RETURN_LINKS=1`. |
| `esig_void_envelope` | prepare (audited) | Cancel a pending or partially-signed envelope. |

Every tool's own `description` (visible to any connected agent) documents its exact input/output contract in more detail than this table.

## Security model

Full threat model: design doc §2. In plain words, the three invariants this package is built around:

- **T1 — an agent can't sign something no human saw.** `esig_create_envelope` mints signing tokens and hands them straight to your configured delivery channel (`file` outbox, `console`, or `webhook` — there is no default); the MCP result the agent gets back contains signer names and delivery receipts, never the token or the `/sign/<token>` link. Set `ESIG_MCP_RETURN_LINKS=1` only for a local demo where you are both the agent and the signer — it is loud on purpose (a warning is written every time it fires) and every affected audit row records that it was on.
- **T2 — the document a human signs is the document that gets sealed.** An envelope's HTML is fixed at creation; no tool can edit it afterwards. Its sha256 is pinned at creation and re-checked immediately before sealing, so a corrupted store (this package's own, or a future one) fails loudly instead of silently sealing something else.
- **T9 — agent-authored HTML can't attack the signer's browser.** Two independent layers: `<script>` tags, `on*=` event handlers, `javascript:` URLs, and `<iframe>/<object>/<embed>/<form>` are stripped from envelope HTML before it is ever stored; and the approval page only ever renders that HTML inside a fully sandboxed `<iframe sandbox srcdoc="…">` — no `allow-scripts`, no `allow-same-origin`, no forms — behind a `Content-Security-Policy: default-src 'none'` baseline whose own inline `<script>` (the signature pad) runs under a fresh, per-response nonce rather than `'unsafe-inline'`.
- **G1 — the seal render can't be turned into SSRF.** JavaScript-off (core's default for the HTML→PDF render) stops scripts, not resource loading: a plain `<img>`, `<link rel=stylesheet>`, CSS `url()`, `<object>`, or `<meta http-equiv=refresh>` in agent-authored envelope HTML would otherwise still reach the network from the *operator's own machine* — the one holding the signing keys — at the moment the document is sealed, and whatever it fetches gets baked into the *signed* PDF. The seal-time Chrome launch always carries `--host-resolver-rules=MAP * ~NOTFOUND` (`SEAL_RENDER_LAUNCH_ARGS`), which fails every hostname/IP lookup the renderer could make while leaving `data:` URLs (the signature image) untouched — measured 6/6 SSRF vectors blocked with the rule, 0/6 without it.
- **G3 — the default delivery channel can't hand the signing capability to the agent.** `ESIG_MCP_DELIVERY` has **no default** — you must pick one. The channel this package used to default to, `console`, prints signing links to stderr; in the canonical stdio MCP deployment, stderr is captured straight into the connecting agent harness's own log. Since a signing link IS the signing capability (`POST /sign/<token>` needs no browser), a silent console default would have handed T1/T8's exact threat — the untrusted agent signing something no human reviewed — a working bypass. `console` still exists, but it's opt-in only, prints a loud startup warning every time it's selected, and every `envelope.created` audit row records which channel was actually used (and any per-signer delivery failure) regardless of channel.

Link custody, end to end: a raw signing token exists in exactly one place outside the envelope store — the delivery channel you configured (the `file` outbox, console output, or your webhook). No MCP tool ever returns it, no HTTP response ever logs it, and the approval page's own JavaScript reads it only from the URL the browser already has (it does not need to be told).

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `ESIG_MCP_PASSPHRASE` | *(required)* | Encrypts the tenant's signing cert + PQ key bundle at rest. Must be at least 24 characters — matching `@e-sig/core`'s own encryption floor exactly, so a passphrase that passes this check never later throws at first seal. |
| `ESIG_MCP_MODES` | `H` | Comma-separated. Only `H` is implemented in v0.1 — anything containing `A` or `C` refuses to start. |
| `ESIG_MCP_DATA_DIR` | `./.esig-mcp` | Root for the filesystem-backed stores (certs, envelopes, audit log, PQ keys, PDF blobs). |
| `ESIG_MCP_DOCS_ROOT` | `<ESIG_MCP_DATA_DIR>/inbox` | Confines the `path` input on `esig_verify_document` / `esig_ingest_document` — a connected agent is untrusted by default, so a caller-supplied filesystem path may only resolve inside this directory (never an absolute path outside it, a `..` segment, or a symlink escaping it). |
| `ESIG_MCP_TENANT` | `default` | Partition key for certs/keys/envelopes. |
| `ESIG_MCP_SUBJECT_NAME` | `e-sig MCP` | Signing cert subject CN. |
| `ESIG_MCP_HTTP_HOST` | `127.0.0.1` | Approval-page bind host. |
| `ESIG_MCP_HTTP_PORT` | `7433` | Approval-page bind port. |
| `ESIG_MCP_BASE_URL` | derived from host:port | Base URL signing links are built from. Set this to a real, reachable URL for anything beyond `localhost`. |
| `ESIG_MCP_RETURN_LINKS` | off | Set to exactly `1` to include raw signing links in `esig_create_envelope`'s result. Local demos only — see T1 above. |
| `ESIG_MCP_DELIVERY` | *(required)* | `file` (writes `<ESIG_MCP_DATA_DIR>/outbox/<envelopeId>.json`, mode `0600` — the quickstart channel), `console` (prints links to stderr — opt-in only, loud startup warning; see "Security model" above), or `webhook`. No default: an operator must pick where signing links go. |
| `ESIG_MCP_DELIVERY_WEBHOOK_URL` | — | Required when `ESIG_MCP_DELIVERY=webhook`. Must be `https://` unless `ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1`. |
| `ESIG_MCP_ALLOW_INSECURE_WEBHOOK` | off | Set to exactly `1` to allow a plain `http://` `ESIG_MCP_DELIVERY_WEBHOOK_URL` (e.g. a trusted loopback receiver). Leave unset for anything reachable over a real network — the signing link is the signing capability. |
| `ESIG_MCP_PQ` | on | Set to `0` to disable the hybrid Ed25519 + ML-DSA-65 post-quantum seal at completion. |
| `ESIG_MCP_MAX_HTML_BYTES` | `524288` (512 KiB) | Envelope HTML size cap. |
| `ESIG_MCP_MAX_PDF_BYTES` | `26214400` (25 MiB) | Ingested/sealed PDF size cap. |
| `ESIG_MCP_ENVELOPES_PER_HOUR` | `60` | Per-process rate limit on envelope creation. |

## v0.2 roadmap

- **Mode A** — the server signs as a dedicated agent identity (never the operator's primary cert), for low-stakes or machine-to-machine documents. Gated by policy (allowlist, size cap, hourly cap) and a RedTeam review before it ships.
- **Mode C** — dual-key co-sign: an envelope with both an agent signer and a human signer, completing only once both have signed.
- Supabase-backed audit chain, envelope-completion webhooks, and anchoring the tenant audit chain head to UUAID's Polygon-anchored ledger.

See design doc §8 for the full rollout plan.
