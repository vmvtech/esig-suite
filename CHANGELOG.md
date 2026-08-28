# Changelog

All notable changes to the `@e-sig/*` packages. This project follows
[Semantic Versioning](https://semver.org/). Dates are ISO-8601.

## @e-sig/mcp 0.4.0 — 2026-08-28

### `@e-sig/mcp` 0.4.0: email delivery + reminders (docs/architecture/esig-mcp.md §15)

New `ESIG_MCP_DELIVERY=email` channel: each signer's tokenized link is sent as
an email through a new `EmailTransport` seam with two built-ins — `smtp`
(dependency-free `node:net`/`node:tls`: EHLO, STARTTLS required unless
`ESIG_MCP_SMTP_ALLOW_PLAINTEXT=1`, implicit TLS on port 465 /
`ESIG_MCP_SMTP_SECURE=1`, AUTH PLAIN with AUTH LOGIN fallback, CRLF
normalization + RFC 5321 dot-stuffing on `DATA`) and `ses` (SESv2
`SendEmail` via `@aws-sdk/client-sesv2`, loaded with a dynamic `import()` as
an **optional peer dependency this package never installs** — a missing
module fails with a clear `npm install @aws-sdk/client-sesv2` error, not a
silent no-op). Config: `ESIG_MCP_EMAIL_TRANSPORT`, `ESIG_MCP_EMAIL_FROM`
(required), `ESIG_MCP_EMAIL_REPLY_TO`/`ESIG_MCP_EMAIL_SUBJECT_PREFIX`
(optional), `ESIG_MCP_SMTP_HOST/PORT/USER/PASS/SECURE`,
`ESIG_MCP_SES_REGION`. Credentials are env-only, never logged, never in a
tool result or audit row (redacted out of every SMTP error message too).

The email itself (`email/templates.ts`) contains only the envelope title, the
configured from-address, an optional sender note
(`esig_create_envelope`'s new `message`, ≤ 500 chars — stored on the
envelope and surfaced in `esig_envelope_status`), the signing link, and the
expiry — never the document body or other signers' details. Title/note are
stripped of control characters (SMTP header injection) and HTML-escaped.

**Reminders.** `ESIG_MCP_REMINDERS="24h,72h"` (durations after the envelope
was created; default off) + `ESIG_MCP_REMINDER_MAX` (default 3) — requires
`ESIG_MCP_DELIVERY=email`, refused at startup otherwise. A new in-process
`Scheduler` (`reminders.ts`, pure `computeDue()` + a 60s tick) sends a
reminder to each still-pending signer whose next one is due, skipping
voided/expired/completed envelopes, and persists send history per signer so
a restart resumes rather than re-sends. New tool `esig_send_reminder
(envelopeId, signerId?)` sends one on demand — audited
(`envelope.reminder_sent`) and rate-limited under its own bucket, separate
from the scheduler's own throttle (schedule + max), so the manual and
automatic paths can never starve each other.

**Link persistence — the one custody change.** Core mints a signing token
once and never re-mints it, so a reminder needs the original link. When
reminders are configured, every signer's link is stored **encrypted at
rest** (AES-256-GCM — core's `encryptKeyPem`/`decryptKeyPem`, the same
helpers `ensureActiveCert`/`wrapPqKeyBundle` already use) under
`envelopes.json`, decrypted only inside the reminder-sending path, and never
returned by any tool (I8 unchanged — extended test asserts `envelopes.json`
never contains a plaintext `/sign/` link). Off entirely (no ciphertext
written) unless `ESIG_MCP_REMINDERS` is set.

`package.json` -> 0.4.0; `@aws-sdk/client-sesv2` added as an optional peer
dependency (`peerDependenciesMeta.optional`), not installed.

### `@e-sig/mcp` 0.4.0: lifecycle events + webhooks (docs/architecture/esig-mcp.md §16)

Every state change on an envelope now appends an event
(`envelope.created | .viewed | .signed | .declined | .completed | .sealed |
.seal_failed | .voided | .expired | .reminder_sent |
signer.identity_verified | signer.identity_rejected`) to a per-envelope log
(`metadata.mcp.events[]`, capped at 200 — oldest trimmed off into an
`events.trimmed` audit row). New tool `esig_list_events(envelopeId, since?)`
returns the full log; `esig_envelope_status` now also returns the last 10.
`envelope.viewed` fires once per signer, the first time `GET /sign/<token>`
resolves `"ok"` for them; `envelope.expired` fires once, from a new 60s
expiry tick (`events/expiry.ts`) sharing the existing reminder scheduler's
loop — core itself only expires an envelope lazily on token resolution and
never touches the event log, so the tick catches every envelope nobody
happened to poll. Every event's `data` — like the webhook payload below —
never contains a signing link, token, proof, or document byte.

**Decline.** The approval page gains a "Decline to sign" control (optional
reason, ≤ 500 chars, control characters stripped) — `POST
/sign/<token>/decline {reason?}` calls core's `declineEnvelope` (marks the
signer declined, voids the envelope), audits `envelope.declined`, and the
page then shows a declined-by-name state instead of the generic
sender-voided sentence. Deliberately not an MCP tool, same as signing.

**Webhook delivery.** `ESIG_MCP_EVENTS_WEBHOOK_URL` + `_SECRET` (both
required together, secret ≥ 32 chars, operator config only) POST every
event as JSON, headers `X-Esig-Event-Id`/`X-Esig-Timestamp`/`X-Esig-
Signature: sha256=HMAC(secret, timestamp + "." + body)`. At-least-once with
backoff: every event is persisted to
`<DATA_DIR>/events/queue/<eventId>.json` **before** any delivery attempt
(enqueuing never blocks the signer-facing HTTP handlers — a slow/hung
receiver cannot slow down `POST /sign`), a worker loop delivers in order
per envelope, retries non-2xx/timeout/any-3xx (redirects are never
followed) with exponential backoff (1m→2m→4m→8m→16m→32m, up to 6
attempts), then dead-letters (audited `webhook.dead_lettered`). Restart-safe
— the queue directory is re-scanned from scratch every pass.

**T18 (SSRF).** `ESIG_MCP_EVENTS_WEBHOOK_URL` must be `https://` unless
`ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1` (shared with the pre-existing `webhook`
delivery channel). Before every send, the target is DNS-resolved
(`dns.promises.lookup`, all addresses) and refused if any address is
loopback, link-local (`169.254/16`, incl. cloud metadata, and `fe80::/10`),
RFC1918, unique-local (`fc00::/7`), or unspecified — unless
`ESIG_MCP_ALLOW_PRIVATE_WEBHOOK=1`. A literal IP goes through the identical
check.

New exports: `EsigEvent`/`EsigEventType`, `appendEvent`/`listEvents`
(`events/log.ts`), `expiryTick` (`events/expiry.ts`), `signPayload`/
`sendWebhook`/`assertSafeWebhookTarget`/`WebhookSsrfError`
(`events/webhook.ts`), `EventQueue` (`events/queue.ts`).

### `@e-sig/mcp` 0.4.0: RedTeam RT-2026-08-27-05 fixes (§15/§16 pre-publish + verifier findings) — 2026-08-27

**F1 (HIGH) reminders — CAS conflict across signers could duplicate a send.**
`sendOneReminder` used to mutate an in-hand `Envelope` object shared across
every due signer in one tick (or one `esig_send_reminder` call with no
`signerId`) — a concurrent `emit()` elsewhere in the same call independently
bumped the store's revision, so the SECOND+ signer's own `store.update()`
CAS-failed *after* that signer's email had already gone out, reporting a
bogus failure and never persisting the schedule state (so the next tick
re-sent it). Fixed: a new `EnvelopeService.updateWithRetry` helper (fresh
read + CAS-write + retry, mirroring `events/log.ts`'s `appendEvent`) now
persists the "this reminder was sent" state *before* the email is actually
sent, retried against a fresh read on conflict — a CAS conflict can now only
delay a send, never duplicate one.

**F3 (MED) SMTP — a server echoing the AUTH command could leak
base64(password).** `email/transport.ts`'s AUTH PLAIN/LOGIN failure paths no
longer embed the server's raw reply text at all (only the numeric reply
code) — a malicious or broken server that reflects the AUTH line back in a
535 can no longer put base64(password) into a thrown error, audit row, or
tool result. Defense in depth: every error message this transport throws is
also redacted for the raw password, `base64(password)`,
`base64("\0user\0pass")`, and `base64(user)`.

**F4 (MED) webhook SSRF — a private-range URL was only refused at send
time.** `bin.ts` now calls `assertSafeWebhookTarget` right after
`loadConfig` for both `ESIG_MCP_EVENTS_WEBHOOK_URL` and (previously
unchecked at startup) `ESIG_MCP_DELIVERY_WEBHOOK_URL`, refusing to start
(clear error, non-zero exit) rather than only failing on the first delivery
attempt.

**G1 (pre-publish) webhook SSRF, hardened further.** IPv6 forms — `::1`,
`fe80::/10`, `fc00::/7`, and IPv4-mapped literals in both dotted
(`::ffff:a.b.c.d`) and all-hex (`::ffff:0a00:0001`) form — are refused, and
refusal fires if *any* resolved A/AAAA record is private. The bigger fix:
`sendWebhook` now **connects to the vetted address**, never the hostname —
`node:http`/`node:https` directly (Host header + TLS SNI kept on the
original hostname) — closing a DNS-rebinding TOCTOU where the HTTP client's
own internal DNS lookup could return a different (private) address than the
one just vetted. Every send re-resolves and re-vets fresh, including every
retry. Redirects: `redirect: "error"` (was `"manual"`) on the unpinned path,
matched by an explicit non-2xx check on the pinned path — any 3xx is a
failure either way, never followed.

**G2 (pre-publish) SMTP TLS policy, made explicit.** Server certificate
verification against the system CA is confirmed ON by default; a new,
loud opt-out `ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS=1` (startup WARNING
whenever set) sets `rejectUnauthorized:false`. STARTTLS-missing/refused
still hard-fails unless `ESIG_MCP_SMTP_ALLOW_PLAINTEXT=1`; AUTH is
confirmed to run only after the TLS upgrade completes (a new test asserts
the server's own received-command order). Implicit TLS (port 465 /
`ESIG_MCP_SMTP_SECURE=1`) gets its own test too.

**G3 stored signing links erased at terminal states.** A link persisted for
reminders (§15) is now deleted from `metadata.mcp.delivery.links` the
moment it can never be used again: per-signer on that signer's own `signed`
event, and for the whole envelope on `declined`/`voided`/`expired`/
`completed`. A new `EnvelopeService.purgeStaleReminderLinks()`, called once
by the scheduler's first tick, also sweeps any links a *prior* run left
encrypted at rest if this run's `ESIG_MCP_REMINDERS` is unset.

**G4 events-queue file permissions** — `0700`/`0600` were already correct;
added an explicit assertion test (`test/webhooks.test.ts`).

**G5 separate insecure-http flag per webhook channel.** New
`ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK`, for the events webhook only —
`ESIG_MCP_ALLOW_INSECURE_WEBHOOK` now governs the `ESIG_MCP_DELIVERY=webhook`
link-delivery channel exclusively; the two can no longer be relaxed
together by accident.

**G6 per-envelope signer cap.** New `ESIG_MCP_MAX_SIGNERS` (default 25) —
`esig_create_envelope` refuses with a clear error above the cap, bounding
the email/webhook fan-out one call can trigger. The webhook receiver
snippet (README) now also notes deduplicating by `X-Esig-Event-Id` inside
the replay window.

**R1 (MED) reminders — a manual send no longer consumes a scheduled slot.** `esig_send_reminder`/`sendReminder` now record into a separate `manualSentAt[]` instead of the scheduler's own `sentAt[]`, so a manual nudge can never make a later scheduled reminder skip; both arrays still count toward `ESIG_MCP_REMINDER_MAX` combined.

**R3 (LOW) reminders — a failed send is rolled back and retried, not silently dropped.** A transport failure now un-persists the slot `sendOneReminder` recorded before sending (so the next tick/manual call retries) and audits `envelope.reminder_failed` instead of a misleading `envelope.reminder_sent`.

New `Config` fields: `maxSigners`, `allowInsecureEventsWebhook`. New
`SmtpDeliveryConfig` field: `allowUnverifiedTls`. `events/webhook.ts` new
exports: `LookupFn`, `PinnedRequestFn`, `SendWebhookOptions` — `sendWebhook`'s
4th parameter is now an options bag (`{fetchImpl?, lookupFn?, requestImpl?}`)
rather than a bare `fetchImpl`; `EventQueueDeps` grew matching
`lookupFn`/`requestImpl` fields. `assertSafeWebhookTarget` gained an
optional 3rd `lookupFn` parameter (tests only; defaults to
`dns.promises.lookup`) — its existing 2-argument call sites are unaffected.

## @e-sig/core 0.8.0, verify-in-CI, and document templates — 2026-08-27

### `@e-sig/core` 0.8.0: `esig verify` CLI

(0.7.1 was a docs-only bump that was never published; 0.8.0 supersedes it.)
`@e-sig/core` now ships an `esig` binary — `npx -y -p @e-sig/core esig verify
<file.pdf …> [--json] [--require-pq] [--expected-uuaid <u>]
[--expected-mldsa65-fpr <hex>] [--quiet]` — wrapping `verifyDocument()` for
terminals and CI. Exit codes: `0` all files verified, `1` at least one failed
verification, `2` usage or I/O error. `--json` prints one array and nothing
else. No key material is involved. New file `src/bin/esig.ts` only; no other
core source changed.

### GitHub Action `vmvtech/esig-suite` (`action.yml`): verify signed PDFs in CI

Composite action — inputs `files` (newline-separated paths/globs; paths with
spaces are safe), `require-pq`, `expected-uuaid`, `version` — runs the CLI
and writes a per-file table to the job summary; fails the job on exit `1`.
Usage in `docs/verify-in-ci.md`.

### `examples/templates/`: six ready-to-fill document templates

Mutual NDA, IRB research consent (with consent-to-electronic-records and
copy-to-participant language), data-use / material-transfer agreement,
internal grant approval with an approver chain, K-12 permission slip,
employment offer letter. Self-contained HTML, inline CSS only, no scripts, no
external resources, print-friendly, mustache-style `{{placeholders}}`
documented inline, and a visible "TEMPLATE — not legal advice" banner.
`scripts/templates.test.mjs` (part of `test:scripts`) enforces all of that and
proves `@e-sig/mcp`'s sanitizer is a byte-for-byte no-op on each template.
Note: only the MCP path sanitizes; core's `createEnvelope` stores HTML
verbatim.

## @e-sig/mcp 0.3.0 — 2026-08-27

### `@e-sig/mcp` 0.3.0: PDF envelopes — sign an existing PDF, Chrome-free, WYSIWYS (docs/architecture/esig-mcp.md §13)

`esig_create_envelope` now accepts **exactly one of `html` or `docId`**.
Passing `docId` — a docId returned by `esig_ingest_document` — creates a
**PDF envelope**: the signer reviews and signs the *exact ingested bytes*
(What You See Is What You Sign), and the seal step signs those same bytes
directly with core's `signPdf` — **no HTML rendering, so no Chrome anywhere
on this path**.

- **`esig_create_envelope`:** `docId` input, validated to start with the
  `%PDF-` magic bytes (`docId is not a PDF` otherwise) and within
  `ESIG_MCP_MAX_PDF_BYTES`. A PDF envelope's `html` (what core's
  token/order/`recordSignature` flow runs on) is a generated, escaped cover
  sheet — title, docId, sha256, byte size, ordered signer list, and the
  sentence "This envelope signs the PDF document with sha256 &lt;hex&gt;" —
  so the existing identity-challenge `htmlSha256` pin (mechanism unchanged)
  binds the PDF transitively. `metadata.mcp.document = {docId, sha256, size,
  kind:"pdf"}` is persisted at creation and surfaced on
  `esig_create_envelope`/`esig_envelope_status`/`esig_list_envelopes`.
- **`GET /sign/<token>/document.pdf`:** streams the exact ingested bytes for
  a PDF envelope (any resolvable token state except invalid),
  `Content-Type: application/pdf`, `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store`, `Content-Disposition: inline` with a filename
  derived from the envelope title. The approval page swaps the sandboxed
  `srcdoc` iframe (which cannot host a PDF viewer) for a plain same-origin
  `<iframe src="/sign/<token>/document.pdf">`, an "Open the PDF in a new tab"
  link, and the document sha256 — HTML envelopes are unchanged. The existing
  CSP already allowed this (`frame-src` already included `'self'`); no CSP
  change was needed.
- **Seal step:** branches on `metadata.mcp.document` — a PDF envelope loads
  the ingested bytes, re-verifies their sha256 against the value pinned at
  creation (content binding, mismatch → `seal_failed` with a reason), and
  signs them directly (`reason: "Signed via e-sig envelope <id> by <n>
  signer(s)"`, `name`: signer names joined by `, `), with the same
  operator-cert/PQ-seal wiring as an HTML envelope. It never calls the
  HTML→PDF renderer. The completion receipt now also carries `document`
  (when present) and, per signer, `signedAt` and a sha256 of the drawn
  signature image (never the full data URL).
- **`esig_ingest_document`** and **`esig_create_envelope`**'s own
  descriptions now tell an agent it can ingest a PDF and sign it directly
  with no HTML/Chrome step.

### `@e-sig/mcp` 0.3.0: `esig-mcp init` and `esig-mcp demo` (docs/architecture/esig-mcp.md §14)

Two new CLI subcommands (`esig-mcp init [--dir] [--force]`,
`esig-mcp demo [--auto] [--keep]`), dispatched from `bin.ts` before any MCP
Config is loaded — both exit (or, `demo` without `--auto`, block on
Ctrl-C/stdin EOF) well before `StdioServerTransport` is ever constructed, so
stdout is as free to use here as it already was for `--help`/`--version`.

- **`init`:** creates `<dir>/esig-data/{inbox,outbox,blobs}` (`<dir>`
  defaults to `cwd`), generates a fresh `ESIG_MCP_PASSPHRASE` (32 random
  bytes, base64url) into `<dir>/.esig-mcp.env` (mode `0600`, refuses to
  overwrite without `--force`), prints a ready-to-paste `.mcp.json` snippet
  (absolute paths; the passphrase itself is never printed — only
  `<see .esig-mcp.env>`), and runs the existing Chrome preflight so an
  operator learns `sealReady` up front.
- **`demo`:** an end-to-end, Chrome-free PDF-envelope signing run in a temp
  data dir — ingests the newly bundled `assets/sample.pdf`, creates a
  one-signer envelope, and prints the signing URL, the outbox file path, and
  a curl one-liner. `--auto` performs that signature itself (in-process
  `fetch`) and prints the sealed PDF's path plus an
  `esig_verify_document`-style verdict; without it, `demo` waits for a human
  to sign from a browser. Chrome-free by construction, not by injection: a
  PDF envelope's seal step never calls the HTML renderer at all (§13), and
  `demo` only ever creates PDF envelopes.
- **README:** the quickstart now leads with `npx @e-sig/mcp demo --auto` as
  a 30-second, zero-config proof, then `npx @e-sig/mcp init` as the setup
  path, then the `.mcp.json` wiring (manual env-var configuration is still
  documented as an alternative to `init`).
- **`package.json`:** ships `assets/sample.pdf` alongside `dist/` (added to
  `files`); `tsconfig.build.json`'s `src`-only `include` already left it
  untouched by the build.

### `@e-sig/mcp` 0.3.0: L2 now verifies the registry-signed badge

L2's key↔uuaid check moved off `GET /resolve/{uuaid}` and onto
`GET /iaaso/v1/badge/{uuaid}` — the registry's signed identity snapshot
(IAASO-0003). `/resolve` carries **no signer key material for any agent**
(Uuaid-Lead, live-measured); the original `/resolve`-based check
(`L2_KEY_NOT_LISTED`) was a guaranteed false negative for every agent, not an
edge case. The badge is also registry-signed, so it's now verified against a
pinned trust anchor instead of TLS alone: `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY`
(the registry's Ed25519 public key, 64 hex chars, from its
`/.well-known/uuaid-registry.json`) — hash binding, an Ed25519 signature, and
freshness (`freshUntil`), all fail-closed.

**Blind-verifier finding, closed same day:** verifying the badge against the
pinned key proves the registry signed *a* badge — not that it's a badge FOR
the uuaid being proven. `identity/verify.ts` now additionally asserts the
badge's `subject.uuaid` equals the uuaid being proven, refusing with the new
`L2_BADGE_SUBJECT_MISMATCH` otherwise (also catches a missing/empty
`subject.uuaid`); without this, a registry-signed badge for a *different*
subject that happens to share the proof's key would have passed every other
L2 check. A badge `404` (absent, or tombstoned — where `/resolve` would still
return `200`) refuses with `L2_UUAID_NOT_FOUND`.

## @e-sig/mcp 0.2.0 — 2026-08-27

### `@e-sig/mcp` 0.2.0: add signer identity via UUAID + IAASO (docs/architecture/esig-mcp.md §12)

Bind *who signed* to a verifiable identity, without inventing a new identity
system: UUAID identifiers and the IAASO assurance ladder (`none`/`L0`/`L1`/
`L2`, ADR-006). Off by default — set `ESIG_MCP_IDENTITY_MIN_LEVEL` server-wide
and/or `identity: {minLevel, signers[].uuaid}` per envelope (may only
*raise* the server floor, never lower it).

**Docs honesty (verifier R3):** `L1` proves control of a *key* — it binds
the presented `uuaid` to that key only by the signer's own **self-assertion**
(the signer says "this uuaid is mine" and proves they hold the matching
private key; nothing here checks that assertion against anything external).
Only `L2` binds key↔uuaid via the UUAID registry. Read `L1` as "sole
control of a key, self-asserted identity" — not as "verified identity" —
until `L2` is in play.

- `L0` (asserted) — the signer's `uuaid` is well-formed and, if pinned at
  creation, matches it. No cryptographic proof, no key↔uuaid binding at all.
- `L1` (proven, self-asserted binding) — the signer presents an
  `eddsa-jcs-2022` `DataIntegrityProof` (new `@e-sig/uaid-exch` dependency:
  `verifyChallengeProof`, `publicKeyFromVerificationMethod`) over a
  server-issued, single-use, 15-minute sole-control challenge (`type,
  envelopeId, signerId, htmlSha256, nonce, issuedAt, expiresAt`) — obtained
  via the new MCP tool `esig_identity_challenge(envelopeId, signerId)` or
  `GET /sign/<token>/challenge` (same gate states as `GET /sign`), and
  presented as `identityProof` on `POST /sign`. This proves the presenter
  controls the private key behind `proof.verificationMethod`; it does
  **not** prove that key belongs to the claimed `uuaid` — that binding is
  self-asserted until `L2`. The nonce is consumed atomically alongside the
  verified record, in one read-CAS-write (I3 class), only once every
  required check for the requested level has already passed — a proof is
  never accepted twice, and a proof over one envelope's challenge is
  rejected against another's.
- `L2` (registry-bound — key↔uuaid actually verified) — L1 plus the
  registry's signed badge: `GET /iaaso/v1/badge/{uuaid}` (registry-signed
  hybrid Ed25519 + ML-DSA-65 envelope, IAASO-0003) must verify against the
  PINNED registry key (`ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` — hash
  binding, Ed25519 signature, `freshUntil` freshness, `status === "active"`),
  and its `subject.presentationKey` (64 **lowercase hex** Ed25519 — not
  multibase/JWK/did:key) must equal the proof's key, and (if a `credential`
  is presented) its `credentialSubject.key.publicKey` must equal the proof's
  key, and `GET /verify/{credentialId}` must say `valid && active &&
  notExpired` **and report an `agent_uuaid` equal to the proving uuaid** (a
  credential can be minted through a path that never checked the caller owns
  the handle — the binding assert closes that on this side). A
  down/unreachable/malformed registry response is a hard failure — this
  never silently drops to L1 (`ESIG_MCP_UUAID_REGISTRY_URL` is validated
  `https://`-only at config time and, for a per-envelope request, at
  creation time, and is *pinned per envelope* at creation — see below).
  *Corrected same day (Uuaid-Lead, live-measured):* `/resolve/{uuaid}`
  carries NO signer key material for any agent — the original
  `/resolve`-based key check (`L2_KEY_NOT_LISTED`) was a guaranteed false
  negative; the badge is the only registry surface carrying an agent's
  presentation key, and a badge 404 (absent/tombstoned) now refuses with
  `L2_UUAID_NOT_FOUND` instead of a generic unavailability error.
  Superseded by the badge mechanism in 0.3.0 (above), which additionally
  pins the badge to the proving uuaid (`L2_BADGE_SUBJECT_MISMATCH`).

A rejected identity throws a typed `IdentityError` — `POST /sign` maps it to
`403 {error, reason}`; `esig_create_envelope`/`esig_envelope_status`/
`esig_list_envelopes` expose the policy and each signer's verified record
(`{level, uuaid, keyFingerprint, proofDigest, credentialDigest?, verifiedAt,
registry?: {resolvedAt, credentialId?, credentialValid?,
registrySnapshotDigest?, receiptId?, anchor?}}`); the `file` outbox receipt
carries the identity requirement; a verified signer gets an escaped
"Identity attestations" line in the composed HTML *before* it is sealed.
Full artifacts (proof/credential JSON, the registry's signed badge
envelope) are persisted content-addressed to `blobs/identity/<sha256>.json`
(never in audit metadata — only digests and identifiers, PII minimization);
the operator's own post-quantum seal never carries a signer's `uuaid`.

New env vars: `ESIG_MCP_IDENTITY_MIN_LEVEL` (default `none`),
`ESIG_MCP_UUAID_REGISTRY_URL`, `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` (the
registry's pinned Ed25519 public key, 64 hex chars from its
`/.well-known/uuaid-registry.json` — required for L2 alongside the URL),
`ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC` (default `900`, max `3600`).

`toolError()` now returns `content[0]` as a JSON `{"error": message}` text
block (mirroring `toolResult()`'s own JSON-first `content[0]`) with the same
plain-text summary moved to `content[1]` — finishes the JSON-first change
0.1.1 started for successful results.

New dependency: `@e-sig/uaid-exch@^0.1.0-preview.2` (workspace).

### `@e-sig/mcp` 0.2.0: signer-identity hardening (2026-08-27 — closing RedTeam rt-verdict-ESIGMCP-V02-IDENTITY-20260827 APPROVE_WITH_GAPS, plus a blind-verifier pass)

- **G1 (HIGH) — the key whitelist named a field that does not exist.**
  `identityProof.credential.credentialSubject.authenticator.public_key_jwk`
  was never a real field in `@e-sig/uaid-exch`'s `UaidSigningCredential`
  (see that package's own entry below for the type reconciliation). When a
  `credential` is presented alongside a proof, its
  `credentialSubject.key.publicKey` (the real tae/v1 field) is now decoded
  (did:key or a `{kty:"OKP",crv:"Ed25519",x}` JWK — never a
  network-dereferenced form like did:web or an http(s) URL) and MUST equal
  the proof's own key; a mismatch is rejected (`L1_CREDENTIAL_KEY_MISMATCH`),
  at whatever level the credential is presented at, not only L2.
- **G2 (MED) — htmlSha256 anchoring confirmed and pinned.** The sole-control
  challenge's `htmlSha256` is now read from the IMMUTABLE
  `metadata.mcp.htmlSha256` pinned at creation (`identity/types.ts`'s new
  `getPinnedHtmlSha256`), never recomputed from `envelope.html` (which would
  silently track any future drift) and never derived from the
  composed/render HTML (which only ever exists as a local variable at seal
  time). A new test signs with signer 1 and confirms signer 2's
  subsequently-issued challenge still names the same digest.
- **G3 (MED) — the registry URL is pinned per envelope at creation.** A new
  `identityPolicy.registryUrl` (set only when `minLevel` is `L2`) is compared
  against the server's CURRENTLY configured `ESIG_MCP_UUAID_REGISTRY_URL` at
  verify time, before any network call; a mismatch refuses with
  `L2_REGISTRY_URL_CHANGED` — closing the window where repointing the
  registry between an envelope's creation and a signer's proof would
  silently change which registry attests the key↔uuaid binding for an
  already-issued envelope.
- **G4 (MED) — identity verification confirmed structurally outside the
  seal-time try/catch.** `EnvelopeService.sign()` runs identity verification
  BEFORE `recordSignature`, with no enclosing try/catch that could swallow a
  non-`IdentityError` throw — a new test injects a verifier
  (`EnvelopeServiceDeps.verifySignerIdentity`, a new DI seam added for this
  test) that throws a plain `Error` and confirms: the signature is never
  recorded, `POST /sign` never returns 2xx, and no `envelope.signed` audit
  row is written.
- **G5 (LOW) — challenge re-issue is now idempotent within TTL.**
  `esig_identity_challenge` / `GET /sign/<token>/challenge` return the SAME
  live, unconsumed, unexpired challenge on re-issue instead of rotating the
  nonce — a nonce is only ever rotated when the prior one is missing,
  consumed, or expired. (`signerId` was already validated as belonging to
  the target envelope, and the per-IP rate limit is unchanged.)
- **G6 (LOW) — JWK hygiene.** `@e-sig/uaid-exch`'s
  `publicKeyFromVerificationMethod` now accepts ONLY the exact
  `{kty, crv, x}` triple — any additional field (notably a private-key `d`)
  is rejected outright, never silently ignored.
- **G7 (LOW) — registry-sourced/attacker-supplied strings are bounded before
  use.** `identityProof.credential.id`, `credentialSubject.key.keyId`, and
  the registry's `verifyCredential` `reason` text are now length-capped
  (256) and control-character-rejected before reaching an `IdentityError`
  message or an audit row. `uuaid` itself was already length-capped (255)
  and charset-restricted (`[A-Za-z0-9_-]`) by core's
  `isWellFormedUuaidAssertion` — unchanged, just confirmed and cited.
- **G8 (LOW) — TOFU conditions for L2 documented** (see the README section
  below): https-only, and the full registry response is snapshotted to a
  content-addressed blob (R1) with the verification record referencing its
  digest. *Corrected same day:* the trust anchor is now an actual key pin —
  `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY`, verified over the registry's signed
  badge (hash binding + Ed25519 + freshness) — so L2 no longer rests on
  TLS/TOFU alone.
- **R1 (verifier) — identity artifacts are now actually persisted.** The
  proof JSON, the presented credential JSON (if any), and the registry's
  signed badge envelope (L2) are written to
  `blobs/identity/<sha256>.json` via the same `PdfStorageStore` seam
  `EnvelopeService` already holds for the sealed PDF — never in audit
  metadata. `proofDigest` (pre-existing) is now literally the digest that
  names its own blob file; `credentialDigest` and
  `registry.registrySnapshotDigest` are new, present only when applicable.
- **R2 (verifier) — a COMPLETION receipt.** `<dataDir>/outbox/
  <envelopeId>.completed.json` is now written on every terminal seal outcome
  (`sealed` or `seal_failed`), regardless of which delivery channel is
  configured, containing `signers[].identity` — distinct from, and in
  addition to, the pre-existing CREATION receipt (unchanged). Best-effort:
  a failure to write it never turns an otherwise-successful (or
  already-recorded-failed) seal into a `sign()`-level error.
- **R4** — same as G5 above.
- **R5 (verifier, no code change)** — see the `@e-sig/uaid-exch` entry
  below: `DataIntegrityProof` fields outside the signed bytes (`created`,
  etc.) mean `proofDigest` covers the exact proof object presented,
  including those mutable-by-construction fields, not just the signed core.
- **R6 (verifier, no code change)** — see the `@e-sig/uaid-exch` README:
  `AgentSigner.verificationMethod` forms like `uuaid:...#sk-...` are
  unverifiable by `verifyExchange` without `opts.agentPublicKey`.

No public API removed; `EnvelopeServiceDeps.verifySignerIdentity` (G4) and
`VerifySignerIdentityInput.pinnedRegistryUrl`/`.configuredRegistryUrl` (G3)/
`.blobStore` (R1) are new, optional fields — every existing call site is
unaffected.

## @e-sig/uaid-exch 0.1.0-preview.2 — 2026-08-27

### `@e-sig/uaid-exch` 0.1.0-preview.2: add local proof verification (`verifyExchange`, `verifyDataIntegrityProof`, `verifyChallengeProof`)

Until now this package could only *create* signed exchanges
(`createExchange`) — checking a proof required a round-trip to the UUAID
registry. New `src/verify.ts`, re-exported from the package root:

- `verifyExchange(exchange, opts?)` — verifies both `DataIntegrityProof`s a
  `createExchange()` output carries (`proof[0]` agent/`authentication`,
  `proof[1]` issuer/`assertionMethod`, the fixed order `createExchange`
  itself constructs), resolving each signer's key from its own
  `verificationMethod` unless `opts.agentPublicKey`/`opts.issuerPublicKey`
  overrides it. Returns `{ ok, agent, issuer, failures[] }` and never throws.
- `verifyDataIntegrityProof(document, proof, opts?)` — the primitive
  `verifyExchange` is built on, for any single `eddsa-jcs-2022` proof over a
  JCS-canonicalizable `document` (with `proof` already omitted). Rejects an
  unknown proof type/cryptosuite, a `proofPurpose` mismatch (when
  `opts.expectedProofPurpose` is given), a bad multibase `proofValue`, a
  wrong-length public key, or a bad signature — all fail-closed as
  `{ ok: false, reason }`, matching this package's existing
  `verifyRevocationListIntegrity` convention.
- `verifyChallengeProof(challenge, proof, opts?)` — thin alias of the above
  for a standalone document with no embedded `proof` field, e.g. the MCP
  sole-control challenge (docs/architecture/esig-mcp.md § 12).
- `publicKeyFromVerificationMethod(vm)` — resolves the raw 32-byte Ed25519
  key from a `did:key:z...` URI (multibase + Ed25519 multicodec `0xed 0x01`)
  or a raw JWK (`{kty:"OKP", crv:"Ed25519", x}`); anything else throws the
  new `UnsupportedVerificationMethodError`.
- `decodeMultibase`/`encodeMultibase` — dependency-free `z` (base58btc) /
  `u` (base64url) codecs, exported standalone.

**Signed-bytes note (divergence from the W3C `eddsa-jcs-2022` cryptosuite,
intentional, documented in `src/verify.ts`):** `createExchange()`
(`src/index.ts:229-234`) signs `jcsBytes(document-with-proof-omitted)`
directly — it does not build the W3C construction's
`sha256(JCS(proofConfig)) || sha256(JCS(document))`. Verification mirrors
`createExchange` exactly, for interop with our own artifacts, and a proof
computed the W3C way over an identical document+key is (correctly) rejected
— pinned by a dedicated test in `tests/verify.test.ts`.

No new dependencies (base58btc, base64url, and multicodec parsing are all
inline; Ed25519 verification uses `node:crypto`).

### `@e-sig/uaid-exch` 0.1.0-preview.2: `UaidSigningCredential` reconciled against the real tae/v1 schema (RedTeam G1a); JWK hygiene (G6)

**G1(a) — the `UaidSigningCredential` TS type was never checked against the
authoritative schema and did not match it.** Reconciled field-for-field
against `/Volumes/X/VMV/iaaso/artifacts/schemas/tae/v1/signing-credential/
schema.json`, which is `additionalProperties: false` at both the root and
`credentialSubject`/`scope`/`key`:

| | Before | After |
|---|---|---|
| root `type` | `["VerifiableCredential", "UaidSigningCredential"]` | `"IAASOSigningCredential"` (schema `const`) |
| root `@context` | `string[]` (required) | **removed** — not a schema property |
| root, added | — | `schemaVersion`, `issuedAt`, `subjectRef` (all required by the schema) |
| `credentialSubject.id` | `string` (agent uuaid) | **removed** — not a schema property |
| `credentialSubject.principal` | `string` | **removed** — not a schema property |
| `credentialSubject.authenticator.public_key_jwk` | `JsonWebKey` | **removed** — this is the field RedTeam G1 flagged: it does not exist in the schema at all |
| `credentialSubject.assurance_evidence` | optional array | **removed** — not a schema property |
| `credentialSubject.kya_hash` | `string` | **removed** — not a schema property |
| `credentialSubject.key` | *(did not exist)* | **added**: `{keyId: string, publicKey: string}` (schema.json:80-89) — the REAL field a key check belongs on |
| `credentialSubject.scope.counterparty_allowlist` | optional | renamed to `counterparties` (required, matches schema) |
| `credentialSubject.scope.geographies` | optional | renamed to `geography` (matches schema) |
| `credentialSubject.scope.resource_pattern` / `.assurance_min` | optional | **removed** — not schema properties |
| `proof` | `DataIntegrityProof` (singular) | `unknown[]` — the schema's `proof` is an array of an EXTERNAL `signatureEnvelope` shape (`common/base-object/v1.1` `$defs`, not fetched), not this package's own `DataIntegrityProof` |
| `signatureSuite` | *(did not exist)* | **added**, `unknown` (also external, not fetched) |

`RevocableCredential = Pick<UaidSigningCredential, "id"|"validFrom"|
"validUntil">` (revocation.ts) is unaffected — all three fields still exist
with the same `string` type. No other file in this package or `@e-sig/mcp`
constructed a full `UaidSigningCredential` literal or read the removed
fields (checked); only a type-only import.

**G6 — JWK hygiene.** `publicKeyFromVerificationMethod` now rejects a JWK
carrying ANY field beyond `{kty, crv, x}` — most notably a private-key `d`
(RFC 8037 §2) — instead of silently ignoring extras.

## @e-sig/mcp 0.1.1 — 2026-08-27

Fixes from a fresh-eyes onboarding audit of the published 0.1.0.

### `@e-sig/mcp` 0.1.1: fix — a seal failure could strand a validly-signed envelope (P0, data-corrupting)

`EnvelopeService.sign()` let core's `recordSignature` persist
`status: "completed"` and then called the seal step; if sealing threw (most
commonly: no Chrome/Chromium on the host) the envelope was stranded —
`completed` with no sealed PDF, the signing token already spent (a retry hit
409), the audit trail showing `envelope.signed` but never
`envelope.completed`, and `POST /sign` returning `500` even though the
signature itself was genuinely recorded.

Sealing is now an explicit, retryable, tracked step. A failed attempt is
caught and persisted as `metadata.mcp.seal = {status:"failed", error,
attempts, lastAttemptAt}`, audited as `envelope.seal_failed` instead of
throwing — `POST /sign` now responds `202` (`{status:"signed", sealed:false,
message}`) rather than `500`, and `GET /sign/<token>` shows the same
"signature recorded, sealing pending" sentence. A successful attempt sets
`seal.status = "sealed"` and audits `envelope.completed` exactly once, for
that attempt. `esig_envelope_status`/`esig_list_envelopes` now return a
`phase` (`sent | partially_signed | awaiting_seal | sealed | seal_failed |
voided | expired`) and the envelope's `seal` state. New tool `esig_reseal`
retries the seal step for a completed-but-unsealed envelope from what's
already stored — no re-signing needed — gated by the same hourly rate
limiter `esig_create_envelope` uses.

### `@e-sig/mcp` 0.1.1: fix — Chrome dependency was invisible until the signer's last click

Sealing needs Chrome/Chromium; nothing surfaced that until the last signer
hit "Sign" and it failed. `bin.ts` now runs a startup preflight (filesystem
existence/executable-bit checks only — it never launches a browser) and
prints `[esig-mcp] WARNING: no Chrome/Chromium found — envelopes can be
created and signed but NOT sealed; set ESIG_CHROME_PATH` when nothing is
found; the server still starts either way. `esig_whoami` returns
`sealReady`/`sealReadyReason`; `esig_create_envelope`'s result includes
`sealReady` and, when false, a `warning` field.

### `@e-sig/mcp` 0.1.1: fix — `--help` didn't mention `ESIG_MCP_DELIVERY` as required

`--help` listed only `ESIG_MCP_PASSPHRASE` as required, even though
`ESIG_MCP_DELIVERY` has no default and refuses to start without one.
`--help` now prints the full required/optional environment-variable table
(with defaults) and the 60-second quickstart, to stdout (not stderr — it
exits before the MCP stdio transport is ever constructed, so nothing has
claimed stdout yet). New `--version` flag prints the installed package
version.

### `@e-sig/mcp` 0.1.1: successful tool results are now JSON-first

`content[0]` on every *successful* tool result is now a JSON text block
mirroring `structuredContent`, so an MCP client that only reads `content[]`
(never `structuredContent`) can still `JSON.parse` it; the human-readable
summary line moves to `content[1]`. Error results (`isError: true`) remain a
single plain-text message in this release.

### `@e-sig/mcp` 0.1.1: `ESIG_MCP_DATA_DIR`'s `inbox/`, `outbox/`, `blobs/` are now created at startup

Previously created lazily by whichever store/channel/tool touched them
first. The startup "ready" line on stderr now prints all four paths
(data dir, inbox, outbox, blobs) absolute.

### `@e-sig/mcp` 0.1.1: README rewrite + doc-link fixes

Added a "Requirements" section (Node, Chrome-for-sealing-only, what still
works without Chrome) at the top; replaced every relative `../../docs/…`
link with an absolute GitHub URL (including the one inside a config-error
message that used to point nowhere for an installed npm package);
documented `POST /sign`'s request body and its new `202` case, the data
directory layout, and `esig_reseal`/phase values.

### `@e-sig/core` 0.7.1: docs-only README rewrite

No code changes. `packages/esig-core/README.md` rewritten for the npm
audience: leads with `npm i @e-sig/core`, a Chrome-free quickstart
(`generateSelfSignedCert` → `signPdf` on any existing PDF → `verifyPdfSignature`
→ tamper-and-reject) as the first example, an explicit Requirements section
naming the Chrome env vars only `renderHtmlToPdf` needs, and every
relative link that didn't resolve for an npm consumer (a vendored-directory
`../adapters/*` path, a `supabase/migrations/00106…` path, `.planning/…` —
none of which exist in this repo's actual layout) replaced with absolute
GitHub URLs into `vmvtech/esig-suite`. Removed the "drop this directory into
your project" vendoring narrative and its per-file install instructions,
which no longer describe how this package is actually consumed (`npm i
@e-sig/core`).

## 0.7.0 wave — published 2026-08-27

Ships everything in this section **and** the "0.7.0 — 2026-07-07" section
below in one publish: `@e-sig/core@0.7.0`, `@e-sig/supabase@0.3.1`,
`@e-sig/uuaid@0.1.1`, `@e-sig/uaid-exch@0.1.0-preview.1` (tag `preview`),
`@e-sig/worm@0.1.0`, `@e-sig/hsm-pkcs11@0.1.0`, and the new
`@e-sig/mcp@0.1.0`. `@e-sig/react@0.2.1` was already current.

### `@e-sig/mcp` 0.1.0: new package — agent-driven signing with human approval

An MCP server over `@e-sig/core` that lets an untrusted-by-default AI agent
ingest documents, create multi-signer envelopes, poll status, and verify
signed PDFs, while signing stays with humans via single-use tokenized links
in a built-in approval page. Signing tokens never cross MCP; link delivery
is an explicit operator channel (`ESIG_MCP_DELIVERY`: file outbox, opt-in
console, https webhook). Design and threat model:
`docs/architecture/esig-mcp.md`. RedTeam-reviewed before publish.

### `@e-sig/core`: fix signature-dictionary injection via `signPdf` options (security)

Reported by the UUAID lane on 2026-08-11, found while adversarially testing an
independent verifier against `@e-sig/core@0.6.0`. A caller of `signPdf` could
splice arbitrary keys into the PDF signature dictionary through its options —
including viewer-actionable ones such as `/OpenAction`. The resulting document
is *validly signed*: the signature genuinely covers the injected content, which
is what makes it dangerous. It matters wherever `signPdf` options are fed from
user or tenant input; a hardcoded call site was never exposed.

Root cause is `PDFObject.convert` in `@signpdf/utils` (inherited from pdfkit),
on two paths:

- **`subFilter`** was passed through as a JS string, which that converter emits
  as a raw unescaped PDF name (`/${value}`) — so whitespace or a delimiter in
  the value ends the `/SubFilter` token early and everything after it becomes
  sibling keys in the signature dictionary.
- **`reason` / `name` / `location` / `contactInfo`** (found while reproducing
  the above, and the more exposed of the two — these commonly come straight
  from a web form). The converter's dictionary branch emits *any* value whose
  string form contains `<<` completely raw — not converted, not escaped, not
  even wrapped in the PDF string parens.

Fixed in two layers:

- **`subFilter` is now validated against a closed set** — `ETSI.CAdES.detached`
  and `adbe.pkcs7.detached`, the only two this signer can actually produce.
  Exported as `SUPPORTED_SUBFILTERS` / the `SubFilter` type. The check is at
  runtime, not only in the types, because the attack surface is JS callers.
  Narrowing `subFilter?: string` to `subFilter?: SubFilter` is a compile-time
  breaking change for TS callers that pass a plain `string`.
- **The vendored serializer is hardened** (new
  `src/vendor/placeholder-plain/pdfObject.ts`, replacing `@signpdf/utils`'
  `PDFObject` at the one call site): the raw-splice branch is removed outright,
  and PDF names are escaped per ISO 32000-1 §7.3.5. This closes the class, not
  just the two reported paths. It is the only deliberate divergence from
  upstream in that vendored directory.

Output is **byte-identical to upstream for every legitimate input** — verified
on the real path by running `plainAddPlaceholder` through both converters over
the same PDF across 8 cases (both subfilters, unicode and paren-bearing string
fields, `appName`, `widgetRect`, large budget) and diffing bytes. Regression
coverage in `test/sig-dict-injection.test.ts`, which asserts the byte-identity
claim rather than assuming it.

### `@e-sig/core`: optional signer-asserted UUAID in the post-quantum seal

Enables IAASO-0004 (Media Provenance & Attribution) identity attribution for
e-sig-signed PDFs, at the request of the UUAID registry lane.

- **`buildPqSeal({ …, uuaid })` / `signPdf({ pqSeal: { …, uuaid } })`** embed an
  optional `uuaid` field in the seal's *signed* payload, so the assertion is
  bound under both Ed25519 and ML-DSA-65 and cannot be added to, removed from,
  or swapped on an existing seal. `signPdf` returns it as `pqUuaid`.
- **`verifyPqSeal` / `verifyDocument`** surface `verdict.uuaid` and accept
  `expectedUuaid` to pin it (mirroring `expectedMldsa65Fpr`). Pinning against a
  seal that asserts no UUAID fails — no silent downgrade.
- **Fail-closed on malformed claims.** `buildPqSeal` refuses to sign a
  structurally invalid identifier, and `verifyPqSealSignatures` rejects a seal
  carrying one (new `uuaidOk`, folded into `ok`) even when its signatures are
  intact. Validation is structural only — which subject classes and object types
  exist is UUAID's registry to evolve, not this package's to adjudicate.
  `isWellFormedUuaidAssertion` is exported as the wire contract.
- **Not a version bump of the seal.** `PQ_SEAL_VERSION` stays `1`: the field is
  omitted entirely unless supplied, so unattributed seals are byte-identical to
  pre-`uuaid` output, and verifiers that predate the field still verify
  uuaid-bearing seals (the signed payload is reconstructed generically as "the
  seal minus `sig`"). Bumping the version would have been the breaking change.
  Verified twice: 7/7 checks against **`@e-sig/core@0.6.0` installed from npm**
  (the current `latest`, and the version downstream verifiers pin) — it accepts
  attributed seals and PDFs, round-trips the field verbatim, and simply ignores
  it; plus 13/13 cross-version checks, both directions, against a local snapshot
  of the pre-`uuaid` 0.7.0 build (unpublished — 0.7.0 has never been released to
  npm).
- **Semantics — read before relying on it.** A valid `uuaid` proves the seal key
  *claims* that identity (key → uuaid). It does **not** prove the identity's
  owner authorised the document; the uuaid → key direction lives in the UUAID
  registry and is out of scope here. Unmatched, the assertion is worth no more
  than the TOFU fingerprint beside it.
- One additive break for consumers doing exact-shape assertions:
  `PqSealVerification` gained `uuaidOk`.

## 0.7.0 — 2026-07-07 (published 2026-08-27 as part of the wave above)

The "tech behind the add-ons" release: every self-serve vertical add-on now
ships real, tested capability — not a label and a price.

### Pre-publish hardening (2026-07-12)

Folded into 0.7.0 before its first npm publish:

- **`@e-sig/core`: zero-vulnerability consumer installs.** The
  `@signpdf/placeholder-plain` dependency (whose `placeholder-pdfkit010`
  transitive declares a `pdfkit@~0.10.0` peer that npm auto-installs, dragging
  in `crypto-js@3.3.0` with 6 critical advisories) is replaced by a vendored
  TypeScript port (`src/vendor/placeholder-plain/`, MIT, provenance headers +
  `LICENSE-signpdf.md`). Output proven byte-identical to upstream across 12
  input×option combinations, including the already-signed incremental path.
  `npm install @e-sig/core` now audits clean: 0 vulnerabilities.
- **`@e-sig/core`: portable Chrome discovery.** `renderHtmlToPdf` honors
  `ESIG_CHROME_PATH` / `PUPPETEER_EXECUTABLE_PATH` / `CHROME_PATH`, scans
  common Chrome/Chromium/Edge/Brave locations on macOS/Linux/Windows, fails
  loud when an env var points at a non-executable, and the not-found error
  lists every path tried plus the override options.
- **`@e-sig/core`: deterministic PQ key provisioning.**
  `generatePqKeyBundle({ mldsa65Seed, ed25519Pkcs8 })` derives the hybrid
  bundle from caller-supplied key material (same seed → same identity);
  omitted fields stay random. Input validation on seed length and key type.
- **`@e-sig/uaid-exch`: ships its LICENSE.** The package directory was missing
  the LICENSE file that `files` referenced, so the tarball published without
  license text.
- Repo hygiene: workspace devDependencies on `@e-sig/core` pinned to `^0.7.0`
  (stale `^0.6.0` pins nested old registry copies of core — and their pdfkit
  chain — under `packages/*/node_modules`); `esig-uuaid` moved to vitest 4;
  the root `crypto-js` override is gone (nothing pulls crypto-js anymore).
  Root `npm audit`: 0 vulnerabilities.

### `@e-sig/core` 0.7.0 — ExternalSigner (HSM seam)

**`ExternalSigner`.** `signPdf` / `PemSigner` accept `{ externalSigner }` as an
alternative to `keyPem`: `{ keyType, certificatePem, signRsaSha256(data) }`.
The RSA private key never has to enter process memory — signatures are
delegated to hardware (HSM, PKCS#11 token, KMS). Sync or async signers both
work; output is byte-identical to the in-memory path (proven by test). Existing
callers are unaffected — `keyPem` behaves exactly as before (87 pre-existing
tests unchanged, 7 new).

### `@e-sig/hsm-pkcs11` 0.1.0 — NEW (HSM Signer add-on)

`Pkcs11Signer` implements `ExternalSigner` over an injected PKCS#11 session
(CKM_SHA256_RSA_PKCS), fail-closed on login failure / missing key / wrong-size
signatures; fresh session per signature. `pkcs11js` is an optional peer — wire
AWS CloudHSM / YubiHSM / SoftHSM per the README.

### `@e-sig/worm` 0.1.0 — NEW (WORM Archival add-on)

`WormPdfStorageStore` (a core `PdfStorageStore`) writes every object with S3
Object Lock retention set atomically (default COMPLIANCE / 7 years) and a
conditional create (`IfNoneMatch: "*"`) so overwrite is rejected by the store
AND by S3; there is no delete surface. `exportAuditRowsToWorm` snapshots the
tenant audit chain as deterministic NDJSON into the same locked bucket.
Includes a provisioning script and SEC 17a-4 / FINRA framing docs.

### `@e-sig/uaid-exch` 0.1.0-preview.1 — revocation lists

UAP-EXCH-1 § 9 (draft): `createRevocationList` / `revokeCredential`
(append-only, JCS-canonical sha256 digest, idempotent) /
`verifyRevocationListIntegrity` / `assertCredentialUsable`. Fail-closed
everywhere: tampered lists throw on lookup, unparseable validity dates reject,
expiry + revocation both gate use. 14 new tests (26 total in the package).

### `@e-sig/uuaid` 0.1.1 · `@e-sig/supabase` 0.3.1

Peer ranges widened to allow `@e-sig/core` `^0.7.0`; no code changes.

### Compliance packs (repo `docs/compliance/`, ship with paid add-ons)

HIPAA: BAA template (45 CFR 164.504(e)) + healthcare operations runbook.
21 CFR Part 11: clause-by-clause requirements mapping (§ 11.10–11.300 → real
product controls, with an honest customer-responsibility column) + IQ/OQ/PQ
validation protocol templates. All marked DRAFT pending counsel review.

## 0.6.0 — 2026-07-06

### `@e-sig/core` 0.6.0 — post-quantum hybrid seal + ML-DSA-65 X.509

**Post-quantum signing (FIPS 204).** New optional hybrid **Ed25519 + ML-DSA-65**
seal, embedded *under* the classical PKCS#7/PAdES RSA signature so signed PDFs
stay valid in every reader (Adobe Acrobat included) while gaining quantum
resistance — the NIST / CNSA 2.0 migration path. `signPdf` / `signDocument`
accept a `pqSeal` / `pq` option; `verifyDocument` returns both the classical and
post-quantum verdicts, with optional in-band fingerprint pinning
(`expectedMldsa65Fpr`) and `requirePq` (no silent downgrade). The seal covers
SHA-256 of the pre-seal PDF and is embedded append-only so the classical
`/ByteRange` protects it — tampering the document breaks **both** layers. Managed
keys via `ensureActivePqKeys` / `rotatePqKeys` over a bring-your-own `PqKeyStore`.

**ML-DSA-65 X.509 identity (RFC 9881).** `issueMlDsaCertificate` mints a
self-signed ML-DSA-65 certificate (SubjectPublicKeyInfo *and* signature both
`id-ml-dsa-65`, OID `2.16.840.1.101.3.4.3.18`) — parses and verifies in
OpenSSL 3.5+. `verifyDocument({ signerCert })` binds a certificate to a seal by
public-key fingerprint; `verifyMlDsaCertificate` / `certMatchesPqSeal` are also
exported. Fully backward compatible — the seal is opt-in and unsealed documents
verify exactly as before.

### `@e-sig/supabase` 0.3.0 — managed post-quantum keys

`SupabasePqKeyStore` implements the core `PqKeyStore` over a new `org_pq_keys`
table (migration `0003_esig_pq_keys.sql`): one active hybrid bundle per tenant,
AES-256-GCM-wrapped at rest, RLS mirroring `org_signing_certs`. Peer dependency
widened to allow `@e-sig/core` `^0.6.0`.

### `@e-sig/react` 0.2.1

Version bump for the coordinated 0.6.0 release; no code changes.

## 0.5.0 — 2026-07-03

### `@e-sig/core` 0.5.0 — envelopes, fs adapters, verifier fix

**Multi-signer envelopes + tokenized signing links.** New storage-agnostic
envelope model (`createEnvelope`, `resolveSigningToken`, `recordSignature`,
`declineEnvelope`, `voidEnvelope`, `composeEnvelopeHtml`, `EnvelopeStore`
interface): N ordered signers over one document, each addressed by an opaque
single-use 32-byte token returned exactly once — only SHA-256 hashes are
persisted. Equal order signs in parallel; lower orders gate higher ones; a
decline voids the envelope; expiry applies lazily. Completion composes all
signature blocks for the single cryptographic seal via `signDocument()`.
Sequential *PDF* re-signing remains deliberately out of scope (single
/ByteRange signer+verifier) and is documented as such. Audit vocabulary gains
`envelope.*` actions.

**Filesystem adapters (`@e-sig/core/fs`).** `FsCertStore`, `FsAuditLogStore`
(append-only NDJSON), `FsPdfStorageStore` (traversal-guarded), and
`FsEnvelopeStore` run the entire pipeline on a bare directory — no Supabase,
no database. Single-process semantics, atomic-replace JSON state.

**Verifier fix (false rejection).** `/Contents` placeholder padding is now
stripped by slicing at the DER's TLV-declared length instead of trimming
trailing `00` hex pairs, which truncated any PKCS#7 blob whose final byte was
legitimately `0x00` (~1/256 of RSA signatures) and rejected valid documents.
Could never false-accept — a truncated DER never parses.

**Signature block.** The audit footer no longer hardcodes an origin-project
name, and the caller-supplied `platformLabel` is HTML-escaped like every other
interpolation.

### `@e-sig/supabase` 0.2.0 — tamper-evident audit chain

Migration `0002_esig_audit_hashchain.sql` chains `esig_audit_log` per tenant
(SHA-256 linkage computed by a `BEFORE INSERT` trigger under an advisory lock)
and blocks UPDATE/DELETE/TRUNCATE even for `service_role`; existing rows are
backfilled. New `verifyAuditChain()` re-derives the chain client-side,
cross-checks each row's columns against its canonical payload, and fails loudly
when a server row cap truncates pages. The audit action CHECK now admits
`envelope.*` / `verify.*`. Vitest suite added and wired into root `npm test`.
Peer range widened to `@e-sig/core ^0.4.0 || ^0.5.0`.

### `@e-sig/react` 0.2.0 — VerifyPanel + honest consent evidence

New `VerifyPanel` component: verdict badge, structure/digest/signature rows,
signer and RFC-3161 timestamp details, failure list, and a fixed scope caveat
(embedded-cert validation, first signature only, no chain/revocation). Zero
dependency on core (structural `VerifyResult` mirror).

`SelfSignFlow` now POSTs `consent_given` plus the exact consent text it
rendered (`consent_text_shown`), so servers can record what the signer actually
saw instead of a hardcoded string. Servers should require these fields — the
example app's sign route now does.

## 0.4.0 — 2026-07-03

### `@e-sig/core` 0.4.0 — cryptographic hardening

Security- and correctness-focused release. Signature output changed (an extra
signed attribute is added and the signature is recomputed), so it is a minor
bump; previously-signed PDFs are unaffected and still verify.

**Verification is now cryptographic.** `verifyPdfStructure()` (aliased as the
clearer `verifyPdfSignature()`) no longer only checks byte-range structure — it
recomputes SHA-256 over the ByteRange-covered bytes and compares it to the
`messageDigest` signed attribute, then RSA-verifies the signature over the
signed attributes against the embedded signer certificate. `ok === true` now
means the signature is valid over the exact document; a single flipped byte
under the signature yields `ok:false` / `digestValid:false`. New result fields:
`digestValid`, `signatureValid`.

**PAdES / CAdES cert binding.** Every signature now carries the ESS
`signing-certificate-v2` signed attribute (RFC 5035), binding the signer
certificate into the signed data. New `padesStrict` option on `signPdf` /
`PemSigner` additionally drops the PAdES-forbidden `signing-time` attribute for
strict ETSI EN 319 142-1 **PAdES-B-B** conformance. Default mode is additive and
backward-compatible (keeps `signing-time`).

**Certificate hygiene.** Serial numbers are now 128 bits of CSPRNG entropy
(RFC 5280 §4.1.2.2) instead of `Date.now()`. The extended-key-usage no longer
claims `clientAuth` (TLS client, semantically wrong for document signing) — it
is `emailProtection` only, plus a Subject Key Identifier.

**Rendering.** `renderHtmlToPdf` now disables in-page JavaScript by default
(`javascriptEnabled` to opt back in) and waits for the `load` event (not
`domcontentloaded`) so embedded signature images and logos are present in the
PDF rather than occasionally blank. Added a `timeoutMs` option.

**Injection guard.** `renderSignatureBlocksHtml` (and the new exported
`assertImageDataUrl`) reject anything that is not a base64 image data URL before
interpolating it into the signed document, closing an attribute-breakout /
script-injection surface.

**Tests + CI.** Added a real Vitest suite (cert issuance, AES-GCM key wrapping,
sign→verify, tamper rejection, ESS attribute presence, strict-PAdES, data-URL
guard) run against the built package, plus a GitHub Actions workflow on Node
20/22. The Chrome-free smoke test now asserts the signature is valid and that a
tampered PDF is rejected.

### `@e-sig/supabase`

- Peer/dev dependency on `@e-sig/core` bumped to `^0.4.0`.
