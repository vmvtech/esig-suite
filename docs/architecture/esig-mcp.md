# @e-sig/mcp — MCP server for agent-driven signing with cryptographic human approval

Status: LIVING DESIGN. §1–§10 = v0.1 design (2026-08-26, shipped as
`@e-sig/mcp@0.1.0`); §11 = v0.1.1 sealing state; §12 = v0.2 signer identity
(shipped on `main` 2026-08-27, RedTeam RT-2026-08-27-04 CLOSED); §13–§14 =
v0.3 PDF envelopes + `init`/`demo`. API bindings were verified against
`packages/esig-core/src` (file:line cites below).

## 1. Understanding and scope

An MCP (Model Context Protocol) server, `@e-sig/mcp`, that lets any
MCP-capable AI agent (Claude, GPT, local agents, IDE agents) drive
e-signature workflows against `@e-sig/core` — prepare documents, create
envelopes, watch signing progress, verify signed PDFs — while
**cryptographic control of signing stays with humans by default**.

Positioning (2026-08 market recon, 22 sources): the trending adjacency is
"AI agents negotiate and prepare contracts; cryptographically bounded human
approval signs." Nobody ships this as OSS. esig-suite already owns every
ingredient: hybrid PQ seal with signer-asserted `uuaid` attribution
(pq-seal.ts), `@e-sig/uuaid` audit-actor stamping + Polygon chain-head
anchoring, single-use tokenized signing links (envelope.ts), and an
`/agents` page + `agent.json` already courting agent traffic. This package
gives those agents something to *do*.

**Non-goals (v0.1):** not a hosted service (local/self-hosted; hosted mode
later reuses the assurance-gateway auth model); no QES/eIDAS; no
key-custody changes (private keys never transit MCP); not a general PDF
toolkit.

## 2. Threat model

Actors: the **agent** (untrusted-by-default MCP caller — assume it can be
prompt-injected), the **human signer** (trusted, reached out-of-band via
browser), the **operator** (deploys the server, owns keys, policy, and the
link-delivery channel).

| # | Threat | Mitigation |
|---|--------|-----------|
| T1 | Agent signs something no human saw | Mode H default: the agent can create an envelope but **never receives the raw signing token or link**. `createEnvelope` returns raw tokens exactly once (envelope.ts:103-165; only SHA-256 `tokenHash` is persisted) — the MCP server consumes them immediately into the operator-configured delivery channel (console/QR, email hook, webhook). The agent gets signer IDs and delivery receipts only. |
| T2 | TOCTOU: agent swaps the document between human review and signature | The envelope row owns the `html`; the token resolves to that envelope via unique `findByTokenHash` (envelope.ts:73-81). The MCP server exposes **no tool that mutates envelope content after creation**, and records `sha256(html)` in the creation audit row so the sealed output can be tied back to what was reviewed. |
| T3 | Prompt-injected agent exfiltrates key material | No tool returns key bytes, seeds, or PEM. `ensureActiveCert` / `ensureActivePqKeys` results (which contain decrypted PEM in-process, cert-lifecycle.ts:22-52) never cross the MCP boundary. Invariant I1 tested. |
| T4 | Attribution spoofing: agent claims another agent's identity | Attribution has two prongs, both server-owned: `withUuaidActor(store, agentUuaid)` stamps every audit row's metadata (esig-uuaid/uuaid-actor.ts:25-35 — decorator is authoritative, caller-supplied values overwritten), and `signPdf({ pqSeal: { keys, uuaid } })` (sign-pdf.ts SignPdfInput) takes the uuaid from **server config**, never from tool parameters. |
| T5 | Approval replay | Tokens are 32-byte CSPRNG, base64url, stored only as SHA-256 hash, single-use, order-gated, lazily expired (envelope.ts:167-209). Concurrency honesty: core delegates write atomicity to `EnvelopeStore.update` ("full replace; apply optimistic concurrency here") — so the MCP default store MUST implement conditional update (see I3). |
| T6 | Flooding / runaway agent | Per-session rate limits, per-hour envelope caps, max HTML/PDF size, audit row per state-changing call. |
| T7 | Silent downgrade (agent-signed passes as human-signed) | Agent-signed artifacts carry `uuaid` in the seal; `verifyDocument` surfaces `postQuantum.uuaid` + `uuaidMatches` and supports `requirePq` (pq-verify.ts:172-225), so any verifier distinguishes agent-signed from human-signed. |
| T8 | Agent scripts the approval page (holds no token but knows the URL pattern) | Tokens are unguessable (32-byte CSPRNG) and never surfaced through MCP (T1); the approval endpoint accepts only a valid raw token. Link secrecy = delivery-channel custody, which is the operator's, not the agent's. |
| T9 | **Agent-authored HTML attacks the human's browser** — the envelope body is written by the agent and rendered to the signer; injected script could auto-submit the signature pad or read the token out of the URL | Envelope HTML is rendered inside a fully sandboxed `<iframe sandbox srcdoc>` (no `allow-scripts`, no `allow-same-origin`, no forms), the approval page ships `Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'` + `Referrer-Policy: no-referrer`, and `<script>`/event-handler attributes are stripped at `esig_create_envelope` (defense in depth; core already disables JS at seal-time render). |

## 3. The three signing modes

**Mode H — human signs (default, always on).** The agent prepares HTML
(directly, or via markdown→HTML), then `esig_create_envelope`. The server
calls core `createEnvelope` (mints tokens), immediately dispatches signing
links through the operator's delivery channel, and returns only envelope +
signer IDs. Humans open the link: the built-in approval page renders the
envelope HTML, runs `resolveSigningToken` (order gating: `not_your_turn`,
`already_signed`, `completed|voided|expired`, `invalid` — envelope.ts
TokenResolution), collects the drawn signature, and calls
`recordSignature` (auto-completes on the last signer, envelope.ts:218-258).
On completion the server composes `composeEnvelopeHtml` (requires
`status === "completed"`, envelope.ts:302-327) and seals it through
`signDocument` (render→sign→audit→store orchestrator, sign-document.ts) —
optionally with the operator's PQ seal and TSA. The agent polls
`esig_envelope_status` and finishes by verifying the sealed artifact.

**Mode A — agent signs as itself (policy-gated, off by default).** For
machine-to-machine or low-stakes documents the operator explicitly allows:
the server signs with a **dedicated agent certificate** (never the
operator's primary cert) via `signPdf`/`signDocument` with
`pqSeal: { keys, uuaid }` — the seal permanently marks the artifact as
agent-signed (result carries `pqSealed`, `pqKeyId`, `pqMldsa65Fpr`,
`pqUuaid`). Audit store wrapped in `withUuaidActor`. Gated by policy:
enabled flag, document-size cap, purpose allowlist, hourly cap.

**Mode C — dual-key co-sign (policy-gated, off by default, v0.2).** The
"cryptographically bounded human approval" story: an envelope whose signers
include the agent identity and a human. The agent's half is applied with
Mode A mechanics; the envelope completes only when the human signs their
tokenized link. Composition of shipped primitives, not new crypto.

## 4. Tool surface

Design rule (Anthropic agent-design guidance): dedicated, typed tools —
never a generic escape hatch — because dedicated tools are what the server
can **gate, audit, and rate-limit**. Reads are parallel-safe; writes
serialize per envelope.

### Read tools (always allowed)

| Tool | Input | Output (bound to real result shapes) |
|------|-------|--------------------------------------|
| `esig_verify_document` | pdf (path/base64/docId) + optional `expectedUuaid`, `expectedMldsa65Fpr`, `requirePq` | `DocumentVerification`: `ok`, `classical` (digestValid, signatureValid, signerCommonName, timestamped, failures[]), `postQuantum` (present, ok, ed25519, mldsa65, fingerprintOk, keyId, mldsa65Fpr, uuaid, uuaidMatches, failures[]) — pq-verify.ts:172-225 |
| `esig_envelope_status` | envelopeId | Envelope status (`sent → partially_signed → completed \| voided \| expired`), per-signer status (`pending \| signed \| declined`), timestamps; plus sealed-PDF URL once completed |
| `esig_list_envelopes` | filter | Envelope summaries |
| `esig_whoami` | — | Session identity: configured uuaid assertion, cert + `mldsa65Fpr` fingerprints, enabled modes, policy caps. **Never key material.** |

`esig_verify_document` is deliberately the widest-open tool: *any* agent
verifying *any* e-sig document is the viral loop.

### Prepare tools (allowed, audited)

| Tool | Input | Output |
|------|-------|--------|
| `esig_ingest_document` | pdf bytes/path | docId = sha256 (content-addressed workdir; mode A + verify input) |
| `esig_create_envelope` | title, html (or markdown), signers[{name, email, roleLabel?, order?}], expiresAt? | envelopeId, signer IDs, delivery receipts, `sha256(html)`. **Raw tokens/links are NOT returned** (see T1); `ESIG_MCP_RETURN_LINKS=1` relaxes for local demos only, loudly. |
| `esig_void_envelope` | envelopeId | Sender-side cancel via core `voidEnvelope` (no token needed, envelope.ts:260-298) |

Declining is human-side only (requires the token) — deliberately not an
MCP tool.

### Sign tools (gated)

| Tool | Gate | Behavior |
|------|------|----------|
| `esig_sign_as_agent` | Mode A enabled + policy | Signs docId with the agent cert + PQ seal + config uuaid; returns signed docId + immediate `verifyDocument` summary |
| `esig_cosign_start` | Mode C enabled (v0.2) | Two-signer envelope (agent + human); agent half signed immediately, human link dispatched |

There is no tool that: exports keys, mutates envelope content, changes
policy, returns raw signing tokens (by default), or signs without either a
human link (H/C) or an explicit operator-enabled mode (A).

## 5. Architecture

```
agent ── MCP (stdio | streamable HTTP) ──> @e-sig/mcp
                                             ├─ policy.ts      deny-by-default gates
                                             ├─ tools/*.ts     one module per tool
                                             ├─ delivery.ts    console/QR | email | webhook link dispatch
                                             ├─ audit           AuditLogStore (adapters.ts:55-98), wrapped
                                             │                  in withUuaidActor for A/C
                                             ├─ workdir/        content-addressed docs (id = sha256)
                                             ├─ @e-sig/core     createEnvelope/resolveSigningToken/
                                             │                  recordSignature/composeEnvelopeHtml/
                                             │                  signPdf/signDocument/verifyDocument
                                             ├─ @e-sig/core/fs  Fs* stores (fs-adapters.ts) — default
                                             └─ approval page   renders envelope HTML + signature pad
human ── browser ── signing link (delivered out-of-band) ──┘
```

- **Package:** `packages/esig-mcp`, npm `@e-sig/mcp` (404 — free, verified
  2026-08-26). MIT, workspace member, standard build/test chain.
- **SDK:** `@modelcontextprotocol/sdk` (TypeScript). Transports: stdio
  (default) and streamable HTTP. The approval page needs HTTP regardless,
  so the server always runs a minimal HTTP listener when mode H is used;
  stdio remains the MCP transport in local setups.
- **Approval page (v0.1, built-in):** renders envelope HTML, shows signer
  gate states from `TokenResolution`, captures a drawn signature
  (`signatureImageDataUrl` per `recordSignature`), records consent. A
  config hook lets an integrating app supply its own signing UI instead —
  the token contract is host-agnostic.
- **Rendering:** HTML→PDF only at seal time via core's `renderHtmlToPdf`
  (puppeteer-core, JavaScript disabled by default, render-pdf.ts:106-146;
  Chrome resolved via env/platform scan, loud fail). **JS-off is NOT
  SSRF-safe** (RedTeam G1, 2026-08-27): Chrome still fetches `<img>`,
  `<link>`, CSS `url()`, `<object>`, and follows `<meta http-equiv=refresh>`
  with `waitUntil:"load"`, from the operator's machine, and bakes the result
  into the *signed* PDF. The seal render therefore launches Chrome with
  `--host-resolver-rules=MAP * ~NOTFOUND` (`SEAL_RENDER_LAUNCH_ARGS`,
  envelopes.ts) so every network lookup fails while `data:` URLs (the
  signature image) still render — measured 6/6 vectors fetched without the
  rule, 0/6 with it.
- **Config:** env-first, gateway-precedent style: `ESIG_MCP_MODES`
  (default `H`), `ESIG_MCP_UUAID` (required for A/C), `ESIG_MCP_PASSPHRASE`
  (cert/PQ key at-rest encryption, per `ensureActiveCert`/`wrapPqKeyBundle`),
  delivery channel config, `ESIG_MCP_BASE_URL`, caps. Fail-closed: A/C
  refuse to start without a dedicated agent cert tenant + uuaid.
- **Stores:** `@e-sig/core/fs` adapters by default (zero-dependency
  quickstart); `@e-sig/supabase` opt-in for the hash-chained audit trail;
  all four seams (`CertStore`, `AuditLogStore`, `PdfStorageStore`,
  `PqKeyStore`, `EnvelopeStore`) injectable, mirroring core.
- **Later (hosted):** the gateway's `Authenticator`/tenant-registry
  pattern (esig-gateway/src) is the auth model for multi-tenant HTTP
  deployments; `ExternalSigner` (RSASSA-PKCS1-v1_5/SHA-256 seam,
  types.ts:59-75) is the HSM/KMS path — both deferred, both already exist.

## 6. Security invariants (each becomes a test)

1. **I1 — no key egress:** no tool result, log line, or error ever contains
   private-key bytes, seeds, or PEM (harness greps every serialized result
   across the suite).
2. **I2 — fail closed:** `esig_sign_as_agent`/`esig_cosign_start` refuse
   when their mode is disabled; fresh install = mode H only.
3. **I3 — atomic single-use:** the default EnvelopeStore implements
   conditional update (optimistic concurrency), so two concurrent
   `recordSignature` calls on one token yield exactly one success. Core
   explicitly delegates this to the store — the MCP store must supply the
   mechanism, and the test races it.
4. **I4 — content binding:** envelope content is immutable post-creation
   through MCP; `sha256(html)` recorded at creation and re-checked at seal
   time; mode A signs only content-addressed bytes.
5. **I5 — server-owned attribution:** the uuaid in any seal or audit row
   equals server config; tool parameters can never influence it
   (`withUuaidActor` decorator is authoritative by construction).
6. **I6 — audit before ack:** every state-changing tool writes its
   `AuditLogStore` row (actions: `envelope.created/.signed/.voided/
   .completed`, `pdf.signed`, `pdf.verified`) before returning success.
7. **I7 — no silent downgrade:** verification output always distinguishes
   agent-signed (uuaid present) from human-signed; `requirePq` exposed.
8. **I8 — token custody:** raw tokens/links never appear in an MCP tool
   result unless `ESIG_MCP_RETURN_LINKS=1`, and that flag's state is
   stamped into every affected audit row (transitional-auth precedent from
   the gateway).
9. **I9 — signer-browser isolation:** the approval page response carries
   the CSP + Referrer-Policy headers above, envelope HTML is only ever
   emitted inside the sandboxed iframe, and an envelope created with
   `<script>`/`onload=` content is stored stripped (test asserts all three).
   The sanitizer runs to a **fixpoint** (RedTeam G2: a single pass let
   `<ifr<form></form>ame>` re-assemble into a live tag after the form strip).
10. **I10 — seal-render egress denied:** the seal-time Chrome launch always
   carries the host-resolver deny rule (RedTeam G1); a test pins the args.
11. **I11 — link delivery is explicit:** `ESIG_MCP_DELIVERY` has no default
   (RedTeam G3: stderr is the agent harness's log surface in stdio
   deployments, so a silent console default hands the signing capability to
   the very principal T1/T8 exclude). `file` (0600 outbox) is the quickstart
   channel; `console` is opt-in with a startup warning and an audit stamp;
   `webhook` requires https and times out.

## 7. Testing and release gates

- vitest in-package: policy gates (I2), token race (I3), content pinning
  (I4), attribution pinning (I5), key-egress sweep (I1), token custody
  (I8), plus end-to-end: agent creates envelope → link delivered → human
  simulated via HTTP against the real approval endpoint → envelope
  completes → sealed PDF → `verifyDocument.ok` → tamper flips it.
- MCP-level integration test through a real MCP client session (SDK
  in-memory transport) — the consumer path, not internal calls.
- **RedTeam review before first publish** (fleet SOP: new attack surface).
  Submit threat model + invariant tests + e2e evidence.
- Publish via `scripts/publish-preflight.mjs`; new-name manual
  first-publish + trusted-publisher setup applies (known gate).

## 8. Rollout

- **v0.1 (launch-ready):** verify + mode H + built-in approval page +
  quickstart demo ("agent drafts an NDA, human signs from their phone,
  agent verifies and files it"), README, MCP registry listing, site
  `/agents` update.
- **v0.2:** modes A and C, policy file, Supabase audit chain,
  envelope-completion webhooks, `anchorChainHead` integration (agent
  anchors the tenant audit chain head to UUAID's Polygon-anchored ledger —
  esig-uuaid/anchor.ts:51-70 — external tamper evidence as a tool).
- **Later:** hosted multi-tenant mode on the gateway auth model, C2PA
  content credentials, verification receipts (playbook Day 8-30).

## 9. Decision log

- 2026-08-26 — Dedicated typed tools over a generic command tool: signing
  is the gate/audit class; a generic tool cannot be policy-gated per action.
- 2026-08-26 — Mode H is the only default: the wedge is *trustless* agent
  participation; a fresh install that can sign autonomously would poison
  the security story.
- 2026-08-26 — Reuse core envelope tokenized links as the HITL mechanism:
  shipped, tested, hash-only-at-rest, order-gated; the human reviews the
  real document.
- 2026-08-26 — **Raw tokens never cross MCP** (v2 hardening, from reading
  the real `CreateEnvelopeResult` contract): link custody belongs to the
  operator's delivery channel, closing both T1 and T8 by construction
  rather than by policy.
- 2026-08-26 — **Envelopes are HTML-first** (v2 correction): core's
  envelope flow operates on HTML with drawn-signature capture and produces
  the sealed PDF at completion via `composeEnvelopeHtml` → `signDocument`;
  the earlier PDF-envelope draft assumption was wrong.
- 2026-08-26 — Built-in approval page ships in v0.1: without it the
  five-minute demo requires an integrating web app.
- 2026-08-26 — `@e-sig/mcp` npm name confirmed free; `@e-sig/core/fs`
  subpath confirmed (fs-adapters.ts).
- 2026-08-26 — v0.1 scope trims at build time: envelopes accept **HTML
  only** (no markdown dependency yet); no `@e-sig/uuaid` dependency in
  v0.1 (only modes A/C need attribution, and `@e-sig/uuaid` pulls the
  UUAID network SDK); no QR dependency — console delivery prints the URL.
  Operator PQ seal on the sealed envelope PDF is **on by default**
  (`ESIG_MCP_PQ=1`) via a package-local `FsPqKeyStore`, since core's fs
  adapters ship no PQ key store.
- 2026-08-26 — Build executed as lib worker → server worker → blind
  verifier (workflow `wf_8ddd0633-49d`); root gates re-run by the lead
  after the verifier's verdict.

## 10. Open questions (owner)

1. Approve package name `@e-sig/mcp` + placement `packages/esig-mcp`?
2. v0.1 scope: mode H only at launch (A/C in v0.2 after RedTeam), or hold
   launch until all three modes clear review?
3. Approval page branding: e-sig footer + "verify this document" link
   (distribution loop) or neutral?
4. Launch slot: does the MCP story lead the Show HN or follow it?
5. Default delivery channel for v0.1: console/QR only, or also ship the
   email hook (needs SES config → more setup friction in the quickstart)?
   *(Resolved 2026-08-27 by RedTeam G3: no default; file/console/webhook.)*

## 11. Sealing state and `esig_reseal` (v0.1.1)

Core's `recordSignature` persists `status: "completed"` on the last signer
*before* the seal step runs, so sealing is modelled as its own tracked,
retryable step: `metadata.mcp.seal = {status: "sealed" | "failed", error?,
attempts, lastAttemptAt, sealedPdfPath?}`. A derived `phase` — `sent |
partially_signed | awaiting_seal | sealed | seal_failed | voided | expired`
— is what tools report. A seal failure is audited as `envelope.seal_failed`,
`POST /sign` answers `202 {sealed:false}` (the signature *is* recorded), and
`esig_reseal(envelopeId)` retries from stored state; `envelope.completed` is
audited exactly once, on the successful attempt. Startup runs a
filesystem-only Chrome preflight; `esig_whoami.sealReady` exposes it.

## 12. Signer identity via UUAID + IAASO (v0.2 design, 2026-08-27)

**Goal.** Bind *who signed* to a verifiable identity without inventing a new
identity system: UUAID identities (`uuaid:<subjectClass>:<jurisdiction>:
<authority>:<localId>` or `uuaid:foundation:<objectType>:<uuid>`, grammar in
core `pq-seal.ts`) and IAASO TAE artifacts (`tae/v1` signing-credential /
exchange / exchange-receipt, assurance ladder L0–L5, ADR-006). Owner
direction: "uuaid and iaaso integration can help signer identity."

**Levels (map 1:1 to the IAASO ladder; we do not define our own).**

| Level | What is checked | Where |
|---|---|---|
| none | nothing (v0.1 behavior) | — |
| L0 asserted | signer's `uuaid` is well-formed (`isWellFormedUuaidAssertion`) and, if the envelope pinned an expected uuaid at creation, equal to it | local |
| L1 proven | the signer presents a `DataIntegrityProof` (`eddsa-jcs-2022`, Ed25519) over a server-issued **sole-control challenge**; signature verified locally; key ↔ uuaid binding is self-asserted (IAASO L0/L1 semantics) | local, new `verifyDataIntegrityProof` / `verifyExchange` in `@e-sig/uaid-exch` |
| L2 registry-bound | L1 plus the registry attests the key: **`GET /iaaso/v1/badge/{uuaid}`** (public, registry-signed hybrid Ed25519 + ML-DSA-65) must carry `payload.subject.presentationKey = {alg:"ed25519", publicKey:<64 lowercase hex>, keyId}` byte-equal to the proof key (`/resolve/{uuaid}` carries **no agent keys** — Uuaid-Lead, live-measured 2026-08-27; a badge `404 tombstoned` refuses); any presented `UaidSigningCredential` passes `GET /verify/{credentialId}` (valid, active, notExpired **and `agent_uuaid` equal to the signer's uuaid**); optionally the exchange is submitted and the **receipt** (validation material + anchor) is stored | network, `ESIG_MCP_UUAID_REGISTRY_URL` |
| L3–L5 | out of scope for v0.2 (DSalvus attestation, chain anchor, QES) | — |

**Challenge (the sole-control evidence).** Issued per signer, single-use,
15-minute TTL, JCS-canonical:
`{type:"esig-signer-challenge/v1", envelopeId, signerId, htmlSha256, nonce(32B b64url), issuedAt, expiresAt}`.
The nonce is stored on the signer (`metadata.identity.challenge`) and
**consumed atomically** under the envelope store mutex when a proof is
accepted (I3 class). Obtainable two ways: `GET /sign/<token>/challenge`
(the human's own link) and the MCP tool `esig_identity_challenge(envelopeId,
signerId)` (audited) so a sender-side agent can relay it to the signer's
agent/wallet — the IAASO agent-to-agent exchange path. The challenge is not
secret; the *proof* is what matters, and it is bound to
envelope + signer + content digest + nonce + expiry.

**Presenting a proof.** `POST /sign/<token>` gains an optional
`identityProof: {uuaid, proof: DataIntegrityProof, credential?:
UaidSigningCredential, exchange?: UaidExchange}`; the approval page gets an
"attach identity proof" field (paste JSON) for humans whose wallet/agent
produced it. Verification runs **before** `recordSignature`; a failed or
mismatched proof refuses the signature (`403`, audited
`signer.identity_rejected`) — never a silent downgrade.

**Policy.** `ESIG_MCP_IDENTITY_MIN_LEVEL` = `none` (default) | `L0` | `L1` |
`L2`; `esig_create_envelope` may set `identity: {minLevel, signers[].uuaid}`
and may only **raise** the level. L2 requires `ESIG_MCP_UUAID_REGISTRY_URL`
(https) **and** `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY` (the registry's Ed25519
public key, 64 hex, from its `/.well-known/uuaid-registry.json` — pinned at
config time, never fetched per-request) — refused otherwise (fail closed);
the URL in force is **pinned on the envelope at creation**
(`metadata.mcp.identity.registryUrl`) and a verify attempt under a different
configured URL refuses with `L2_REGISTRY_URL_CHANGED` (RedTeam G3). The
signing key is deliberately NOT pinned per envelope: the URL pin already
fixes which registry attests, and a registry key rotation must not strand
already-created envelopes — a rotated key simply fails verification (fail
closed) until config is updated.

**What gets recorded.** Per signer: `{level, uuaid, keyFingerprint
(sha256 of raw Ed25519 key), proofDigest (sha256 of JCS proof),
credentialDigest?, verifiedAt, registry?: {resolvedAt, registrySnapshotDigest,
credentialId?, credentialValid?, receiptId?, anchor?}}` — every digest names a
content-addressed file under `blobs/identity/<sha256>.json` (proof,
credential, badge snapshot)
— in the envelope, in audit rows (`signer.identity_verified`), in the file
outbox receipt, and as an "Identity" line in the composed signature block
that is sealed into the PDF. Full proof JSON is kept in `blobs/`
(content-addressed), not in audit metadata (PII minimization). The
operator's PQ-seal `uuaid` stays the *operator's* assertion; signer
identities are not written into the seal (the seal key is not theirs).
Phase 2 (core, later): staple the signer-identity manifest into the PDF as
an append-only incremental update under `/ByteRange`, so
`esig_verify_document` can surface `signers[]` offline — the PDF-native
receipt stapling from the IAASO 2701 position.

**Threats added (extend §2).**

| # | Threat | Mitigation |
|---|---|---|
| T10 | Forged proof | Ed25519 verified over the exact JCS challenge; unknown cryptosuite/proofPurpose → reject; key from `verificationMethod` (`did:key` Ed25519 multicodec, or a bare JWK `{kty:OKP, crv:Ed25519, x}`) and, when a signing credential is presented, it MUST equal the credential's `credentialSubject.key.publicKey` (the tae/v1 schema field — RedTeam G1 corrected the earlier `authenticator.public_key_jwk`, which does not exist); network-dereferenced methods (`did:web`, URLs) are refused |
| T11 | Replay / cross-envelope reuse | challenge carries envelopeId + signerId + htmlSha256 + nonce + expiry; nonce single-use, consumed atomically; expired → reject |
| T12 | Identity substitution | expected uuaid pinned at creation; mismatch refuses; minLevel can only be raised |
| T13 | Registry trust (L2) | https only; the registry's badge is **verified against the pinned registry key** (`ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY`, 64 hex — hash binding + Ed25519 + freshness), so trust rests on the pinned key, not TLS alone (TOFU no longer required for the attestation itself; the ML-DSA half of the hybrid badge signature is not yet verified — Ed25519-only trust anchor); the badge's `subject.uuaid` **must equal the uuaid being proven** (a signed badge for a *different* subject that shares the presentation key is refused with `L2_BADGE_SUBJECT_MISMATCH` — blind-verifier finding 2026-08-27); the registry URL is **pinned per envelope at creation** and a changed URL refuses (RedTeam G3); the full badge envelope is snapshotted into `blobs/` and its digest recorded; registry down ⇒ L2 refuses (never silently drops to L1); a badge 404 (absent/tombstoned) refuses with `L2_UUAID_NOT_FOUND` |
| T15 | Downgrade through an error-swallowing path | identity verification runs before `recordSignature` and structurally outside the seal `try/catch` (RedTeam G4); a throwing verifier can never lead to a recorded signature (tested) |

**Clarifications after RedTeam RT-2026-08-27-04 and the build verifier:**
the challenge's `htmlSha256` is the sha256 of the *immutable base HTML pinned
at creation* (`metadata.mcp.htmlSha256`), never the composed render, so it is
stable across signers (G2); challenge issuance is idempotent within the TTL
and rotates only after consumption or expiry (G5); **L1 proves control of a
key and binds the `uuaid` only by self-assertion — only L2 binds key ↔ uuaid
through the registry** (verifier R3); full proof / credential / registry
snapshot artifacts live in content-addressed `blobs/` with digests in the
signer record, and a completion receipt `<outbox>/<envelopeId>.completed.json`
carries `signers[].identity` (verifier R1/R2); `createExchange` signs raw JCS
bytes (not the W3C double-hash form), so proof *options* are outside the
signed bytes and `proofDigest` covers them (verifier R5).
| T14 | PII in proofs/credentials | only digests, uuaid, key fingerprint in audit; full artifacts in content-addressed blobs |

## 13. PDF envelopes — sign an existing PDF, Chrome-free, WYSIWYS (v0.3)

`esig_create_envelope` accepts exactly one of `html` or `docId` (an ingested
PDF; `%PDF-` magic required). For a PDF envelope:

- **WYSIWYS by construction.** The signer views the *exact ingested bytes*
  (`GET /sign/<token>/document.pdf`, same origin, `nosniff`, `no-store`,
  inline, embedded in a plain same-origin iframe plus an "open" link — not
  the sandboxed `srcdoc` iframe, which cannot host a PDF viewer), and the
  seal signs those same bytes with core `signPdf` (+ PQ seal): the
  `/ByteRange` covers the original document byte-for-byte. No rendering, so
  no Chrome anywhere on this path.
- **Core stays unchanged.** Core envelopes require `html`; a PDF envelope's
  `html` is a generated, escaped *cover sheet* (title, docId/sha256, size,
  signer list) that drives core's token/order/`recordSignature` flow.
  `metadata.mcp.document = {docId, sha256, size, kind:"pdf"}`.
- **Identity challenge format unchanged** (RedTeam re-probe trigger avoided):
  the pinned `htmlSha256` is the cover sheet's digest, and the cover sheet
  embeds the document sha256, so the challenge binds the PDF transitively.
- Drawn signatures and identity records are evidence in the envelope,
  audit, and completion receipt; the PDF's signature is invisible (standard
  PKCS#7 detached). A rendered "signing certificate" page appended to the
  PDF is the later Certificate-of-Completion item (needs a renderer).
- Threat note: a malicious ingested PDF can only attack the signer's PDF
  viewer, which is no worse than opening any PDF; the page's CSP and the
  token model are unaffected.

## 14. `esig-mcp init` and `esig-mcp demo` (v0.3)

`init [--dir]` creates the data dirs, generates a passphrase into a `0600`
env file (never overwrites without `--force`), prints an `.mcp.json` snippet
with absolute paths, and runs the Chrome preflight. `demo [--auto]` runs an
end-to-end, Chrome-free PDF envelope on a temp data dir with `file` delivery
and `ESIG_MCP_RETURN_LINKS=1` (loud, demo-only): ingest the bundled
`assets/sample.pdf`, create a one-signer envelope, print the signing URL and
a curl one-liner; with `--auto` it performs the signature itself and prints
the sealed PDF path plus the `verifyDocument` verdict.

**Bindings (verified 2026-08-27 by scout).** `@e-sig/uaid-exch`:
`createExchange`, `exchangeInputFromEsigEnvelope`, `jcs/jcsBytes`,
`DataIntegrityProof`, `UaidSigningCredential`, `UaidExchange`,
`assertCredentialUsable` (revocation.ts) — **no verifier exists; must be
built** (`verifyDataIntegrityProof`, `verifyExchange`, did:key/JWK key
decoding). Registry (live-measured 2026-08-27, Uuaid-Lead evidence +
esig-l2-live-probe): `GET /iaaso/v1/badge/{uuaid}` — registry-signed
SignatureEnvelope `{payload, payloadHash:"0x"+sha256(JCS(payload)),
signatures[]}`, hybrid ed25519 `uuaid-registry-1` + ml-dsa-65; payload's
`subject.presentationKey` = `{alg:"ed25519", publicKey:<64 lowercase hex>,
keyId}` | null (HEX — not multibase/JWK/did:key); trust anchor
`/.well-known/uuaid-registry.json` keys[].publicKey (PIN it);
`/resolve/{uuaid}` carries **no signer key material at all** (only
`credentials[].signingKeyId` = AIAU's issuer key). `GET /verify/{credentialId}`
→ `{credential_id, agent_uuaid, valid, signatureValid, active, notExpired,
keyId}`. Core:
`isWellFormedUuaidAssertion`. IAASO: `/Volumes/X/VMV/iaaso/artifacts/schemas/tae/v1/*`.
