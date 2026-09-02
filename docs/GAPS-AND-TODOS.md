# esig-suite — Gaps & Todos (Lead review, 2026-09-01)

Consolidated ledger from a full review of `main` @ `53d14ff` (tree clean, CI
green, all nine `@e-sig/*` packages live on npm). Every claim was either
verified directly by the Lead (marked **[verified]**) or comes from a cited
`file:line` in the two audit passes (esig-suite product/marketing audit;
AlliShare integration recon at `/Volumes/X/VMV/allishare`). Items with no
citation do not exist in this document.

Executable versions of these todos live in the fleet Auto Run folder:
`/Volumes/X/VMV/vmv-office/.maestro/playbooks/fleet/esig/2026-09-01-Gaps-Program/`
(one `GAPS-0N.md` per phase, task-based).

This ledger sits **under** `docs/growth/90-day-playbook.md` — it does not
change the playbook's gates (checkout stays closed, WVOA stays the north
star, no vote manipulation, no analytics scripts). It fills the execution
trail the playbook asked for and never got.

Priorities: **P0** = data corruption / lies to the customer / breaks a clean
clone. **P1** = required before the feature can honestly be called shipped.
**P2** = makes it good. **P3** = polish. Effort: S (≤ ½ day), M (1–3 days),
L (a week+).

---

## 0. State of the project in ten lines

1. The SDK is real and shipped: core 0.8.0, mcp 0.5.0, supabase 0.3.1,
   react 0.2.1, uuaid 0.1.1, worm/hsm/pillar-bridge 0.1.0, uaid-exch preview;
   80 test files; CI (`ci.yml`) builds, tests, smokes and runs the quickstart
   on Node 20 + 22. Released via Trusted Publisher only. **[verified]**
2. Baseline today **[verified 2026-09-01]**: GitHub 4 stars / 0 forks / 0
   open issues, Discussions **enabled**, repo `homepage` **null**, `topics`
   **0**. npm last-week downloads: core 442, mcp 467, supabase 140, react 10.
   WVOA (the north star) has **never been recorded**.
3. **One demo asset exists for eleven packages** — `examples/quickstart/demo.gif`
   (43 KB, committed 2026-07-23 against core 0.4.x, now 0.8.0), byte-duplicated
   into `site/assets/quickstart-demo.gif`. No script can regenerate it. The
   README's headline CTA `npx @e-sig/mcp demo --auto` has no visual at all.
4. **Signer messaging exists only inside `@e-sig/mcp`** (SMTP/SES transport,
   signing-link template, reminders, 13 envelope event kinds). A plain
   `@e-sig/core` / `@e-sig/react` adopter gets zero invite/reminder machinery;
   `envelope.ts:117` tells them to deliver tokens "out-of-band".
5. **There is no support channel.** No `support@e-sig.org`; the only technical
   route is "GitHub issues & discussions", rendered `class="dim"` on pricing.
   No support policy, no contact form, no status page.
6. **The waitlist is a black hole to the submitter**: DynamoDB row + internal
   sales SQS message (email deliberately omitted), no confirmation, every
   record permanently `email_verification_status: "unverified"` → the list is
   not mailable.
7. **Marketing has no owned channel.** Zero social handles in the repo (only
   `twitter:image` meta, no `twitter:site`). The one launch action (Show HN
   2026-08-28, item 49475553) was auto-flagged on a 1-karma account; the
   appeal email is still with the owner. The launch thread that *did* go out
   went through **AlliShare's API to VMVTech's Bluesky**, using the
   cross-tenant admin key — not an e-sig account, not an e-sig org.
   *Update 2026-09-02:* the e-sig org and its own scoped key now exist
   (§8.2); zero platform accounts are connected to it yet (EX-03).
8. **AlliShare can carry e-sig marketing today, narrowly:** prod is live
   (`api.allishare.com` 200) but runs 2026-07-13 code; only **Bluesky +
   Telegram** can publish without a platform developer app. X/LinkedIn/Reddit
   wait on AlliShare's own OAuth-app blockers (their `EX-02`).
9. **AlliShare support cannot be reused as-is:** every support route is behind
   org auth (unauthenticated `POST /support/chat` → 401), the staff inbox is
   cross-org platform-admin-only, the assistant persona and `From:` are
   hard-coded AlliShare, and API-key tickets carry no requester email.
10. Product gaps behind the front door: `@e-sig/react` has **no test script**
    and documents 3 of 4 components; `examples/nextjs-supabase` has **no
    `package.json`** (advertised as "the full wiring"); the public browser
    verifier `site/verify/verify.js` is a committed bundle with **no build
    config, no tests, and no PQ-seal check**; root README lists 4 of 10
    packages; no `CONTRIBUTING.md` / issue templates. **[verified]**

---

## 1. P0 — fix first

**None.** No data-corruption, customer-facing lie, or clean-clone break was
found. Checkout is fail-closed by design and tested
(`infra/lambda-checkout/index.js` = 18-line 302 **[verified]**;
`scripts/checkout-gate.test.mjs`; `site/finish.sh:87`). The verify page
carries an explicit "What this does not check" section
(`site/verify/index.html:111` **[verified]**). Keep it that way.

---

## 2. Workstream A — Demo GIFs & videos (DM)

**Goal:** every headline feature has a reproducible, versioned demo; the
same source renders a README GIF and a social-ready MP4.

**Tooling decision [verified on this machine]:** `asciinema` + `agg` are
installed (`/opt/homebrew/bin`), `ffmpeg` 7 is installed; `vhs` and `gifski`
are not. **Playwright, Puppeteer, and every headless browser driver are
banned fleet-wide** (owner directive 2026-08-23, re-affirmed for e-sig
2026-09-02): the only browser path is **kimi-webbridge**, the local daemon
at `http://127.0.0.1:10086` that drives the owner's real Chrome
(`~/.claude/skills/kimi-webbridge/SKILL.md`; probed live 2026-09-02). If the
daemon is down, fix it or stop and tell the owner — never substitute a
headless browser. Terminal demos = `asciinema rec` → `.cast` (text,
diffable, committed) → `agg` → GIF. Browser demos = a dependency-free Node
script driving kimi-webbridge (`navigate` → `upload` → timed `screenshot`s
to disk) → PNG sequence → `ffmpeg` → GIF + MP4. Every demo is a script under
`demos/`, never a hand-recorded blob.

| ID | Pri | Item | Files | Effort |
|----|-----|------|-------|--------|
| DM-01 | P1 | **Demo toolchain.** `demos/` workspace: `record-terminal.sh <name> -- <cmd>` (fixed 100×30, `--idle-time-limit 1`, deterministic theme/font via `agg --theme --font-size`), `render.sh` (`.cast` → `assets/<name>.gif`, plus `ffmpeg` → `<name>.mp4` 1280×720 and a square 1080×1080 variant for social), `demos/README.md`, root `npm run demos`. Commit `.cast` sources. | new `demos/`, root `package.json` | S |
| DM-02 | P1 | **Regenerate the quickstart GIF** at core 0.8.0 through DM-01; replace `examples/quickstart/demo.gif` and `site/assets/quickstart-demo.gif`; add a test that the two are byte-identical (or make the site copy a build step in `site/finish.sh`). | `examples/quickstart/demo.gif`, `site/assets/quickstart-demo.gif`, `scripts/*.test.mjs` | S |
| DM-03 | P1 | **MCP demo GIF** — `npx @e-sig/mcp demo --auto` (Chrome-free by construction, `packages/esig-mcp/src/cli-demo.ts:1-16`). Wire into `README.md:39`, `packages/esig-mcp/README.md:18`, `docs/index.html` `#mcp`, `site/agents/index.html`. | `demos/mcp-demo.cast`, READMEs | S |
| DM-04 | P1 | **Multi-signer envelope GIF** — create envelope → signer A signs → signer B signs → seal → `esig verify` (`packages/esig-core/src/bin/esig.ts:208` only knows `verify`; drive the envelope through a small `demos/envelope.mjs` over `@e-sig/core/fs`). Shows tokenised links + order gating. | `demos/envelope.mjs`, `demos/envelope.cast` | M |
| DM-05 | P1 | **Post-quantum hybrid seal GIF** — sign with PQ seal → `esig verify --require-pq` ✓ → flip one byte → both layers ✗. This is the homepage's `NEW` pill (`site/index.html:132-137`); it currently has an illustrated readout and no proof. | `demos/pq-seal.cast`, `site/index.html` | S |
| DM-06 | P1 | **Verify-in-browser GIF** (kimi-webbridge driving the owner's real Chrome — no Playwright): `upload` a signed fixture into the page's `#file` input → valid readout; `upload` the tampered fixture → invalid. Frames are timed `screenshot`s → `ffmpeg`. Fixtures come from GP-03. | `demos/browser/verify.mjs` | M |
| DM-07 | P2 | **React `SelfSignFlow` + `SignaturePadCanvas` GIF** via a Vite playground (`examples/react-playground`) mounting the components against a mock `signEndpoint`. This playground doubles as the `@e-sig/react` test harness (GP-01). Recorded through kimi-webbridge like DM-06. | `examples/react-playground/`, `demos/browser/selfsign.mjs` | M |
| DM-08 | P2 | **Pillar agent-to-agent GIF** — `examples/pillar-agent` two-terminal run (split with `tmux` inside the recording). | `demos/pillar-a2a.cast` | S |
| DM-09 | P1 | **Wire assets everywhere they are promised**: per-package README top-fold, `site/index.html` feature rows, `docs/index.html` sections, `site/press/index.html` (press kit downloads), `site/llms-full.txt` regen (`scripts/ops/gen-llms-full.mjs`). | READMEs, site, docs | S |
| DM-10 | P2 | **Social cuts**: from each `.cast`/WebM produce a ≤ 60 s MP4 with a 3-line title card (Bluesky video limit; Telegram mp4), poster PNG, and alt text in `demos/manifest.json` — consumed by MK-04. | `demos/render.sh`, `demos/manifest.json` | S |

---

## 3. Workstream B — Signer messaging & notifications (MSG)

**Today (all real, MCP-only):** `packages/esig-mcp/src/email/transport.ts`
(`SmtpTransport` STARTTLS-default, `SesTransport` via optional
`@aws-sdk/client-sesv2`, `CapturingTransport`), `templates.ts`
`renderSigningEmail` (subject/text/html, header-injection stripped),
`delivery.ts` one email per signer link, `reminders.ts` (`computeDue` +
60 s scheduler, `ESIG_MCP_REMINDERS`, off by default, requires
`delivery.kind === "email"` per `config.ts:162`), 13 event kinds
(`envelope.created|viewed|signed|declined|completed|sealed|voided|expired|
reminder_sent|reminder_failed|reseal_requested|seal_failed`) with webhook
delivery. **Missing:** any of it for non-MCP adopters; any notification to
the *sender*; any customer-facing confirmation on the waitlist.

| ID | Pri | Item | Files | Effort |
|----|-----|------|-------|--------|
| MSG-01 | P1 | **Extract `@e-sig/notify`** from `packages/esig-mcp/src/{email/*,reminders.ts}`: transports, `renderSigningEmail`, `EmailDelivery`, `computeDue`/`Scheduler`, with no MCP imports; `@e-sig/mcp` re-exports and depends on it (no behaviour change; mcp's 26 test files stay green). Owner decision needed on the package name — a new npm name needs Trusted-Publisher web-UI setup before first publish (see EX-08). | new `packages/esig-notify/`, `packages/esig-mcp/src/*` | M |
| MSG-02 | P1 | **`signDocument`/envelope recipe with delivery** — `@e-sig/core` `createEnvelope` returns `signingTokens[]` and says deliver out-of-band (`packages/esig-core/src/envelope.ts:117`). Ship a documented, tested recipe `examples/envelope-email/` that mints tokens and sends them through `@e-sig/notify`; link from the core README "Envelopes" section and docs. | `examples/envelope-email/`, `packages/esig-core/README.md`, `docs/index.html` | S |
| MSG-03 | P1 | **Sender notifications**: on `envelope.signed` / `completed` / `declined` / `expired`, email the envelope owner (opt-in `notifyOwner`), reusing `EmailDelivery`; template `renderOwnerEmail`. Events already fire (`packages/esig-mcp/src/events/`), nothing consumes them for the owner. | `packages/esig-notify/src/templates.ts`, `packages/esig-mcp/src/envelopes.ts` | M |
| MSG-04 | P2 | **Template branding**: `EmailTemplateInput` takes only `url`, `expiresAt`, `prefix` (`templates.ts:20-25`). Add `brand: { name, logoUrl?, supportEmail?, footer? }`, keep plain-text parity, keep `stripControlChars` on every field. Test snapshot both renderings. | `packages/esig-notify/src/templates.ts` + tests | S |
| MSG-05 | P1 | **Waitlist confirmation (double opt-in).** `infra/waitlist/src/handler.js` writes DynamoDB + outbox; `notifier.js` fans out to the sales SQS with the address stripped; nothing emails the submitter. Add: SES send of a confirmation with a signed verify link → `GET /waitlist/verify?t=` flips `email_verification_status` to `verified`; sales payload gains `email_verification_status`. Needs an SES sending identity for `e-sig.org` (EX-02). Keep the `@example.com` smoke path. | `infra/waitlist/src/{handler,verify,mailer}.js`, `template.yaml`, tests | M |
| MSG-06 | P2 | **Docs page "Notifications, reminders & events"** on docs.e-sig.org consolidating `#mcp-email`/`#mcp-events` for SDK users (not just agents), with the DM-04 GIF. | `docs/index.html` | S |
| MSG-07 | P2 | **Actionable errors** (playbook Day 8-30 §5): every thrown `EsigError`/MCP tool error carries `docsUrl` + "ask in Discussions" link, no document content. | `packages/esig-core/src/errors.ts`, `packages/esig-mcp/src/tools/*` | S |

---

## 4. Workstream C — Support system (SU)

**Today:** `sales@`, `legal@`, `security@` (`site/agent.json:91-92`,
`site/press/index.html:116-118`), `SECURITY.md` (advisories, 3-day ack),
"GitHub issues & discussions" (`site/press/index.html:119`,
`site/pricing/index.html:139` dimmed). Discussions are enabled on the repo
**[verified]** but never linked with categories. No `support@`, no form, no
policy, no SLA statement, no status page.

**Design decision (Lead):** *Use AlliShare as the ticket system, but bridge
through an e-sig-owned intake.* AlliShare's support model
(`packages/db/prisma/schema.prisma:1032-1072`, routes `apps/api/src/routes/
support.ts`) is org-scoped for customers but single-queue/single-brand for
staff and has no public intake; until AlliShare ships the items in §8 we
front it with a tiny e-sig Lambda that holds the e-sig org key server-side.
When AlliShare's public intake + per-tenant branding land, the Lambda becomes
a pass-through or is deleted.

| ID | Pri | Item | Files | Effort |
|----|-----|------|-------|--------|
| SU-01 | P1 | **`support@e-sig.org` exists and is published**: add to `site/agent.json`, `site/press/index.html`, footer partial on all 12 pages, `site/llms.txt`/`llms-full.txt`, `packages/*/README.md` "Support" line. Mailbox provisioning is EX-02. | site, READMEs | S |
| SU-02 | P1 | **Support policy page** `site/support/index.html`: channels (Discussions for Q&A, issues for bugs, `support@` for private, `security@` per `SECURITY.md`), response targets (community best-effort; Cloud preview / design partners 1 business day), what to include (never the document). Replace the dimmed line at `site/pricing/index.html:139`; add to `sitemap.xml`, `robots.txt` untouched. | `site/support/`, `site/pricing/index.html`, `site/sitemap.xml` | S |
| SU-03 | P1 | **Contact form + intake Lambda** (`infra/support-intake/`, same SAM shape as `infra/waitlist/`): honeypot + per-IP rate limit (no captcha scripts — site stays tracker-free), validates `{email, subject, message, context: 'sdk'|'cloud'|'billing'|'other'}`, then (a) `POST https://api.allishare.com/api/v1/support/chat` under the e-sig org key with the requester email embedded in the first line, (b) copies to `support@e-sig.org` via SES, (c) returns the AlliShare conversation id as a ticket ref. Fail closed: if AlliShare is down, (b) still sends and the form still succeeds. Tests mirror `infra/waitlist/test/*`. | `infra/support-intake/`, `site/support/index.html`, `scripts/support-form.test.mjs` | M |
| SU-04 | P1 | **Community health files**: `CONTRIBUTING.md` (build/test/smoke, PR rules, TP-only releases), `CODE_OF_CONDUCT.md`, `.github/ISSUE_TEMPLATE/{bug,feature,question→Discussions}.yml`, `PULL_REQUEST_TEMPLATE.md`, `.github/FUNDING.yml` (only if Sponsors is enabled — EX-07). `.github/` today holds only `workflows/` **[verified]**. | `.github/`, root | S |
| SU-05 | P1 | **Discussions categories + Show & Tell as the WVOA ledger**: create `Q&A`, `Ideas`, `Show and tell` (pinned template: "what you signed, how you verified, what tamper test you ran, may we count you?"). Every accepted Show-and-tell post is one WVOA entry in `docs/growth/evidence/`. Link from README, support page, MSG-07 error links. | GitHub settings (owner), `README.md`, `site/support/` | S |
| SU-06 | P2 | **Escalation to the swarm**: a Cue subscription (`.maestro/cue.yaml`) polling AlliShare for e-sig-org conversations in `escalated` status and nudging Esig-Lead; needs an org-scoped list endpoint (AS-REQ-02). Until then, `support@` mail + the AlliShare `/ops/support` deep link email (`WORKLOG.md:641-659`) is the path. | `.maestro/cue.yaml`, `scripts/ops/support-poll.mjs` | S (after AS-REQ-02) |
| SU-07 | P2 | **Status page**: static `site/status/index.html` fed by a tiny probe (e-sig.org, docs, verify, npm) written by `scripts/ops/probe.mjs` on a schedule; no third-party status SaaS. | `site/status/`, `scripts/ops/probe.mjs` | S |
| SU-08 | P2 | **Repo metadata** (quick win, owner-clickable or `gh api`): `homepage` → `https://e-sig.org`, topics `e-signature pdf pkcs7 pades cades rfc3161 post-quantum mit sdk typescript self-hosted mcp`, description updated to list mcp + pq. Today `homepage: null`, `topics: 0` **[verified]**. | GitHub | S |

---

## 5. Workstream D — Marketing via AlliShare (MK)

**Guardrails (from the 90-day playbook, unchanged):** one reproducible proof
per week; disclose affiliation; never ask for votes or coordinate
engagement; no identical cross-posts; no analytics scripts on the site; broad
distribution only after the Day-30 go/no-go (WVOA ≥ 10). Today WVOA is
unrecorded, so the current phase is **build the loop and post proofs**, not
a splash.

**AlliShare facts this plan relies on [from recon, paths in
`/Volumes/X/VMV/allishare`]:** `POST /api/v1/post` (`apps/api/src/routes/
post.ts:66`; schema `packages/shared/src/schemas/post.ts:150-178`) with
`scheduleAt`, `shortenLinks`, `firstComment`, `idempotencyKey`,
`platformOptions`; `POST /api/v1/rss` article-to-post with
`requiresApproval`; webhooks `post.published|post.failed|account.connected`
(`packages/shared/src/constants.ts:101-118`, HMAC `t=,v1=`); Bluesky connect
= `POST /oauth/bluesky/connect {handle, appPassword}`; Telegram =
`{accessToken, chatId}`; org provisioning `POST /enterprise/tenants` or
`packages/db/scripts/onboard-client.ts` (one-off ECS task). Approval is a
2-call `PATCH {requiresApproval:false}` + `PUT /post/:id/retry` dance.

| ID | Pri | Item | Files | Effort |
|----|-----|------|-------|--------|
| MK-01 | **DONE 2026-09-02** | **Dedicated e-sig org on AlliShare** — provisioned: org `e-sig`, profile `title:"e-sig.org", refId:"esig-marketing"`, org-scoped key live in Secrets Station at `allishare/esig/api_key` → env **`ALLISHARE_API_KEY_ESIG`**. Ids and the `profileKey` are deliberately not recorded in this public repo (§8.2). Verified by Esig-Lead: `/user` 200, `/profiles` 200, `/admin/orgs` **403**. `AISWARA_ADMIN_KEY_ALLISHARE` is VMVTech-only — never used here, and **never rotated or revoked by us**. Remaining work is the checker script (GAPS-05). | Secrets Station, `docs/growth/allishare.md` | S |
| MK-02 | P1 | **First owned channels: Bluesky + Telegram** (the only wave-0 platforms). Bluesky handle as a **domain handle** `@e-sig.org` (DNS `TXT _atproto.e-sig.org "did=did:plc:…"` — a trust signal that matches the brand); Telegram channel `@esig_dev` with a bot as admin. Connect both through the profile from MK-01. Accounts/DNS/bot token are EX-03. | AlliShare profile, DNS, `site/press/index.html` | S (after EX-03) |
| MK-03 | P1 | **Blog index + RSS on docs.e-sig.org** — `docs/blog/` has one post (`der-length-bug.md`) linked only from press/llms/HN draft; no index, no `/blog` route, no feed **[verified]**. Generate `docs/blog/index.html` + `docs/blog/feed.xml` from `docs/blog/*.md` (front-matter `title/date/summary`) with a script beside `scripts/ops/gen-llms-full.mjs`; nav link on `docs/index.html` and `site/index.html`. Then register the feed on AlliShare `POST /api/v1/rss {feedUrl, platforms:['bluesky','telegram'], requiresApproval:true, template}` so every proof post auto-drafts. | `scripts/ops/gen-blog.mjs`, `docs/blog/`, `docs/index.html` | M |
| MK-04 | P1 | **Publish queue → AlliShare** `scripts/growth/publish.mjs`: reads `docs/growth/queue/*.json` (`{id, platforms, text per platform, mediaRef→demos/manifest.json, scheduleAt, utm_campaign}`), adds `utm_source=<platform>&utm_medium=social&utm_campaign=<id>`, `shortenLinks:true`, `idempotencyKey:id`, `firstComment` for the repo link; **dry-run by default**, `--live` requires `ALLISHARE_API_KEY_ESIG` (Secrets Station `allishare/esig/api_key`, loaded via `secrets run`) plus the `Profile-Key` header resolved at runtime from `refId "esig-marketing"`; writes the API response to `docs/growth/evidence/week-NN/<id>.json`. Unit-test with mocked fetch like `scripts/publish-preflight.test.mjs`. | `scripts/growth/publish.mjs` + test, `docs/growth/queue/` | M |
| MK-05 | P1 | **Evidence + baseline, weeks 1-5.** Create `docs/growth/evidence/week-01`…`week-13/` and `experiments/`; `scripts/growth/baseline.mjs` snapshots GitHub (stars/forks/issues/discussions) + npm last-week per package (public APIs, no auth) into `week-NN/baseline.md`; re-score weeks 1-4 pass/fail against `90-day-playbook.md:185` board from git history; record WVOA = 0 honestly with the Show-and-tell ledger (SU-05) as the counting rule. | `docs/growth/evidence/`, `scripts/growth/baseline.mjs` | S |
| MK-06 | P1 | **Weekly proof calendar, weeks 5-13** (`docs/growth/calendar.md`): wk5 MIT-SDK-vs-app architecture proof (+DM-02), wk6 tamper anatomy (+DM-05/06), wk7 Supabase recipe (+GP-02), wk8 verification receipt prototype (MK-10), wk9 launch candidate dry run, wk10 OSS launch (r/selfhosted, r/node, Lobsters, dev.to — **not HN**, per the one-submission rule), wk11-13 per playbook. Each row: proof URL, platform copy (Bluesky ≤ 300 chars, Telegram long-form), media from DM-10, `queue/*.json` id. | `docs/growth/calendar.md`, `docs/growth/queue/` | S |
| MK-07 | P2 | **Site social wiring**: footer + press kit list Bluesky/Telegram/GitHub Discussions; `site/agent.json` `sameAs`; add `twitter:site` **only** when an X handle exists. | `site/*` | S |
| MK-08 | P2 | **Evidence webhook**: AlliShare `post.published`/`post.failed` → the SU-03 Lambda (`/hooks/allishare`, HMAC-verified per `docs/integration-guide.md:313-330`) → appends to the week's evidence file. Automates MK-04's bookkeeping. | `infra/support-intake/src/hooks.js` | S |
| MK-09 | P2 | **LinkedIn / X / Reddit** — blocked on AlliShare OAuth apps (their `EX-02`; X write is a paid tier) and human-required account creation (AlliShare registration plane wave 3). Draft the copy now in the calendar; do not open accounts by hand outside the registration plane (it records the checkpoints). | `docs/growth/calendar.md` | — (EX-04) |
| MK-10 | P2 | **Optional verification receipt / share link** (playbook week 8, the actual propagation mechanism): result + cert fingerprint + verifier version, no PII, "Verify with e-sig" / "Build with the MIT SDK" actions, off switch. Threat-model doc first. | `packages/esig-core`, `site/verify/` | L |
| MK-11 | P2 | **dev.to + Product Hunt**: not in AlliShare's 13-platform enum; dev.to has an API key API (`POST /api/articles`) — request an adapter (AS-REQ-04) or post manually with the blog canonical URL. Product Hunt only after Day-60 go/no-go. | — | S (manual) |

---

## 6. Workstream E — Product & repo gaps (GP)

| ID | Pri | Item | Files | Effort |
|----|-----|------|-------|--------|
| GP-01 | P1 | **`@e-sig/react` has no `test` script and 0 tests** **[verified]**; root `npm test` and CI skip it silently; README documents 3 of 4 exports (`VerifyPanel` missing). Add vitest + `@testing-library/react` + jsdom, tests for all four components (render, consent gating, `signEndpoint` call shape, `VerifyPanel` result states), add to root `test` chain, document `VerifyPanel`. | `packages/esig-react/{package.json,README.md,test/}` , root `package.json` | M |
| GP-02 | P1 | **`examples/nextjs-supabase` is not runnable** — `README.md` + `app/` only, no `package.json`/`next.config`/`tsconfig` **[verified]**, yet `README.md:29` and the quickstart README route users there. Make it a real app (workspace member), `npm run typecheck` in CI. | `examples/nextjs-supabase/`, root `package.json`, `ci.yml` | M |
| GP-03 | P1 | **Browser verifier: build it, test it, add PQ.** `site/verify/verify.js` is a ~270 KB committed bundle; `verify-browser.js` (548 lines) is a hand-port of `packages/esig-core/src/verify-pdf.ts`; no bundler config, no tests, 0 ML-DSA refs while core has `pq-verify.ts` **[verified]**. Build from core via esbuild (`site/verify/build.mjs`), run the core fixtures (valid, tampered, malformed, CAdES-T) against the bundle in Node + jsdom, add `verifyPqSeal` readout, keep the "does not check" copy exact. | `site/verify/`, `packages/esig-core/src/pq-verify.ts` | L |
| GP-04 | P2 | **Doc drift**: root `README.md:19-30` lists 4 of 10 packages; `packages/esig-supabase/README.md` omits `SupabasePqKeyStore` + `verifyAuditChain` and names only migration 0001 (index doc needs 0002/0003); `site/README.md:28` → nonexistent runbook; `packages/esig-uaid-exch/README.md` links outside the repo; `@e-sig/pillar-bridge@0.1.0` has no CHANGELOG entry. | READMEs, `CHANGELOG.md` | S |
| GP-05 | P1 | **Deploy scripts are hazardous** (handoff risks 2-3): `docs/deploy.sh` runs bare `aws` (broken v1 on this machine) and `s3 sync --delete` of all `docs/` → publishes `docs/growth`, `docs/launch`, this file to docs.e-sig.org. Restrict to an explicit allowlist (`index.html`, `blog/`, assets) and require `aws2`/pinned CLI; lengthen `site/finish.sh`'s CloudFront DEPLOYED wait. | `docs/deploy.sh`, `site/finish.sh` | S |
| GP-06 | P2 | **Workspace orphans**: `examples/pillar-agent` has a `test` script but is not in `workspaces` (never installed/run in CI); `infra/waitlist` reached only via `--prefix` with vendored `node_modules`. Add both to `workspaces`, drop vendored modules. | root `package.json`, `examples/pillar-agent/`, `infra/waitlist/` | S |
| GP-07 | P2 | **Missing READMEs** for `infra/provisioning` (`@e-sig/cloud-provisioning`), `infra/waitlist`, `infra/lambda-checkout` (state the fail-closed intent in prose, not just the header comment). | `infra/*/README.md` | S |
| GP-08 | P3 | Root clutter is **untracked** **[verified]** (`pricing-preview.png`, `*.zip`, three planning `.md`) — move to `_stage/` or delete locally; add patterns to `.gitignore` so they cannot be added by accident. `scripts/seed-stripe.mjs` is referenced by nothing and `stripe` is not a dependency — keep only if the Cloud gate work will use it; otherwise delete. | `.gitignore`, `scripts/` | S |
| GP-09 | P3 | **No linter** (July HEALTH finding, still true): add `eslint` flat config + `npm run lint` to CI. | root, `ci.yml` | S |

---

## 7. External / human blockers — escalate to Z (EX)

| ID | Item | Blocks | Source |
|----|------|--------|--------|
| EX-01 | **Email `hn@ycombinator.com`** about item 49475553 (auto-flagged, new-account filter). Draft is in `memory/esig-launch-worklog.md`. Do **not** resubmit. | nothing else; closes the HN thread | `docs/growth/evidence/2026-08-28-show-hn.md`, `.maestro/handoff.md` |
| EX-02 | **`support@e-sig.org` mailbox** (Stalwart via vmv-one, same track as AlliShare's `EX-05`) **and** an **SES sending identity for `e-sig.org`** (DKIM) in the waitlist AWS account. Also the owner login identity of the e-sig AlliShare org (AS-REQ-05): until it exists there is no magic-link into that dashboard and owner mail bounces silently (§8.1). | SU-01, SU-03, MSG-05, AS-REQ-05 dashboard login | AlliShare `WORKLOG.md:602-640` |
| EX-03 | **Bluesky account** for e-sig (+ DNS `TXT _atproto.e-sig.org` for the `@e-sig.org` handle, + app password → Secrets Station) and a **Telegram channel + bot token**. | MK-02 → every MK post | AlliShare `LAUNCH.md:454-455` |
| EX-04 | **X / LinkedIn / Reddit** accounts (human-required, through AlliShare's registration plane so checkpoints are recorded) and AlliShare's platform OAuth apps; X write = paid tier decision. | MK-09 | AlliShare `docs/GAPS-AND-TODOS.md` EX-02; `registration-policy.ts:407-715` |
| EX-05 | **AlliShare prod deploy decision** — the support features we bridge to (staff replies, escalation email) are merged but not deployed (live OpenAPI lacks `POST /support/admin/conversations/{id}/messages`). | SU-03 usefulness, SU-06 | AlliShare `WORKLOG.md:455-483`, their EX-03 |
| EX-06 | **Approve the AlliShare cross-project requests** in §8 — **done 2026-09-01/02**: all six accepted by Allishare-Lead (§8.1), AS-REQ-05 provisioned and the key handed over by Key-Master. Remaining AlliShare work is on their side. | SU-03 (long-term), SU-06, MK-01 | this doc §8 |
| EX-07 | GitHub: enable **Sponsors** (optional), set repo `homepage`/topics if `gh api` lacks rights (SU-08), create Discussion categories (SU-05). | SU-04/05/08 | `gh api repos/vmvtech/esig-suite` |
| EX-08 | **New npm name `@e-sig/notify`** (MSG-01): Trusted-Publisher web-UI setup before first publish; first publish of a new name cannot be OIDC (pillar-bridge precedent). | MSG-01 release | `memory/release-via-trusted-publisher.md` |

---

## 8. Cross-project requests to AlliShare (AS-REQ) — sent to Allishare-Lead

These are AlliShare changes e-sig needs; they map onto items already in
`/Volumes/X/VMV/allishare/docs/GAPS-AND-TODOS.md`. e-sig does not edit the
AlliShare repo.

| ID | Request | Maps to their item | Why e-sig needs it |
|----|---------|--------------------|--------------------|
| AS-REQ-05 | **Provision an `e-sig` org + profile + scoped API key**, hand the key to Key-Master. — **DELIVERED 2026-09-02**: org `e-sig`/`e-sig-cb48b1`, profile `esig-marketing`, key at Secrets Station `allishare/esig/api_key` → `ALLISHARE_API_KEY_ESIG`. | — (ops) | MK-01 — **closed**; admin-key use retired |
| AS-REQ-01 | **Public, captcha'd/rate-limited support intake** with `brand`/org scoping and a `requesterEmail` field on `SupportConversation`, so staff replies go to the third party, not org owners (`core/support.ts:246`). | SU-11 + a schema field | SU-03 long-term |
| AS-REQ-02 | **Org-scoped ticket list** `GET /support/conversations` + **`support.escalated` / `support.replied` webhook events**. | SU-02, IN-03 | SU-06 |
| AS-REQ-03 | **Per-tenant support branding**: `From:` address and assistant persona per org (today hard-coded `support@allishare.com`, `core/support.ts:28-42,235`). | new | SU-03 reply quality |
| AS-REQ-04 | **dev.to adapter** (API-key `POST /api/articles`, canonical URL) — low priority. | new platform | MK-11 |
| AS-REQ-06 | **Fix `POST /oauth/twitter/connect` to fail closed** when `TWITTER_CLIENT_ID` is unset (`apps/api/src/routes/oauth.ts:78-88` vs `:181-186`) — found during recon, not e-sig-blocking. | new | correctness |

### 8.1 Allishare-Lead's answer (2026-09-01) — all six accepted

Their ledger: `/Volumes/X/VMV/allishare/docs/GAPS-AND-TODOS.md` §7 E3;
playbooks: `/Volumes/X/VMV/vmv-office/.maestro/playbooks/fleet/allishare/2026-09-01-Gaps-Program/`.

| Ours | Theirs | Playbook | What we actually get | Effect on our plan |
|------|--------|----------|----------------------|--------------------|
| AS-REQ-05 — **DELIVERED 2026-09-02** | MK-17 + EX-08 | GAPS-05 (human step, done) | `scripts/ops/provision-tenant.mjs` (zero-dep, idempotent on org slug + profile refId): `POST /admin/orgs` → impersonate → `POST /profiles` (refId `esig-marketing`, title `e-sig.org`) → `POST /user/api-keys` (read,write, org-scoped, 0600 file). Runs against **prod as-is**. Z runs it with a platform-admin session (~2 min). Key → Key-Master only. | MK-01 unblocked once Z runs it. They need `TENANT_OWNER_EMAIL` from us → **`support@e-sig.org`** (see EX-02). **No further posts with `AISWARA_ADMIN_KEY_ALLISHARE`.** |
| AS-REQ-01 | SU-14 (near) + SU-11 (later) | GAPS-03 / GAPS-06 | SU-14: `requesterEmail`/`requesterName` on `POST /support/chat`, honoured for API-key callers only; staff-reply mail goes requesterEmail → user.email → org owners. SU-11: `POST /public/support/intake { orgSlug, name, email, message, captchaToken }`, per-org opt-in `features.publicSupportIntake`. | Keep our own intake Lambda (SU-03) — it is the org-key caller that SU-14 is designed for. |
| AS-REQ-02 | SU-02 + SU-15 | GAPS-03 | `GET /support/conversations?status&cursor&limit` (API-key caller sees every ticket in its org; api-key tickets have `userId null`); `support.escalated` / `support.replied` in `WEBHOOK_EVENTS`, payload `{ conversationId, status, topic, requesterEmail, message:{id,role,content,createdAt} }`. | SU-06 poll and MK-08 webhook handler target these shapes; not merged yet — build v1 against prod (below). |
| AS-REQ-03 | SU-16 | GAPS-06 block B | `Organization.supportBranding { displayName, replyTo, persona }` → From **name**, Reply-To, persona. From **address stays `support@allishare.com`** until per-tenant sender domains are verified. | Site copy must not say "we reply from support@e-sig.org" for desk replies — say "reply-to support@e-sig.org". |
| AS-REQ-04 | MK-18 | GAPS-06 block E (P3) | dev.to `direct_credentials` adapter, `POST https://dev.to/api/articles` with `canonical_url`. | MK-11 stays manual until then. |
| AS-REQ-06 | P0-14 | GAPS-01 | Confirmed: `buildOAuthAuthorizationRequired` twitter branch calls `authorizeUrl` with empty client_id. Fix = `oauthClientConfigured('twitter')` guard → 501 + route/mutation tests. | none |

**Prod reality for `infra/support-intake` (from their reply):**
- On prod today (commit `3b11895`, 2026-07-13): `POST /support/chat { message, conversationId? }` with the org key creates/continues a ticket (AI reply inline; **escalation = `status: "escalated"` on the conversation, no email** — PR #25 undeployed); `GET /support/conversations/:id` → `{ id, status, messages[{ role, content, createdAt }] }` with `status ∈ open|escalated|resolved|closed` and `role ∈ user|assistant` only (`apps/api/src/routes/support.ts:46-54` at that commit — no `staff` role, no message `id`); `POST /post`, `POST|GET /profiles`, `POST /links`, webhooks for existing `WEBHOOK_EVENTS`.
- Merged, undeployed (PRs #21–#25): staff role, `POST /support/admin/conversations/:id/messages`, staff-reply email, escalation deep link. Transcript shape does not change at deploy.
- Not merged (their GAPS-03): the list route (SU-02), `requesterEmail` (SU-14), `support.*` events (SU-15 — same `x-allishare-signature: t=<unix>,v1=<hex>` path as every existing event, 300 s tolerance; written into their GAPS-03 as an invariant with a header-shape test).
- Deploy: nothing scheduled; merge-to-main auto-deploys, gated on their P0 fixes (GAPS-01) first — Z's call (their EX-03).
- Therefore **v1** = create via `POST /support/chat` (requester email on the first line of `message` until SU-14) + poll `GET /support/conversations/:id` and alert on `status === "escalated"` (the staff-message branch is coded but dormant until their deploy); **v2** = `requesterEmail` field, list route, `support.*` webhooks. GAPS-05 SU-03a and GAPS-06 SU-06 are written this way.
- Tenant provisioning (their `core/tenancy.ts:105-109`): succeeds even if `support@e-sig.org` bounces — welcome mail is best-effort, the API key is unaffected. Until EX-02 lands, nobody can magic-link into the e-sig AlliShare dashboard (owner address is the only login identity; admin impersonation still works) and owner-notification mail bounces silently. Provisioning completed 2026-09-02 (§8.2).

### 8.2 Credential of record (Key-Master handoff, 2026-09-02)

The e-sig AlliShare tenant exists and its key is live. **[verified by Esig-Lead
2026-09-02]** — `GET /api/v1/user` 200, `GET /api/v1/profiles` 200,
`GET /api/v1/admin/orgs` **403** (org-scoped, not admin).

| Fact | Value |
|------|-------|
| Secrets Station path | `allishare/esig/api_key` (grant: project `x-vmv-esig-suite`, kind env, holds-copy) |
| Env var | `ALLISHARE_API_KEY_ESIG` |
| Org | name `e-sig` — id and slug are **not recorded here** (this repo is public); Key-Master holds them, and `GET /api/v1/user` returns them |
| Profile | `title "e-sig.org"`, `refId "esig-marketing"` — the stable handle scripts look up by |
| `profileKey` | **never written to this repo.** Returned by `GET /api/v1/profiles` for `refId "esig-marketing"`; a wrong value is rejected **403** by the API, so treat it as a credential, not a label |
| Connected accounts | **0** — publishing still blocked by EX-03 |

Rules, binding on every script and playbook in this repo:

1. **Load via Secrets Station only** — `~/secrets-station/.venv/bin/secrets run -- <cmd>`
   (preferred; it dies with the process), or the standard `set -a` / source of
   `~/.config/secrets-station/.env` documented in the global CLAUDE.md. A key
   *value* never enters a file, fixture, log, PR, commit message, or transcript.
2. **`Profile-Key` header**: resolve the `profileKey` at runtime from
   `GET /api/v1/profiles` where `refId === "esig-marketing"`. **Never hardcode it
   and never commit it** — verified 2026-09-03 that the API answers **403** to a
   tampered value, i.e. it is enforced like a credential. This repo is public.
3. **`AISWARA_ADMIN_KEY_ALLISHARE` is VMVTech-only.** Not used for any AlliShare
   call from this repo, and **never rotated or revoked by us** — that authority
   belongs to VMVTech alone.
4. **Fail closed**: any script touching AlliShare exits non-zero if
   `organization.name !== "e-sig"`, if the key lacks the `as_` prefix, or if
   `/admin/orgs` answers anything but 401/403 (admin-capable key tripwire).


---

## 9. Delegation plan

Order is dependency-driven; each phase is one playbook doc in
`/Volumes/X/VMV/vmv-office/.maestro/playbooks/fleet/esig/2026-09-01-Gaps-Program/`.
Builders: Esig-Build (MiniMax-M3 default; opus-4.8/glm-5.2/deepseek/local
selectable) for code; Esig-Codex for test-heavy items; Esig-Gem for
site/docs copy; Esig-Ops for infra/SAM. Lead reviews every diff before it
ships. Humans commit; agents never `git push` to `main` or publish.

| Phase | Playbook | Scope | Gate before ship |
|-------|----------|-------|------------------|
| 1 | `GAPS-01` | DM-01…05, 09 (terminal demos + wiring) + GP-04, GP-05, GP-08 | `npm run demos` regenerates every GIF from committed `.cast`; byte-identical test green; `npm run build && npm test && npm run smoke` green; no `s3 sync --delete` of `docs/`. |
| 2 | `GAPS-02` | GP-01, GP-02, GP-06, GP-07, GP-09 + DM-07 | `@e-sig/react` in the root test chain with ≥ 12 tests; `examples/nextjs-supabase` typechecks in CI; pillar-agent test runs in CI. |
| 3 | `GAPS-03` | SU-01, 02, 04, 05, 08 + MK-03, 05, 06, 07 | support page live in `site/`; Discussions categories exist; `docs/blog/feed.xml` validates; evidence dirs + baseline committed; calendar has 9 rows with copy. |
| 4 | `GAPS-04` | MSG-01…04, 06, 07 | `@e-sig/notify` builds, mcp tests unchanged and green; recipe example runs against `CapturingTransport`; owner email sent on `envelope.completed` in a test. |
| 5 | `GAPS-05` | SU-03, MSG-05, MK-08 (infra) + MK-01, 02, 04 (channels) | **one real e-sig post published to Bluesky + Telegram from the e-sig org via `scripts/growth/publish.mjs --live`, with a UTM short link, recorded in `docs/growth/evidence/week-05/`**; a form submission on e-sig.org creates a ticket in the e-sig AlliShare org and a copy at `support@`; a waitlist signup receives a confirmation and verifies. |
| 6 | `GAPS-06` | GP-03, DM-06, DM-08, DM-10, SU-06, SU-07, MK-09…11 | per-item; GP-03 gate = fixture suite (valid/tampered/malformed) passes against the built bundle and no fixture is reported valid that core rejects. |

Rules for every builder ticket:
- Work on a branch; open a PR; **never push to `main`, never `npm publish`** (Trusted Publisher / owner go only).
- RTFM before touching: read the package README + the cited file first; NFAE — do not assume an API shape, grep it.
- Every claim in a commit message links to a test or a command output.
- Never put a document, signer data, credential, or customer PII in evidence files, demos, or fixtures — demos use `assets/sample.pdf` and `@example.com` identities.
- Keep the site free of analytics/pixels/third-party scripts; keep checkout fail-closed.
- The Bash tool is zsh: no word-splitting of `$LIST` in `for` loops — use arrays or literal words.
