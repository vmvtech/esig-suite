# e-sig OSS-First 90-Day Growth Playbook

**Direction:** approved · **Start:** 2026-08-03 · **Horizon:** 90 days  
**Primary motion:** open-source developer adoption · **Cloud:** private-preview waitlist until the provisioning gate passes

## Accountability and evidence

The **e-sig owner** is the accountable DRI for every gate in this playbook until
a delegation is written into the decision log. Workstream labels such as Web,
Trust, Growth, and Cloud describe the work; they do not transfer accountability.

- Weekly evidence: `docs/growth/evidence/week-01/` through `week-13/`.
- Experiment records: `docs/growth/evidence/experiments/`.
- Release records: the production publisher's `release-manifest.json`, linked
  from the applicable weekly evidence note.
- Deadlines: the dated thirteen-week board below. A missed gate moves the work
  to the next week; it never waives the gate.
- Evidence must contain the command or observation, timestamp, result, and DRI.
  Never copy credentials, documents, signer data, or customer PII into it.

## Executive verdict

e-sig is ready to earn open-source attention, but it is not yet set up to compound that attention into a viral loop.

The acquisition and activation surfaces are credible: a public MIT repository, a short quickstart, npm packages, a working website, a public verifier, comparison pages, and multi-signer primitives. The missing layer is propagation. A developer or signer can get value, but the product does not yet give them a safe, useful reason to expose e-sig to the next developer.

**Current readiness: 3/10.** Treat the first 30 days as loop construction, not a splash launch.

| Dimension | Readiness | Evidence / gap |
|---|---:|---|
| Discoverability | 6/10 | Public GitHub, npm, comparison pages, social preview |
| First value | 7/10 | Build, 180 tests, five smoke tests, and the exact quickstart pass locally |
| Trust | 4/10 | Strong primitives, but browser-verifier claims exceed the implementation in timestamp and canonical-range verification |
| Propagation | 1/10 | No recipient-to-builder CTA, shareable verification result, referral path, or integration badge |
| Retention | 2/10 | No defined activation cohort, follow-up cadence, or repeat-use measure |
| Measurement | 1/10 | No product analytics by design; no privacy-safe activation ledger yet |
| Commerce safety | 2/10 | Checkout existed before automated provisioning, webhooks, account setup, and first-use proof were complete |

## The model to build

The growth model is utility-led, not incentive-led:

1. A developer discovers a technical proof, comparison, integration, or signed artifact.
2. They reach first value by running the quickstart and verifying a tamper test.
3. They embed the SDK and create a real signature workflow.
4. A recipient or reviewer sees an optional e-sig verification receipt, public verification link, or integration badge.
5. That proof offers a low-friction “verify this” and “build this yourself” path.
6. The next developer runs the quickstart, closing the loop.

The reward is trustworthy proof and saved engineering time. Do not add token rewards, paid referrals, forced PDF branding, address-book harvesting, or dark-pattern invitations.

## Operating rules

- The MIT SDK remains complete and useful. Paid value is hosting, support, assurance, and operations.
- Checkout remains disabled until every Cloud provisioning gate below is evidenced.
- Never charge a customer whose usable workspace cannot be provisioned automatically or by an explicitly agreed private-preview process.
- Keep the website free of analytics scripts, cookies, pixels, and SDK telemetry.
- Measure through public aggregate platform signals and explicit, opt-in confirmations. Never inspect document or signer content for growth.
- Do not make legal, timestamp, certificate-trust, or verifier claims beyond the exact path tested.
- Do not ask anyone to upvote, manufacture comments, coordinate engagement, or otherwise manipulate launch platforms.
- One experiment changes one meaningful variable. Record the baseline, hypothesis, result, and decision.

## Scoreboard

### North-star metric

**Weekly Verified OSS Activations (WVOA):** unique external developers who explicitly confirm that they completed both of these actions in a non-e-sig-owned environment:

1. generated or signed a PDF with e-sig; and
2. verified the signature or demonstrated tamper detection.

Valid evidence is an opt-in tester report, GitHub Discussion, issue, public integration, or recorded design-partner check-in. npm downloads, page views, stars, and internal runs do not count as verified activations.

### Day-90 targets

| Outcome | Day 30 | Day 60 | Day 90 |
|---|---:|---:|---:|
| Cumulative verified OSS activations | 10 | 25 | 50 |
| External integrations still active four weeks later | establish cohort | 40% of eligible cohort | 50% of eligible cohort |
| Public examples, integrations, or dependents | 2 | 5 | 10 |
| Qualified Cloud waitlist organizations | 5 | 15 | 30 |
| Cloud design partners completing an end-to-end provisioned run | 0 | 2 | 5 |
| Charged without a usable provisioned workspace | 0 | 0 | 0 |
| Known false-valid verifier results | 0 | 0 | 0 |

GitHub stars, forks, npm downloads, documentation visits, and waitlist emails are leading indicators. Report them, but do not substitute them for activation or retention.

## Day 0-7: freeze unsafe growth and establish truth

**Exit gate:** every public conversion path is honest, checkout is fail-closed, the verifier contract is accurate, and the baseline is recorded.

| Work | Workstream | Acceptance evidence |
|---|---|---|
| Replace Cloud checkout with the private-preview waitlist | Web | Pricing has no checkout links; old `/api/checkout` requests redirect to `#cloud-waitlist`; no Stripe session is created |
| Resolve verifier claim mismatch | Trust | Either implement and test TSA-signature plus canonical ByteRange verification across browser/core, or narrow public copy to exactly what each verifier proves |
| Establish release truth | Release | Versions, tags, changelog, npm contents, and first-publish package ownership agree; clean-machine install and quickstart pass — **partially green (2026-08-27):** `@e-sig/mcp` 0.5.0 and `@e-sig/pillar-bridge` 0.1.0 are committed to `main` but untagged and unpublished; npm still serves `@e-sig/mcp` 0.3.0 and has never served `@e-sig/pillar-bridge` |
| Capture baseline | Growth | Dated snapshot of GitHub stars/forks/discussions/traffic, npm downloads/dependents, WVOA, and waitlist count |
| Create the activation ledger | Growth | Minimal table with date, anonymous cohort ID, source category, quickstart result, integration result, four-week follow-up, and opt-in evidence link |
| Retire stale launch instructions | Release | Older launch and monetization plans point to this playbook and cannot be mistaken for current execution truth |

Run and record these exact Day 0-7 gates from a clean checkout:

```bash
npm ci
npm run build
npm test
npm run smoke
npm run quickstart
node scripts/publish-preflight.mjs
```

For the website release, run the probes and canonical publisher in
`docs/RUNBOOK-production-publish.md`. A failed npm publish preflight blocks
an npm release but does not authorize bypassing it; the website waitlist release
is a separate artifact.

**Rollback trigger:** any checkout reaches Stripe, any old branded route exposes stale copy, or a verifier can report valid for a known malformed/tampered fixture. Revert the affected surface immediately and stop promotion.

## Day 8-30: build the loop before buying attention

### Product work

1. Make one canonical activation path: install → sign sample → verify → tamper → verify failure.
2. Add copy-paste recipes for the two real adoption paths observed in interviews, not speculative frameworks.
3. Design an **optional** verification receipt with:
   - result, certificate fingerprint, signing time semantics, and verifier version;
   - a safe share link or downloadable receipt that contains no document or signer PII;
   - “Verify with e-sig” and “Build with the MIT SDK” actions;
   - an explicit off switch and no forced watermark in signed PDFs.
4. Add a repository/integration badge only after it links to a durable verification or quickstart page.
5. Make errors actionable: exact failed invariant, safe remediation, and an issue/discussion link without uploading the document.

### Learning work

- Recruit 10 external developers across three cohorts: two e-signature implementers, two regulated-workflow engineers, and six general TypeScript/Node developers.
- Observe the canonical path without coaching for the first ten minutes.
- Record time-to-first-valid-signature, time-to-tamper-failure, blockers, and whether they can explain the trust result.
- Ship the smallest fix that removes the most repeated blocker each week.

### Content work

- Publish one reproducible technical proof per week: MIT embedding, ByteRange/tamper anatomy, RFC-3161 limits, or audit-chain verification.
- Every claim must link to runnable code, a fixture, or a test. Avoid generic thought leadership.
- End each proof with one action: run the quickstart. Do not split attention across stars, newsletter, Cloud, and demos.

**Day-30 go/no-go:** proceed to broad community distribution only if WVOA is at least 10, median unassisted quickstart is under 10 minutes, zero trust blockers remain open, and five external users can accurately describe what the verifier did and did not prove.

## Day 31-60: distribute proofs and establish retention

### Weekly campaign cadence

| Week | Proof | Audience | Conversion | Decision rule |
|---|---|---|---|---|
| 5 | MIT SDK vs deploy-an-app architecture | TypeScript/Node builders | Quickstart completion | Keep the message only if it produces verified activations, not just clicks |
| 6 | Tamper-detection fixture and explanation | Security and PDF engineers | Reproduce pass/fail locally | Fix trust confusion before increasing reach |
| 7 | Supabase or chosen real integration | SaaS teams | Complete integration recipe | Retain only recipes used by two external developers |
| 8 | Optional verification receipt prototype | Recipients and implementers | Share → verify → quickstart loop | Ship only if no PII leaks and recipients understand the result |

### Community rules

- Publish where the proof is native to the community and participate as the builder.
- For Hacker News, follow the site guidelines: submit once, disclose affiliation, answer technical questions, and never ask for votes or coordinated comments.
- For Reddit, GitHub, and specialist communities, lead with the artifact and limitations; do not cross-post identical promotional copy.
- Convert repeated questions into docs or tests within seven days.

### Retention

- Follow up with each consenting activation at days 7 and 28.
- Count retained only if the integration remains in use, has advanced to a real workflow, or has produced a second signed-and-verified artifact.
- Interview every churned tester. Tag one primary reason: setup, missing capability, trust, performance, documentation, or project priority.

**Day-60 go/no-go:** proceed to a coordinated OSS launch only if cumulative WVOA is at least 25, at least 40% of eligible activations retain at four weeks, two unrelated users have completed the share/verify/build loop, and no P0/P1 trust issue is open.

## Day 61-90: compound what retained

1. Launch the strongest single proof, not the entire feature inventory.
2. Staff the first 24 hours for technical responses, reproductions, and fixes.
3. Publish a transparent “what failed during launch” follow-up within seven days.
4. Turn the top two retained integrations into maintained examples with owners and CI.
5. Invite qualified waitlist organizations into small Cloud design-partner cohorts only after manual provisioning is documented and contractually explicit.
6. Run a day-90 review: double down, narrow the wedge, or pause distribution based on activation and retention—not attention.

### Thirteen-week execution board

**Re-baseline note (2026-08-27):** Weeks 1-4 (Aug 3-30) are elapsed. This
board has not been re-scored against them since drafting — treat rows 1-4 as
needing a fresh pass/fail read before trusting week 5 onward.

| Week | Window (2026) | DRI | Must ship | Success test |
|---:|---|---|---|---|
| 1 | Aug 3-9 | e-sig owner | Commerce safety, trust-copy parity, baseline | All Day 0-7 gates green |
| 2 | Aug 10-16 | e-sig owner | Canonical activation path and ledger | Two fresh external runs complete |
| 3 | Aug 17-23 | e-sig owner | First integration recipe | Two external users complete it |
| 4 | Aug 24-30 | e-sig owner | Receipt/share threat model and prototype | No PII; verifier semantics understood |
| 5 | Aug 31-Sep 6 | e-sig owner | Architecture proof | WVOA increases from the prior weekly baseline |
| 6 | Sep 7-13 | e-sig owner | Tamper proof | External user reproduces both outcomes |
| 7 | Sep 14-20 | e-sig owner | Second observed-use-case recipe | Two real uses, or discard it |
| 8 | Sep 21-27 | e-sig owner | Closed-loop pilot | Two independent share → verify → build loops |
| 9 | Sep 28-Oct 4 | e-sig owner | Launch candidate and dry run | All links, packages, fixtures, rollback tested |
| 10 | Oct 5-11 | e-sig owner | OSS launch | Technical responses covered for 24 hours |
| 11 | Oct 12-18 | e-sig owner | Fix launch blockers | Top repeated blocker removed and retested |
| 12 | Oct 19-25 | e-sig owner | Retention follow-up | Eligible day-28 cohort measured |
| 13 | Oct 26-31 | e-sig owner | Decision review | Written continue/narrow/pause decision with evidence |

## Cloud checkout provisioning gate

Checkout may be restored only when one release candidate passes every item below in a production-like environment and the evidence is linked from the release record.

### Offer model while checkout is closed

| Offer | Isolation | Support-backed planning price | Founding preview |
| --- | --- | ---: | --- |
| Shared Starter | Shared Supabase project; tenant RLS and tenant-prefixed storage | $79/month | May be $19/month for 90 days, best effort |
| Shared Team | Shared Supabase project; tenant RLS and tenant-prefixed storage | $199/month | May be $49/month for 90 days, best effort |
| Shared Scale | Shared Supabase project; tenant RLS and tenant-prefixed storage | $499/month | May be $79/month for 90 days, best effort |
| Dedicated Cloud | Separate Supabase project and separate AWS data-plane stack | From $30,000/year + $5,000 setup | Design-partner contract only |

The current planning contribution-margin range is roughly 51–77%, including a
support reserve. Treat custom integrations, enhanced compliance, private
networking, premium SLA coverage, and excess usage as pass-through or separately
quoted work. Recalculate the model from actual provider bills and recorded
support time after the first five design partners; do not restore checkout from
the estimate alone.

### Commercial truth

- Plan name, price, interval, included envelopes, overage, tax behavior, and any trial are identical across pricing copy, Stripe, contracts, and application state.
- There is no “free trial” label unless Stripe and the provisioning system both implement the exact trial and cancellation behavior.
- Refund, cancellation, failed-payment, and downgrade behavior is written and tested.

### Payment and order state

- Stripe webhook signatures are verified.
- Checkout and webhook handling are idempotent under retries and out-of-order delivery.
- A durable order/subscription state machine covers pending, active, past-due, canceled, refunded, and provisioning-failed states.
- A failed payment immediately suspends signing and revokes the published API credential; a later paid event resumes the same tenant with a newly rotated credential, while cancellation and refund remain terminal.
- Logs and alerts identify failures without exposing keys, payment data, documents, or signer PII.

### Provisioning and first value

- Successful payment creates the correct organization, owner, plan limits, API credentials, storage, database state, and email/domain configuration.
- The customer can sign in, send or sign one envelope, verify it, and retrieve its audit record without operator intervention.
- Duplicate events cannot create duplicate tenants, keys, or charges.
- Credential delivery uses an immutable per-generation secret plus a lease-fenced authoritative pointer; a delayed expired worker cannot republish an older credential.
- A compensating path disables or removes partial resources after failure.
- Provisioning has a measured timeout, retry policy, owner, and on-call alert.

### Customer control and operations

- Billing portal supports invoice access, payment-method update, cancellation, and plan changes.
- Key rotation, account recovery, data export, deletion, backup restore, and support escalation are exercised.
- Rate limits and quotas match the purchased plan and fail clearly.
- Privacy Policy, Terms, DPA/subprocessor list, support policy, and status communication match the deployed service.

### Final live proof

1. Use a real test customer and the exact public checkout route.
2. Complete payment, webhook processing, provisioning, login, first envelope, verification, billing portal, cancellation, and cleanup.
3. Repeat the run with a duplicated webhook and a forced provisioning failure.
4. Confirm zero duplicate charge/resource creation and a recoverable customer state.
5. Obtain Product, Engineering, Security, and Operations sign-off.

If any item fails, checkout stays redirected to the waitlist. A deadline, launch announcement, or successful Stripe payment is not an exception.

## Experiment record

Use one row per experiment.

| Field | Required entry |
|---|---|
| Hypothesis | One causal statement |
| Audience | One defined cohort |
| Change | One meaningful variable |
| Baseline | Prior WVOA and relevant leading signal |
| Window | Start/end date and minimum sample |
| Guardrails | Trust, privacy, support, and failure thresholds |
| Result | Counts plus qualitative evidence |
| Decision | Keep, revise, or discard |

## Decision log

| Date | Decision | Why | Revisit when |
|---|---|---|---|
| 2026-08-03 | OSS-first, not Cloud-first | The SDK and quickstart are usable; Cloud provisioning is not yet proven | Cloud gate is fully evidenced |
| 2026-08-03 | Email waitlist, not a hosted form | It works with the static site and existing privacy posture, and adds no tracker or new data processor | Volume makes email handling unreliable |
| 2026-08-03 | No product analytics or SDK telemetry | Trust and privacy are part of the wedge | Only after an explicit privacy decision and updated policy |
| 2026-08-03 | Verified activation is primary; stars are secondary | Attention without first value or retention does not compound | Never; the target level may change |
| 2026-08-03 | No forced artifact branding or paid referral scheme | The loop should spread proof, not impose promotion | Research shows an optional, user-controlled mechanism is insufficient |

## Stop conditions

Pause promotion and return to product work if any of these occurs:

- a known malformed or tampered document is reported valid;
- public trust or compliance copy exceeds the implementation;
- any visitor can reach paid checkout before the Cloud gate passes;
- a charge succeeds without a usable workspace and tested recovery;
- a growth change exposes document, signer, certificate-owner, or customer PII;
- support backlog exceeds two business days during a launch;
- WVOA fails to improve across three completed experiments.

At day 90, success is not “went viral.” Success is a trustworthy loop that repeatedly turns technical proof into external activation, retained integrations, and qualified Cloud demand without compromising the open-source product.
