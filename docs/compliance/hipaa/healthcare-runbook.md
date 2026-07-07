# Healthcare Operations Runbook — HIPAA Deployments

**DRAFT — requires review by qualified counsel and your Security Officer
before adoption.**

> e-sig provides technical controls, not legal advice. This runbook is the
> operational companion to the BAA template
> (`docs/compliance/hipaa/BAA-template.md`). It tells your engineering and
> compliance teams exactly where PHI can live in the e-sig pipeline, how to
> configure the platform for minimum necessary, how to rotate keys, what to do
> in the first hours of a suspected breach, and how to dispose of PHI at end
> of life. Part of the **HIPAA BAA + Healthcare Runbook** add-on ($500/mo).

Applies to: `@e-sig/core` ≥ 0.6.0, `@e-sig/supabase` ≥ 0.3.0, migrations
`0001`–`0003`.

---

## 1. Roles this runbook assumes

| Role | Responsibility here |
|---|---|
| **Security Officer** (45 CFR 164.308(a)(2)) | Owns breach response (§5), workforce access review (§7) |
| **Privacy Officer** | Owns minimum-necessary policy (§3), individual-rights fulfillment |
| **Platform engineer** | Executes key rotation (§4), disposal (§6), chain verification |
| **Vendor (vmvtech)** | Cloud-tier infrastructure controls; breach notification to you per BAA §8 |

Self-hosted deployments: every "Vendor" infrastructure duty below is yours.

## 2. PHI data-flow map

The pipeline has four stages. PHI enters at stage 1 and persists in exactly
the locations tabulated below — nowhere else.

```
 render                sign                    store                    verify
 ──────────────────    ────────────────────    ─────────────────────    ────────────────────
 HTML (customer) ──►   PKCS#7 CAdES sign  ──►  signed-documents     ──► verifyPdfSignature()
 renderHtmlToPdf()     signPdf()/              bucket (private,         verifyDocument()
 puppeteer, scripting  signDocument()          {tenant_id}/… path)      verifyAuditChain()
 disabled, in-memory   + optional PQ seal      + esig_audit_log row     (read-only; no PHI
                       + optional RFC 3161                              leaves the tenant)
```

### 2.1 Fields that can contain PHI

| Location | Field(s) | PHI exposure | Notes |
|---|---|---|---|
| Envelope / document input | `html`, `title` | **High** — the document body is whatever you submit (consent forms, DUAs, treatment agreements) | Held in your `EnvelopeStore`; embedded verbatim in the signed PDF |
| Signer records (`EnvelopeSigner`) | `name`, `email`, `roleLabel`, `signatureImageDataUrl` | **High** — patient/participant identity; a drawn signature is biometric-adjacent | Persisted by your `EnvelopeStore`; rendered into the PDF by `renderSignatureBlocksHtml()` |
| Signed PDF | entire object | **High** — contains document body + signature blocks | `signed-documents` bucket, path `{tenant_id}/{document_id}/{ts}.pdf`; private, tenant-prefix RLS |
| `esig_audit_log.metadata` (jsonb) | whatever you put in `auditMetadata` | **Configurable — keep PHI out** (see §3.2) | The metadata's md5 is welded into the tamper-evident chain; rows are undeletable by design |
| `esig_audit_log` scalar columns | `actor_user_id`, `ip`, `user_agent`, `session_id`, `signed_pdf_url` | **Moderate** — identifiers, not clinical data | IP + user agent are attribution evidence (UETA §13); they are identifiers under HIPAA when tied to a patient-signer |
| Signing-link email/SMS (Postmark/Twilio) | recipient address/number, subject line, link | **Moderate** — recipient identity can itself reveal patient status | Keep subject lines generic (§3.3) |
| `org_signing_certs.cert_pem` subject CN | tenant display name | Low — org-level, not individual | Choose org names without patient identifiers |

### 2.2 Where PHI can NOT go (verified properties)

- **RFC 3161 timestamp authority** — receives only `sha256(SignerInfo.signature)`,
  never document bytes (see `@e-sig/core` README, "RFC 3161 trusted timestamps").
- **Signing tokens** — the raw 32-byte token is returned exactly once at
  `createEnvelope()`; only its SHA-256 hash (`tokenHash`) is persisted, so a
  database leak does not yield working signing links.
- **Private keys** — never persisted in plaintext (AES-256-GCM wrap; §4).
- **Render stage** — `renderHtmlToPdf()` runs headless Chromium with
  scripting disabled; the unsigned PDF exists in memory/function scratch only
  until stored.
- **Cross-tenant reads** — RLS on every table + bucket path prefix; the
  shipped `esig_tenant_member()` stub denies all reads until you install your
  membership predicate. Deny-by-default, not allow-by-default.

## 3. Minimum-necessary configuration (45 CFR 164.502(b))

### 3.1 Baseline checklist

- [ ] Deploy migrations `0001`–`0003` unmodified; replace the
      `esig_tenant_member()` stub with your real membership predicate.
      **Never** ship the predicate returning `true`.
- [ ] Service-role key: server-side only, never in a browser bundle,
      stored in your secret manager, rotated on personnel change.
- [ ] `signed-documents` bucket stays **private** (shipped default). Serve
      PDFs through short-lived signed URLs generated per authorized request.
- [ ] `ESIG_CERT_PASSPHRASE` (and PQ passphrase) in a secret manager;
      distinct per environment; not in `.env` files committed anywhere.
- [ ] Envelope `expiresAt` set on every envelope (stale signing links are
      dormant PHI-access credentials).

### 3.2 Keep PHI out of `esig_audit_log.metadata` — this one is structural

The audit chain (`migrations/0002_esig_audit_hashchain.sql`) makes every row
**permanent**: UPDATE/DELETE/TRUNCATE raise, and any row you could somehow
remove breaks `prev_hash` linkage for every verifier. That is exactly what
you want for attribution evidence — and exactly what you do not want for
clinical content, because §6 disposal cannot reach inside the chain.

Policy: `auditMetadata` (the `metadata` jsonb on `signDocument()` /
envelope actions) may contain **references** (envelope id, document id,
consent-version id, form type) — never clinical values, never document text,
never diagnosis/treatment data. The shipped audit columns (actor, action,
target, cert fingerprint, timestamp, ip, user agent) already satisfy ESIGN
R3 / UETA §13 attribution without any PHI payload.

### 3.3 Notification hygiene

- Email/SMS subject and body: "You have a document to sign" — no document
  titles that reveal condition or treatment ("Oncology consent — J. Doe" ✗).
- Signing-link URLs carry only the opaque token — never names, MRNs, or
  document titles in query strings.

### 3.4 Workforce-facing minimum necessary

Grant your staff tenant membership (the `esig_tenant_member()` predicate)
only where their function requires reading that tenant's signed documents or
audit rows. Verification tasks need audit-chain read access, not document
read access — split roles accordingly if your predicate supports it.

## 4. Key rotation procedure

Three key classes. All rotations are **non-destructive**: previously signed
documents keep verifying (RSA certs are embedded per signature; PQ seals
embed their public key).

### 4.1 RSA signing certificate

Mechanism: `ensureActiveCert()` (`@e-sig/core`, `cert-lifecycle.ts`)
rotates automatically at expiry — it deactivates the expired cert and issues
a fresh one with `rotatedFromId` pointing at the predecessor. Rotation is
recorded by the `cert.rotated` audit action and the
`org_signing_certs.rotated_from` linkage.

Forced rotation (suspected compromise, policy roll):

1. Deactivate the active cert row: `CertStore.deactivate(id)`
   (or flip `org_signing_certs.active = false` via service role).
2. Call `ensureActiveCert({ store, tenantId, subjectName, passphrase })` —
   finding no active cert, it mints and wraps a new one.
3. Confirm the audit trail: expect `cert.deactivated` + `cert.created` (or
   `cert.rotated`) rows for the tenant.
4. Confirm exactly one active cert: the partial unique index
   `one_active_cert_per_tenant` guarantees it; spot-check with
   `SELECT count(*) FROM org_signing_certs WHERE tenant_id = $1 AND active;` → 1.
5. Sign a scratch document and run `verifyPdfSignature()`; also re-verify one
   **pre-rotation** document to confirm non-destruction.

### 4.2 Post-quantum key bundle

Mechanism: `rotatePqKeys({ store, tenantId, passphrase })`
(`@e-sig/core`, `pq-lifecycle.ts`) — deactivates the current bundle and
mints a fresh Ed25519 + ML-DSA-65 bundle with `rotatedFromId` set.

1. Run `rotatePqKeys(...)`.
2. Record and republish the new ML-DSA-65 fingerprint (`mldsa65_fpr` on the
   new `org_pq_keys` row) wherever relying parties pin it
   (`expectedMldsa65Fpr` at verify time).
3. Verify one pre-rotation sealed document still passes
   `verifyDocument()` (seals carry their own public key).

### 4.3 Wrapping passphrase (`ESIG_CERT_PASSPHRASE` / PQ passphrase)

The passphrase wraps keys at rest; there is no bulk re-wrap helper. Rotating
it means rotating the keys it wraps:

1. Set the new passphrase in your secret manager.
2. Force-rotate certs (§4.1) and PQ bundles (§4.2) per tenant — new key
   material is wrapped under the new passphrase.
3. Keep the old passphrase escrowed until no active key material remains
   wrapped under it, then destroy it. Old **inactive** rows become
   unrecoverable once the old passphrase is destroyed — acceptable, since
   verification never needs private keys.

### 4.4 Cadence

| Asset | Rotate |
|---|---|
| RSA signing cert | Automatic at expiry; forced on suspected compromise |
| PQ bundle | Explicit only — on suspected compromise or policy roll (no clock expiry by design; see `0003` header) |
| Wrapping passphrase | Annually, and on any departure of a person who could have read it |
| Service-role key | Per your IAM policy; immediately on suspected leak |

## 5. Breach-response playbook

Trigger: any suspected impermissible access, acquisition, use, or disclosure
of PHI involving the e-sig pipeline (leaked service key, mis-scoped
membership predicate, exposed bucket, lost signing link containing an
unsigned envelope, vendor notice under BAA §8).

### The clock

| T | Milestone | Regulatory anchor |
|---|---|---|
| **T0** | **Discovery** — first day anyone in your org knows, or reasonably should have known. Start the log; the 60-day clock runs from here | 45 CFR 164.404(a)(2) / 164.410(a)(2) |
| T0 + 24h | Containment done; scoping under way | — |
| T0 + 72h | Four-factor risk assessment drafted; vendor/customer cross-notification exchanged (BAA §8 target) | 45 CFR 164.402; BAA §8.2 |
| ≤ T0 + 60 days | Individual notifications sent (if Breach confirmed); HHS notified now if ≥ 500 individuals; media if ≥ 500 in one state/jurisdiction | 45 CFR 164.404 / 164.406 / 164.408 |
| Year-end + 60 days | HHS log submission for < 500-individual breaches | 45 CFR 164.408(c) |

### Phase 1 — Contain (hours 0–24)

- [ ] Leaked service-role key → rotate it at the platform (Supabase
      dashboard) immediately; audit-log writes fail closed until services get
      the new key.
- [ ] Suspected signing-key compromise → force-rotate per §4.1/§4.2.
- [ ] Mis-scoped `esig_tenant_member()` → redeploy the deny-all stub first,
      fix the predicate second.
- [ ] Leaked signing link → `voidEnvelope()` the affected envelope (voiding
      invalidates its tokens for signing).
- [ ] Preserve evidence: snapshot the tenant's audit rows **before** any
      remediation writes; record the latest `row_hash` + `seq` out-of-band.

### Phase 2 — Assess (days 1–7)

- [ ] Run `verifyAuditChain(client, { tenantId })` per affected tenant.
      `ok: true` = the attribution record itself is intact; any `failures[]`
      entries (first broken `seq`, reason) go into the incident file — a
      broken chain is itself evidence of tampering and escalates severity.
- [ ] Reconstruct the access window from `esig_audit_log` (actor, ip,
      user_agent, action, created_at are all chained).
- [ ] Enumerate affected objects: bucket listing under `{tenant_id}/…`
      against `signed_pdf_url` values in the window.
- [ ] Four-factor risk assessment (45 CFR 164.402): nature/extent of PHI;
      unauthorized person; whether PHI was actually acquired or viewed;
      extent of mitigation. Document the conclusion even if "low probability
      of compromise" (that documentation is your defense).
- [ ] Encryption safe-harbor check: PHI encrypted per HHS guidance is not
      "Unsecured PHI". Wrapped keys likely qualify; PDFs in a private bucket
      rely on the storage layer's at-rest encryption — have counsel assess.

### Phase 3 — Notify

- [ ] You are the CE: individuals ≤ 60 days from discovery; HHS + media per
      thresholds above.
- [ ] You are a BA to an upstream CE: notify your CE per your BAA (this
      product's BAA: 72-hour target, 60-day outer bound) with the 164.410(c)
      content set.
- [ ] Vendor incident (cloud tier): expect notice per BAA §8; request the
      tenant audit-chain extract + verification report (BAA §8.5).

### Phase 4 — Close

- [ ] Post-incident review; corrective actions with owners + dates.
- [ ] Re-run the §3.1 baseline checklist.
- [ ] Retain the incident file ≥ 6 years (45 CFR 164.316(b)(2)).

## 6. Retention and disposal

### 6.1 What you must keep

- HIPAA documentation (policies, risk assessments, incident files, this
  runbook's completed checklists): **6 years** (45 CFR 164.316(b)(2)).
- Signed documents: per your legal/medical-records retention schedule (often
  ≥ 6–10 years; state law varies — counsel decides).
- Audit chain rows: retain for at least the life of the documents they
  attribute. They are designed never to be deleted.

### 6.2 Disposal procedure (per document / per individual)

1. Identify objects: `signed_pdf_url` values from the tenant's audit rows /
   your domain tables.
2. Delete the PDF objects from the `signed-documents` bucket (service role).
   If AWS S3 Object Lock / WORM was enabled (Enterprise), disposal is only
   possible after the lock period — plan retention classes accordingly.
3. Delete your domain rows (envelopes, signer records) per your schedule.
4. **Audit rows are not deleted.** UPDATE/DELETE/TRUNCATE raise by trigger,
   and removal would break the hash chain. This is why §3.2 keeps PHI out of
   `metadata`: after steps 2–3, remaining audit rows hold only identifiers
   and hashes. If an individual-rights request demands erasure of a scalar
   identifier inside the chain (e.g. an `actor_user_id`), the compliant path
   is documented infeasibility per BAA §9.3 — counsel call, not an
   engineering call.
5. Record the disposal itself in your compliance log (date, scope, operator,
   method).

### 6.3 Tenant offboarding / termination

Follow BAA §9.3: 30-day export window (PDFs via storage API, audit rows via
PostgREST), then deletion within 60 days, certificate of deletion on request.

## 7. Workforce access checklist (45 CFR 164.308(a)(3)–(4))

Run quarterly and on every role change:

- [ ] Enumerate humans + service identities with: service-role key access;
      membership in each production tenant (`esig_tenant_member()` inputs);
      secret-manager read on the wrapping passphrases; Supabase dashboard or
      infrastructure-console access.
- [ ] Every entry maps to a current job function (minimum necessary).
- [ ] Departures in the quarter: access removed ≤ 1 business day; passphrase
      + service-key rotation evaluated per §4.4.
- [ ] MFA verified on all production-capable accounts.
- [ ] Spot-check: as a non-member test user, confirm SELECT on
      `esig_audit_log` and object reads under another tenant's prefix return
      nothing.
- [ ] Sign and file the completed checklist (6-year retention).

## 8. BAA execution checklist

Before the first byte of PHI touches the pipeline:

- [ ] **HIPAA BAA + Healthcare Runbook** add-on active on the subscription.
- [ ] BAA (from `BAA-template.md`) reviewed by counsel **for both parties**;
      brackets filled; signed by authorized officers; countersigned copy filed.
- [ ] Exhibit A subprocessor list reviewed; change-notification subscription
      active (`subprocessors@e-sig.org` / RSS).
- [ ] Optional add-ons that touch PHI (Twilio SMS) explicitly accepted or
      disabled.
- [ ] §3.1 minimum-necessary baseline checklist completed and filed.
- [ ] §5 breach playbook: names + phone numbers filled in for Security
      Officer, counsel, vendor contact; T0 log template staged.
- [ ] Chain-verification cadence scheduled (recommended: weekly
      `verifyAuditChain()` per production tenant, alert on `ok: false`;
      anchor the latest `row_hash` externally per the `0002` migration
      header's guidance for hard guarantees).
- [ ] Workforce trained on §3.3 notification hygiene and §5 escalation.
- [ ] Date + owner recorded for the first quarterly §7 review.
