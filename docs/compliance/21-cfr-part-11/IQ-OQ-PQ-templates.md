# Validation Protocol Templates — IQ / OQ / PQ

**DRAFT — requires review and approval by the customer's quality unit before
execution.**

> e-sig provides technical controls, not legal advice. These are executable
> protocol templates for validating an e-sig deployment against its intended
> use (21 CFR 11.10(a)). The vendor supplies the templates and the verifiable
> test substrate; **you** execute them in your environment, under your change
> control, with your approvals. An unexecuted template validates nothing.
> Part of the **21 CFR Part 11** add-on ($1,200/mo); companion to
> `requirements-mapping.md`.

**Conventions**

- Record **Actual result** verbatim (paste command output or attach as a
  numbered exhibit). "As expected" is not an acceptable entry.
- **Pass/Fail** is binary. Any Fail → open a deviation, resolve, and either
  re-execute the step or justify acceptance in the summary report.
- **Initials/Date**: executor initials + date of execution (ISO 8601).
- Baseline versions in this template: `@e-sig/core` **0.6.0**,
  `@e-sig/supabase` **0.3.0**, migrations `0001`–`0003`, Node.js ≥ 20,
  vitest 4.x. Update the version table (IQ-02) to your actual baseline and
  re-execute IQ on every change (change control).

---

## Protocol approval (all three protocols)

| Role | Name | Signature | Date |
|---|---|---|---|
| Protocol author | | | |
| System owner | | | |
| Quality unit | | | |

Validation plan reference: `[VP-____]`  ·  System ID: `[________]`
Environment under test: `[ ] self-hosted  [ ] e-sig Cloud  — region: ______`

---

# Part 1 — Installation Qualification (IQ)

**Objective.** Verify the software components, versions, integrity, database
schema, and security posture of the installed system match the approved
baseline.

**Prerequisites.** Shell access to the deployment host/CI; service-role
database access for schema queries; the approved baseline version table.

### IQ test steps

| # | Step (command / action) | Expected result | Actual result | Pass/Fail | Initials/Date |
|---|---|---|---|---|---|
| IQ-01 | Record runtime: `node --version` | Node.js ≥ 20 (engines requirement of all `@e-sig/*` packages) | | | |
| IQ-02 | Record installed package versions: `npm ls @e-sig/core @e-sig/supabase` (add `@e-sig/react`, `@e-sig/uuaid` if deployed) | Exact versions match the approved baseline table (e.g., `@e-sig/core@0.6.0`, `@e-sig/supabase@0.3.0`); no `invalid`/`UNMET` markers | | | |
| IQ-03 | Compute the distribution checksum and compare to the vendor-published value for the pinned version: `find node_modules/@e-sig/core/dist -type f \| sort \| xargs shasum -a 256 \| shasum -a 256`; repeat for `@e-sig/supabase/dist` | Digest matches the recorded baseline digest for that version (record both digests; on first validation, this step **establishes** the baseline) | | | |
| IQ-04 | Verify migrations applied — tables exist: `select table_name from information_schema.tables where table_name in ('org_signing_certs','esig_audit_log','org_pq_keys');` | All three tables present (`org_pq_keys` required only if the PQ seal is in scope) | | | |
| IQ-05 | Verify audit-chain columns (migration 0002): `select column_name from information_schema.columns where table_name='esig_audit_log' and column_name in ('seq','prev_hash','row_hash','payload_canonical');` | All four chain columns present | | | |
| IQ-06 | Verify append-only triggers: `select tgname from pg_trigger where tgrelid='esig_audit_log'::regclass and tgname like 'esig_audit_log_block%';` | Triggers blocking UPDATE, DELETE, TRUNCATE all present (`…_block_update`, `…_block_delete`, `…_block_truncate`) | | | |
| IQ-07 | Verify RLS enabled: `select relname, relrowsecurity from pg_class where relname in ('org_signing_certs','esig_audit_log','org_pq_keys');` | `relrowsecurity = true` for every listed table | | | |
| IQ-08 | Verify tenant predicate is not the shipped deny-all stub **and** not a permissive placeholder: review `select prosrc from pg_proc where proname='esig_tenant_member';` | Function body implements the documented membership check for this deployment (attach body as exhibit); it is neither `RETURN false` (stub) nor unconditional `RETURN true` | | | |
| IQ-09 | Verify storage bucket privacy: `select id, public from storage.buckets where id='signed-documents';` | Row exists, `public = false` | | | |
| IQ-10 | Verify secrets placement: confirm `ESIG_CERT_PASSPHRASE` (and PQ passphrase, if in scope) resolves from the approved secret manager, and that the service-role key is absent from client-delivered bundles | Documented secret-manager references; grep of built client assets finds no service key | | | |
| IQ-11 | Record infrastructure baseline: database provider + version, storage backend, region(s), TLS termination point | Matches approved architecture document `[ref]` | | | |

### IQ summary

Executed steps: ___ / 11 · Failures: ___ · Deviations opened: ___________

---

# Part 2 — Operational Qualification (OQ)

**Objective.** Verify the installed system operates according to its
functional specification: signing, verification, tamper evidence, audit
chaining, sequencing, and access control — using the vendor's machine-
verifiable test substrate plus targeted manual challenges.

**Prerequisites.** IQ passed. A non-production tenant. Repo or package
checkout matching the deployed versions (for OQ-01/02/03), or vendor-provided
test-run attestation for the pinned version if you do not execute the suite
yourself (record which).

### OQ test steps

| # | Step (command / action) | Expected result | Actual result | Pass/Fail | Initials/Date |
|---|---|---|---|---|---|
| OQ-01 | Execute the core automated suite: `cd packages/esig-core && npx vitest run` | All test files pass. Baseline for 0.6.0: **7 files, 87 tests, 0 failures** — suites include `crypto.test.ts` (issuance; AES-256-GCM + scrypt key wrapping; sign → verify cryptographic; PAdES/CAdES signed attributes; data-URL guard), `envelope.test.ts` (createEnvelope, resolveSigningToken, recordSignature, decline + void, composeEnvelopeHtml), `pq-seal/pq-pdf/pq-cert/pq-lifecycle` (tamper-evidence, hybrid AND-semantics, substitution defeated), `fs-adapters.test.ts` | | | |
| OQ-02 | Execute the persistence-layer suite: `cd packages/esig-supabase && npx vitest run` | All pass. Baseline for 0.3.0: **2 files, 9 tests, 0 failures** (`audit-chain.test.ts` — verifyAuditChain detects edits, deletions, reordering, re-hashing; `pq-key-store.test.ts`) | | | |
| OQ-03 | Execute the runtime smoke against the **built** artifacts: `npm run build && npm run smoke` | Smoke completes: **5 checks passed** — ensureActiveCert create+reuse; signPdf → verifyPdfStructure round-trip (cryptographically valid); tampered PDF rejected (digest mismatch); signDocument orchestrator exported; store interfaces implementable | | | |
| OQ-04 | **End-to-end sign in the target environment**: through the deployed application, sign a test document as a test signer | Signed PDF produced and stored under `{tenant_id}/…` in `signed-documents`; PDF opens in Adobe Reader/Preview with a signature panel; manifestation block shows printed name, email, role label, ISO timestamp | | | |
| OQ-05 | **Verification of the OQ-04 record**: run `verifyPdfSignature()` (or `verifyDocument()` if PQ in scope) against the stored bytes | `ok: true`, `digestValid: true`, `signatureValid: true`; with PQ: `classical.ok` and `postQuantum.ok` both true | | | |
| OQ-06 | **Tamper challenge**: flip one byte in a copy of the OQ-04 PDF (e.g., `printf '\x00' \| dd of=copy.pdf bs=1 seek=1000 conv=notrunc`), re-verify | Verification fails (`ok: false` / `digestValid: false`); with PQ, **both** layers fail; Adobe signature panel reports the document was altered | | | |
| OQ-07 | **Two-component signing challenge** (§11.200(a)(1)): attempt to open a signing link (valid token) without an authenticated application session | Signing ceremony refused until login completes (knowledge component) — token alone is insufficient. *If your deployment does not front signing with login, record a documented deviation and the compensating control approved by QA* | | | |
| OQ-08 | **Sequencing challenge** (§11.10(f)): create a 2-signer envelope with orders 1 and 2; attempt to sign with signer 2's token first | Rejected with `not_your_turn`; signer 1 can sign; then signer 2 succeeds; envelope transitions sent → partially_signed → completed | | | |
| OQ-09 | **Replay challenge**: after signer 1 signs in OQ-08, re-use signer 1's link | Rejected (`already_signed`); no duplicate signature recorded | | | |
| OQ-10 | **Void/loss-management challenge** (§11.300(c)): create an envelope, `voidEnvelope()`, then attempt its token | Rejected (`not_signable`); void event present in audit trail | | | |
| OQ-11 | **Audit-trail completeness** (§11.10(e)): for the OQ-04 event, query the tenant's `esig_audit_log` rows | Row(s) present with correct `action` (e.g., `pdf.signed`), `actor_user_id`, `cert_fingerprint`, `signed_pdf_url`, `ip`, `user_agent`, server-side `created_at` | | | |
| OQ-12 | **Chain integrity**: run `verifyAuditChain(client, { tenantId })` for the test tenant | `ok: true`, `checkedRows` equals the tenant's row count, `failures: []` | | | |
| OQ-13 | **Append-only challenge**: as service role, attempt `UPDATE esig_audit_log SET action='pdf.verified' WHERE …` and `DELETE FROM esig_audit_log WHERE …` on one test row | Both statements **fail** with the trigger's RAISE; row unchanged; subsequent OQ-12 re-run still `ok: true` | | | |
| OQ-14 | **Access-control challenge** (§11.10(d)): as an authenticated user who is NOT a member of the test tenant, SELECT from `esig_audit_log` and fetch a stored PDF path | Zero rows returned; object fetch denied — RLS scopes both to tenant members | | | |
| OQ-15 | **Key rotation** (§11.300(b)): force-rotate the signing cert (Healthcare Runbook §4.1) and, if in scope, `rotatePqKeys()`; re-verify a pre-rotation document | New active cert/bundle with `rotated_from` linkage; `cert.deactivated`/`cert.created` (or `cert.rotated`) audit rows; pre-rotation document still verifies | | | |
| OQ-16 | *(If RFC 3161 in scope)* Sign with the configured `tsa` transport | `timestamped: true`; `verifyPdfStructure` reports `timestampTime` and `tsaCommonName`; §2.4.2 binding check passes (`ok: true`) | | | |
| OQ-17 | *(If PQ pinning in scope)* Verify with `expectedMldsa65Fpr` set to the published fingerprint, then with a wrong fingerprint, then with `requirePq: true` against an unsealed PDF | Correct fingerprint: passes. Wrong fingerprint: fails. `requirePq` on unsealed document: fails (no silent downgrade) | | | |

### OQ summary

Executed steps: ___ / 17 (N/A steps justified: ___) · Failures: ___ ·
Deviations: ___________

---

# Part 3 — Performance Qualification (PQ)

**Objective.** Demonstrate the system performs reliably under the customer's
real workload, users, SOPs, and data over a sustained window. PQ is
necessarily customer-specific: define acceptance criteria from your intended
use **before** execution.

**Prerequisites.** IQ + OQ passed and approved. Trained users (11.10(i)
records on file). Approved SOPs for signing, verification, incident response,
and record retention. A defined PQ window (typically 10–30 business days of
representative use).

### PQ acceptance criteria (complete before execution)

| Metric | Your criterion (example) | Source |
|---|---|---|
| Signing round-trip latency | e.g., ≤ 10 s warm, ≤ 30 s cold (vendor-measured reference: ~4.5 s cold / 1–1.5 s warm on serverless) | `[SOP/URS ref]` |
| Signing success rate over window | e.g., ≥ 99.5% excluding user abandonment | |
| Verification pass rate on completed records | 100% — any failure is a deviation, no threshold | |
| Audit-chain verification | `ok: true` on every scheduled run — no threshold | |
| Concurrent load | e.g., N envelopes/hour peak without degradation | |

### PQ test steps

| # | Step | Expected result | Actual result | Pass/Fail | Initials/Date |
|---|---|---|---|---|---|
| PQ-01 | **Representative workload**: over the PQ window, process ≥ `[N]` real or production-representative envelopes through the approved SOP (actual document templates, actual roles/ordering, actual signer population) | All envelopes complete or terminate per SOP (declined/voided/expired handled correctly); success-rate criterion met | | | |
| PQ-02 | **User-acceptance script**: each user role (author, signer, approver, QA reviewer) executes its SOP tasks end-to-end and confirms the manifestation (name, time, meaning) is correct and legible on the output PDF | Each role signs off its script; discrepancies logged | | | |
| PQ-03 | **Sustained verification**: verify every PDF produced in PQ-01 (`verifyPdfSignature()` / `verifyDocument()` batch) | 100% pass; count recorded | | | |
| PQ-04 | **Scheduled chain verification**: run `verifyAuditChain()` per production tenant on the approved cadence (e.g., weekly) throughout the window; record `checkedRows` growth | `ok: true` every run; row counts monotonically increasing | | | |
| PQ-05 | **Backup/restore drill** (11.10(c)): restore database + storage backup to an isolated environment; re-run OQ-05 verification on a sample record and OQ-12 chain verification on its tenant | Restored records verify; restored chain `ok: true`; restore time within your RTO | | | |
| PQ-06 | **Peak-load exercise**: drive the defined peak (concurrent envelope creation + signing) | Latency and success-rate criteria met; no cross-tenant leakage under load (spot-check OQ-14) | | | |
| PQ-07 | **Incident-drill tabletop**: walk the breach/compromise playbook (Healthcare Runbook §5 or your SOP) against a simulated leaked signing link, including void + re-issue + audit-extract | Playbook executable as written; gaps become CAPA items | | | |
| PQ-08 | **Retention spot-check**: confirm the oldest in-scope record remains retrievable and verifiable; confirm disposal procedure has NOT touched audit rows | Record retrievable, verification passes, chain intact | | | |

### PQ summary

Window: `[start]` → `[end]` · Envelopes processed: ___ · Verification pass
rate: ___% · Chain runs `ok`: ___ / ___ · Failures/deviations: ___________

---

# Validation Summary Report (VSR) — skeleton

**System:** `[name / System ID]` · **Baseline:** `@e-sig/core [ver]`,
`@e-sig/supabase [ver]`, migrations `[list]` · **VSR ID:** `[____]`

1. **Purpose and scope** — intended use validated; environments covered;
   explicit exclusions (e.g., PQ seal not in scope).
2. **Protocol execution summary**

   | Protocol | Steps executed | Passed | Failed | N/A (justified) | Deviations |
   |---|---|---|---|---|---|
   | IQ | /11 | | | | |
   | OQ | /17 | | | | |
   | PQ | /8 | | | | |

3. **Deviation log** — ID, description, root cause, resolution
   (re-executed / accepted with justification), QA approval.
4. **Requirements traceability** — cross-reference each executed step to the
   §11 clauses in `requirements-mapping.md` (e.g., OQ-06 → 11.10(a)+11.70;
   OQ-08 → 11.10(f); OQ-13/OQ-12 → 11.10(e); OQ-14 → 11.10(d);
   OQ-07 → 11.200(a)(1); OQ-10/OQ-15 → 11.300(b)(c)).
5. **Customer-responsibility attestations** — training records current
   (11.10(i)); accountability policy signed (11.10(j)); identity-verification
   SOP in force (11.100(b)); FDA e-signature certification letter filed
   (11.100(c)) — attach evidence references.
6. **Residual risk and known gaps** — carry forward applicable items from
   `requirements-mapping.md` "Known gaps" with their compensating controls.
7. **Change-control statement** — the validated state is version-pinned
   (IQ-02/IQ-03 digests); any package upgrade, migration, or predicate change
   triggers impact assessment and re-execution of affected steps.
8. **Conclusion** — statement of fitness for intended use.

**Approvals**

| Role | Name | Signature | Date |
|---|---|---|---|
| System owner | | | |
| Quality unit | | | |
| IT/Engineering | | | |
