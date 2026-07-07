# Business Associate Agreement (BAA) — Template

**DRAFT — requires review by qualified counsel before execution.**

> e-sig provides technical controls, not legal advice. This template maps the
> contractual obligations of 45 CFR 164.504(e) onto the platform's actual,
> verifiable technical controls. It must be reviewed, completed, and executed
> by qualified counsel for both parties before any Protected Health
> Information is processed. Bracketed fields `[LIKE THIS]` are placeholders.

**Business Associate Agreement under the Health Insurance Portability and
Accountability Act of 1996 ("HIPAA"), the Health Information Technology for
Economic and Clinical Health Act ("HITECH"), and their implementing
regulations at 45 CFR Parts 160 and 164.**

| Field | Value |
|---|---|
| Covered Entity ("CE") | `[CUSTOMER LEGAL NAME]` |
| Business Associate ("BA") | vmvtech ("Vendor"), operator of the e-sig Cloud Services (`cloud.e-sig.org`, `api.e-sig.org`, `verify.e-sig.org`) |
| Underlying Agreement | The Terms of Service or Master Services Agreement between the parties, effective `[DATE]` |
| Effective Date of this BAA | `[DATE]` |
| Requires add-on | **HIPAA BAA + Healthcare Runbook** ($500/mo) — this BAA is only offered to subscribers of that add-on |

This BAA also applies, mutatis mutandis, where the Customer is itself a
business associate and Vendor acts as its **subcontractor** under 45 CFR
164.308(b)(2) and 164.502(e)(1)(ii); in that case references to "Covered
Entity" include the upstream business associate.

---

## 1. Definitions

Terms used but not otherwise defined in this BAA have the meanings given in
45 CFR Parts 160 and 164.

- **"Breach"** has the meaning at 45 CFR 164.402, including the presumption
  that an impermissible acquisition, access, use, or disclosure of PHI is a
  Breach unless demonstrated otherwise via the four-factor risk assessment.
- **"Electronic PHI" / "ePHI"** has the meaning at 45 CFR 160.103, limited to
  the information BA creates, receives, maintains, or transmits on behalf of CE.
- **"PHI"** has the meaning at 45 CFR 160.103, limited to the information BA
  creates, receives, maintains, or transmits on behalf of CE. In the context
  of the Services, PHI may appear in: document content submitted for signing
  (HTML and rendered/signed PDFs), envelope titles, signer names and email
  addresses, drawn signature images, consent text, and any metadata CE
  attaches to envelopes or audit entries. See the Healthcare Runbook
  (`docs/compliance/hipaa/healthcare-runbook.md`) §2 for the authoritative
  field-level data-flow map.
- **"Security Incident"** has the meaning at 45 CFR 164.304. The parties agree
  that unsuccessful attempts that do not result in unauthorized access, use,
  disclosure, modification, or destruction of ePHI (e.g., pings, port scans,
  rejected authentication attempts, dropped malformed packets) are reported
  by this paragraph in the aggregate and require no further per-event notice.
- **"Services"** means the e-sig Cloud Services and self-hosted support
  services provided under the Underlying Agreement.
- **"Subcontractor"** has the meaning at 45 CFR 160.103 and includes the
  subprocessors listed in Exhibit A.

## 2. Permitted Uses and Disclosures

2.1 **Service provision.** BA may use and disclose PHI only (a) to perform
the Services for CE as specified in the Underlying Agreement and as directed
by CE's API calls and configuration; (b) as required by law; and (c) as
expressly permitted by Sections 2.2–2.4.

2.2 **Management and administration.** BA may use PHI as necessary for BA's
proper management and administration and to carry out BA's legal
responsibilities, and may disclose PHI for those purposes if (a) the
disclosure is required by law, or (b) BA obtains reasonable assurances from
the recipient that the PHI will be held confidentially, used or further
disclosed only as required by law or for the purposes for which it was
disclosed, and the recipient notifies BA of any breach of confidentiality.

2.3 **Data aggregation.** BA may use PHI to provide data aggregation services
relating to CE's health care operations only if CE separately instructs BA to
do so in writing. By default the Services perform no aggregation across
tenants: all persistence is partitioned by `tenant_id` and enforced by
row-level security (Section 4.2).

2.4 **De-identification.** BA may de-identify PHI only on CE's written
instruction and in accordance with 45 CFR 164.514(a)–(c). De-identified
information is no longer PHI.

2.5 **Prohibitions.** BA shall not (a) use or disclose PHI other than as
permitted by this BAA or required by law; (b) sell PHI; (c) use PHI for
marketing or fundraising; (d) use PHI to train machine-learning or artificial
intelligence models. Item (d) restates the standing commitment in BA's DPA §3.

2.6 **Minimum necessary.** BA shall limit its uses, disclosures, and requests
of PHI to the minimum necessary to accomplish the intended purpose, consistent
with 45 CFR 164.502(b), and shall make available the minimum-necessary
configuration guidance in the Healthcare Runbook §3 so CE can avoid submitting
PHI the Services do not require (e.g., PHI in audit `metadata`).

## 3. Obligations of Covered Entity

3.1 CE shall not request or cause BA to use or disclose PHI in any manner
that would violate Subpart E of 45 CFR Part 164 if done by CE.

3.2 CE shall notify BA of (a) any limitation in CE's notice of privacy
practices, (b) any change in or revocation of an individual's permission to
use or disclose PHI, and (c) any restriction agreed to under 45 CFR 164.522,
in each case to the extent the change affects BA's permitted uses or
disclosures.

3.3 CE is responsible for the lawfulness of the PHI it submits, for
implementing the tenant-membership predicate that gates read access
(`esig_tenant_member()` — see Section 4.2), for workforce authentication in
front of the Services, and for the customer-side controls identified in the
Healthcare Runbook.

## 4. Safeguards

BA shall use appropriate safeguards to prevent use or disclosure of PHI other
than as provided by this BAA, and shall comply with Subpart C of 45 CFR Part
164 (the Security Rule) with respect to ePHI. Without limiting that general
obligation, BA maintains the following **specific technical controls**, which
are part of the shipped product and independently verifiable by CE:

4.1 **Encryption at rest — key material.** Tenant signing private keys are
never stored in plaintext. RSA signing keys are wrapped with **AES-256-GCM**
under a scrypt-derived key before persistence (`encryptKeyPem()` in
`@e-sig/core`; column `org_signing_certs.key_pem_encrypted`). Post-quantum
key bundles are likewise AES-256-GCM-wrapped (`wrapPqKeyBundle()`; column
`org_pq_keys.key_bundle_encrypted`). Database- and storage-level encryption
at rest (AES-256) applies additionally per the DPA §5.

4.2 **Tenant isolation.** All PHI-bearing tables (`org_signing_certs`,
`esig_audit_log`, `org_pq_keys`) and the `signed-documents` storage bucket
enforce Postgres **row-level security** keyed on `tenant_id`. Read access
requires the `esig_tenant_member(tenant_id)` predicate to return true; the
shipped default is deny-all until CE installs its membership check. Writes
are restricted to the service role. Signed PDFs are stored under
tenant-prefixed paths (`{tenant_id}/{document_id}/{ts}.pdf`) in a private
bucket, so path-prefix RLS scopes object reads to tenant members.

4.3 **Integrity and tamper evidence.** Every signing event is recorded in an
**append-only, hash-chained audit log** (`esig_audit_log`): each row carries a
per-tenant sequence number, the previous row's SHA-256 hash, and its own hash
over a versioned canonical payload; database triggers reject UPDATE, DELETE,
and TRUNCATE. CE can independently verify the chain at any time with
`verifyAuditChain()` (`@e-sig/supabase`). Signed PDFs carry a PKCS#7
(ETSI.CAdES.detached) signature such that any post-signing modification
invalidates the signature; `verifyPdfSignature()` performs this check
cryptographically.

4.4 **Encryption in transit.** TLS 1.2+ on all Service endpoints (DPA §5).

4.5 **Access control and logging.** Least-privilege access, MFA for all BA
engineers with production access, and admin-action logging retained at least
one year (DPA §5).

4.6 **Optional trusted timestamping.** Where CE enables RFC 3161
timestamping, only a SHA-256 hash of the signature value is sent to the
timestamp authority — never the document or any PHI.

4.7 CE acknowledges that safeguards 4.1–4.3 are effective only when CE
deploys the shipped Row-Level Security migrations unmodified and replaces the
`esig_tenant_member()` stub with a correct membership predicate (self-hosted
deployments), or uses the managed Cloud Services where BA operates them.

## 5. Subcontractors

5.1 BA shall ensure, in accordance with 45 CFR 164.502(e)(1)(ii) and
164.308(b)(2), that any Subcontractor that creates, receives, maintains, or
transmits PHI on behalf of BA agrees in writing to restrictions and
conditions at least as protective as those that apply to BA under this BAA,
including compliance with Subpart C of 45 CFR Part 164 for ePHI.

5.2 The Subcontractors as of the Effective Date are listed in **Exhibit A**,
which incorporates BA's living subprocessor list (`legal/SUBPROCESSORS.md`;
published at `e-sig.org`). BA shall give CE at least **30 days' prior
written notice** of any new Subcontractor that will handle PHI. If CE
reasonably objects on data-protection grounds and the parties cannot resolve
the objection within the notice period, CE may terminate the affected
Services without penalty.

5.3 BA remains liable to CE for its Subcontractors' performance.

## 6. Individual Rights Support

6.1 **Access (45 CFR 164.524).** BA shall make PHI in a designated record set
available to CE within **10 business days** of CE's request so CE can meet
its access obligations. The Services provide direct export: CE can retrieve
signed PDFs from its tenant-scoped storage and query its tenant's audit rows
via the API at any time without BA involvement.

6.2 **Amendment (45 CFR 164.526).** BA shall incorporate amendments to PHI in
a designated record set as directed by CE within **15 business days**. The
parties acknowledge a deliberate technical property: **signed PDFs and audit
rows are immutable by design** (amendment-by-overwrite would destroy the
evidentiary value of the signature and break the audit hash chain). Amendment
is therefore effected by appending a correcting record — a new signed
document and/or a new audit entry referencing the original — never by
altering the original. Counsel should confirm this append-only amendment
model is acceptable for CE's designated record sets.

6.3 **Accounting of disclosures (45 CFR 164.528).** BA shall document and,
within **15 business days** of request, provide to CE the information
required for CE to respond to an individual's request for an accounting of
disclosures. The hash-chained audit log records actor, action, target,
timestamp, IP, and user agent for every signing-pipeline event and is
queryable by CE per tenant.

6.4 **Restrictions and confidential communications (45 CFR 164.522).** BA
shall comply with any restriction or confidential-communication requirement
CE communicates under Section 3.2(c), to the extent it affects the Services.

## 7. Availability to the Secretary

BA shall make its internal practices, books, and records relating to the use
and disclosure of PHI received from, or created or received by BA on behalf
of, CE available to the Secretary of Health and Human Services for purposes
of determining CE's compliance with the HIPAA Rules.

## 8. Security Incident and Breach Notification

8.1 **Security Incidents.** BA shall report to CE any Security Incident of
which it becomes aware, subject to the aggregate-reporting convention for
unsuccessful attempts in Section 1.

8.2 **Breach notification.** Following discovery of a Breach of Unsecured PHI
(a Breach is "discovered" as of the first day it is known to BA or would have
been known by exercising reasonable diligence, per 45 CFR 164.410(a)(2)), BA
shall notify CE:

- **without unreasonable delay**, with a target of **72 hours** from
  confirmation (matching BA's standing DPA §8 commitment), and
- **in no case later than 60 calendar days after discovery** — the outer
  bound of 45 CFR 164.410(b).

8.3 **Content.** The notification shall include, to the extent known: the
identification of each individual whose Unsecured PHI has been or is
reasonably believed to have been accessed, acquired, used, or disclosed; a
description of what happened, the date of the Breach and the date of
discovery; the types of PHI involved; mitigation and remediation steps taken
or proposed; and a contact point. BA shall supplement the notification as
additional information becomes available (45 CFR 164.410(c)).

8.4 **Cooperation.** BA shall cooperate with CE's own risk assessment under
45 CFR 164.402 and with CE's notification obligations to individuals
(164.404), the media (164.406), and the Secretary (164.408). As between the
parties, CE is responsible for those downstream notifications unless the
parties agree otherwise in writing.

8.5 **Forensic support.** On request, BA shall provide CE the relevant
tenant's audit-chain extract and a `verifyAuditChain()` verification report
covering the incident window.

## 9. Term and Termination

9.1 **Term.** This BAA is effective as of the Effective Date and terminates
when the Underlying Agreement terminates or when the HIPAA BAA add-on
subscription lapses, whichever is earlier — except that BA's obligations
survive as long as BA retains any PHI.

9.2 **Termination for cause.** CE may terminate this BAA and the affected
Services if BA materially breaches this BAA and fails to cure within **30
days** of written notice, or immediately if cure is not possible.

9.3 **Return or destruction.** Upon termination, BA shall, at CE's election,
return or destroy all PHI that BA still maintains, consistent with the DPA
§9 export-then-delete mechanics:

- CE may export all documents and audit data via the API for **30 days**
  after termination.
- After the export window, BA shall delete remaining PHI within **60 days**,
  and shall provide a **certificate of deletion** on written request.
- If return or destruction of a specific data element is **infeasible**
  (e.g., where law requires retention, or where removal of an individual
  audit row is technically prevented by the append-only hash chain), BA shall
  notify CE of the conditions making it infeasible, and shall extend the
  protections of this BAA to that PHI and limit further use and disclosure to
  the purposes that make return or destruction infeasible, for as long as BA
  maintains it. The Healthcare Runbook §6 describes the disposal mechanics
  and the minimum-necessary configuration that keeps PHI out of the
  append-only structures in the first place.

## 10. Miscellaneous

10.1 **Regulatory references.** A reference to a section of the HIPAA Rules
means the section as in effect or as amended.

10.2 **Interpretation.** Any ambiguity shall be interpreted to permit
compliance with the HIPAA Rules. If this BAA conflicts with the Underlying
Agreement or the DPA with respect to PHI, this BAA controls.

10.3 **Amendment.** The parties shall amend this BAA as necessary to comply
with changes to the HIPAA Rules. No other amendment is effective unless in
writing and signed by both parties.

10.4 **No third-party beneficiaries.** Nothing in this BAA confers rights on
any person other than the parties.

**IN WITNESS WHEREOF**, the parties execute this BAA as of the Effective Date.

| | Covered Entity | Business Associate |
|---|---|---|
| Signature | ______________________ | ______________________ |
| Name | `[NAME]` | `[NAME]` |
| Title | `[TITLE]` | `[TITLE]` |
| Date | `[DATE]` | `[DATE]` |

---

## Exhibit A — Subcontractors handling PHI

Incorporated from the living list in `legal/SUBPROCESSORS.md` (esig-monetize
kit; published at `e-sig.org`, RSS `https://e-sig.org/subprocessors.rss`;
change-notification subscription: email `subprocessors@e-sig.org`, subject
"subscribe"). Entries marked **PHI: yes** create, receive, maintain, or
transmit PHI and are bound by subcontractor BAAs per Section 5; entries
marked **PHI: no** do not handle PHI and are listed for transparency only.

| Subcontractor | Purpose | Data processed | PHI | Region |
|---|---|---|---|---|
| Amazon Web Services (AWS) | Compute, S3 storage, KMS, Object Lock | Signed PDFs, encrypted keys | **yes** | US East / EU West (customer-selectable on Business+) |
| Supabase | Managed Postgres (audit chain, envelopes, tenants) + Storage | Audit rows, envelope metadata, signer PII, signed PDFs | **yes** | US East / EU West (customer-selectable on Business+) |
| Postmark | Transactional email delivery | Signer emails, sign-request subject lines | **yes** (subject lines/recipients may identify patients) | US |
| Twilio (optional add-on) | SMS delivery for signing links | Signer phone numbers, SMS content | **yes** (if enabled) | US |
| Cloudflare | CDN, DDoS protection, R2 (optional storage backend) | Static assets, cached responses; signed PDFs only if R2 backend selected | conditional (R2 only) | Global edge |
| Stripe | Payment processing, billing | Customer billing details (not signer PII) | no | US, EU |
| Vercel | Marketing site + docs hosting | Anonymous analytics | no | Global edge |
| Sentry | Error monitoring (PII scrubbing via allowlist) | Application errors | no (scrubbed) | US |
| BetterStack (or Instatus) | Status page + uptime monitoring | Endpoint response metadata | no | US |
| Vanta (or Drata) | Compliance evidence collection | Vendor-only metadata | no | US |

## Exhibit B — Technical safeguard cross-reference

For auditors: where each Section 4 safeguard lives in the shipped product.

| Safeguard | Implementation | Verifiable via |
|---|---|---|
| AES-256-GCM key wrapping | `encryptKeyPem()` / `wrapPqKeyBundle()` (`@e-sig/core`); `org_signing_certs.key_pem_encrypted`, `org_pq_keys.key_bundle_encrypted` | `packages/esig-core/test/crypto.test.ts` ("at-rest key wrapping (AES-256-GCM + scrypt)") |
| RLS tenancy | `migrations/0001_esig_self_contained.sql`, `0003_esig_pq_keys.sql`; predicate `esig_tenant_member(tenant_id)` | `pg_policies` inspection (IQ-04 in the Part 11 IQ template) |
| Audit hash chain, append-only | `migrations/0002_esig_audit_hashchain.sql` (triggers block UPDATE/DELETE/TRUNCATE) | `verifyAuditChain()` (`@e-sig/supabase`); `packages/esig-supabase/test/audit-chain.test.ts` |
| Signature integrity | PKCS#7 ETSI.CAdES.detached; `verifyPdfSignature()` | `packages/esig-core/test/crypto.test.ts` ("sign → verify (cryptographic)") |
| Post-quantum seal (optional) | Ed25519 + ML-DSA-65 (FIPS 204); `verifyDocument()` | `packages/esig-core/test/pq-*.test.ts` |
| TLS in transit | Service endpoints, TLS 1.2+ | DPA §5; external scan |
