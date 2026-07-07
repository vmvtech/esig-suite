# 21 CFR Part 11 — Requirements Mapping

**DRAFT — requires review by qualified counsel and your quality unit before
reliance in a regulated submission.**

> e-sig provides technical controls, not legal advice. Part 11 compliance is
> a property of a **validated system in an operating quality environment**,
> never of a software library alone. This document maps each relevant §11
> clause to the concrete, named product control that supports it — and states
> honestly, in the right-hand column, what the platform cannot do for you.
> Part of the **21 CFR Part 11** add-on ($1,200/mo), together with the
> IQ/OQ/PQ templates (`IQ-OQ-PQ-templates.md`).

**Scope.** `@e-sig/core` 0.6.0, `@e-sig/supabase` 0.3.0, migrations
`0001_esig_self_contained.sql`, `0002_esig_audit_hashchain.sql`,
`0003_esig_pq_keys.sql`, deployed either self-hosted or on the e-sig Cloud
Services. The mapping assumes the customer operates the system as **closed**
(§11.10) — access controlled by the persons responsible for the records —
with §11.30 addressed for any open-system topology.

**Reading the table.** *Product control* = shipped, testable behavior with
the real function/table/test names. *Customer responsibility* = procedural
or configuration work the regulation requires of the record owner; the
platform cannot perform it. Where a row says **shared**, both columns are
load-bearing.

---

## §11.10 — Controls for closed systems

### 11.10(a) — Validation of systems to ensure accuracy, reliability, consistent intended performance, and the ability to discern invalid or altered records

| Product control | Customer responsibility |
|---|---|
| Versioned, deterministic packages with a machine-verifiable test suite: `npx vitest run` across `packages/esig-core/test/` (crypto, envelope, fs-adapters, pq-seal, pq-pdf, pq-cert, pq-lifecycle) and `packages/esig-supabase/test/` (audit-chain, pq-key-store); Chrome-free runtime smoke `scripts/smoke.mjs`. Invalid/altered-record discernment is a first-class function: `verifyPdfSignature()` recomputes the digest over the signed /ByteRange and RSA-verifies; `verifyDocument()` adds the PQ verdict; `verifyAuditChain()` detects edited, deleted, reordered, or re-hashed audit rows. Tamper tests exist in-suite (`pq-pdf: tamper breaks BOTH layers`; `audit-chain.test.ts`). | **Execute validation in your context** — the vendor cannot validate your intended use. Run the IQ/OQ/PQ protocols (`IQ-OQ-PQ-templates.md`), approve them through your quality unit, keep signed records, and re-validate on upgrade (change control). Define intended use and acceptance criteria. |

### 11.10(b) — Ability to generate accurate and complete copies of records in both human readable and electronic form suitable for inspection, review, and copying by the agency

| Product control | Customer responsibility |
|---|---|
| The primary record **is** human-readable: a signed PDF (opens in Adobe Reader/Preview with a signature panel), containing the full document body plus the §11.50 manifestation block. Electronic form: the same PDF byte stream, exportable from the private `signed-documents` bucket (`{tenant_id}/{document_id}/{ts}.pdf`); audit records exportable as rows from `esig_audit_log` (all columns, including chain columns `seq`, `prev_hash`, `row_hash`, `payload_canonical`). Copies are provably accurate: any divergence from the signed bytes fails `verifyPdfSignature()`. | Provide inspection access procedures (who exports, how fast, in what format an investigator receives them). Retain export tooling access for the full retention period. |

### 11.10(c) — Protection of records to enable their accurate and ready retrieval throughout the records retention period

| Product control | Customer responsibility |
|---|---|
| Audit rows are append-only at the database layer: migration `0002` installs triggers that RAISE on UPDATE, DELETE, and TRUNCATE for **every** role, plus the per-tenant hash chain so even privileged tampering is detectable (`verifyAuditChain()`). Signed PDFs live in a private bucket under RLS; Enterprise deployments may add AWS S3 Object Lock (WORM) via the AWS subprocessor. Keys that protect records are themselves protected (AES-256-GCM wrapping, `encryptKeyPem()` / `wrapPqKeyBundle()`). | Define and enforce the retention schedule; configure backups/DR and test restore (PQ template PQ-05); do not delete PDFs before schedule end; if WORM is required by your predicate rules, enable Object Lock and set retention classes. |

### 11.10(d) — Limiting system access to authorized individuals

| Product control | Customer responsibility |
|---|---|
| Deny-by-default row-level security on `org_signing_certs`, `esig_audit_log`, `org_pq_keys`, and `storage.objects` (bucket `signed-documents`), all gated on `esig_tenant_member(tenant_id)`; the shipped stub returns `false` — no reads until the customer installs a real membership predicate. Writes are service-role only. Signer access is per-person, single-use: 32-byte CSPRNG signing tokens, only the SHA-256 `tokenHash` persisted, resolved by `resolveSigningToken()` which rejects unknown, expired, voided, or out-of-order tokens (`EnvelopeError` codes `invalid_token`, `not_your_turn`, `not_signable`). | **Authentication is yours.** The SDK never sees passwords; you supply the identity layer (SSO/IdP), implement `esig_tenant_member()` correctly, protect the service-role key, and run periodic access reviews (Healthcare Runbook §7 pattern). |

### 11.10(e) — Secure, computer-generated, time-stamped audit trails that independently record the date and time of operator entries and actions; record changes shall not obscure previously recorded information; audit trail retained at least as long as the record

| Product control | Customer responsibility |
|---|---|
| `esig_audit_log`: every pipeline action (`cert.created`, `cert.rotated`, `cert.deactivated`, `pdf.rendered`, `pdf.signed`, `pdf.verified`, `consent.recorded`, `envelope.*`, `verify.*` — CHECK-constrained) is inserted by trigger-hashed rows carrying `actor_user_id`, `action`, `target_table`/`target_id`, `ip`, `user_agent`, `session_id`, `cert_fingerprint`, and a server-side `created_at timestamptz` (microsecond precision, welded into `payload_canonical`). "Shall not obscure": structurally guaranteed — rows cannot be updated or deleted (triggers), and the SHA-256 chain (`row_hash = sha256(prev_hash \| payload_canonical)`, contiguous `seq`) makes any suppression or reordering detectable by `verifyAuditChain()`. Optional RFC 3161 timestamp tokens (CAdES-T) bind signature time to an external TSA. | Ensure database clock discipline (NTP) on self-hosted deployments; retain audit rows ≥ record retention; schedule periodic chain verification and (recommended) anchor the latest `row_hash` externally per the `0002` migration header; record **reason for change** at the application level where your SOPs require it (pass it in `auditMetadata`). |

### 11.10(f) — Operational system checks to enforce permitted sequencing of steps and events, as appropriate

| Product control | Customer responsibility |
|---|---|
| Envelope state machine (`envelope.ts`): 1-based signing `order` — lower orders gate higher ones; `resolveSigningToken()` returns `not_your_turn` for out-of-order attempts; `recordSignature()` rejects double-signing (`already_signed`) and signing on non-signable envelopes (`not_signable`: voided/expired/completed); `composeEnvelopeHtml()` refuses composition before completion (`not_complete`); the cryptographic seal is applied once, after the last signer, over the complete composed document. Covered by `packages/esig-core/test/envelope.test.ts`. | Configure signing order to match your controlled process (e.g., author → reviewer → QA approver); enforce any *business* sequencing outside signature collection (e.g., document pre-approval workflow) in your application. |

### 11.10(g) — Authority checks to ensure that only authorized individuals can use the system, electronically sign a record, access the operation or computer system input or output device, alter a record, or perform the operation at hand

| Product control | Customer responsibility |
|---|---|
| Per-action authority enforcement: signing requires possession of that signer's unique unexpired token (hash-matched, single-use); reading requires tenant membership (RLS); writing requires the service role; record alteration is denied to **all** roles (append-only triggers). Voiding/declining are explicit authenticated operations (`voidEnvelope()`, `declineEnvelope()`) that terminate token authority. | Bind tokens to authenticated identities: deliver each signing link only to the verified individual (unique mailbox/phone), require login before token use where your SOPs demand two-factor signing (§11.200 note below), and administer who may create/void envelopes. |

### 11.10(h) — Use of device (e.g., terminal) checks to determine, as appropriate, the validity of the source of data input or operational instruction

| Product control | Customer responsibility |
|---|---|
| Source attribution captured per event: `ip inet`, `user_agent`, `session_id` columns on every audit row, integrity-protected by the chain (via the row's `metadata`/scalar linkage). Signature-image input is strictly validated at the trust boundary: `assertImageDataUrl()` admits only base64 `data:image/(png\|jpe?g\|webp\|gif)` payloads, preventing markup/script injection into the to-be-signed document. | Determine whether device checks are "appropriate" for your process; if so, enforce device posture (managed devices, network allowlists) in front of the application and record device identity into `auditMetadata`. |

### 11.10(i) — Persons who develop, maintain, or use the system have the education, training, and experience to perform their assigned tasks

| Product control | Customer responsibility |
|---|---|
| None — a software control cannot satisfy this clause. The vendor maintains internal engineering training per DPA §5 (annual security/privacy training), which supports the vendor's side of "develop/maintain". | **Entirely yours for your workforce**: documented training on your e-signature SOPs and this system before use; training records retained; requalification on process change. |

### 11.10(j) — Written policies that hold individuals accountable and responsible for actions initiated under their electronic signatures, in order to deter record and signature falsification

| Product control | Customer responsibility |
|---|---|
| Supporting evidence only: the manifestation block states "Signed electronically by" with name/email/time, and the audit chain makes repudiation technically difficult. | **Entirely yours**: adopt a written e-signature accountability policy (each user acknowledges their e-signature is legally binding and equivalent to handwritten), obtain signed acknowledgments, and enforce sanctions. |

### 11.10(k) — Appropriate controls over systems documentation: (1) distribution/access/use of operation-maintenance documentation; (2) revision and change control procedures maintaining an audit trail of documentation changes

| Product control | Customer responsibility |
|---|---|
| Versioned, immutably published packages (`@e-sig/core` 0.6.0 et al.) with per-version READMEs and this compliance pack shipped in-repo under `docs/compliance/`; source control (git) provides the documentation audit trail; `IQ-OQ-PQ-templates.md` IQ section records exact versions + dist checksums installed. | Place system documentation (including your completed validation protocols and SOPs) under your document-control system; control access; re-baseline on every upgrade. |

## §11.30 — Controls for open systems

| Product control | Customer responsibility |
|---|---|
| Where records travel outside access-controlled boundaries: TLS 1.2+ on all endpoints (transit); document **integrity + authenticity travel inside the record itself** — the PKCS#7 ETSI.CAdES.detached signature with ESS signing-certificate-v2 binding, verifiable offline by any party via `verifyPdfSignature()`; optional additional measures explicitly contemplated by §11.30: RFC 3161 trusted timestamps (CAdES-T) and the hybrid post-quantum seal (Ed25519 + ML-DSA-65, FIPS 204) with pinned `expectedMldsa65Fpr` and `requirePq: true` (no silent downgrade), protecting long-retention records against future cryptanalysis. Confidentiality of stored records: private bucket + RLS + at-rest encryption. | Classify your topology (closed vs open); if open, define which additional measures (timestamping, PQ, encryption of transported copies) your risk assessment requires, and enable them; manage recipient-side verification instructions (publish the ML-DSA fingerprint / distribute the org trust anchor). |

## §11.50 — Signature manifestations

*(a) Signed electronic records shall contain information associated with the
signing that clearly indicates: (1) the printed name of the signer; (2) the
date and time when the signature was executed; (3) the meaning (such as
review, approval, responsibility, or authorship) associated with the
signature. (b) These items are subject to the same controls as electronic
records and shall be included in any human readable form.*

| Product control | Customer responsibility |
|---|---|
| `renderSignatureBlocksHtml()` (`signature-block.ts`) renders, per signer, into the document body **before** sealing: (1) printed name + email ("Signed electronically by: *name* &lt;email&gt;"); (2) execution time as ISO 8601 UTC ("Signed at *signedAt*"); (3) meaning via `roleLabel` (e.g., "Approver", "Principal investigator", "Witness") rendered above the block — plus the `reason` field embedded in the PKCS#7 signature dictionary by `signPdf()` (e.g., "Batch record approval") and shown in PDF readers' signature panels. §11.50(b): the block is part of the rendered PDF page content — human-readable in every copy — and lies under the cryptographic seal, so it carries the same integrity controls as the record. | **Set `roleLabel` and `reason` to express the regulatory meaning** of each signature — the platform renders what you pass; a blank meaning is a customer-side gap. Map roles to your SOP-defined signature meanings. |

## §11.70 — Signature/record linking

*(Electronic signatures … shall be linked to their respective electronic
records to ensure that the signatures cannot be excised, copied, or otherwise
transferred to falsify an electronic record by ordinary means.)*

| Product control | Customer responsibility |
|---|---|
| Strongest available linkage — cryptographic, not referential: the PKCS#7 detached signature is computed over the PDF's /ByteRange, which **contains** the manifestation blocks and document body; excising or transplanting a signature, or altering one byte of the record, fails `verifyPdfSignature()` (digest recomputation + RSA verify). The ESS signing-certificate-v2 attribute binds the signing certificate into the signed data (no cert substitution). With the PQ seal, the seal is embedded first and the classical signature covers it — seal-substitution is defeated (test: `pq-pdf: seal-append substitution is defeated`) and tampering fails **both** layers. Off-document linkage: the audit row records `signed_pdf_url`, `cert_id`, `cert_fingerprint`, and (when PQ) the PQ key id + ML-DSA-65 fingerprint, chained per §11.10(e). | Preserve signed PDFs as the authoritative record (do not re-render or "flatten" them); verify on ingest into downstream systems. |

## §11.100 — General requirements (electronic signatures)

| Clause | Product control | Customer responsibility |
|---|---|---|
| (a) Each electronic signature shall be unique to one individual and shall not be reused by, or reassigned to, anyone else | Per-signer uniqueness within the system: each `EnvelopeSigner` has a UUID, a unique single-use token (hash-persisted), an individual drawn `signatureImageDataUrl`, and an individually attributed audit trail. Tokens cannot be reused after signing (`already_signed`) and cannot be recovered from the store. | Guarantee **organizational** uniqueness and non-reassignment: one identity per human in your IdP; never reassign user accounts or re-issue a departed employee's identity. |
| (b) Before an organization establishes, assigns, certifies, or otherwise sanctions an individual's electronic signature … the organization shall verify the identity of the individual | None — identity proofing is inherently procedural. The platform records to whom a token was issued (`signingTokens[].email`) as evidence of your process. | **Entirely yours**: verify identity (per your SOP — government ID, HR onboarding, etc.) before issuing signing credentials; document the verification. |
| (c) Persons using electronic signatures shall, prior to or at the time of such use, certify to the agency that the electronic signatures … are intended to be the legally binding equivalent of traditional handwritten signatures | None — this is a paper letter to FDA. §11.100(c)(1): submit the certification to the Office of Regional Operations. | **Entirely yours**: file the FDA certification letter before first use; provide additional certification for specific signatures upon agency request (§11.100(c)(2)). |

## §11.200 — Electronic signature components and controls

| Clause | Product control | Customer responsibility |
|---|---|---|
| (a)(1)(i) Non-biometric signatures shall employ at least two distinct identification components such as an identification code and password; first signing in a session uses all components, subsequent signings at least one | **Partial (shared).** The signing token is one strong possession component (32-byte CSPRNG, single-use, hash-persisted, expirable). The platform does not implement passwords/login — by design (see `@e-sig/core` README: auth is a wrapper concern). A compliant deployment fronts the signing ceremony with the customer's authentication (login = knowledge component) **plus** the token (possession component), yielding two distinct components; your session policy governs the first-vs-subsequent rule. | Enforce login (IdP/SSO with password or equivalent) before the signing page renders; configure session behavior so an unattended session cannot sign; document the two components in your validation (OQ-07 in the templates). |
| (a)(1)(ii) Continuous sessions vs non-continuous | No session management in the SDK. | Define and enforce continuous-session rules in your application layer. |
| (a)(2) Used only by their genuine owners | Token delivered out-of-band exactly once to the named signer's address; unrecoverable from the store thereafter. | Deliver links only to individually held, verified mailboxes/numbers; prohibit sharing by policy (§11.10(j)). |
| (a)(3) Administered and executed to ensure that attempted use by anyone other than the genuine owner requires collaboration of two or more individuals | Token secrecy means misuse requires the owner's cooperation (forwarding the link) **and**, when fronted by login per (a)(1)(i), also the owner's credentials — i.e., collusion. | Maintain the login-in-front configuration; treat link-forwarding as a sanctionable act in the accountability policy. |
| (b) Biometric signatures | Not provided. The drawn signature image is a manifestation artifact, **not** a biometric authentication factor and is not claimed as one. | If you require biometrics, supply a biometric authentication layer and validate it; otherwise operate under (a). |

## §11.300 — Controls for identification codes/passwords

Applies to the extent your deployment relies on ID/password combinations
(per §11.200(a)(1)(i), passwords live in **your** identity layer; the
platform-side component is the signing token).

| Clause | Product control | Customer responsibility |
|---|---|---|
| (a) Uniqueness of each combined identification code and password | Tokens are unique per signer per envelope (CSPRNG collision-negligible; unique `tokenHash` lookup via `findByTokenHash()`). | Enforce unique user IDs in your IdP; no shared accounts. |
| (b) Periodic checking, recall, or revision (e.g., password aging) | Tokens age structurally: envelope `expiresAt` invalidates outstanding tokens; `voidEnvelope()` recalls them on demand; signing consumes them. Signing certs age via `not_after` with automatic rotation (`ensureActiveCert()`); PQ keys revise via `rotatePqKeys()`. | Password aging/recall policy in your IdP; set `expiresAt` on every envelope per SOP. |
| (c) Loss management — deauthorize lost/stolen/compromised tokens or devices, and issue temporary or permanent replacements under suitable controls | Compromised link → `voidEnvelope()` immediately deauthorizes all of that envelope's tokens; re-issue by creating a fresh envelope (`createEnvelope()` mints new tokens). Compromised keys → §4 rotation procedures (Healthcare Runbook pattern): forced cert rotation, `rotatePqKeys()`. All deauthorizations/rotations land in the audit chain (`cert.deactivated`, `envelope.*`). | Operate the loss-reporting channel (who signers call), execute void/re-issue promptly, and cover devices (badges, phones) your process uses. |
| (d) Transaction safeguards to prevent unauthorized use and to detect and report attempts in an immediate and urgent manner | Prevention: hash-only token storage (a DB leak yields no working links), single-use consumption, order gating, expiry. Detection substrate: failed resolutions are distinguishable (`invalid_token`, `not_your_turn`, `already_signed`) for the application to log; successful pipeline events are chain-logged. | **Alerting is yours**: log rejected token attempts and authentication failures, wire immediate notification to security (SIEM rule), and define the urgent-report procedure. The SDK does not send alerts. |
| (e) Initial and periodic testing of devices that bear or generate identification codes | Token generation is covered by the automated suite (`envelope.test.ts`: token minting, hash persistence, resolution) — re-executable at any time as the periodic test (OQ protocol). | Schedule periodic OQ re-execution per your validation plan; test any physical devices (badge readers, OTP fobs) your layer adds. |

---

## Known gaps — read before your gap assessment

Stated plainly so your validation does not discover them late:

1. **No user authentication layer.** By design (§11.200(a)(1)(i) row). A
   deployment without customer-side login in front of signing does **not**
   meet the two-component rule for non-biometric signatures.
2. **Self-issued X.509 by default.** Signatures are cryptographically valid
   but the RSA cert is self-signed — Adobe shows "validity unknown" absent a
   trust-store import or an AATL/CA signer. Part 11 does not require public
   trust chains, but your SOPs should state the trust model.
3. **No "reason for change" prompt.** §11.10(e) audit rows record what/who/
   when; if your SOPs require a captured reason, pass it via `auditMetadata`
   from your UI.
4. **Superuser threat model.** A database superuser can disable triggers; the
   chain makes this detectable, not impossible. For hard guarantees, anchor
   `row_hash` externally on a cadence (see `0002` migration header).
5. **Training, policies, identity proofing, FDA certification letter** —
   procedural clauses (11.10(i), (j), 11.100(b), (c)) have no software
   control and are entirely customer obligations.
