# Compliance Deliverables

**DRAFT — every document in this directory requires review by qualified
counsel (and, where noted, the customer's quality unit) before execution or
reliance.** e-sig provides technical controls, not legal advice.

This directory contains the customer-facing compliance packs delivered with
the paid add-ons on the [pricing page](https://e-sig.org/pricing). Each
document maps regulatory obligations onto the product's actual, testable
controls — named functions, tables, migrations, and test suites — and states
plainly what the platform cannot do alone.

## Packs

### HIPAA BAA + Healthcare Runbook — $500/mo add-on

| Document | What it is |
|---|---|
| [`hipaa/BAA-template.md`](hipaa/BAA-template.md) | Complete Business Associate Agreement template per 45 CFR 164.504(e): permitted uses/disclosures, safeguards mapped to shipped controls (AES-256-GCM key wrapping, RLS tenancy, audit hash-chain, TLS), subcontractor flow-down with the Exhibit A subprocessor list, individual-rights support (164.524/526/528), breach notification (72-hour target, 60-day outer bound per 164.410), termination and return/destruction, and an auditor-facing technical cross-reference (Exhibit B) |
| [`hipaa/healthcare-runbook.md`](hipaa/healthcare-runbook.md) | Operational runbook: field-level PHI data-flow map through render → sign → store → verify, minimum-necessary configuration (including why PHI must stay out of `esig_audit_log.metadata`), key-rotation procedures (`ensureActiveCert` / `rotatePqKeys`), breach-response playbook with the regulatory clock, retention/disposal, workforce-access checklist, and the BAA execution checklist |

### 21 CFR Part 11 — $1,200/mo add-on

| Document | What it is |
|---|---|
| [`21-cfr-part-11/requirements-mapping.md`](21-cfr-part-11/requirements-mapping.md) | Clause-by-clause mapping of §11.10(a)–(k), §11.30, §11.50, §11.70, §11.100, §11.200, and §11.300 to concrete product controls (audit hash-chain, signature manifestation block, signer token binding, PKCS#7 signature/record linking, PQ seal) with an honest customer-responsibility column and a "Known gaps" section |
| [`21-cfr-part-11/IQ-OQ-PQ-templates.md`](21-cfr-part-11/IQ-OQ-PQ-templates.md) | Executable validation protocol templates: IQ (versions, dist checksums, schema/RLS/trigger verification), OQ (17 steps keyed to the real vitest suites, the smoke script, and manual tamper/sequencing/access challenges), PQ (customer-context workload, UAT, DR drill), plus a Validation Summary Report skeleton with §11 traceability |

## Review status

| Document | Status | Counsel review | Quality-unit review |
|---|---|---|---|
| `hipaa/BAA-template.md` | **DRAFT** | pending | n/a |
| `hipaa/healthcare-runbook.md` | **DRAFT** | pending | n/a |
| `21-cfr-part-11/requirements-mapping.md` | **DRAFT** | pending | pending (customer) |
| `21-cfr-part-11/IQ-OQ-PQ-templates.md` | **DRAFT** | pending | pending (customer) |

No document here may be presented to a customer as executed, approved, or
attorney-reviewed until this table says so. Version-pin any customer delivery
to the git commit that produced it.

## Related material

- Product trust model and crypto: `packages/esig-core/README.md`
- Audit-chain mechanics: `migrations/0002_esig_audit_hashchain.sql`,
  `packages/esig-supabase/src/audit-chain.ts`
- Baseline data-protection terms: DPA / SLA / SUBPROCESSORS in the
  esig-monetize kit (`legal/`)
