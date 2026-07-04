# @e-sig/uuaid

**Opt-in** [UUAID](https://uuaid.org) adapter for [`@e-sig/core`](https://github.com/vmvtech/esig-suite/tree/main/packages/esig-core) —
agent-identity stamping for the audit log, plus external anchoring of the
audit hash-chain head.

```bash
npm i @e-sig/uuaid @uuaid/sdk
```

## Why

The audit hash chain (`migrations/0002` + `verifyAuditChain()` in
`@e-sig/supabase`) is tamper-**evident** *internally*: any edit inside your
database breaks the chain. But an attacker with full DB access can rewrite the
entire chain self-consistently. Anchoring the chain head *outside* your
infrastructure closes that hole — UUAID stores the (encrypted) head and records
its content hash in a hash-chained ledger whose Merkle roots anchor to
**Polygon mainnet**, making the audit trail tamper-**proof** externally:
rewriting your history now means contradicting a public blockchain.

Privacy: only the chain-head hash leaves your infrastructure — never document
bytes, never audit rows — and it is encrypted client-side (AES-256-GCM via
`@uuaid/vault`) before upload. UUAID only ever sees ciphertext.

## Quickstart

```ts
import { UuaidClient } from "@uuaid/sdk";
import { withUuaidActor, anchorChainHead } from "@e-sig/uuaid";

const client = new UuaidClient({ apiKey: process.env.UUAID_API_KEY! });
const agentUuaid = process.env.UUAID_AGENT_UUAID!; // from client.registerAgent(...)

// 1. Stamp the acting agent's UUAID into every audit row (metadata.uuaidAgent):
const auditStore = withUuaidActor(new SupabaseAuditLogStore(service), agentUuaid);
// ...pass auditStore to signDocument() as usual — no other change.

// 2. Anchor the tenant's chain head externally (e.g. after each signing batch):
const { contentHash } = await anchorChainHead({
  client, agentUuaid, vaultKey: process.env.UUAID_VAULT_KEY!, // uvk_… (generateVaultKey)
  tenantId, chainHeadHash: latestRowHash, // row_hash of the tenant's newest audit row
});
```

`withUuaidActor` wraps **any** `AuditLogStore` (Supabase, `@e-sig/core/fs`,
custom) — `AuditLogEntry.metadata` is an open Record, so no core change is
involved. `anchorChainHead` saves the head under vault key
`esig/chain-head/<tenantId>`; read it back with
`client.loadMemory(agentUuaid, key, vaultKey)`.

## Strictly opt-in — core stays SaaS-free

The e-sig suite is self-hosted by design; this package changes nothing about
that. Without it (or with its env unset) the pipeline runs exactly as before:

- `withUuaidActor(store, "")` returns the store unchanged — blank/absent env
  config means stamping is cleanly disabled.
- `anchorChainHead` only talks to the network when you call it, and rejects
  blank options *before* any request.

Getting credentials: one free call — `POST https://api.uuaid.org/signup`
`{"name":"..."}` (or `UuaidClient.signup("...")`) returns a working API key;
`registerAgent()` mints the agent UUAID; `generateVaultKey()` from
`@uuaid/vault` mints the `uvk_…` encryption key (keep it secret — it never
leaves your process).

Peer dep: `@e-sig/core`. License: MIT.
