# @e-sig/uaid-exch

**Preview implementation of the proposed [IAASO Exchange Profile (ADR-006)](../../../../iaaso/proposals/ADR-006-exchange-profile.md).** The doctrine is under review by the IAASO standards council. This package is versioned `0.1.0-preview` and its wire format will be re-shaped to conform to the accepted schemas when ADR-006 lands. Use in production only after ADR-006 is Accepted and the schemas ship under `iaaso/artifacts/schemas/exchange/*/v1/`.

Wraps every `@e-sig/core` signing operation as a per-transaction signed authorization on the UUAID Network — subject + issuer proofs, network-side receipt, scope-checked authorization, and a Polygon-anchored batch inclusion proof that anyone can look up at `tx.uuaid.org/<id>`.

**Wire format note.** The current preview uses W3C `DataIntegrityProof` shape (`eddsa-jcs-2022`) as an ergonomic starting point. Per IAASO ADR-002, the accepted wire format for IAASO objects is the **UUAID SignatureEnvelope** (`{alg, keyId?, publicKey?, sig, created?}` — JCS + Ed25519, keccak256 for anchor). When ADR-006 is Accepted, this package will re-emit both shapes (VC shape for external interop, SignatureEnvelope for IAASO conformance) via a single call.

```bash
npm i @e-sig/uaid-exch @uuaid/sdk
```

MIT-licensed. Opt-in. If UUAID env is unset, this package is a no-op.

## Why

`@e-sig/core` already produces a real cryptographic PDF signature. `@e-sig/uuaid` already stamps the acting agent's UUAID into the audit log. This package closes the loop by producing a **portable, per-exchange Verifiable Credential** that:

- **Public.** Anyone can `GET https://api.uuaid.org/v1/exchanges/<id>` without a key.
- **Three-party attested.** Agent proof + Issuer TSP proof + (asynchronously) a Network receipt.
- **Scope-checked.** The Signing Credential's `scope` (actions, counterparty allowlist, value ceiling, assurance minimum) is machine-enforced by verifiers before the counterparty acts.
- **Anchored.** Every batch of receipts is Merkle-rooted and anchored to Polygon mainnet by the UUAID registry. Rewriting history means contradicting a public blockchain.
- **Interoperable.** Compatible with Google AP2 as an extension credential (`uuaid.exchange.v1`); the AP2 Payment Mandate id can be cross-referenced in `external_refs.ap2_payment_mandate`.

## Quickstart

```ts
import { signDocument } from "@e-sig/core";
import { UuaidClient } from "@uuaid/sdk";
import {
  createExchange,
  exchangeInputFromEsigEnvelope,
  UaidNetworkClient,
} from "@e-sig/uaid-exch";

// 1. Sign the PDF as usual with @e-sig/core.
const signed = await signDocument({ /* ...as usual... */ });

// 2. Build a UAP-EXCH-1 Exchange over that signing action.
const network = new UaidNetworkClient({ apiKey: process.env.UUAID_API_KEY! });

const exchange = await createExchange(
  exchangeInputFromEsigEnvelope({
    envelopeId: signed.envelopeId,
    signingCredentialId: process.env.UUAID_SIGNING_CREDENTIAL_ID!,
    principal: "did:web:acme.com",
    counterparty: "did:web:customer.com",
    pdfSha256: `sha256:${signed.pdfSha256Hex}`,
    pdfSize: signed.signedPdfBytes.length,
    pdfUri: signed.signedPdfUrl,
    purpose: "MSA Q3 renewal",
    value_impact: { currency: "USD", amount: 24000, term_months: 12 },
    soleControl: {
      challenge_type: "webauthn-prf",
      challenge_at: signed.consent.givenAt,
      challenge_evidence_hash: `sha256:${signed.consent.evidenceSha256Hex}`,
    },
  }),
  agentSigner,   // provide { agentUuaid, verificationMethod, sign(bytes) }
  issuerSigner   // provide { issuerDid,  verificationMethod, sign(bytes) }
);

// 3. Submit to the network. The receipt anchors ~10 minutes later.
const { exchange_id, estimated_anchor_at } = await network.submit(exchange);

// 4. Anyone can now verify at tx.uuaid.org/<tx_short_id> once anchored.
console.log(network.resolverUrl(exchange_id));
```

## Assurance ladder

Per [UAP-EXCH-1 § 4](https://github.com/uuaid/spec/blob/main/docs/profiles/UAP-EXCH-1/v0.1.md#4-assurance-ladder):

| Level | Requirements |
|---|---|
| **L0** | Software-key Agent, no KYA. |
| **L1** | Software-key + verified Principal. |
| **L2** | HW-attested key + org-verified Principal. |
| **L3** | L2 + continuous evidence from an Assurance Provider (e.g. DSalvus). |
| **L4** | L3 + industry KYA depth (HIPAA / PCI / SOX / 21 CFR Part 11) + insurance. |
| **L5** | L4 + eIDAS QES by a QTSP on the EU Trusted List. |

Counterparties enforce a minimum level; this SDK renders it into the Signing Credential and Exchange so verification is one JSON check.

## Revocation

Status-list style revocation for Signing Credentials (UAP-EXCH-1 § 9, draft). An issuer publishes an append-only `RevocationList` — `{ id, issuer, issued, revoked: [{ credentialId, revokedAt, reason? }], digest }` — whose `digest` is `sha256:<hex>` over the JCS (RFC 8785) canonicalization of the list body. Any mutation (removing an entry, backdating, issuer swap) fails integrity verification, and verifiers **fail closed**: a list that doesn't verify blocks the credential rather than silently allowing it.

```ts
import {
  createRevocationList,
  revokeCredential,
  isRevoked,
  verifyRevocationListIntegrity,
  assertCredentialUsable,
  CredentialRevokedError,
  CredentialExpiredError,
} from "@e-sig/uaid-exch";

// Issuer side: cut a list, revoke a credential. Every call returns a NEW,
// re-digested list — the input is never mutated, and double-revoking the
// same id is idempotent.
let list = await createRevocationList({ issuer: certifierUuaid });
list = await revokeCredential(list, signingCredentialId, "key compromise");

// Verifier side: gate every use of a Signing Credential.
await isRevoked(list, signingCredentialId);           // → true; THROWS
// RevocationListIntegrityError on a tampered list (fail-closed — a lookup
// against an unverified list could be silently un-revoked by an attacker)
await verifyRevocationListIntegrity(list);            // → true (false on ANY tamper)

try {
  await assertCredentialUsable(signingCredential, list); // checks validFrom,
  // validUntil (malformed dates fail closed), AND the revocation list —
  // throws typed errors: CredentialExpiredError | CredentialNotYetValidError |
  // CredentialMalformedValidityError | CredentialRevokedError |
  // RevocationListIntegrityError
} catch (e) {
  if (e instanceof CredentialRevokedError) console.error(e.entry.reason);
}
```

**Note:** this module has no revocation-check path to hook into (revocation is network-side per § 8), so `assertCredentialUsable()` is exported standalone — call it before acting on a credential, i.e. before `createExchange()` / `UaidNetworkClient.submit()`. Verifying the proofs *themselves* — no revocation check involved — is covered below.

## Verifying proofs locally

Every `DataIntegrityProof` this package produces (both proofs on a `UaidExchange`, or a standalone challenge proof per § 12 of the [MCP signer-identity design](../../docs/architecture/esig-mcp.md)) can be verified **offline, with no network call**, against a `did:key` or JWK public key.

```ts
import { createExchange, verifyExchange, verifyDataIntegrityProof } from "@e-sig/uaid-exch";

const exchange = await createExchange(input, agentSigner, issuerSigner);

// Verifies both proofs — proof[0] (agent, "authentication") and proof[1]
// (issuer, "assertionMethod") — resolving each key from its own
// verificationMethod (a did:key URI) unless you pass one explicitly.
const result = verifyExchange(exchange);
// { ok: true, agent: { ok: true, keyFingerprint, verificationMethod },
//   issuer: { ok: true, keyFingerprint, verificationMethod }, failures: [] }

if (!result.ok) console.error(result.failures); // e.g. ["agent: signature verification failed"]

// Or verify a single arbitrary DataIntegrityProof over any JCS-canonicalizable
// document (the primitive verifyExchange is built on):
verifyDataIntegrityProof(documentWithoutProofField, someProof, {
  expectedProofPurpose: "authentication", // optional
  publicKey: rawEd25519PublicKeyBytes,     // optional — skips verificationMethod resolution
});
```

Key resolution (`publicKeyFromVerificationMethod`) accepts a `did:key:z...` URI (multibase `z` = base58btc, multicodec `0xed 0x01` + 32 raw Ed25519 bytes) or a raw JWK (`{kty:"OKP", crv:"Ed25519", x}` — **exactly** those three fields; any other field, notably a private-key `d`, is rejected outright) — anything else throws `UnsupportedVerificationMethodError`. `decodeMultibase`/`encodeMultibase` (`z` = base58btc, `u` = base64url) are exported standalone too.

**R6 — `uuaid:...#sk-...` verification methods are NOT independently verifiable.** `AgentSigner.verificationMethod` is documented (and used throughout this package's own tests) as a `uuaid:foundation:agent:<uuid>#sk-<label>` fragment identifier, e.g. `uuaid:foundation:agent:018f7abc#sk-2026-07-04` — this is an IDENTIFIER, not a key-encoding scheme `publicKeyFromVerificationMethod` can decode (it only understands `did:key:` URIs and raw JWKs). `verifyExchange(exchange)` called with **no options** will therefore report `agent.ok: false` (a `reason` string sourced from the internal `UnsupportedVerificationMethodError` — `verifyDataIntegrityProof`/`verifyExchange` never throw, per their own doc comments; they catch it and return `{ok:false, reason}`) for any exchange whose agent proof uses this form — that is not a bug, it is this package correctly refusing to invent a resolution for an identifier scheme it cannot cryptographically dereference. To verify such an exchange you MUST already know the agent's public key out-of-band (e.g. from a prior UUAID registry resolution) and pass it explicitly: `verifyExchange(exchange, { agentPublicKey: rawEd25519Bytes })` (same for `issuerPublicKey`). Do not treat a bare `verifyExchange(exchange)` call as sufficient proof when either `verificationMethod` uses the `uuaid:...#sk-...` form.

**Signed-bytes note:** verification mirrors `createExchange()`'s actual construction — Ed25519 over `jcsBytes(document-with-proof-omitted)` directly — not the W3C `eddsa-jcs-2022` cryptosuite's `sha256(JCS(proofConfig)) || sha256(JCS(document))` double-hash. See the `src/verify.ts` module doc comment for the full divergence note.

**R5 — what a proof's digest does and does not cover.** A `DataIntegrityProof`'s `created`, `verificationMethod`, and `proofPurpose` fields sit OUTSIDE the signed bytes by construction (the divergence note above: `createExchange()` signs only the document, with the whole `proof` object — including these fields — omitted). Consequently, anywhere a consumer (e.g. `@e-sig/mcp`'s signer-identity feature) computes a digest over the *entire presented proof object* (`sha256(jcs(proof))`) as an integrity/audit reference, that digest covers those mutable-by-construction fields too, not just the cryptographically-bound core — two proofs with the identical `proofValue`/signed content but a different `created` timestamp produce two different digests. Treat such a digest as "the digest of the artifact as presented," not as "the digest of what was cryptographically signed."

## Strictly opt-in

Absent `UUAID_API_KEY`, the package is a pure library — no network calls. `UaidNetworkClient.submit()` throws early rather than dropping data into a silent no-op. Reads (`get`, `getReceipt`) are unauthenticated per the spec.

## Interoperability

- **AP2 (Google + 60 partners).** UAID Exchange embeds inside an AP2 A2A task under extension key `uuaid.exchange.v1`; conversely, the AP2 Payment Mandate id can be referenced from `external_refs.ap2_payment_mandate`.
- **W3C VC-Data-Model 2.0.** Every artifact this package produces is a conformant VC.
- **eIDAS QES.** At L5, `external_refs` also carries the QTSP-produced PKCS#7/CAdES-T reference.

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT. Part of the [esig-suite](https://github.com/vmvtech/esig-suite) family.
