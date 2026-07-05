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
