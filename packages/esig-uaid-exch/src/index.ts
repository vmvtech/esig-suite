/**
 * @e-sig/uaid-exch — reference implementation of UAP-EXCH-1 v0.1
 * (UUAID Exchange Profile).
 *
 * MIT-licensed. Ships alongside @e-sig/core and @e-sig/uuaid; consumes
 * @uuaid/sdk for identifier resolution and Network submission.
 *
 * See docs/profiles/UAP-EXCH-1/v0.1.md in the uuaid repo for the normative
 * profile. This module implements the § 5 (Signing Credential), § 6 (Exchange),
 * and § 7 (Receipt) shapes plus the § 8 submission API. § 9 (Revocation,
 * draft) lives in ./revocation.ts and is re-exported below.
 */

// ============================================================================
// Revocation (§ 9, draft) — status-list style credential revocation
// ============================================================================
//
// There is no verify entry point in this module to wire into, so the
// usability gate is exported standalone: call assertCredentialUsable()
// before acting on a Signing Credential (e.g. before createExchange /
// UaidNetworkClient.submit).

export * from "./revocation.js";

export type AssuranceLevel = "L0" | "L1" | "L2" | "L3" | "L4" | "L5";

export interface UaidSigningCredential {
  "@context": string[];
  type: ["VerifiableCredential", "UaidSigningCredential"];
  id: string;                         // uuaid:foundation:signing-credential:<uuid>
  issuer: string;                     // uuaid:foundation:certifier:<uuid>
  validFrom: string;                  // ISO 8601
  validUntil: string;                 // ISO 8601, MUST be <= 24h from validFrom
  credentialSubject: {
    id: string;                       // agent uuaid
    principal: string;                // did:web / did:key / did:pkh
    scope: {
      actions: string[];
      resource_pattern?: string;
      counterparty_allowlist?: string[];
      value_ceiling?: { currency: string; amount: number };
      geographies?: string[];
      assurance_min?: AssuranceLevel;
    };
    authenticator: {
      type: "platform" | "hardware" | "hsm" | "qscd";
      attestation?: string;           // e.g. fido-mds3:aaguid:...
      public_key_jwk: JsonWebKey;
    };
    assurance_level: AssuranceLevel;
    assurance_evidence?: Array<{
      provider: string;               // uuaid:foundation:certifier:<uuid>
      evidence_uri: string;
      hash: string;                   // sha256:...
    }>;
    kya_hash: string;                 // sha256:...
  };
  proof: DataIntegrityProof;
}

export interface UaidExchange {
  "@context": string[];
  type: ["VerifiableCredential", "UaidExchange"];
  id: string;                         // uuaid:foundation:exchange:<uuid>
  issuer: string;                     // agent uuaid
  validFrom: string;
  credentialSubject: {
    authorization: {
      signing_credential: string;
      principal: string;
    };
    exchange: {
      action: string;
      counterparty: string;
      resource: {
        type: string;
        sha256: string;               // sha256:... (with prefix)
        size: number;
        uri?: string;
      };
      purpose: string;
      value_impact?: Record<string, unknown>;
      external_refs?: {
        ap2_payment_mandate?: string;
        esign_envelope?: string;
      };
    };
    sole_control: {
      challenge_type: string;
      challenge_at: string;
      challenge_evidence_hash: string;
    };
    policy_evaluation?: {
      provider: string;
      verdict: "PASS" | "FAIL" | "WARN" | "EXCEPTION_APPROVED";
      bundle: string;
      evidence_uri?: string;
      evidence_hash?: string;
    };
  };
  proof: DataIntegrityProof[];        // agent + issuer proofs
}

export interface UaidExchangeReceipt {
  "@context": string[];
  type: ["VerifiableCredential", "UaidExchangeReceipt"];
  id: string;                         // uuaid:foundation:exchange-receipt:<uuid>
  issuer: string;                     // uuaid:foundation:registry-node:<slug>
  validFrom: string;
  credentialSubject: {
    exchange: string;
    verified_proofs: string[];
    policy_evaluation_verified: boolean;
    anchor: {
      chain: string;
      contract: string;
      batch_root: string;
      batch_index: number;
      batch_position: number;
      block_number: number;
      anchored_at: string;
    };
    tx_short_id: string;
  };
  proof: DataIntegrityProof;
}

export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "eddsa-jcs-2022";
  created: string;
  verificationMethod: string;
  proofPurpose: "authentication" | "assertionMethod";
  proofValue: string;                 // z... (multibase)
}

// ============================================================================
// Options + adapter interfaces
// ============================================================================

export interface AgentSigner {
  agentUuaid: string;
  verificationMethod: string;         // e.g. uuaid:foundation:agent:<uuid>#sk-2026-07-04
  sign(canonicalBytes: Uint8Array): Promise<string>; // returns multibase proofValue
}

export interface IssuerSigner {
  issuerDid: string;
  verificationMethod: string;
  sign(canonicalBytes: Uint8Array): Promise<string>;
}

export interface CreateExchangeInput {
  signingCredentialId: string;
  principal: string;
  action: string;
  counterparty: string;
  resource: {
    type: string;
    sha256: string;
    size: number;
    uri?: string;
  };
  purpose: string;
  value_impact?: Record<string, unknown>;
  external_refs?: UaidExchange["credentialSubject"]["exchange"]["external_refs"];
  soleControl: {
    challenge_type: string;
    challenge_at: string;
    challenge_evidence_hash: string;
  };
  policyEvaluation?: UaidExchange["credentialSubject"]["policy_evaluation"];
  now?: () => Date;                   // injectable clock for tests
  idFactory?: () => string;           // injectable urn:uuid factory
}

export interface UaidNetworkClientOptions {
  baseUrl?: string;                   // default https://api.uuaid.org
  apiKey?: string;                    // Bearer partner key; may be absent for reads
  fetchImpl?: typeof fetch;           // injectable for testing
}

// ============================================================================
// Exchange creation
// ============================================================================

const CONTEXT = [
  "https://www.w3.org/ns/credentials/v2",
  "https://uuaid.org/spec/UAP-EXCH-1/v1",
];

/**
 * Build the unsigned Exchange body, canonicalize it (JCS per RFC 8785),
 * sign it once with the Agent key and once with the Issuer key, and return
 * the assembled UaidExchange ready to submit.
 */
export async function createExchange(
  input: CreateExchangeInput,
  agent: AgentSigner,
  issuer: IssuerSigner
): Promise<UaidExchange> {
  const now = (input.now ?? (() => new Date()))();
  const id = `uuaid:foundation:exchange:${(input.idFactory ?? uuidv7)()}`;

  const body: Omit<UaidExchange, "proof"> = {
    "@context": CONTEXT,
    type: ["VerifiableCredential", "UaidExchange"],
    id,
    issuer: agent.agentUuaid,
    validFrom: now.toISOString(),
    credentialSubject: {
      authorization: {
        signing_credential: input.signingCredentialId,
        principal: input.principal,
      },
      exchange: {
        action: input.action,
        counterparty: input.counterparty,
        resource: input.resource,
        purpose: input.purpose,
        value_impact: input.value_impact ?? {},
        external_refs: input.external_refs ?? {},
      },
      sole_control: input.soleControl,
      policy_evaluation: input.policyEvaluation,
    },
  };

  const canonicalBytes = jcsBytes(body);

  const [agentProofValue, issuerProofValue] = await Promise.all([
    agent.sign(canonicalBytes),
    issuer.sign(canonicalBytes),
  ]);

  const agentProof: DataIntegrityProof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: now.toISOString(),
    verificationMethod: agent.verificationMethod,
    proofPurpose: "authentication",
    proofValue: agentProofValue,
  };
  const issuerProof: DataIntegrityProof = {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    created: now.toISOString(),
    verificationMethod: issuer.verificationMethod,
    proofPurpose: "assertionMethod",
    proofValue: issuerProofValue,
  };

  return { ...body, proof: [agentProof, issuerProof] };
}

/**
 * Wrap an existing esig-suite envelope as a UAID Exchange. Convenience helper
 * for the common case where you're signing a PDF via @e-sig/core.signDocument().
 */
export function exchangeInputFromEsigEnvelope(args: {
  envelopeId: string;
  signingCredentialId: string;
  principal: string;
  counterparty: string;
  pdfSha256: string;
  pdfSize: number;
  pdfUri?: string;
  purpose: string;
  value_impact?: Record<string, unknown>;
  soleControl: CreateExchangeInput["soleControl"];
  policyEvaluation?: CreateExchangeInput["policyEvaluation"];
}): CreateExchangeInput {
  return {
    signingCredentialId: args.signingCredentialId,
    principal: args.principal,
    action: "sign.contract",
    counterparty: args.counterparty,
    resource: {
      type: "application/pdf",
      sha256: args.pdfSha256,
      size: args.pdfSize,
      uri: args.pdfUri,
    },
    purpose: args.purpose,
    value_impact: args.value_impact,
    external_refs: { esign_envelope: `esig:envelope:${args.envelopeId}` },
    soleControl: args.soleControl,
    policyEvaluation: args.policyEvaluation,
  };
}

// ============================================================================
// Network client
// ============================================================================

export class UaidNetworkClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: UaidNetworkClientOptions = {}) {
    this.baseUrl = (opts.baseUrl ?? "https://api.uuaid.org").replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /** POST /v1/exchanges — submit a signed Exchange for verification + anchoring. */
  async submit(exchange: UaidExchange): Promise<{
    exchange_id: string;
    status: "verified" | "queued";
    receipt_pending_anchor: boolean;
    estimated_anchor_at?: string;
  }> {
    if (!this.apiKey) {
      throw new Error(
        "UaidNetworkClient.submit requires a partner apiKey (UUAID_API_KEY)."
      );
    }
    const res = await this.fetchImpl(`${this.baseUrl}/v1/exchanges`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(exchange),
    });
    if (res.status !== 201) {
      throw new Error(`submit failed: HTTP ${res.status}: ${await res.text()}`);
    }
    return res.json() as Promise<{
      exchange_id: string;
      status: "verified" | "queued";
      receipt_pending_anchor: boolean;
      estimated_anchor_at?: string;
    }>;
  }

  /** GET /v1/exchanges/:id — unauthenticated. Returns { exchange, receipt? }. */
  async get(exchangeId: string): Promise<{
    exchange: UaidExchange;
    receipt?: UaidExchangeReceipt;
  }> {
    const res = await this.fetchImpl(
      `${this.baseUrl}/v1/exchanges/${encodeURIComponent(exchangeId)}`
    );
    if (!res.ok) {
      throw new Error(`get failed: HTTP ${res.status}`);
    }
    return res.json() as Promise<{
      exchange: UaidExchange;
      receipt?: UaidExchangeReceipt;
    }>;
  }

  /** GET /v1/exchanges/:id/receipt — unauthenticated. */
  async getReceipt(exchangeId: string): Promise<UaidExchangeReceipt> {
    const res = await this.fetchImpl(
      `${this.baseUrl}/v1/exchanges/${encodeURIComponent(exchangeId)}/receipt`
    );
    if (!res.ok) {
      throw new Error(`getReceipt failed: HTTP ${res.status}`);
    }
    return res.json() as Promise<UaidExchangeReceipt>;
  }

  /** Convenience: the public browser URL for a receipt's tx_short_id. */
  txBrowserUrl(txShortId: string): string {
    return `https://tx.uuaid.org/${encodeURIComponent(txShortId)}`;
  }

  /** Convenience: the resolver URL for a full exchange id. */
  resolverUrl(exchangeId: string): string {
    return `https://registry.uuaid.org/exchange/${encodeURIComponent(exchangeId)}`;
  }
}

// ============================================================================
// JCS canonicalization (RFC 8785) — minimal, dependency-free
// ============================================================================

/**
 * RFC 8785 JSON Canonicalization Scheme.
 *
 * Rules implemented:
 * - Object keys sorted lexicographically by UTF-16 code units.
 * - No insignificant whitespace.
 * - Strings encoded with the minimal escape set.
 * - Numbers serialized per ECMA-262 7.1.12.1 (JS default `String(number)` is
 *   compliant for the finite-number subset we accept here).
 *
 * We reject NaN, ±Infinity, and non-integer numeric keys per RFC 8785 § 3.2.
 */
export function jcs(value: unknown): string {
  return jcsSerialize(value);
}

/** Convenience: canonicalize + UTF-8 encode. */
export function jcsBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(jcs(value));
}

function jcsSerialize(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) {
      throw new Error("JCS: non-finite numbers are not permitted");
    }
    return jcsNumber(v);
  }
  if (typeof v === "string") return jcsString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(jcsSerialize).join(",") + "]";
  }
  if (typeof v === "object") {
    const keys = Object.keys(v as Record<string, unknown>)
      .filter((k) => (v as Record<string, unknown>)[k] !== undefined)
      .sort(); // lexicographic on UTF-16 code units is the default
    return (
      "{" +
      keys
        .map(
          (k) =>
            jcsString(k) +
            ":" +
            jcsSerialize((v as Record<string, unknown>)[k])
        )
        .join(",") +
      "}"
    );
  }
  throw new Error(`JCS: unsupported value type: ${typeof v}`);
}

function jcsString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

function jcsNumber(n: number): string {
  if (n === 0) return "0";
  // JavaScript's default number stringification matches ECMA-262 7.1.12.1,
  // which JCS references. This is correct for finite numbers.
  return String(n);
}

// ============================================================================
// UUIDv7 — small, dependency-free
// ============================================================================

/**
 * Generate a UUIDv7 (unix-time-ordered). Matches the format UUAID uses under
 * the hood; safe as an identifier suffix.
 */
export function uuidv7(): string {
  const ms = BigInt(Date.now());
  const rand = new Uint8Array(10);
  cryptoRandomFill(rand);
  const bytes = new Uint8Array(16);
  bytes[0] = Number((ms >> 40n) & 0xffn);
  bytes[1] = Number((ms >> 32n) & 0xffn);
  bytes[2] = Number((ms >> 24n) & 0xffn);
  bytes[3] = Number((ms >> 16n) & 0xffn);
  bytes[4] = Number((ms >> 8n) & 0xffn);
  bytes[5] = Number(ms & 0xffn);
  bytes[6] = 0x70 | (rand[0] & 0x0f); // version 7
  bytes[7] = rand[1];
  bytes[8] = 0x80 | (rand[2] & 0x3f); // variant 10
  bytes.set(rand.slice(3), 9);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(
    12,
    16
  )}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function cryptoRandomFill(out: Uint8Array): void {
  const g = (globalThis as unknown as { crypto?: Crypto }).crypto;
  if (g?.getRandomValues) {
    g.getRandomValues(out);
    return;
  }
  // Fallback — Node 20 always exposes globalThis.crypto, so this branch
  // should never run in production. Kept for defensive symmetry.
  for (let i = 0; i < out.length; i++) out[i] = Math.floor(Math.random() * 256);
}
