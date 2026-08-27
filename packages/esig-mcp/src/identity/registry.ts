// identity/registry.ts
//
// UUAID registry client for identity level L2 (docs/architecture/esig-mcp.md
// §12). Two public, unauthenticated surfaces:
//   • `GET /iaaso/v1/badge/{uuaid}` — the registry's SIGNED identity snapshot
//     (IAASO-0003). The ONLY registry surface that carries an agent's
//     presentation key (`payload.subject.presentationKey`, hex Ed25519, or
//     null): `GET /resolve/{uuaid}` carries NO signer key material for ANY
//     agent — its only key-ish field is `credentials[].signingKeyId`, AIAU's
//     credential-ISSUER key (Uuaid-Lead, evidence
//     /Volumes/X/uuaid/docs/evidence/2026-08-27-resolve-shape-for-esig-mcp-l2.md).
//     The badge is also registry-signed, so L2 can verify it against a pinned
//     key (identity/badge.ts) instead of trusting TLS alone.
//   • `GET /verify/{credentialId}` — a Signing Credential's live status.
// Plain `fetch`, no SDK dependency — `@uuaid/sdk` is deliberately not pulled
// into this package (2026-08-26 decision log, docs/architecture/esig-mcp.md).
// `ESIG_MCP_UUAID_REGISTRY_URL` is validated https-only at config time
// (config.ts, T13); a 5-second timeout and any non-2xx/network failure is a
// hard failure the CALLER (identity/verify.ts) treats as "registry down ⇒
// FAIL, never downgrade" — this client never guesses or silently returns a
// partial/best-effort result.

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

/** A 404 from the registry — for the badge this is AUTHORITATIVE (subject absent, or tombstoned where `/resolve` would still return 200). Distinct so the caller can fail with an honest code instead of "registry unavailable". */
export class RegistryNotFoundError extends RegistryError {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "RegistryNotFoundError";
  }
}

export interface VerifyCredentialResult {
  valid: boolean;
  active: boolean;
  notExpired: boolean;
  reason?: string;
  /**
   * The credential's subject uuaid, verbatim from the registry's
   * `agent_uuaid` field. The CALLER must assert this equals the proving
   * uuaid: AIAU's exam flow does not check that the caller owns the handle,
   * so a credential can exist for a uuaid that never presented anything
   * (same evidence file, §5) — without this assert, presenting someone
   * else's valid credential would pass the L2 credential check.
   */
  agentUuaid?: string;
}

const REGISTRY_TIMEOUT_MS = 5000;

export class RegistryClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs: number = REGISTRY_TIMEOUT_MS,
  ) {}

  /**
   * `GET <base>/iaaso/v1/badge/<uuaid>` — the registry-signed badge envelope
   * (SignatureEnvelope). Returns the raw parsed JSON untyped; callers MUST
   * verify it (identity/badge.ts `verifyRegistryBadge`, against the PINNED
   * registry key) before trusting anything in it. A 404 (absent or
   * tombstoned subject — the badge endpoint is authoritative for tombstones,
   * where `/resolve` still returns 200) throws
   * {@link RegistryNotFoundError}; any other non-2xx/network failure throws
   * {@link RegistryError}.
   */
  async badge(uuaid: string): Promise<unknown> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/iaaso/v1/badge/${encodeURIComponent(uuaid)}`, {
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new RegistryError(`GET /iaaso/v1/badge/${uuaid} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (res.status === 404) {
      throw new RegistryNotFoundError(`GET /iaaso/v1/badge/${uuaid} -> 404 (subject absent or tombstoned)`, 404);
    }
    if (!res.ok) throw new RegistryError(`GET /iaaso/v1/badge/${uuaid} failed: HTTP ${res.status}`);
    return res.json();
  }

  /**
   * `GET <base>/verify/<credentialId>` -> `{valid, active, notExpired,
   * agentUuaid?, reason?}` (design doc §12). Defensive: any field not
   * exactly `true` is treated as `false` rather than trusting a
   * truthy-but-wrong-typed value.
   */
  async verifyCredential(credentialId: string): Promise<VerifyCredentialResult> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/verify/${encodeURIComponent(credentialId)}`, {
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new RegistryError(`GET /verify/${credentialId} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!res.ok) throw new RegistryError(`GET /verify/${credentialId} failed: HTTP ${res.status}`);
    const body: unknown = await res.json();
    const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    return {
      valid: b.valid === true,
      active: b.active === true,
      notExpired: b.notExpired === true,
      reason: typeof b.reason === "string" ? b.reason : undefined,
      agentUuaid: typeof b.agent_uuaid === "string" ? b.agent_uuaid : undefined,
    };
  }
}

/** Exported for reuse by identity/verify.ts's G1(b) credential-key match check — same fixed-shape comparison, one implementation. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
