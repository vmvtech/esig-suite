// identity/registry.ts
//
// UUAID registry client for identity level L2
// (docs/architecture/esig-mcp.md §12): `GET /resolve/{uuaid}` (public — lists
// the key(s) bound to a uuaid) and `GET /verify/{credentialId}` (a Signing
// Credential's live status). Plain `fetch`, no SDK dependency — `@uuaid/sdk`
// is deliberately not pulled into this package (2026-08-26 decision log,
// docs/architecture/esig-mcp.md). `ESIG_MCP_UUAID_REGISTRY_URL` is validated
// https-only at config time (config.ts, T13); a 5-second timeout and any
// non-2xx/network failure is a hard failure the CALLER (identity/verify.ts)
// treats as "registry down ⇒ FAIL, never downgrade" — this client never
// guesses or silently returns a partial/best-effort result.

import type { JsonWebKey } from "node:crypto";

import { publicKeyFromVerificationMethod } from "@e-sig/uaid-exch";

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

export interface VerifyCredentialResult {
  valid: boolean;
  active: boolean;
  notExpired: boolean;
  reason?: string;
}

const REGISTRY_TIMEOUT_MS = 5000;

export class RegistryClient {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly timeoutMs: number = REGISTRY_TIMEOUT_MS,
  ) {}

  /**
   * `GET <base>/resolve/<uuaid>`. Response shape is UNVERIFIED (design doc
   * §12 "Bindings": "response shape unverified") — returns the raw parsed
   * JSON body untyped; callers must type it defensively (see
   * {@link resolveListsKey} below, the one place this package reads it).
   */
  async resolve(uuaid: string): Promise<unknown> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/resolve/${encodeURIComponent(uuaid)}`, {
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      throw new RegistryError(`GET /resolve/${uuaid} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!res.ok) throw new RegistryError(`GET /resolve/${uuaid} failed: HTTP ${res.status}`);
    return res.json();
  }

  /**
   * `GET <base>/verify/<credentialId>` -> `{valid, active, notExpired, reason?}`
   * (design doc §12). Defensive: any field not exactly `true` is treated as
   * `false` rather than trusting a truthy-but-wrong-typed value.
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
    };
  }
}

/**
 * True if the (unverified-shape) `/resolve/{uuaid}` response lists a key
 * whose raw bytes equal `keyBytes`. Defensive by construction (design doc
 * §12: "type the response defensively"): tries every plausible key-carrying
 * shape (`keys[]`, a DID-document-style `verificationMethod[]`, or the body
 * itself as a single key entry) and every plausible key encoding
 * (`publicKeyMultibase`, `publicKeyJwk`, or a bare `verificationMethod`/`id`
 * did:key string) — and never throws. An unrecognized shape simply does not
 * match, which the caller treats as a FAILURE (fail-closed), never a crash.
 */
export function resolveListsKey(resolved: unknown, keyBytes: Uint8Array): boolean {
  const candidates: unknown[] = [];
  if (resolved && typeof resolved === "object") {
    const r = resolved as Record<string, unknown>;
    if (Array.isArray(r.keys)) candidates.push(...r.keys);
    if (Array.isArray(r.verificationMethod)) candidates.push(...r.verificationMethod);
    candidates.push(r);
  }
  for (const candidate of candidates) {
    const raw = tryKeyFromCandidate(candidate);
    if (raw && bytesEqual(raw, keyBytes)) return true;
  }
  return false;
}

function tryKeyFromCandidate(candidate: unknown): Uint8Array | undefined {
  if (!candidate || typeof candidate !== "object") return undefined;
  const c = candidate as Record<string, unknown>;
  // `publicKeyMultibase` (W3C DID-document convention) is the BARE multibase
  // value with no `did:key:` scheme — reuse publicKeyFromVerificationMethod's
  // did:key decoder by re-attaching the scheme it expects.
  if (typeof c.publicKeyMultibase === "string") {
    const raw = tryDidKey(`did:key:${c.publicKeyMultibase}`);
    if (raw) return raw;
  }
  if (c.publicKeyJwk && typeof c.publicKeyJwk === "object") {
    try {
      return publicKeyFromVerificationMethod(c.publicKeyJwk as JsonWebKey);
    } catch {
      /* not a recognizable JWK — try the next field */
    }
  }
  // `verificationMethod`/`id` are, by DID-document convention, already full
  // URIs (e.g. `did:key:z6Mk...#...`) — passed through as-is, unlike
  // `publicKeyMultibase` above.
  if (typeof c.verificationMethod === "string") {
    const raw = tryDidKey(c.verificationMethod);
    if (raw) return raw;
  }
  if (typeof c.id === "string") {
    const raw = tryDidKey(c.id);
    if (raw) return raw;
  }
  return undefined;
}

function tryDidKey(vm: string): Uint8Array | undefined {
  try {
    return publicKeyFromVerificationMethod(vm);
  } catch {
    return undefined;
  }
}

/** Exported for reuse by identity/verify.ts's G1(b) credential-key match check — same fixed-shape comparison, one implementation. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
