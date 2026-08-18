// config.ts
//
// Gateway configuration + the tenant registry.
//
// Two hard rules, both from the dsalvus acceptance criteria (§2, §7.3 of the
// handoff): an unknown tenant or unknown cert alias must fail closed, and the
// gateway must NEVER fall back to a default signing identity. Both are enforced
// here by making the registry an explicit allowlist with no wildcard and no
// implicit "create on first sight" path.
//
// Everything is loaded once at startup and validated eagerly: a gateway that
// cannot prove it has a usable configuration refuses to start rather than
// discovering the problem on the first real dossier of the month.

import { promises as fs } from "node:fs";

import { GatewayError } from "./errors.js";

/**
 * Tenant and alias charset. Deliberately excludes `/` because the CertStore is
 * keyed by a single `tenantId` string and we address a (tenant, alias) pair as
 * `${tenant}/${alias}` — see {@link certKeyFor}. With `/` excluded from both
 * components that encoding is injective, so no pair of distinct (tenant, alias)
 * inputs can ever resolve to the same signing key.
 */
const SLUG_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export interface TenantBinding {
  /** dsalvus tenant slug, exactly as it appears in the request body. */
  tenant: string;
  /**
   * Cert aliases this tenant may request. No wildcard: an alias not listed
   * here is rejected, it is not created.
   */
  aliases: string[];
  /**
   * X.509 subject for certs issued under this tenant. ASCII-only — node-forge
   * mis-parses non-ASCII subjects on round-trip (see cert-issuer.ts).
   */
  subjectName: string;
  /**
   * Caller identities permitted to sign for this tenant. Matched against the
   * authenticated principal: a JWT `sub`, an mTLS SPIFFE URI-SAN or cert
   * SHA-256 fingerprint, or a named API key id in transitional mode.
   * Empty means "no caller may sign for this tenant" — not "any caller".
   */
  callers: string[];
  /** Signature dictionary /Reason. Defaults to the request `purpose`. */
  reason?: string;
  /** Signature dictionary /Location. Default "". */
  location?: string;
  /**
   * Embed the hybrid post-quantum seal (Ed25519 + ML-DSA-65) under the
   * classical PAdES signature. Default true — this is what makes the dsalvus
   * "Ed25519" design intent literally true. See docs/architecture.
   */
  pqSeal?: boolean;
  /**
   * UUAID this tenant's signer asserts in the seal (IAASO-0004 attribution).
   * A claim by the seal key, not proof of identity — see pq-seal.ts.
   */
  uuaid?: string;
}

export type AuthMode = "mtls+jwt" | "mtls" | "jwt" | "api-key";

export interface JwtAuthConfig {
  /** Exact `iss` required. */
  issuer: string;
  /** Exact `aud` required (string or member of the array form). */
  audience: string;
  /** JWKS document URL, or an inline JWKS for air-gapped/test use. */
  jwksUri?: string;
  jwks?: { keys: unknown[] };
  /** Max accepted token lifetime (exp - iat), seconds. Default 600. */
  maxLifetimeSec: number;
  /** Accepted clock skew, seconds. Default 60. */
  clockSkewSec: number;
  /** Required scope token in `scope`/`scp`. Default "esig:sign". */
  requiredScope: string;
}

export interface MtlsAuthConfig {
  /**
   * Where the verified peer identity comes from:
   *  - "socket": this process terminates TLS with requestCert+rejectUnauthorized.
   *  - "xfcc": an in-mesh proxy terminates and forwards Envoy's
   *    `x-forwarded-client-cert`. Only trust this behind a proxy that strips
   *    the header from inbound traffic.
   */
  source: "socket" | "xfcc";
  /** Accepted SPIFFE / URI-SAN values. */
  spiffeIds: string[];
  /** Accepted client-cert SHA-256 fingerprints (hex, lowercase, no colons). */
  fingerprints: string[];
}

export interface AuthConfig {
  mode: AuthMode;
  jwt?: JwtAuthConfig;
  mtls?: MtlsAuthConfig;
  /**
   * Transitional only. Map of `keyId -> secret`. Present ONLY when the operator
   * has explicitly opted in; every audit row signed under it is tagged
   * `transitional_auth: true` so the pilot is visible in the evidence trail.
   */
  apiKeys?: Map<string, string>;
}

export interface TsaConfig {
  /** TSA endpoints, tried in order. Empty = no timestamping. */
  urls: string[];
  /** When true a TSA failure fails the whole sign (no silent CAdES-B downgrade). */
  required: boolean;
  /** Per-attempt timeout, ms. Default 8000. */
  timeoutMs: number;
}

export interface GatewayConfig {
  host: string;
  port: number;
  /** Directory backing the fs CertStore / PqKeyStore / audit log. */
  stateDir: string;
  /** Key-at-rest passphrase (>=24 chars). Injected from Secrets Manager. */
  passphrase: string;
  tenants: Map<string, TenantBinding>;
  auth: AuthConfig;
  tsa: TsaConfig;
  /** Max request body, bytes. Default 12 MiB. */
  maxBodyBytes: number;
  /** Concurrent sign operations. Each holds a Chromium process. Default 2. */
  maxConcurrentSigns: number;
  /** Server-side deadline per sign, ms. Keep below the client's 30s. Default 25000. */
  signDeadlineMs: number;
  /**
   * Max accepted skew between the caller-supplied `timestamp` and our clock,
   * seconds. A freshness check only — the caller's value never becomes the
   * signing time. Default 900 (15 min). 0 disables the check.
   */
  maxClientSkewSec: number;
  /** Optional TLS material for in-process mTLS termination. */
  tls?: { keyPath: string; certPath: string; clientCaPath: string };
  /**
   * S3 Object Lock bucket for sign-time WORM archival. When set, every signed
   * PDF is archived atomically with COMPLIANCE retention before the response
   * is returned. Unset = archival stays off (destinations are dsalvus-side).
   * Owner decision 2026-08-17: ON for the assurance deployment.
   */
  wormBucket?: string;
}

/**
 * The CertStore / PqKeyStore partition key for a (tenant, alias) pair.
 * Injective because neither component may contain `/` (see {@link SLUG_RE}).
 */
export function certKeyFor(tenant: string, alias: string): string {
  return `${tenant}/${alias}`;
}

/** Validate a slug from the wire. Throws a client-safe error. */
export function assertSlug(value: unknown, what: "tenant" | "cert_alias"): string {
  if (typeof value !== "string" || !SLUG_RE.test(value)) {
    throw new GatewayError("bad_request", `${what} must match ${SLUG_RE}`);
  }
  return value;
}

// ---------- Registry loading ----------

function requireString(o: Record<string, unknown>, key: string, where: string): string {
  const v = o[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`tenant registry: ${where}: "${key}" must be a non-empty string`);
  }
  return v;
}

function requireStringArray(o: Record<string, unknown>, key: string, where: string): string[] {
  const v = o[key];
  if (!Array.isArray(v) || v.length === 0 || v.some((x) => typeof x !== "string" || !x)) {
    throw new Error(`tenant registry: ${where}: "${key}" must be a non-empty string array`);
  }
  return v as string[];
}

/**
 * Parse + validate the tenant registry. Rejects anything ambiguous rather than
 * normalising it: a registry that silently accepts `"aliases": []` would be a
 * tenant that can never sign, discovered at 03:00 UTC on the 1st.
 */
export function parseTenantRegistry(raw: unknown): Map<string, TenantBinding> {
  if (!Array.isArray(raw)) {
    throw new Error("tenant registry: expected a JSON array of tenant bindings");
  }
  const out = new Map<string, TenantBinding>();
  for (const [i, entry] of raw.entries()) {
    const where = `entry ${i}`;
    if (!entry || typeof entry !== "object") throw new Error(`tenant registry: ${where}: not an object`);
    const o = entry as Record<string, unknown>;

    const tenant = requireString(o, "tenant", where);
    if (!SLUG_RE.test(tenant)) throw new Error(`tenant registry: ${where}: tenant "${tenant}" must match ${SLUG_RE}`);
    if (out.has(tenant)) throw new Error(`tenant registry: duplicate tenant "${tenant}"`);

    const aliases = requireStringArray(o, "aliases", where);
    for (const a of aliases) {
      if (!SLUG_RE.test(a)) throw new Error(`tenant registry: ${where}: alias "${a}" must match ${SLUG_RE}`);
    }

    const subjectName = requireString(o, "subjectName", where);
    if (!/^[\x20-\x7e]+$/.test(subjectName)) {
      throw new Error(`tenant registry: ${where}: subjectName must be printable ASCII (node-forge round-trip)`);
    }

    const callers = requireStringArray(o, "callers", where);

    const uuaid = o.uuaid === undefined ? undefined : requireString(o, "uuaid", where);

    out.set(tenant, {
      tenant,
      aliases,
      subjectName,
      callers,
      reason: typeof o.reason === "string" ? o.reason : undefined,
      location: typeof o.location === "string" ? o.location : undefined,
      pqSeal: o.pqSeal === undefined ? true : o.pqSeal === true,
      uuaid,
    });
  }
  if (out.size === 0) throw new Error("tenant registry: empty — the gateway would be able to sign nothing");
  return out;
}

/**
 * Resolve a (tenant, alias, caller) triple against the registry.
 * Every rejection is the SAME client-visible answer (403 "caller not permitted
 * for this tenant") so the registry is not enumerable; the operator log
 * distinguishes them via the error detail.
 */
export function resolveBinding(
  cfg: GatewayConfig,
  tenant: string,
  alias: string,
  caller: string,
): TenantBinding {
  const binding = cfg.tenants.get(tenant);
  if (!binding) throw new GatewayError("unknown_tenant", `no registry entry for tenant "${tenant}"`);
  if (!binding.aliases.includes(alias)) {
    throw new GatewayError("unknown_alias", `alias "${alias}" not bound to tenant "${tenant}"`);
  }
  if (!binding.callers.includes(caller)) {
    throw new GatewayError("forbidden", `caller "${caller}" not bound to tenant "${tenant}"`);
  }
  return binding;
}

// ---------- Environment ----------

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) throw new Error(`${name}: expected a non-negative number, got "${v}"`);
  return n;
}

function envList(name: string): string[] {
  return (process.env[name] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function loadAuth(): AuthConfig {
  const mode = process.env.ESIG_GATEWAY_AUTH_MODE as AuthMode | undefined;
  if (!mode) {
    throw new Error(
      "ESIG_GATEWAY_AUTH_MODE is required (mtls+jwt | mtls | jwt | api-key). " +
        "The gateway holds signing keys and will not start unauthenticated.",
    );
  }
  if (!["mtls+jwt", "mtls", "jwt", "api-key"].includes(mode)) {
    throw new Error(`ESIG_GATEWAY_AUTH_MODE: unknown mode "${mode}"`);
  }

  const auth: AuthConfig = { mode };

  if (mode === "jwt" || mode === "mtls+jwt") {
    const issuer = process.env.ESIG_GATEWAY_JWT_ISSUER;
    const audience = process.env.ESIG_GATEWAY_JWT_AUDIENCE;
    const jwksUri = process.env.ESIG_GATEWAY_JWKS_URI;
    if (!issuer || !audience || !jwksUri) {
      throw new Error(
        "auth mode requires ESIG_GATEWAY_JWT_ISSUER, ESIG_GATEWAY_JWT_AUDIENCE and ESIG_GATEWAY_JWKS_URI",
      );
    }
    auth.jwt = {
      issuer,
      audience,
      jwksUri,
      maxLifetimeSec: envInt("ESIG_GATEWAY_JWT_MAX_LIFETIME_SEC", 600),
      clockSkewSec: envInt("ESIG_GATEWAY_JWT_SKEW_SEC", 60),
      requiredScope: process.env.ESIG_GATEWAY_JWT_SCOPE ?? "esig:sign",
    };
  }

  if (mode === "mtls" || mode === "mtls+jwt") {
    const source = (process.env.ESIG_GATEWAY_MTLS_SOURCE ?? "socket") as MtlsAuthConfig["source"];
    if (source !== "socket" && source !== "xfcc") {
      throw new Error(`ESIG_GATEWAY_MTLS_SOURCE: expected "socket" or "xfcc", got "${source}"`);
    }
    const spiffeIds = envList("ESIG_GATEWAY_MTLS_SPIFFE_IDS");
    const fingerprints = envList("ESIG_GATEWAY_MTLS_FINGERPRINTS").map((f) => f.toLowerCase().replace(/:/g, ""));
    if (spiffeIds.length === 0 && fingerprints.length === 0) {
      throw new Error(
        "mTLS auth requires ESIG_GATEWAY_MTLS_SPIFFE_IDS or ESIG_GATEWAY_MTLS_FINGERPRINTS — " +
          "a verified chain alone does not say WHICH workload is calling",
      );
    }
    auth.mtls = { source, spiffeIds, fingerprints };
  }

  if (mode === "api-key") {
    if (process.env.ESIG_GATEWAY_ALLOW_TRANSITIONAL_AUTH !== "1") {
      throw new Error(
        'auth mode "api-key" is transitional and must be opted into explicitly: ' +
          "set ESIG_GATEWAY_ALLOW_TRANSITIONAL_AUTH=1",
      );
    }
    // Format: "keyId:secret,keyId2:secret2" — injected from Secrets Manager.
    const keys = new Map<string, string>();
    for (const pair of envList("ESIG_GATEWAY_API_KEYS")) {
      const idx = pair.indexOf(":");
      if (idx <= 0 || idx === pair.length - 1) throw new Error("ESIG_GATEWAY_API_KEYS: expected keyId:secret pairs");
      const id = pair.slice(0, idx);
      const secret = pair.slice(idx + 1);
      if (secret.length < 32) throw new Error(`ESIG_GATEWAY_API_KEYS: secret for "${id}" must be >= 32 chars`);
      keys.set(id, secret);
    }
    if (keys.size === 0) throw new Error("ESIG_GATEWAY_API_KEYS is required in api-key mode");
    auth.apiKeys = keys;
  }

  return auth;
}

/** Build the full config from the environment + the tenant registry file. */
export async function loadConfigFromEnv(): Promise<GatewayConfig> {
  const registryPath = process.env.ESIG_GATEWAY_TENANTS;
  if (!registryPath) throw new Error("ESIG_GATEWAY_TENANTS (path to the tenant registry JSON) is required");
  const tenants = parseTenantRegistry(JSON.parse(await fs.readFile(registryPath, "utf8")));

  const passphrase = process.env.ESIG_GATEWAY_KEY_PASSPHRASE;
  if (!passphrase || passphrase.length < 24) {
    throw new Error("ESIG_GATEWAY_KEY_PASSPHRASE is required and must be >= 24 chars (inject from Secrets Manager)");
  }

  const stateDir = process.env.ESIG_GATEWAY_STATE_DIR;
  if (!stateDir) throw new Error("ESIG_GATEWAY_STATE_DIR is required");

  const tlsKey = process.env.ESIG_GATEWAY_TLS_KEY;
  const tlsCert = process.env.ESIG_GATEWAY_TLS_CERT;
  const tlsClientCa = process.env.ESIG_GATEWAY_TLS_CLIENT_CA;
  const tls =
    tlsKey && tlsCert && tlsClientCa
      ? { keyPath: tlsKey, certPath: tlsCert, clientCaPath: tlsClientCa }
      : undefined;

  const auth = loadAuth();
  if (auth.mtls?.source === "socket" && !tls) {
    throw new Error(
      'ESIG_GATEWAY_MTLS_SOURCE="socket" requires ESIG_GATEWAY_TLS_KEY, _TLS_CERT and _TLS_CLIENT_CA ' +
        "(this process must terminate TLS to see a peer certificate)",
    );
  }

  return {
    host: process.env.ESIG_GATEWAY_HOST ?? "0.0.0.0",
    port: envInt("ESIG_GATEWAY_PORT", 8443),
    stateDir,
    passphrase,
    tenants,
    auth,
    tsa: {
      urls: envList("ESIG_GATEWAY_TSA_URLS"),
      required: process.env.ESIG_GATEWAY_TSA_REQUIRED === "1",
      timeoutMs: envInt("ESIG_GATEWAY_TSA_TIMEOUT_MS", 8000),
    },
    maxBodyBytes: envInt("ESIG_GATEWAY_MAX_BODY_BYTES", 12 * 1024 * 1024),
    maxConcurrentSigns: Math.max(1, envInt("ESIG_GATEWAY_MAX_CONCURRENT_SIGNS", 2)),
    signDeadlineMs: envInt("ESIG_GATEWAY_SIGN_DEADLINE_MS", 25_000),
    maxClientSkewSec: envInt("ESIG_GATEWAY_MAX_CLIENT_SKEW_SEC", 900),
    wormBucket: process.env.ESIG_GATEWAY_WORM_BUCKET || undefined,
    tls,
  };
}
