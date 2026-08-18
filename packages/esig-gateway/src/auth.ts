// auth.ts
//
// Caller authentication. The gateway holds signing keys, so this is the control
// that decides whether a request may produce a signature at all.
//
// Production shape (what dsalvus' design note asks for, and what vmv-one/HP-001
// should wire): short-lived mTLS + JWT from the calling pod's workload identity.
// Both halves are verified here and both are needed, because they answer
// different questions:
//
//   mTLS  — "is this connection from a workload the mesh vouches for?"
//   JWT   — "did the PDP authorise THIS workload to sign for THIS tenant, now?"
//
// A mesh-issued client certificate alone proves membership, not authorisation,
// and it is long-lived relative to a monthly batch job. A bearer JWT alone is
// replayable by anything that can reach the port. Hence `mtls+jwt` is the
// recommended mode; `mtls` and `jwt` exist for deployments where one half is
// enforced by infrastructure the gateway cannot see.
//
// ---- The JWT contract HP-001 must satisfy -------------------------------
//   alg     RS256 | PS256 | ES256   (no HS*, no "none" — asymmetric only)
//   iss     exactly ESIG_GATEWAY_JWT_ISSUER
//   aud     exactly ESIG_GATEWAY_JWT_AUDIENCE (string, or a member of the array)
//   sub     the workload identity, e.g.
//           spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance
//           — this is the value that must appear in a tenant's `callers` list
//   exp     required; exp - iat must be <= ESIG_GATEWAY_JWT_MAX_LIFETIME_SEC
//   iat     required
//   nbf     optional; honoured when present
//   jti     required and unique — replayed jti inside the token lifetime is
//           rejected (single-use credentials for a once-a-month batch signer)
//   scope   space-delimited, must contain ESIG_GATEWAY_JWT_SCOPE (esig:sign).
//           `scp` accepted as an alias (string or array).
//   tenant  optional. When present it MUST equal the request body `tenant` —
//           this is how the PDP can mint a credential scoped to one tenant
//           rather than to every tenant the workload is listed against.
// -------------------------------------------------------------------------

import crypto from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { TLSSocket } from "node:tls";

import type { AuthConfig, JwtAuthConfig, MtlsAuthConfig } from "./config.js";
import { GatewayError } from "./errors.js";

/** The authenticated caller, as matched against a tenant's `callers` list. */
export interface Principal {
  /** Identity string: JWT `sub`, SPIFFE URI-SAN, cert fingerprint, or `apikey:<id>`. */
  id: string;
  /** How the identity was established, for the audit row. */
  via: "jwt" | "mtls" | "mtls+jwt" | "api-key";
  /** Tenant the credential is scoped to, when it carries one. */
  tenantClaim?: string;
  /** True when authenticated by the transitional API-key path. */
  transitional: boolean;
  /** mTLS peer identity, when one was verified (recorded alongside `id`). */
  peer?: string;
}

const SUPPORTED_ALGS = new Set(["RS256", "PS256", "ES256"]);

// ---------- base64url ----------

function b64u(part: string): Buffer {
  return Buffer.from(part, "base64url");
}

// ---------- JWKS ----------

interface Jwk {
  kid?: string;
  kty?: string;
  alg?: string;
  use?: string;
  [k: string]: unknown;
}

/**
 * JWKS cache with a cooldown. A request for an unknown `kid` triggers at most
 * one refetch per `minRefetchMs` — otherwise an attacker can drive unbounded
 * egress to the PDP by sending tokens with random kids.
 */
export class JwksCache {
  private keys: Jwk[] = [];
  private fetchedAt = 0;
  private inflight: Promise<void> | null = null;

  constructor(
    private readonly uri: string | undefined,
    private readonly inline: { keys: unknown[] } | undefined,
    private readonly ttlMs = 300_000,
    private readonly minRefetchMs = 30_000,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    if (inline) {
      this.keys = inline.keys as Jwk[];
      this.fetchedAt = Number.POSITIVE_INFINITY; // never expires
    }
  }

  private async refresh(): Promise<void> {
    if (!this.uri) return;
    if (this.inflight) return this.inflight;
    this.inflight = (async () => {
      const ac = new AbortController();
      const t = setTimeout(() => ac.abort(), 5000);
      try {
        const res = await this.fetchImpl(this.uri!, { signal: ac.signal });
        if (!res.ok) throw new Error(`JWKS ${res.status}`);
        const doc = (await res.json()) as { keys?: unknown };
        if (!Array.isArray(doc.keys)) throw new Error("JWKS: missing keys array");
        this.keys = doc.keys as Jwk[];
        this.fetchedAt = Date.now();
      } finally {
        clearTimeout(t);
        this.inflight = null;
      }
    })();
    return this.inflight;
  }

  /** Resolve a kid, refetching at most once per cooldown when it is unknown. */
  async get(kid: string | undefined): Promise<Jwk> {
    const now = Date.now();
    const stale = now - this.fetchedAt > this.ttlMs;
    if (this.keys.length === 0 || stale) await this.refresh();

    let key = this.select(kid);
    if (!key && this.uri && now - this.fetchedAt > this.minRefetchMs) {
      await this.refresh();
      key = this.select(kid);
    }
    if (!key) throw new GatewayError("unauthenticated", `no JWKS key for kid=${kid ?? "<none>"}`);
    return key;
  }

  private select(kid: string | undefined): Jwk | undefined {
    const usable = this.keys.filter((k) => k.use === undefined || k.use === "sig");
    if (kid) return usable.find((k) => k.kid === kid);
    // A JWKS with exactly one signing key needs no kid; more than one does.
    return usable.length === 1 ? usable[0] : undefined;
  }

  /** True once at least one key is loaded — used by /ready. */
  get loaded(): boolean {
    return this.keys.length > 0;
  }

  async warm(): Promise<void> {
    if (!this.loaded) await this.refresh();
  }
}

// ---------- Replay cache ----------

/** Bounded single-use `jti` cache. Entries expire with the token they came from. */
export class ReplayCache {
  private seen = new Map<string, number>();

  constructor(private readonly maxEntries = 10_000) {}

  /** Record a jti. Throws if it was already used and has not yet expired. */
  use(jti: string, expiresAtMs: number, now = Date.now()): void {
    this.sweep(now);
    const existing = this.seen.get(jti);
    if (existing !== undefined && existing > now) {
      throw new GatewayError("unauthenticated", `jti replay: ${jti}`);
    }
    if (this.seen.size >= this.maxEntries) {
      // Full cache must not silently become permissive: drop the single oldest
      // entry after sweeping, which can only expose an already-near-expiry jti.
      const oldest = [...this.seen.entries()].sort((a, b) => a[1] - b[1])[0];
      if (oldest) this.seen.delete(oldest[0]);
    }
    this.seen.set(jti, expiresAtMs);
  }

  private sweep(now: number): void {
    for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
  }
}

// ---------- JWT verification ----------

interface JwtClaims {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  scope?: string;
  scp?: string | string[];
  tenant?: string;
}

function verifySignature(alg: string, key: crypto.KeyObject, signingInput: string, sig: Buffer): boolean {
  const data = Buffer.from(signingInput, "ascii");
  switch (alg) {
    case "RS256":
      return crypto.verify("sha256", data, key, sig);
    case "PS256":
      return crypto.verify(
        "sha256",
        data,
        {
          key,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
        },
        sig,
      );
    case "ES256":
      // JWS ES256 signatures are raw r||s, not DER — tell Node so.
      return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
    default:
      return false;
  }
}

function scopesOf(claims: JwtClaims): string[] {
  if (typeof claims.scope === "string") return claims.scope.split(/\s+/).filter(Boolean);
  if (Array.isArray(claims.scp)) return claims.scp;
  if (typeof claims.scp === "string") return claims.scp.split(/\s+/).filter(Boolean);
  return [];
}

export async function verifyJwt(
  token: string,
  cfg: JwtAuthConfig,
  jwks: JwksCache,
  replay: ReplayCache,
  now = Date.now(),
): Promise<JwtClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new GatewayError("unauthenticated", "malformed JWT");
  const [rawHeader, rawPayload, rawSig] = parts;

  let header: { alg?: string; kid?: string; typ?: string };
  let claims: JwtClaims;
  try {
    header = JSON.parse(b64u(rawHeader).toString("utf8"));
    claims = JSON.parse(b64u(rawPayload).toString("utf8"));
  } catch {
    throw new GatewayError("unauthenticated", "malformed JWT segments");
  }

  // Algorithm is pinned to an asymmetric set BEFORE any key lookup: this is the
  // alg-confusion / "alg:none" defence, and it must not be derived from the JWK.
  if (!header.alg || !SUPPORTED_ALGS.has(header.alg)) {
    throw new GatewayError("unauthenticated", `unsupported alg ${header.alg}`);
  }

  const jwk = await jwks.get(header.kid);
  if (jwk.alg && jwk.alg !== header.alg) {
    throw new GatewayError("unauthenticated", `alg ${header.alg} does not match JWK alg ${jwk.alg}`);
  }
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: "jwk" });
  } catch {
    throw new GatewayError("unauthenticated", "unusable JWKS key");
  }
  // Bind key type to alg — an RSA key must never satisfy an EC alg, or vice versa.
  const expectedType = header.alg === "ES256" ? "ec" : "rsa";
  if (key.asymmetricKeyType !== expectedType && !(expectedType === "rsa" && key.asymmetricKeyType === "rsa-pss")) {
    throw new GatewayError("unauthenticated", `key type ${key.asymmetricKeyType} does not match alg ${header.alg}`);
  }

  if (!verifySignature(header.alg, key, `${rawHeader}.${rawPayload}`, b64u(rawSig))) {
    throw new GatewayError("unauthenticated", "JWT signature verification failed");
  }

  const skewMs = cfg.clockSkewSec * 1000;
  if (claims.iss !== cfg.issuer) throw new GatewayError("unauthenticated", `iss mismatch: ${claims.iss}`);
  const auds = Array.isArray(claims.aud) ? claims.aud : claims.aud === undefined ? [] : [claims.aud];
  if (!auds.includes(cfg.audience)) throw new GatewayError("unauthenticated", `aud mismatch: ${String(claims.aud)}`);
  if (typeof claims.sub !== "string" || !claims.sub) throw new GatewayError("unauthenticated", "missing sub");
  if (typeof claims.exp !== "number") throw new GatewayError("unauthenticated", "missing exp");
  if (typeof claims.iat !== "number") throw new GatewayError("unauthenticated", "missing iat");
  if (claims.exp * 1000 + skewMs <= now) throw new GatewayError("unauthenticated", "token expired");
  if (claims.iat * 1000 - skewMs > now) throw new GatewayError("unauthenticated", "token issued in the future");
  if (typeof claims.nbf === "number" && claims.nbf * 1000 - skewMs > now) {
    throw new GatewayError("unauthenticated", "token not yet valid");
  }
  if (claims.exp - claims.iat > cfg.maxLifetimeSec) {
    throw new GatewayError("unauthenticated", `token lifetime ${claims.exp - claims.iat}s exceeds max`);
  }
  if (typeof claims.jti !== "string" || !claims.jti) throw new GatewayError("unauthenticated", "missing jti");
  if (!scopesOf(claims).includes(cfg.requiredScope)) {
    throw new GatewayError("unauthenticated", `missing scope ${cfg.requiredScope}`);
  }
  if (claims.tenant !== undefined && typeof claims.tenant !== "string") {
    throw new GatewayError("unauthenticated", "tenant claim must be a string");
  }

  // Replay is recorded last so a token rejected for any other reason does not
  // burn its jti (which would let an attacker DoS a legitimate credential by
  // replaying it against a deliberately-wrong audience first).
  replay.use(claims.jti, claims.exp * 1000 + skewMs, now);

  return claims;
}

// ---------- mTLS peer identity ----------

function sha256Hex(der: Buffer): string {
  return crypto.createHash("sha256").update(der).digest("hex");
}

/**
 * Parse Envoy's `x-forwarded-client-cert`. Only `URI=` (the SPIFFE ID) and
 * `Cert=`/`Chain=` (URL-encoded PEM) are used; `Subject=` is deliberately
 * ignored because it is trivially spoofable across intermediates.
 */
export function parseXfcc(value: string): { uris: string[]; fingerprints: string[] } {
  const uris: string[] = [];
  const fingerprints: string[] = [];
  // XFCC is a comma-separated list of elements, each a `;`-separated k=v set.
  for (const element of value.split(",")) {
    for (const kv of element.split(";")) {
      const eq = kv.indexOf("=");
      if (eq <= 0) continue;
      const k = kv.slice(0, eq).trim().toLowerCase();
      let v = kv.slice(eq + 1).trim();
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      if (k === "uri") uris.push(v);
      else if (k === "cert") {
        const pem = decodeURIComponent(v);
        const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
        if (b64) fingerprints.push(sha256Hex(Buffer.from(b64, "base64")));
      }
    }
  }
  return { uris, fingerprints };
}

/** Identity of the TLS peer, from the socket or from a trusted proxy header. */
export function verifyPeer(req: IncomingMessage, cfg: MtlsAuthConfig): string {
  if (cfg.source === "socket") {
    const socket = req.socket as TLSSocket;
    if (typeof socket.getPeerCertificate !== "function" || !socket.authorized) {
      throw new GatewayError("unauthenticated", "no authorized TLS peer certificate");
    }
    const peer = socket.getPeerCertificate(false);
    if (!peer || !peer.raw) throw new GatewayError("unauthenticated", "no peer certificate presented");
    const fpr = sha256Hex(peer.raw);
    if (cfg.fingerprints.includes(fpr)) return `sha256:${fpr}`;
    // subjectaltname: 'URI:spiffe://…, DNS:…'
    const sans = String(peer.subjectaltname ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.startsWith("URI:"))
      .map((s) => s.slice(4));
    for (const uri of sans) if (cfg.spiffeIds.includes(uri)) return uri;
    throw new GatewayError("forbidden", `peer identity not allowlisted (fpr=${fpr}, sans=${sans.join("|")})`);
  }

  const raw = req.headers["x-forwarded-client-cert"];
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (!header) throw new GatewayError("unauthenticated", "missing x-forwarded-client-cert");
  const { uris, fingerprints } = parseXfcc(header);
  for (const uri of uris) if (cfg.spiffeIds.includes(uri)) return uri;
  for (const f of fingerprints) if (cfg.fingerprints.includes(f)) return `sha256:${f}`;
  throw new GatewayError("forbidden", "XFCC identity not allowlisted");
}

// ---------- API key (transitional) ----------

function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  // Compare a fixed-width digest so length itself is not a side channel.
  return crypto.timingSafeEqual(
    crypto.createHash("sha256").update(ab).digest(),
    crypto.createHash("sha256").update(bb).digest(),
  );
}

function verifyApiKey(req: IncomingMessage, keys: Map<string, string>): string {
  const raw = req.headers.authorization;
  const header = Array.isArray(raw) ? raw[0] : raw;
  if (!header || !header.startsWith("Bearer ")) {
    throw new GatewayError("unauthenticated", "missing bearer credential");
  }
  const presented = header.slice("Bearer ".length).trim();
  // Format: "<keyId>.<secret>" so we can look up without a linear scan of secrets.
  const dot = presented.indexOf(".");
  if (dot <= 0) throw new GatewayError("unauthenticated", "malformed api key");
  const id = presented.slice(0, dot);
  const secret = presented.slice(dot + 1);
  const expected = keys.get(id);
  if (!expected || !timingSafeEqualStr(secret, expected)) {
    throw new GatewayError("unauthenticated", `api key rejected for id "${id}"`);
  }
  return `apikey:${id}`;
}

// ---------- Authenticator ----------

export class Authenticator {
  readonly jwks?: JwksCache;
  private readonly replay = new ReplayCache();

  constructor(
    private readonly cfg: AuthConfig,
    jwks?: JwksCache,
  ) {
    if (cfg.jwt) this.jwks = jwks ?? new JwksCache(cfg.jwt.jwksUri, cfg.jwt.jwks);
  }

  async authenticate(req: IncomingMessage, now = Date.now()): Promise<Principal> {
    const mode = this.cfg.mode;

    if (mode === "api-key") {
      return { id: verifyApiKey(req, this.cfg.apiKeys!), via: "api-key", transitional: true };
    }

    let peer: string | undefined;
    if (this.cfg.mtls) peer = verifyPeer(req, this.cfg.mtls);

    if (mode === "mtls") {
      return { id: peer!, via: "mtls", transitional: false, peer };
    }

    const raw = req.headers.authorization;
    const header = Array.isArray(raw) ? raw[0] : raw;
    if (!header || !header.startsWith("Bearer ")) {
      throw new GatewayError("unauthenticated", "missing bearer JWT");
    }
    const claims = await verifyJwt(header.slice(7).trim(), this.cfg.jwt!, this.jwks!, this.replay, now);

    return {
      id: claims.sub!,
      via: mode === "mtls+jwt" ? "mtls+jwt" : "jwt",
      tenantClaim: claims.tenant,
      transitional: false,
      peer,
    };
  }
}
