/**
 * @e-sig/uaid-exch — UAP-EXCH-1 § 9 (Revocation, draft) — status-list style
 * credential revocation.
 *
 * A RevocationList is an append-only, issuer-published list of revoked
 * Signing Credential ids. Integrity is a sha256 digest over the JCS
 * (RFC 8785) canonicalization of the list body (everything except the
 * `digest` field itself), so any mutation — reordering, backdating, entry
 * removal — is detectable offline. Verifiers MUST fail closed: a list whose
 * digest does not verify is treated as unusable, not as "nothing revoked".
 *
 * Like § 5–§ 8 in ./index.ts this is a preview shape; it will be re-cut to
 * the accepted IAASO ADR-006 schemas when the doctrine lands.
 */

import { jcsBytes, uuidv7, type UaidSigningCredential } from "./index.js";

// ============================================================================
// Shapes
// ============================================================================

export interface RevocationEntry {
  credentialId: string;               // uuaid:foundation:signing-credential:<uuid>
  revokedAt: string;                  // ISO 8601
  reason?: string;
}

export interface RevocationList {
  id: string;                         // uuaid:foundation:revocation-list:<uuid>
  issuer: string;                     // uuaid:foundation:certifier:<uuid>
  issued: string;                     // ISO 8601 — when this list revision was cut
  revoked: RevocationEntry[];
  digest: string;                     // sha256:<hex> over JCS of { id, issuer, issued, revoked }
}

/**
 * The minimal credential surface needed for a usability check. Structural
 * (Pick-style) so any § 5 UaidSigningCredential — or anything with the same
 * id + validity window — is accepted without a hard dependency.
 */
export type RevocableCredential = Pick<
  UaidSigningCredential,
  "id" | "validFrom" | "validUntil"
>;

export interface CreateRevocationListInput {
  issuer: string;                     // uuaid:foundation:certifier:<uuid>
  now?: () => Date;                   // injectable clock for tests
  idFactory?: () => string;           // injectable urn:uuid factory
}

// ============================================================================
// Typed errors
// ============================================================================

export type CredentialUsabilityErrorCode =
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_NOT_YET_VALID"
  | "CREDENTIAL_REVOKED"
  | "CREDENTIAL_MALFORMED_VALIDITY"
  | "REVOCATION_LIST_INTEGRITY";

export class CredentialUsabilityError extends Error {
  readonly code: CredentialUsabilityErrorCode;

  constructor(code: CredentialUsabilityErrorCode, message: string) {
    super(message);
    this.name = "CredentialUsabilityError";
    this.code = code;
  }
}

export class CredentialExpiredError extends CredentialUsabilityError {
  constructor(credentialId: string, validUntil: string, now: Date) {
    super(
      "CREDENTIAL_EXPIRED",
      `credential ${credentialId} expired at ${validUntil} (now ${now.toISOString()})`
    );
    this.name = "CredentialExpiredError";
  }
}

export class CredentialNotYetValidError extends CredentialUsabilityError {
  constructor(credentialId: string, validFrom: string, now: Date) {
    super(
      "CREDENTIAL_NOT_YET_VALID",
      `credential ${credentialId} is not valid until ${validFrom} (now ${now.toISOString()})`
    );
    this.name = "CredentialNotYetValidError";
  }
}

export class CredentialRevokedError extends CredentialUsabilityError {
  readonly entry: RevocationEntry;

  constructor(entry: RevocationEntry) {
    super(
      "CREDENTIAL_REVOKED",
      `credential ${entry.credentialId} was revoked at ${entry.revokedAt}` +
        (entry.reason ? ` (${entry.reason})` : "")
    );
    this.name = "CredentialRevokedError";
    this.entry = entry;
  }
}

export class CredentialMalformedValidityError extends CredentialUsabilityError {
  constructor(credentialId: string, field: "validFrom" | "validUntil", value: string) {
    super(
      "CREDENTIAL_MALFORMED_VALIDITY",
      `credential ${credentialId} has unparseable ${field} ${JSON.stringify(value)}; failing closed`
    );
    this.name = "CredentialMalformedValidityError";
  }
}

export class RevocationListIntegrityError extends CredentialUsabilityError {
  constructor(listId: string) {
    super(
      "REVOCATION_LIST_INTEGRITY",
      `revocation list ${listId} failed integrity verification; failing closed`
    );
    this.name = "RevocationListIntegrityError";
  }
}

// ============================================================================
// List construction + mutation (append-only, always re-digested)
// ============================================================================

/** Create an empty, digested revocation list for an issuer. */
export async function createRevocationList(
  input: CreateRevocationListInput
): Promise<RevocationList> {
  const now = (input.now ?? (() => new Date()))();
  const body: Omit<RevocationList, "digest"> = {
    id: `uuaid:foundation:revocation-list:${(input.idFactory ?? uuidv7)()}`,
    issuer: input.issuer,
    issued: now.toISOString(),
    revoked: [],
  };
  return { ...body, digest: await computeListDigest(body) };
}

/**
 * Revoke a credential id. Returns a NEW list — the input is never mutated —
 * with the entry appended and the digest recomputed. Revoking an id that is
 * already revoked is idempotent: the input list is returned unchanged (the
 * original entry, including its `revokedAt` and `reason`, is authoritative).
 *
 * Fails closed: refuses to append to a list that does not verify.
 */
export async function revokeCredential(
  list: RevocationList,
  credentialId: string,
  reason?: string,
  opts?: { now?: () => Date }
): Promise<RevocationList> {
  if (!(await verifyRevocationListIntegrity(list))) {
    throw new RevocationListIntegrityError(list.id);
  }
  // Integrity verified above — the unverified lookup is safe here.
  if (findRevocationEntry(list, credentialId)) {
    return list;
  }
  const now = (opts?.now ?? (() => new Date()))();
  const entry: RevocationEntry = {
    credentialId,
    revokedAt: now.toISOString(),
    ...(reason !== undefined ? { reason } : {}),
  };
  const body: Omit<RevocationList, "digest"> = {
    id: list.id,
    issuer: list.issuer,
    issued: now.toISOString(),
    revoked: [...list.revoked, entry],
  };
  return { ...body, digest: await computeListDigest(body) };
}

/** Entry lookup WITHOUT integrity verification — internal use only, after
 * the caller has already verified the list digest. */
function findRevocationEntry(
  list: RevocationList,
  credentialId: string
): RevocationEntry | undefined {
  return list.revoked.find((e) => e.credentialId === credentialId);
}

/**
 * True if `credentialId` appears in the list's revoked entries.
 *
 * Verifies list integrity first and throws {@link RevocationListIntegrityError}
 * on any tampered/malformed list — a lookup against an unverified list would
 * fail open (an attacker who can strip an entry could un-revoke a credential).
 */
export async function isRevoked(
  list: RevocationList,
  credentialId: string
): Promise<boolean> {
  if (!(await verifyRevocationListIntegrity(list))) {
    throw new RevocationListIntegrityError(list.id);
  }
  return findRevocationEntry(list, credentialId) !== undefined;
}

/**
 * Look up the revocation entry for a credential id, if any. Same fail-closed
 * integrity gate as {@link isRevoked}.
 */
export async function getRevocationEntry(
  list: RevocationList,
  credentialId: string
): Promise<RevocationEntry | undefined> {
  if (!(await verifyRevocationListIntegrity(list))) {
    throw new RevocationListIntegrityError(list.id);
  }
  return findRevocationEntry(list, credentialId);
}

/**
 * Recompute the JCS + sha256 digest over the list body and compare against
 * `list.digest`. Fail-closed: any structural anomaly, canonicalization error,
 * or digest mismatch returns false — it never throws.
 */
export async function verifyRevocationListIntegrity(
  list: RevocationList
): Promise<boolean> {
  try {
    if (
      typeof list !== "object" ||
      list === null ||
      typeof list.id !== "string" ||
      typeof list.issuer !== "string" ||
      typeof list.issued !== "string" ||
      typeof list.digest !== "string" ||
      !Array.isArray(list.revoked)
    ) {
      return false;
    }
    const body: Omit<RevocationList, "digest"> = {
      id: list.id,
      issuer: list.issuer,
      issued: list.issued,
      revoked: list.revoked,
    };
    return (await computeListDigest(body)) === list.digest;
  } catch {
    return false;
  }
}

// ============================================================================
// Usability gate
// ============================================================================

/**
 * Assert a Signing Credential is currently usable: the revocation list
 * verifies, the credential's § 5 validity window (validFrom/validUntil)
 * covers `now`, and the credential id is not revoked.
 *
 * Throws a typed CredentialUsabilityError subclass on the first failure;
 * resolves (void) on the happy path. Standalone by design — ./index.ts has
 * no verify entry point to wire into, so call this before acting on a
 * credential (e.g. before createExchange / UaidNetworkClient.submit).
 */
export async function assertCredentialUsable(
  credential: RevocableCredential,
  list: RevocationList,
  now?: Date
): Promise<void> {
  if (!(await verifyRevocationListIntegrity(list))) {
    throw new RevocationListIntegrityError(list.id);
  }
  const at = now ?? new Date();
  const from = Date.parse(credential.validFrom);
  const until = Date.parse(credential.validUntil);
  if (!Number.isFinite(from)) {
    throw new CredentialMalformedValidityError(credential.id, "validFrom", credential.validFrom);
  }
  if (!Number.isFinite(until)) {
    throw new CredentialMalformedValidityError(credential.id, "validUntil", credential.validUntil);
  }
  if (at.getTime() < from) {
    throw new CredentialNotYetValidError(credential.id, credential.validFrom, at);
  }
  if (at.getTime() > until) {
    throw new CredentialExpiredError(credential.id, credential.validUntil, at);
  }
  // List integrity was verified above — the unverified lookup is safe here.
  const entry = findRevocationEntry(list, credential.id);
  if (entry) {
    throw new CredentialRevokedError(entry);
  }
}

// ============================================================================
// Digest — JCS (RFC 8785) canonical body → sha256:<hex>
// ============================================================================

async function computeListDigest(
  body: Omit<RevocationList, "digest">
): Promise<string> {
  return `sha256:${await sha256Hex(jcsBytes(body))}`;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = (globalThis as unknown as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    // Node >= 20 and all modern browsers expose WebCrypto; integrity cannot
    // be computed without it, so refuse rather than degrade.
    throw new Error("WebCrypto subtle digest unavailable (requires Node >= 20)");
  }
  const digest = await subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
