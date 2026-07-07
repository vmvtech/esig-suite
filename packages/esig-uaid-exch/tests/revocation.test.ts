import { describe, it, expect } from "vitest";
import {
  createRevocationList,
  revokeCredential,
  isRevoked,
  getRevocationEntry,
  verifyRevocationListIntegrity,
  assertCredentialUsable,
  CredentialExpiredError,
  CredentialNotYetValidError,
  CredentialRevokedError,
  CredentialMalformedValidityError,
  RevocationListIntegrityError,
  type RevocationList,
  type RevocableCredential,
} from "../src/index.js";

const ISSUER = "uuaid:foundation:certifier:018f7aaa";
const CRED_ID = "uuaid:foundation:signing-credential:018f7ac8";

const NOW = new Date("2026-07-04T18:12:33.412Z");

function freshList(): Promise<RevocationList> {
  return createRevocationList({
    issuer: ISSUER,
    now: () => NOW,
    idFactory: () => "018f7ad5-4d3d-7ac8-8e11-4e6c9e2c6b3a",
  });
}

function credential(overrides?: Partial<RevocableCredential>): RevocableCredential {
  return {
    id: CRED_ID,
    validFrom: "2026-07-04T18:00:00.000Z",
    validUntil: "2026-07-05T18:00:00.000Z", // <= 24h window per § 5
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// createRevocationList
// ---------------------------------------------------------------------------

describe("createRevocationList", () => {
  it("returns an empty, digested list that verifies", async () => {
    const list = await freshList();
    expect(list.id).toBe(
      "uuaid:foundation:revocation-list:018f7ad5-4d3d-7ac8-8e11-4e6c9e2c6b3a"
    );
    expect(list.issuer).toBe(ISSUER);
    expect(list.issued).toBe(NOW.toISOString());
    expect(list.revoked).toEqual([]);
    expect(list.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(await verifyRevocationListIntegrity(list)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// revokeCredential / isRevoked
// ---------------------------------------------------------------------------

describe("revokeCredential", () => {
  it("revoke → isRevoked true, entry carries revokedAt + reason", async () => {
    const list = await freshList();
    const next = await revokeCredential(list, CRED_ID, "key compromise", {
      now: () => NOW,
    });
    expect(await isRevoked(next, CRED_ID)).toBe(true);
    expect(await getRevocationEntry(next, CRED_ID)).toEqual({
      credentialId: CRED_ID,
      revokedAt: NOW.toISOString(),
      reason: "key compromise",
    });
    expect(await verifyRevocationListIntegrity(next)).toBe(true);
  });

  it("is append-only: the input list is not mutated", async () => {
    const list = await freshList();
    const before = JSON.stringify(list);
    await revokeCredential(list, CRED_ID);
    expect(JSON.stringify(list)).toBe(before);
    expect(await isRevoked(list, CRED_ID)).toBe(false);
  });

  it("unrevoked id reports false", async () => {
    const list = await revokeCredential(await freshList(), CRED_ID);
    expect(await isRevoked(list, "uuaid:foundation:signing-credential:other")).toBe(
      false
    );
  });

  it("double-revoke is idempotent", async () => {
    const once = await revokeCredential(await freshList(), CRED_ID, "first", {
      now: () => NOW,
    });
    const twice = await revokeCredential(once, CRED_ID, "second", {
      now: () => new Date("2026-07-05T00:00:00.000Z"),
    });
    expect(twice).toBe(once); // unchanged — original entry authoritative
    expect(twice.revoked).toHaveLength(1);
    expect(twice.revoked[0].reason).toBe("first");
    expect(await verifyRevocationListIntegrity(twice)).toBe(true);
  });

  it("refuses to append to a tampered list (fail-closed)", async () => {
    const list = await revokeCredential(await freshList(), CRED_ID);
    const tampered: RevocationList = { ...list, revoked: [] };
    await expect(revokeCredential(tampered, "x")).rejects.toBeInstanceOf(
      RevocationListIntegrityError
    );
  });

  it("bare isRevoked / getRevocationEntry throw on a tampered list — a stripped entry must not read as un-revoked", async () => {
    const list = await revokeCredential(await freshList(), CRED_ID);
    const stripped: RevocationList = { ...list, revoked: [] };
    await expect(isRevoked(stripped, CRED_ID)).rejects.toBeInstanceOf(
      RevocationListIntegrityError
    );
    await expect(getRevocationEntry(stripped, CRED_ID)).rejects.toBeInstanceOf(
      RevocationListIntegrityError
    );
  });
});

// ---------------------------------------------------------------------------
// verifyRevocationListIntegrity
// ---------------------------------------------------------------------------

describe("verifyRevocationListIntegrity", () => {
  it("fails on any mutation of the list body", async () => {
    const list = await revokeCredential(await freshList(), CRED_ID, "fraud", {
      now: () => NOW,
    });
    expect(await verifyRevocationListIntegrity(list)).toBe(true);

    // Entry silently removed (un-revoking without re-issuing).
    expect(
      await verifyRevocationListIntegrity({ ...list, revoked: [] })
    ).toBe(false);
    // Backdated revocation time.
    expect(
      await verifyRevocationListIntegrity({
        ...list,
        revoked: [{ ...list.revoked[0], revokedAt: "2020-01-01T00:00:00Z" }],
      })
    ).toBe(false);
    // Issuer swap.
    expect(
      await verifyRevocationListIntegrity({ ...list, issuer: "uuaid:evil" })
    ).toBe(false);
    // Digest swap.
    expect(
      await verifyRevocationListIntegrity({
        ...list,
        digest: `sha256:${"0".repeat(64)}`,
      })
    ).toBe(false);
    // Structural garbage never throws — fails closed.
    expect(
      await verifyRevocationListIntegrity({} as never)
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// assertCredentialUsable
// ---------------------------------------------------------------------------

describe("assertCredentialUsable", () => {
  it("happy path: valid window, unrevoked, intact list → resolves", async () => {
    const list = await freshList();
    await expect(
      assertCredentialUsable(credential(), list, NOW)
    ).resolves.toBeUndefined();
  });

  it("rejects an expired credential (validUntil in the past)", async () => {
    const list = await freshList();
    const err = await assertCredentialUsable(
      credential({ validUntil: "2026-07-04T18:00:01.000Z" }),
      list,
      NOW
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CredentialExpiredError);
    expect((err as CredentialExpiredError).code).toBe("CREDENTIAL_EXPIRED");
  });

  it("rejects a credential that is not yet valid", async () => {
    const list = await freshList();
    await expect(
      assertCredentialUsable(
        credential({ validFrom: "2026-07-04T19:00:00.000Z" }),
        list,
        NOW
      )
    ).rejects.toBeInstanceOf(CredentialNotYetValidError);
  });

  it("rejects a revoked credential even inside its validity window", async () => {
    const list = await revokeCredential(await freshList(), CRED_ID, "fraud", {
      now: () => NOW,
    });
    const err = await assertCredentialUsable(credential(), list, NOW).catch(
      (e: unknown) => e
    );
    expect(err).toBeInstanceOf(CredentialRevokedError);
    expect((err as CredentialRevokedError).code).toBe("CREDENTIAL_REVOKED");
    expect((err as CredentialRevokedError).entry.reason).toBe("fraud");
  });

  it("fails closed on a tampered list before checking anything else", async () => {
    const list = await revokeCredential(await freshList(), CRED_ID);
    const tampered: RevocationList = { ...list, revoked: [] }; // "un-revoked"
    await expect(
      assertCredentialUsable(credential(), tampered, NOW)
    ).rejects.toBeInstanceOf(RevocationListIntegrityError);
  });

  it("fails closed on unparseable validity dates (NaN must not pass the window gate)", async () => {
    const list = await freshList();
    const err1 = await assertCredentialUsable(
      credential({ validFrom: "not-a-date" }),
      list,
      NOW
    ).catch((e: unknown) => e);
    expect(err1).toBeInstanceOf(CredentialMalformedValidityError);
    expect((err1 as CredentialMalformedValidityError).code).toBe(
      "CREDENTIAL_MALFORMED_VALIDITY"
    );
    await expect(
      assertCredentialUsable(credential({ validUntil: "garbage" }), list, NOW)
    ).rejects.toBeInstanceOf(CredentialMalformedValidityError);
  });
});
