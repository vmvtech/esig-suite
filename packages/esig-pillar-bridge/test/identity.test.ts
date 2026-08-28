import { describe, expect, it } from "vitest";
import { mkdtempSync, existsSync, statSync, readdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

import { loadPillar } from "../src/shim.js";
import { PillarIdentity, localIdFromEd25519Key, uuaidFromEd25519Key } from "../src/identity.js";

describe("identity: localIdFromEd25519Key cross-check", () => {
  it("matches the real Keychain._localIdFromKey on 50 random keys", async () => {
    const pillar = await loadPillar();
    for (let i = 0; i < 50; i++) {
      const raw = randomBytes(32);
      const ours = localIdFromEd25519Key(raw);
      const theirs = pillar.Keychain._localIdFromKey(raw);
      expect(ours).toBe(theirs);
      expect(ours).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    }
  });

  it("uuaidFromEd25519Key prefixes the local id correctly", () => {
    const raw = randomBytes(32);
    const uuaid = uuaidFromEd25519Key(raw);
    expect(uuaid).toBe(`uuaid:foundation:agent:${localIdFromEd25519Key(raw)}`);
  });

  it("rejects a key that is not exactly 32 bytes", () => {
    expect(() => localIdFromEd25519Key(randomBytes(31))).toThrow();
    expect(() => localIdFromEd25519Key(randomBytes(33))).toThrow();
  });
});

describe("identity: PillarIdentity.generate / .load round-trip", () => {
  it("generates a fresh identity, persists it 0600, and reloads it identically", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-"));
    const generated = await PillarIdentity.generate({ home, passphrase: "test-passphrase-0123456789" });

    expect(generated.uuaid).toMatch(/^uuaid:foundation:agent:[0-9a-f-]{36}$/);
    expect(generated.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);

    const keychainPath = path.join(home, "keychain.json");
    expect(existsSync(keychainPath)).toBe(true);
    const mode = statSync(keychainPath).mode & 0o777;
    expect(mode).toBe(0o600);

    const loaded = await PillarIdentity.load({ home, passphrase: "test-passphrase-0123456789" });
    expect(loaded.uuaid).toBe(generated.uuaid);
    expect(loaded.publicKeyHex).toBe(generated.publicKeyHex);

    // sign() round-trip: both identities sign the same bytes; both signatures
    // verify against the shared public key (Ed25519 is deterministic per RFC 8032,
    // so the signatures should also be byte-identical).
    const message = Buffer.from("esig-pillar-bridge identity test", "utf-8");
    const sigA = generated.sign(message);
    const sigB = loaded.sign(message);
    expect(sigA.equals(sigB)).toBe(true);
  });

  it("falls back to ESIG_PILLAR_PASSPHRASE when no explicit passphrase is given", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-env-"));
    const prevA = process.env.ESIG_PILLAR_PASSPHRASE;
    const prevB = process.env.PILLAR_PASSPHRASE;
    process.env.ESIG_PILLAR_PASSPHRASE = "env-passphrase-0123456789";
    delete process.env.PILLAR_PASSPHRASE;
    try {
      const generated = await PillarIdentity.generate({ home });
      const loaded = await PillarIdentity.load({ home });
      expect(loaded.uuaid).toBe(generated.uuaid);
    } finally {
      if (prevA === undefined) delete process.env.ESIG_PILLAR_PASSPHRASE;
      else process.env.ESIG_PILLAR_PASSPHRASE = prevA;
      if (prevB === undefined) delete process.env.PILLAR_PASSPHRASE;
      else process.env.PILLAR_PASSPHRASE = prevB;
    }
  });

  it("refuses to load a keychain with the wrong passphrase", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-wrongpass-"));
    await PillarIdentity.generate({ home, passphrase: "correct-passphrase-0123456789" });
    await expect(PillarIdentity.load({ home, passphrase: "wrong-passphrase-0123456789" })).rejects.toThrow();
  });

  it("generate() never overwrites an existing keychain", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-noclobber-"));
    await PillarIdentity.generate({ home, passphrase: "noclobber-passphrase-aaaa" });
    await expect(PillarIdentity.generate({ home, passphrase: "noclobber-passphrase-bbbb" })).rejects.toThrow();
  });
});

describe("identity: RT-2026-08-28-01 F4/G4 keychain custody", () => {
  it("generate() refuses an empty passphrase, naming ESIG_PILLAR_PASSPHRASE", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-empty-"));
    await expect(PillarIdentity.generate({ home, passphrase: "" })).rejects.toThrow(/ESIG_PILLAR_PASSPHRASE/);
  });

  it("generate() refuses a passphrase under 24 characters, naming ESIG_PILLAR_PASSPHRASE", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-short-"));
    await expect(PillarIdentity.generate({ home, passphrase: "short-passphrase-23c" })).rejects.toThrow(
      /ESIG_PILLAR_PASSPHRASE/
    );
    // Sanity: 20 chars, one under the 21 needed to hit 24 at all — a boundary check on the fixture, not the code.
    expect("short-passphrase-23c".length).toBeLessThan(24);
  });

  it("load() refuses an empty/short passphrase before ever touching the keychain file", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-load-short-"));
    await PillarIdentity.generate({ home, passphrase: "a-perfectly-fine-passphrase-1" });
    await expect(PillarIdentity.load({ home, passphrase: "" })).rejects.toThrow(/ESIG_PILLAR_PASSPHRASE/);
    await expect(PillarIdentity.load({ home, passphrase: "too-short" })).rejects.toThrow(/ESIG_PILLAR_PASSPHRASE/);
  });

  it("never writes the passphrase to disk beside keychain.json — the home dir holds only keychain.json", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-nosidecar-"));
    await PillarIdentity.generate({ home, passphrase: "generated-passphrase-0123456789" });
    expect(readdirSync(home)).toEqual(["keychain.json"]);
  });

  it("refuses to load a keychain whose file mode is group/other-readable", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-badmode-"));
    const passphrase = "mode-check-passphrase-0123456789";
    await PillarIdentity.generate({ home, passphrase });
    const keychainPath = path.join(home, "keychain.json");
    expect(statSync(keychainPath).mode & 0o777).toBe(0o600);

    chmodSync(keychainPath, 0o644);
    await expect(PillarIdentity.load({ home, passphrase })).rejects.toThrow(/group or other/);

    // Restoring 0600 makes it loadable again — proving the mode check, not
    // something else, is what rejected the 0644 case above.
    chmodSync(keychainPath, 0o600);
    const loaded = await PillarIdentity.load({ home, passphrase });
    expect(loaded.uuaid).toMatch(/^uuaid:foundation:agent:/);
  });

  it("onAudit fires pillar.identity_generated then pillar.identity_loaded with {uuaid, fingerprint} only", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "pillar-identity-audit-"));
    const passphrase = "audit-event-passphrase-0123456789";
    const events: Array<{ action: string; uuaid?: unknown; fingerprint?: unknown }> = [];

    const generated = await PillarIdentity.generate({ home, passphrase, onAudit: (e) => events.push(e) });
    expect(events).toHaveLength(1);
    expect(events[0].action).toBe("pillar.identity_generated");
    expect(events[0].uuaid).toBe(generated.uuaid);
    expect(events[0].fingerprint).toMatch(/^[0-9a-f]{16}$/);
    // Never the passphrase or key material.
    expect(JSON.stringify(events[0])).not.toContain(passphrase);

    const loaded = await PillarIdentity.load({ home, passphrase, onAudit: (e) => events.push(e) });
    expect(events).toHaveLength(2);
    expect(events[1]).toEqual({ action: "pillar.identity_loaded", uuaid: loaded.uuaid, fingerprint: events[0].fingerprint });
  });
});
