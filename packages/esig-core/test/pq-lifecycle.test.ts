// pq-lifecycle: ensureActivePqKeys / rotatePqKeys against an in-memory PqKeyStore.

import crypto from "node:crypto";
import { describe, it, expect } from "vitest";

import {
  ensureActivePqKeys,
  rotatePqKeys,
  buildPqSeal,
  verifyPqSealSignatures,
  type PqKeyStore,
  type StoredPqKeys,
} from "../dist/index.js";

const PASSPHRASE = "test-passphrase-at-least-24-chars-long!!";

function memStore(): PqKeyStore {
  const rows: StoredPqKeys[] = [];
  return {
    async findActive(tenantId) {
      return rows.find((r) => r.tenantId === tenantId && r.active) ?? null;
    },
    async insert(input) {
      const row: StoredPqKeys = {
        id: crypto.randomUUID(),
        tenantId: input.tenantId,
        keyBundleEncrypted: input.keyBundleEncrypted,
        ed25519Public: input.public.ed25519,
        mldsa65Public: input.public.mldsa65,
        mldsa65Fpr: input.public.mldsa65Fpr,
        keyId: input.public.keyId,
        active: true,
        rotatedFromId: input.rotatedFromId ?? null,
        createdAt: new Date(),
      };
      rows.push(row);
      return row;
    },
    async deactivate(id) {
      const r = rows.find((x) => x.id === id);
      if (r) r.active = false;
    },
  };
}

describe("pq-lifecycle", () => {
  it("generates on first use and reuses the same identity thereafter", async () => {
    const store = memStore();
    const a = await ensureActivePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    const b = await ensureActivePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    expect(b.record.id).toBe(a.record.id);
    expect(b.public.keyId).toBe(a.public.keyId);

    // The reloaded keys can seal + verify.
    const seal = buildPqSeal({ digestHex: crypto.createHash("sha256").update("d").digest("hex"), coveredBytes: 1, keys: b.keys });
    expect(verifyPqSealSignatures(seal).ok).toBe(true);
  });

  it("isolates tenants", async () => {
    const store = memStore();
    const t1 = await ensureActivePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    const t2 = await ensureActivePqKeys({ store, tenantId: "t2", passphrase: PASSPHRASE });
    expect(t2.public.keyId).not.toBe(t1.public.keyId);
  });

  it("rotates: new identity, predecessor linked + deactivated", async () => {
    const store = memStore();
    const before = await ensureActivePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    const after = await rotatePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    expect(after.public.keyId).not.toBe(before.public.keyId);
    expect(after.record.rotatedFromId).toBe(before.record.id);

    // ensureActive now returns the rotated (active) bundle.
    const active = await ensureActivePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    expect(active.record.id).toBe(after.record.id);
  });

  it("wrong passphrase cannot unwrap an existing bundle", async () => {
    const store = memStore();
    await ensureActivePqKeys({ store, tenantId: "t1", passphrase: PASSPHRASE });
    await expect(
      ensureActivePqKeys({ store, tenantId: "t1", passphrase: "another-wrong-passphrase-24ch!!" }),
    ).rejects.toThrow();
  });
});
