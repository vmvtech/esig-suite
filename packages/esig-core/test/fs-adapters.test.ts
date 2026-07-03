// Filesystem adapter suite — the full pipeline against @e-sig/core/fs with a
// temp directory, no external services. Runs against the BUILT package.

import { mkdtempSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";

import {
  ensureActiveCert,
  createEnvelope,
  recordSignature,
  composeEnvelopeHtml,
} from "../dist/index.js";
import {
  FsCertStore,
  FsAuditLogStore,
  FsPdfStorageStore,
  FsEnvelopeStore,
} from "../dist/fs-adapters.js";

const PASSPHRASE = "fs-adapter-passphrase-at-least-24-chars!!";
const PNG_1PX =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "esig-fs-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("FsCertStore", () => {
  it("persists across instances and keeps one active cert per tenant", async () => {
    const a = await ensureActiveCert({
      store: new FsCertStore(root),
      tenantId: "t1",
      subjectName: "Acme Inc",
      passphrase: PASSPHRASE,
    });
    // Fresh instance = fresh read from disk (dates + key bytes revive).
    const b = await ensureActiveCert({
      store: new FsCertStore(root),
      tenantId: "t1",
      subjectName: "Acme Inc",
      passphrase: PASSPHRASE,
    });
    expect(b.cert.id).toBe(a.cert.id);
    expect(b.cert.notAfter).toBeInstanceOf(Date);
    expect(b.keyPem).toBe(a.keyPem); // encrypted key round-trips through base64
  });

  it("findExpiring sees only certs inside the horizon", async () => {
    const store = new FsCertStore(root);
    await ensureActiveCert({ store, tenantId: "t1", subjectName: "Acme", passphrase: PASSPHRASE });
    expect(await store.findExpiring(30)).toHaveLength(0); // fresh cert: ~1y left
    expect((await store.findExpiring(400)).length).toBe(1);
  });
});

describe("FsAuditLogStore", () => {
  it("appends NDJSON rows and reads them back", async () => {
    const store = new FsAuditLogStore(root);
    const r1 = await store.insert({ tenantId: "t1", action: "pdf.signed" });
    await store.insert({ tenantId: "t1", action: "envelope.created", metadata: { n: 2 } });
    expect(r1.id).toMatch(/^[0-9a-f-]{36}$/);

    const all = await new FsAuditLogStore(root).readAll();
    expect(all.map((r) => r.action)).toEqual(["pdf.signed", "envelope.created"]);
    expect(all[1].metadata).toEqual({ n: 2 });
    expect(all[0].createdAt).toBeInstanceOf(Date);
  });
});

describe("FsPdfStorageStore", () => {
  it("writes bytes under blobs/ and returns a readable location", async () => {
    const store = new FsPdfStorageStore(root);
    const bytes = new Uint8Array([37, 80, 68, 70]); // %PDF
    const { url } = await store.upload({ path: "t1/doc1/a.pdf", bytes, contentType: "application/pdf" });
    expect(url).toContain(`blobs${sep}t1`);
    expect(new Uint8Array(await readFile(url))).toEqual(bytes);
  });

  it("refuses path traversal out of the storage root", async () => {
    const store = new FsPdfStorageStore(root);
    await expect(
      store.upload({ path: "../../escape.pdf", bytes: new Uint8Array([1]), contentType: "application/pdf" }),
    ).rejects.toThrow(/escapes storage root/);
  });
});

describe("FsEnvelopeStore", () => {
  it("runs the whole envelope flow across separate store instances", async () => {
    const { signingTokens } = await createEnvelope({
      store: new FsEnvelopeStore(root),
      tenantId: "t1",
      title: "MSA",
      html: "<h1>MSA</h1>",
      signers: [
        { name: "Ada", email: "ada@x.y", order: 1 },
        { name: "Grace", email: "grace@x.y", order: 2 },
      ],
    });

    // Every step re-reads from disk via a new instance (dates must revive).
    const s1 = await recordSignature({
      store: new FsEnvelopeStore(root),
      token: signingTokens[0].token,
      signatureImageDataUrl: PNG_1PX,
    });
    expect(s1.status).toBe("partially_signed");

    const s2 = await recordSignature({
      store: new FsEnvelopeStore(root),
      token: signingTokens[1].token,
      signatureImageDataUrl: PNG_1PX,
    });
    expect(s2.status).toBe("completed");
    expect(s2.signers[0].signedAt).toBeInstanceOf(Date);

    const html = composeEnvelopeHtml(s2);
    expect(html).toContain("Ada");
    expect(html).toContain("Grace");
  });
});
