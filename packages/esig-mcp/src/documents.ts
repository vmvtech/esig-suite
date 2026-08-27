// documents.ts
//
// Content-addressed workdir for standalone PDF bytes (design doc §4
// `esig_ingest_document`; mode A + `esig_verify_document` input in a future
// worker). `docId` IS the sha256 hex of the bytes, so identical uploads are
// naturally deduplicated and a docId can never be forged to name different
// bytes than the ones that produced it.

import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

/** 64 lowercase hex chars — exactly a sha256 digest, nothing else. */
const DOC_ID_RE = /^[0-9a-f]{64}$/;

export interface DocumentStore {
  ingest(bytes: Uint8Array): Promise<{ docId: string; size: number }>;
  get(docId: string): Promise<Buffer>;
  has(docId: string): Promise<boolean>;
}

export class FsDocumentStore implements DocumentStore {
  private readonly root: string;

  constructor(
    rootDir: string,
    private readonly maxBytes: number = 25 * 1024 * 1024,
  ) {
    this.root = path.join(rootDir, "documents");
  }

  async ingest(bytes: Uint8Array): Promise<{ docId: string; size: number }> {
    if (bytes.byteLength === 0) throw new Error("ingest: empty document");
    if (bytes.byteLength > this.maxBytes) {
      throw new Error(`ingest: document is ${bytes.byteLength} bytes, exceeds the ${this.maxBytes}-byte cap`);
    }
    const docId = crypto.createHash("sha256").update(bytes).digest("hex");
    const file = this.pathFor(docId);
    await fs.mkdir(path.dirname(file), { recursive: true });
    // Content-addressed: if this exact content was already ingested, the file
    // already holds byte-identical content at this exact path — skip the
    // rewrite rather than erroring.
    try {
      await fs.writeFile(file, bytes, { flag: "wx" });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    return { docId, size: bytes.byteLength };
  }

  async get(docId: string): Promise<Buffer> {
    return fs.readFile(this.pathFor(docId));
  }

  async has(docId: string): Promise<boolean> {
    try {
      await fs.access(this.pathFor(docId));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * docId is validated as EXACTLY a 64-char lowercase hex sha256 before it
   * ever reaches `path.join` — no traversal sequence, absolute path, or
   * separator can pass that check, so no caller-supplied docId can name a
   * path outside `this.root` regardless of what a caller sends.
   */
  private pathFor(docId: string): string {
    if (!DOC_ID_RE.test(docId)) {
      throw new Error(`invalid docId: ${docId}`);
    }
    return path.join(this.root, `${docId}.bin`);
  }
}
