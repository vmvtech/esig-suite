// bin-esig.test.ts — spawns the REAL compiled dist/bin/esig.js (the actual
// thing an operator or CI job runs), not the library functions directly, same
// approach as esig-mcp's test/bin-cli.test.ts. No Chrome: signs the quickstart
// sample-unsigned.pdf fixture with signPdf() directly (no HTML rendering).

import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, it, expect, afterEach } from "vitest";

import { generateSelfSignedCert, signPdf, generatePqKeyBundle, loadPqSigningKeys } from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const BIN = join(here, "..", "dist", "bin", "esig.js");
const PACKAGE_VERSION: string = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")).version;
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

function run(args: string[]) {
  return spawnSync("node", [BIN, ...args], { encoding: "utf8", timeout: 15_000 });
}

async function signPlain(): Promise<Buffer> {
  const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
  const r = await signPdf({
    pdf: SAMPLE_PDF,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: "esig CLI test",
    location: "",
    contactInfo: "a@b.co",
    name: "Acme Inc",
  });
  return r.signedPdf;
}

async function signSealed(): Promise<Buffer> {
  const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });
  const keys = loadPqSigningKeys(generatePqKeyBundle().bundle);
  const r = await signPdf({
    pdf: SAMPLE_PDF,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: "esig CLI test (sealed)",
    location: "",
    contactInfo: "a@b.co",
    name: "Acme Inc",
    pqSeal: { keys },
  });
  return r.signedPdf;
}

const tmpDirs: string[] = [];
async function tmpFile(name: string, bytes: Buffer): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "esig-cli-test-"));
  tmpDirs.push(dir);
  const file = path.join(dir, name);
  await writeFile(file, bytes);
  return file;
}

afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("esig --help / --version", () => {
  it("--help: exit 0, usage on stdout, stderr empty", () => {
    const res = run(["--help"]);
    expect(res.status).toBe(0);
    expect(res.stderr).toBe("");
    expect(res.stdout).toMatch(/esig verify <file\.pdf>/);
    expect(res.stdout).toMatch(/--json/);
    expect(res.stdout).toMatch(/--require-pq/);
  });

  it("--version: exit 0, prints package.json version", () => {
    const res = run(["--version"]);
    expect(res.status).toBe(0);
    expect(res.stderr).toBe("");
    expect(res.stdout.trim()).toBe(PACKAGE_VERSION);
  });

  it("no args: exit 2, usage on stderr", () => {
    const res = run([]);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/esig verify <file\.pdf>/);
  });

  it("unknown command: exit 2", () => {
    const res = run(["frobnicate"]);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/unknown command/);
  });
});

describe("esig verify — classical signature", () => {
  it("a validly signed PDF: exit 0, human output shows OK", async () => {
    const file = await tmpFile("signed.pdf", await signPlain());
    const res = run(["verify", file]);
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(new RegExp(`${file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}: OK`));
    expect(res.stdout).toMatch(/digest valid:\s+yes/);
    expect(res.stdout).toMatch(/signature valid:\s+yes/);
    expect(res.stdout).toMatch(/signer:\s+E-sig \(Acme Inc\)/);
  });

  it("--json: exit 0, stdout is exactly one JSON array with ok:true, stderr empty", async () => {
    const file = await tmpFile("signed.pdf", await signPlain());
    const res = run(["verify", file, "--json"]);
    expect(res.status).toBe(0);
    expect(res.stderr).toBe("");
    const parsed = JSON.parse(res.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].file).toBe(file);
    expect(parsed[0].verification.ok).toBe(true);
    expect(parsed[0].verification.classical.ok).toBe(true);
  });

  it("a tampered byte: exit 1, FAIL reported", async () => {
    const signed = await signPlain();
    const tampered = Buffer.from(signed);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff;
    const file = await tmpFile("tampered.pdf", tampered);

    const res = run(["verify", file, "--json"]);
    expect(res.status).toBe(1);
    const parsed = JSON.parse(res.stdout);
    expect(parsed[0].verification.ok).toBe(false);
  });

  it("--require-pq on an unsealed document: exit 1", async () => {
    const file = await tmpFile("unsealed.pdf", await signPlain());
    const res = run(["verify", file, "--require-pq", "--json"]);
    expect(res.status).toBe(1);
    const parsed = JSON.parse(res.stdout);
    expect(parsed[0].verification.ok).toBe(false);
    expect(parsed[0].verification.postQuantum.present).toBe(false);
  });
});

describe("esig verify — post-quantum seal", () => {
  it("a sealed document with --require-pq: exit 0, PQ fields present", async () => {
    const file = await tmpFile("sealed.pdf", await signSealed());
    const res = run(["verify", file, "--require-pq", "--json"]);
    expect(res.status).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed[0].verification.ok).toBe(true);
    expect(parsed[0].verification.postQuantum.present).toBe(true);
    expect(parsed[0].verification.postQuantum.ok).toBe(true);
    expect(parsed[0].verification.postQuantum.mldsa65Fpr).toMatch(/^[0-9a-f]{64}$/);
  });

  it("human output for a sealed document shows the post-quantum block", async () => {
    const file = await tmpFile("sealed.pdf", await signSealed());
    const res = run(["verify", file]);
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/post-quantum:\s+present, ok/);
    expect(res.stdout).toMatch(/mldsa65Fpr:/);
  });
});

describe("esig verify — usage / I/O errors", () => {
  it("missing file: exit 2", () => {
    const res = run(["verify", "/nonexistent/path/does-not-exist.pdf"]);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/cannot read/);
  });

  it("unknown flag: exit 2", async () => {
    const file = await tmpFile("signed.pdf", await signPlain());
    const res = run(["verify", file, "--bogus-flag"]);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/unknown option/);
  });

  it("no files given: exit 2", () => {
    const res = run(["verify"]);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/no files given/);
  });
});

describe("esig verify — multiple files, --quiet", () => {
  it("one ok + one tampered: exit 1, one line each under --quiet", async () => {
    const okFile = await tmpFile("ok.pdf", await signPlain());
    const bad = Buffer.from(await signPlain());
    bad[Math.floor(bad.length / 2)] ^= 0xff;
    const badFile = await tmpFile("bad.pdf", bad);

    const res = run(["verify", okFile, badFile, "--quiet"]);
    expect(res.status).toBe(1);
    const lines = res.stdout.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe(`${okFile}: OK`);
    expect(lines[1]).toMatch(new RegExp(`^${badFile.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}: FAIL`));
  });
});
