// Post-quantum seal demo — classical PAdES/RSA plus an ML-DSA-65 hybrid seal.
//
// The repository sample is signed and verified through the real compiled CLI.
// All output files live in a temporary directory that is removed on exit.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  generatePqKeyBundle,
  generateSelfSignedCert,
  loadPqSigningKeys,
  signPdf,
} from "@e-sig/core";

const PQ_DIGEST_FAILURE = "post-quantum digest does not match the document — content altered";
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const cliPath = join(repoRoot, "packages", "esig-core", "dist", "bin", "esig.js");
const samplePath = join(repoRoot, "examples", "quickstart", "sample.pdf");
const workDir = await mkdtemp(join(tmpdir(), "esig-pq-seal-demo-"));

function verify(file, fingerprint) {
  return spawnSync(
    process.execPath,
    [
      cliPath,
      "verify",
      "--require-pq",
      "--expected-mldsa65-fpr",
      fingerprint,
      file,
    ],
    { cwd: workDir, encoding: "utf8" },
  );
}

function printVerification(file, fingerprint, result) {
  console.log(
    `$ node packages/esig-core/dist/bin/esig.js verify --require-pq ` +
      `--expected-mldsa65-fpr ${fingerprint} ${file}`,
  );
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
}

try {
  const unsigned = await readFile(samplePath);
  const cert = generateSelfSignedCert({ subjectName: "Example Organization" });
  console.log(`1. issued classical cert  sha256:${cert.fingerprint.slice(0, 16)}…`);

  const { bundle } = generatePqKeyBundle();
  const keys = loadPqSigningKeys(bundle);
  const result = await signPdf({
    pdf: unsigned,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    reason: "Post-quantum seal demonstration",
    location: "",
    contactInfo: "signer@example.com",
    name: "Example Signer",
    pqSeal: { keys },
  });

  assert.equal(result.pqSealed, true);
  assert.match(result.pqMldsa65Fpr ?? "", /^[0-9a-f]{64}$/);
  const fingerprint = result.pqMldsa65Fpr;
  await writeFile(join(workDir, "out.pdf"), result.signedPdf);
  console.log(`2. signed out.pdf       pqSealed=${result.pqSealed}`);
  console.log(`   ML-DSA-65 fingerprint=${fingerprint}`);

  console.log("3. verify sealed document");
  const valid = verify("out.pdf", fingerprint);
  printVerification("out.pdf", fingerprint, valid);
  assert.equal(valid.error, undefined);
  assert.equal(valid.status, 0, valid.stderr || valid.stdout);
  assert.match(valid.stdout, /out\.pdf: OK/);
  assert.match(valid.stdout, /post-quantum:\s+present, ok/);
  console.log("   ✓ classical + post-quantum verification passed");

  const tampered = Buffer.from(result.signedPdf);
  const tamperOffset = Math.floor(unsigned.length / 2);
  tampered[tamperOffset] ^= 0xff;
  await writeFile(join(workDir, "tampered.pdf"), tampered);
  console.log(`4. flipped byte ${tamperOffset} inside the signed PDF body`);

  console.log("5. verify tampered document (expected failure)");
  const invalid = verify("tampered.pdf", fingerprint);
  printVerification("tampered.pdf", fingerprint, invalid);
  assert.equal(invalid.error, undefined);
  assert.equal(invalid.status, 1, invalid.stderr || invalid.stdout);
  assert.match(invalid.stdout, /tampered\.pdf: FAIL/);
  assert.match(invalid.stdout, /digest valid:\s+no/);
  assert.match(invalid.stdout, /post-quantum:\s+present, FAIL/);
  assert.ok(invalid.stdout.includes(PQ_DIGEST_FAILURE));

  console.log("\npost-quantum seal demo passed ✓");
} finally {
  await rm(workDir, { recursive: true, force: true });
}
