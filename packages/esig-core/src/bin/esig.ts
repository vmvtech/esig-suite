#!/usr/bin/env node
// bin/esig.ts — the `esig` CLI: verify e-signed PDFs from a terminal or CI.
//
// Thin wrapper over verifyDocument() (classical PAdES/PKCS#7 + optional
// post-quantum hybrid seal, ./index.ts). There is no key material anywhere in
// this process — verification is a pure function of the PDF bytes plus,
// optionally, an expected identity pinned on the command line — so there is
// nothing here that could ever leak a secret. Every code path that can fail
// is caught and reported as text; nothing throws a raw stack to the user.
//
// stdout contract: `--json` writes exactly one line (the JSON array) and
// nothing else to stdout; human mode writes one block (or, with `--quiet`,
// one line) per file. All diagnostics (usage errors, I/O errors) go to
// stderr, mirroring esig-mcp's bin.ts stdout/stderr split.
//
// Exit codes:
//   0 — every file verified ok
//   1 — at least one file failed verification
//   2 — usage error or I/O error (bad flags, missing/unreadable file)

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyDocument, type DocumentVerification, type VerifyDocumentOptions } from "../index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
// dist/bin/esig.js -> package root is two levels up (dist/bin -> dist -> package
// root), same technique as esig-mcp's bin.ts (which is one level up from dist/).
const PACKAGE_VERSION: string = JSON.parse(
  readFileSync(path.join(here, "..", "..", "package.json"), "utf8"),
).version;

function usage(): string {
  return [
    "esig — verify e-signed PDFs (classical PAdES/PKCS#7 + optional post-quantum seal).",
    "",
    "Usage:",
    "  esig verify <file.pdf> [file2.pdf ...] [options]",
    "  esig --version",
    "  esig --help",
    "",
    "Options:",
    "  --json                        print a JSON array of {file, verification} and nothing else to stdout",
    "  --require-pq                  fail (per file) when the document has no valid post-quantum seal",
    "  --expected-uuaid <uuaid>      pin the seal's asserted UUAID; a mismatch fails",
    "  --expected-mldsa65-fpr <hex>  pin the seal's ML-DSA-65 signer fingerprint; a mismatch fails",
    "  --quiet                       one line per file instead of the full block (human mode only)",
    "",
    "Exit codes:",
    "  0  every file verified ok",
    "  1  at least one file failed verification",
    "  2  usage error or I/O error (bad flags, missing/unreadable file)",
    "",
    "Examples:",
    "  esig verify signed.pdf",
    "  esig verify signed1.pdf signed2.pdf --json",
    "  esig verify signed.pdf --require-pq --expected-uuaid uuaid:acme:agent:018f...",
  ].join("\n");
}

class UsageError extends Error {}

interface ParsedArgs {
  files: string[];
  json: boolean;
  quiet: boolean;
  verifyOpts: VerifyDocumentOptions;
}

function parseVerifyArgs(argv: string[]): ParsedArgs {
  const files: string[] = [];
  let json = false;
  let quiet = false;
  const verifyOpts: VerifyDocumentOptions = {};

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--json":
        json = true;
        break;
      case "--quiet":
        quiet = true;
        break;
      case "--require-pq":
        verifyOpts.requirePq = true;
        break;
      case "--expected-uuaid": {
        const value = argv[++i];
        if (value === undefined) throw new UsageError("--expected-uuaid requires a value");
        verifyOpts.expectedUuaid = value;
        break;
      }
      case "--expected-mldsa65-fpr": {
        const value = argv[++i];
        if (value === undefined) throw new UsageError("--expected-mldsa65-fpr requires a value");
        verifyOpts.expectedMldsa65Fpr = value;
        break;
      }
      default:
        if (arg.startsWith("--")) {
          throw new UsageError(`unknown option: ${arg}`);
        }
        files.push(arg);
    }
  }

  if (files.length === 0) {
    throw new UsageError("no files given — usage: esig verify <file.pdf> [more files...]");
  }

  return { files, json, quiet, verifyOpts };
}

function yn(v: boolean | undefined): string {
  return v === undefined ? "n/a" : v ? "yes" : "no";
}

function formatHuman(file: string, v: DocumentVerification): string {
  const { classical, postQuantum } = v;
  const lines: string[] = [`${file}: ${v.ok ? "OK" : "FAIL"}`];
  lines.push(`  digest valid:      ${yn(classical.digestValid)}`);
  lines.push(`  signature valid:   ${yn(classical.signatureValid)}`);
  lines.push(`  signer:            ${classical.signerCommonName ?? "(unknown)"}`);
  lines.push(
    `  timestamped:       ${classical.timestamped ? `yes (${classical.timestampTime ?? "time unknown"})` : "no"}`,
  );
  if (postQuantum.present) {
    lines.push(`  post-quantum:      present, ${postQuantum.ok ? "ok" : "FAIL"}`);
    lines.push(`    mldsa65Fpr:      ${postQuantum.mldsa65Fpr ?? "(none)"}`);
    lines.push(`    uuaid:           ${postQuantum.uuaid ?? "(none)"}`);
  } else {
    lines.push("  post-quantum:      not present");
  }
  const failures = [...classical.failures, ...postQuantum.failures];
  lines.push(`  failures:          ${failures.length === 0 ? "(none)" : ""}`);
  for (const f of failures) lines.push(`    - ${f}`);
  return lines.join("\n");
}

function formatQuiet(file: string, v: DocumentVerification): string {
  if (v.ok) return `${file}: OK`;
  const failures = [...v.classical.failures, ...v.postQuantum.failures];
  return `${file}: FAIL (${failures.join("; ") || "unknown reason"})`;
}

/** Runs `verify`; returns the process exit code. Never throws. */
function runVerify(args: ParsedArgs): number {
  const results: Array<{ file: string; verification: DocumentVerification }> = [];

  for (const file of args.files) {
    let bytes: Buffer;
    try {
      bytes = readFileSync(file);
    } catch (e) {
      process.stderr.write(`esig verify: cannot read ${file}: ${(e as Error).message}\n`);
      return 2;
    }

    let verification: DocumentVerification;
    try {
      verification = verifyDocument(bytes, args.verifyOpts);
    } catch (e) {
      // verifyDocument/verifyPqSeal are documented to never throw; this is a
      // last-resort guard so a caller never sees a raw stack trace.
      const message = `internal error: ${e instanceof Error ? e.message : String(e)}`;
      verification = {
        ok: false,
        classical: { ok: false, timestamped: false, failures: [message] },
        postQuantum: { present: false, ok: false, failures: [message] },
      };
    }
    results.push({ file, verification });
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(results)}\n`);
  } else {
    for (const { file, verification } of results) {
      const line = args.quiet ? formatQuiet(file, verification) : formatHuman(file, verification);
      process.stdout.write(`${line}\n`);
    }
  }

  return results.every((r) => r.verification.ok) ? 0 : 1;
}

function main(): void {
  const argv = process.argv.slice(2);

  if (argv.includes("--version")) {
    process.stdout.write(`${PACKAGE_VERSION}\n`);
    process.exitCode = 0;
    return;
  }
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(`${usage()}\n`);
    process.exitCode = 0;
    return;
  }
  if (argv.length === 0) {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 2;
    return;
  }

  const [command, ...rest] = argv;
  if (command !== "verify") {
    process.stderr.write(`esig: unknown command "${command}"\n\n${usage()}\n`);
    process.exitCode = 2;
    return;
  }

  try {
    const args = parseVerifyArgs(rest);
    process.exitCode = runVerify(args);
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`esig verify: ${e.message}\n`);
      process.exitCode = 2;
      return;
    }
    process.stderr.write(`esig: fatal: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  }
}

main();
