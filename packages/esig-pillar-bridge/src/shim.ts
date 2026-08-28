// shim.ts
//
// The "verified interim" load path for @uuaid/pillar
// (docs/architecture/esig-mcp.md §17 "Packaging decision").
//
// Pillar's package.json declares real dependencies on libp2p (a dozen+
// packages) and native better-sqlite3. Importing the package's "." entry
// (`src/index.mjs`) re-exports `Mailbox`, `Pillar`, and `createTransport`,
// which statically pull that entire graph into the process — 763 modules,
// ~107 MiB RSS, even though this bridge only ever needs a handful of small,
// dependency-light modules: envelope sealing/opening (net/envelope.mjs,
// which itself transitively imports crypto/e2e.mjs), the keychain, JCS
// canonicalization, the carrier HTTP client, and tier grants.
//
// Node's package `exports` encapsulation only gates resolution of a bare
// specifier through the package's own name (`import "@uuaid/pillar/x"`) —
// it does NOT apply to an absolute `file://` URL constructed by the
// caller and imported directly. So: resolve the package's real on-disk
// root via `createRequire().resolve()` (which follows the package's own
// "." export, giving us `<pkg>/src/index.mjs`), take its `dirname` (the
// `src/` directory), and `import()` the files we need from THERE by
// `file://` path — never touching `index.mjs`, `mailbox.mjs`,
// `transport.mjs`, or anything that would drag in libp2p/better-sqlite3.
//
// This is scaffolding, not a pattern (§17): its removal is gated on
// Pillar source recovery at the vendor, not on Pillar's `exports` map
// growing subpaths. npm latest (`0.2.0-alpha.12`) DOES now export
// `./envelope`, `./keychain`, `./jcs`, `./tier`, `./carrier-client` (and
// `./e2e`) — the design doc's older "exports still {\".\"}\"" note holds
// only for `0.2.0-alpha.11`, not `alpha.12`. This module now PREFERS a
// bare subpath import (`import("@uuaid/pillar/envelope")`, resolved through
// Node's own package resolution + `exports` map) whenever the resolved
// package's `package.json` actually declares those subpaths — probed at
// runtime by reading that `package.json`, never assumed from the version
// string alone — and falls back to the `file://` deep import for a package
// that doesn't (alpha.11). Either route is only used AFTER the hash assert
// below has verified the exact bytes on disk at the resolved `root`, so
// both routes are pinned before use. The one exception: when a caller
// overrides `root` (test fixtures only, see {@link ResolvePillarOptions}),
// subpath routing is disabled unconditionally — a bare specifier resolves
// through Node's own module resolution, which does not know about a
// caller-supplied `root` override, so honoring it there would import a
// *different* file than the one just hash-asserted. That would defeat the
// entire point of the assert (hash what you're about to import, not
// something else that happens to share a version number).
//
// Two safety nets on top of the bypass itself:
//   1. A static import-graph walk from the entry files (and whatever they
//      transitively import from elsewhere in Pillar's own `src/` tree)
//      that refuses to proceed if any specifier — resolved path OR raw
//      text — mentions libp2p, better-sqlite3, mailbox, transport, or
//      index.mjs.
//   2. A startup hash assert over the FULL walked closure (not just the
//      entry files) — sha256 of every file the walk actually visited must
//      match a pinned table for the npm-published versions this bridge has
//      been measured against (0.2.0-alpha.11, 0.2.0-alpha.12, and
//      0.2.0-alpha.13 — the last tarball-verified 2026-08-28, see the
//      provenance note). A
//      version drift, a tampered file, OR a new transitive import that
//      isn't in the pinned table at all (its `expected` hash comes back
//      `undefined`, which never equals a real `actual` hash) throws unless
//      `ESIG_PILLAR_ALLOW_UNPINNED=1` (which still warns loudly to stderr
//      AND fires a structured audit event via `onAudit` — a deliberate,
//      visible, audited escape hatch, never a silent downgrade).
//
// Provenance note: the pinned hashes below were (re-)verified for this
// fix — RT-2026-08-28-01 finding F1 (the previous table pinned only the 5
// entry files, missing the transitively-imported `crypto/e2e.mjs`) — by
// running `npm pack @uuaid/pillar@0.2.0-alpha.11` and
// `npm pack @uuaid/pillar@0.2.0-alpha.12` in a scratch directory, then
// hashing every file `walkImportGraph` actually visits from each
// extracted tree. Verified 2026-08-28T02:35Z (UTC, `date -u`, the real
// clock at verification time — not a placeholder). Tarball shasums:
// alpha.11 sha256 31d841cc5deb5883546520c9bb550885ce9f5f64912886b7e0870141182afa87
// (matches the value already cited in docs/architecture/esig-mcp.md §17),
// alpha.12 sha256 6f94df7facc4e470a7f78f84f7a44ac863fb9bc64cf56979de780a9f5806800d.
// `crypto/e2e.mjs` is byte-identical between the two versions (same hash
// below); `net/carrier-client.mjs` is the only closure file that differs
// between them (a comment + an `onError` context-argument addition,
// alpha.12 only — no behavior change to anything this bridge calls); the
// rest are byte-identical, matching the design doc's "keychain/jcs/e2e/
// envelope byte-identical" note.
//
// alpha.13's block was PRE-STAGED (not tarball-measured at the time): the
// closure sha256 computed from the publish-source tree
// /Users/z/zz-station/pillar/uuaid-pillar-node @ a5c165889418… (HEAD, clean)
// on 2026-08-28T02:57Z (Esig-Lead, independently reproducing Uuaid-Lead's
// pre-measurement of 02:51Z). Preconditions measured, not assumed: no
// prepack/prepare/build in `scripts`, `files` ships `src` verbatim, and 5/5
// unchanged closure files match the tarball-derived alpha.12 pins
// byte-for-byte — empirically confirming git blob bytes == tarball bytes on
// this tree. Exactly ONE hash moves vs alpha.12 (identity/keychain.mjs — the
// localIdFromKey ask-back commit 1d68303); keychain's import edges are
// identical 9f1a021↔a5c1658, so the closure set stays at six; the version
// bump lives in package.json, which is not a closure member.
// VALID IFF alpha.13 publishes from a5c1658 or a descendant whose only delta
// is the package.json version bump — ANY other source change VOIDS the
// block. Tarball gate RUN 2026-08-28T03:20Z (Esig-Lead): downloaded
// https://registry.npmjs.org/@uuaid/pillar/-/pillar-0.2.0-alpha.13.tgz from
// the live registry — sha1 8bea09b6861d7be47873cd0bcf567fd4efc58c3f ==
// npm dist.shasum, 38 files, package.json version 0.2.0-alpha.13 (dist-tag
// latest) — and hashed 6/6 against the block below: exactly one mover vs
// alpha.12 (identity/keychain.mjs — the localIdFromKey ask-back commit
// 1d68303), the other five byte-identical to the alpha.12 pins. The
// publish condition held; the block is no longer provisional.
// Diagnostic note (saves a future misread): the startup throw is keyed on
// VERSION, not file — an unpinned version reports all six closure files as
// mismatched (`expected === undefined`), five of which are unchanged. Do not
// chase phantom diffs.

import { createRequire } from "node:module";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type {
  PillarCarrierClientCtor,
  PillarEnvelopeModule,
  PillarKeychainCtor,
  PillarModules,
  PillarTierModule,
} from "./pillar-types.js";
import type { PillarAuditCallback } from "./types.js";

/** The five modules this bridge imports directly, as paths relative to Pillar's `src/` dir. */
export const PILLAR_FILES = [
  "net/envelope.mjs",
  "identity/keychain.mjs",
  "identity/jcs.mjs",
  "net/carrier-client.mjs",
  "identity/tier.mjs",
] as const;

export type PillarFile = (typeof PILLAR_FILES)[number];

/** `PILLAR_FILES` entry -> the bare subpath specifier Pillar's own `exports` map declares for it (alpha.12+). */
const PILLAR_FILE_SUBPATHS: Record<PillarFile, string> = {
  "net/envelope.mjs": "@uuaid/pillar/envelope",
  "identity/keychain.mjs": "@uuaid/pillar/keychain",
  "identity/jcs.mjs": "@uuaid/pillar/jcs",
  "net/carrier-client.mjs": "@uuaid/pillar/carrier-client",
  "identity/tier.mjs": "@uuaid/pillar/tier",
};

/** `exports` map keys required before this bridge will prefer subpath imports over the `file://` bypass. */
const REQUIRED_EXPORT_SUBPATHS = ["./envelope", "./keychain", "./jcs", "./tier", "./carrier-client"] as const;

/**
 * Pinned sha256 of every file the static import-graph walk visits from the
 * five entry files, per `@uuaid/pillar` version — the FULL closure
 * (`walkImportGraph(PILLAR_FILES, root).visited`), not just the five entry
 * files themselves (RT-2026-08-28-01 F1: `net/envelope.mjs` transitively
 * imports `crypto/e2e.mjs`, which a five-file-only table left unpinned —
 * a tampered `crypto/e2e.mjs` would load unverified). Keys are POSIX-style
 * paths relative to Pillar's `src/` root, matching what
 * `path.relative(root, visitedAbsPath)` produces on this platform.
 * Computed from the real published tarballs (see the provenance note
 * above `npm pack @uuaid/pillar@0.2.0-alpha.11` /
 * `npm pack @uuaid/pillar@0.2.0-alpha.12`, hashed via `walkImportGraph`
 * over each extracted tree — not guessed, not hand-derived). 0.2.0-alpha.13
 * was pre-measured from the publish-source tree at a5c1658 and has since
 * been tarball-verified against the live registry artifact (2026-08-28,
 * see the provenance note).
 */
export const pinnedPillarHashes: Record<string, Record<string, string>> = JSON.parse(`{
  "0.2.0-alpha.11": {
    "net/envelope.mjs": "29f8399305192d68ba70ea0e598707dcef6e4de060dd8b026ce6d9655a038b07",
    "identity/keychain.mjs": "b74c3ae70869df7d81956b14ba627130d976378e7a85a1896e20f6ad4bd1aa9b",
    "identity/jcs.mjs": "31fb70dea7a5d2bfda4f3ec28301467132962a5a1c64dc99c8f6f89d87be33dc",
    "net/carrier-client.mjs": "ae9d71f7fdb119f68abcc22f21d4a23f4d87d85bd3da6e23778ed3f8e7557dbc",
    "identity/tier.mjs": "402cf7c4d3226745b6df872acf2cd17bb186e96ff1aeb816ff18f8a756aa3ba8",
    "crypto/e2e.mjs": "538965c2834c7bae4c508fd203ae757c3e2a286c4395dc90b0f5131cc123f159"
  },
  "0.2.0-alpha.12": {
    "net/envelope.mjs": "29f8399305192d68ba70ea0e598707dcef6e4de060dd8b026ce6d9655a038b07",
    "identity/keychain.mjs": "b74c3ae70869df7d81956b14ba627130d976378e7a85a1896e20f6ad4bd1aa9b",
    "identity/jcs.mjs": "31fb70dea7a5d2bfda4f3ec28301467132962a5a1c64dc99c8f6f89d87be33dc",
    "net/carrier-client.mjs": "633ee8248e92e8f98fb0fd2afe5c95cf45e5f3c86063cc930428d1e23745907d",
    "identity/tier.mjs": "402cf7c4d3226745b6df872acf2cd17bb186e96ff1aeb816ff18f8a756aa3ba8",
    "crypto/e2e.mjs": "538965c2834c7bae4c508fd203ae757c3e2a286c4395dc90b0f5131cc123f159"
  },
  "0.2.0-alpha.13": {
    "net/envelope.mjs": "29f8399305192d68ba70ea0e598707dcef6e4de060dd8b026ce6d9655a038b07",
    "identity/keychain.mjs": "0842c925cef3236eefec546e98f72bbbddd58a0f6defc7d7995ecec62badef7e",
    "identity/jcs.mjs": "31fb70dea7a5d2bfda4f3ec28301467132962a5a1c64dc99c8f6f89d87be33dc",
    "net/carrier-client.mjs": "633ee8248e92e8f98fb0fd2afe5c95cf45e5f3c86063cc930428d1e23745907d",
    "identity/tier.mjs": "402cf7c4d3226745b6df872acf2cd17bb186e96ff1aeb816ff18f8a756aa3ba8",
    "crypto/e2e.mjs": "538965c2834c7bae4c508fd203ae757c3e2a286c4395dc90b0f5131cc123f159"
  }
}`);

/** Substrings/patterns that must never appear in the resolved import graph. */
const BANNED_PATTERNS: Array<{ name: string; test: (specifierOrPath: string) => boolean }> = [
  { name: "libp2p", test: (s) => /libp2p/i.test(s) },
  { name: "better-sqlite3", test: (s) => /better-sqlite3/i.test(s) },
  { name: "mailbox", test: (s) => /(^|[\\/])mailbox([\\/.]|$)/i.test(s) },
  { name: "transport", test: (s) => /(^|[\\/])transport([\\/.]|$)/i.test(s) },
  { name: "index.mjs", test: (s) => /(^|[\\/])index\.mjs$/i.test(s) },
];

export class PillarIsolationError extends Error {
  constructor(public readonly violations: Array<{ file: string; specifier: string; reason: string }>) {
    super(
      `pillar-bridge: refused to load — the import graph references banned module(s): ${violations
        .map((v) => `${v.file} -> "${v.specifier}" (${v.reason})`)
        .join("; ")}`
    );
    this.name = "PillarIsolationError";
  }
}

export class PillarHashMismatchError extends Error {
  constructor(public readonly mismatches: Array<{ file: string; expected: string | undefined; actual: string }>) {
    super(
      `pillar-bridge: hash assert failed — ${mismatches
        .map((m) => `${m.file}: expected ${m.expected ?? "<no pin>"}, got ${m.actual}`)
        .join("; ")}. Set ESIG_PILLAR_ALLOW_UNPINNED=1 to bypass (loud warning, not silent).`
    );
    this.name = "PillarHashMismatchError";
  }
}

/** Matches `import ... from "spec"`, `export ... from "spec"`, and bare `import "spec"`. */
const IMPORT_SPECIFIER_RE = /(?:^|\n)\s*(?:import|export)\s[^'"\n]*?from\s+["']([^"']+)["']|(?:^|\n)\s*import\s+["']([^"']+)["']/g;

function extractSpecifiers(source: string): string[] {
  const out: string[] = [];
  for (const m of source.matchAll(IMPORT_SPECIFIER_RE)) {
    const spec = m[1] ?? m[2];
    if (spec) out.push(spec);
  }
  return out;
}

/**
 * Walk the static import graph starting from `entryFiles` (relative to
 * `srcRoot`), following only RELATIVE specifiers within `srcRoot` itself
 * (Pillar's own `src/` tree — we never recurse into `node_modules`).
 * Returns every banned reference found; an empty array means clear.
 */
export function walkImportGraph(
  entryFiles: readonly string[],
  srcRoot: string
): { visited: string[]; violations: Array<{ file: string; specifier: string; reason: string }> } {
  const visited = new Set<string>();
  const violations: Array<{ file: string; specifier: string; reason: string }> = [];
  const queue = [...entryFiles];

  while (queue.length) {
    const rel = queue.shift()!;
    const abs = path.normalize(path.join(srcRoot, rel));
    if (visited.has(abs)) continue;
    visited.add(abs);

    if (!existsSync(abs)) {
      violations.push({ file: rel, specifier: rel, reason: "file does not exist" });
      continue;
    }
    const source = readFileSync(abs, "utf-8");
    for (const spec of extractSpecifiers(source)) {
      for (const banned of BANNED_PATTERNS) {
        if (banned.test(spec)) {
          violations.push({ file: rel, specifier: spec, reason: `banned: ${banned.name}` });
        }
      }
      if (spec.startsWith(".") || spec.startsWith("/")) {
        const targetAbs = path.normalize(path.join(path.dirname(abs), spec));
        for (const banned of BANNED_PATTERNS) {
          if (banned.test(targetAbs)) {
            violations.push({ file: rel, specifier: spec, reason: `banned (resolved path): ${banned.name}` });
          }
        }
        const targetRel = path.relative(srcRoot, targetAbs);
        // Only keep walking within Pillar's own src tree.
        if (!targetRel.startsWith("..") && !path.isAbsolute(targetRel) && !visited.has(targetAbs)) {
          queue.push(targetRel);
        }
      }
      // Bare specifiers (node:*, @noble/curves/*) are not walked further —
      // they are outside "the pillar src tree" by definition, but the
      // text-based banned check above still runs on them.
    }
  }
  return { visited: [...visited], violations };
}

export interface ResolvePillarOptions {
  /**
   * Override the resolved `src/` root — used by tests to point at a fixture
   * directory (e.g. a tampered copy of one of the closure files) instead of
   * the real installed `@uuaid/pillar`. The override directory must sit next
   * to a `package.json` one level up (`<root>/../package.json`), exactly
   * like the real package layout, since `version` and the `exports` map are
   * both read from there. Setting this ALSO disables subpath-import
   * preference for this load (see the file header) — every file loaded is
   * imported via `file://` straight from `root`, so what gets hash-asserted
   * is always exactly what gets imported.
   */
  root?: string;
  /**
   * Fires once, only when `ESIG_PILLAR_ALLOW_UNPINNED=1` is set AND the hash
   * assert actually found a mismatch (i.e. only on the audited bypass path,
   * never on a normal clean load) — `{action:"pillar.unpinned_allowed",
   * version, files}`. esig-mcp wires this to its own audit store
   * (RT-2026-08-28-01 F2/G1: the bypass must be loud AND audited, not just
   * loud).
   */
  onAudit?: PillarAuditCallback;
}

export interface ResolvePillarResult {
  /** The package's `src/` directory (dirname of the resolved "." entry). */
  root: string;
  /** `@uuaid/pillar`'s own `version` field, read from `<root>/../package.json` via `fs`, never via `import`. */
  version: string;
  /**
   * True when `<root>/../package.json`'s own `exports` map declares
   * subpaths for every module in {@link PILLAR_FILE_SUBPATHS} (alpha.12+).
   * False for a package whose `exports` is still just `{"."}` (alpha.11),
   * in which case the bridge falls back to the `file://` deep import.
   */
  supportsSubpathExports: boolean;
}

/**
 * Resolve `@uuaid/pillar`'s on-disk `src/` root, version, and subpath-export
 * support WITHOUT importing anything.
 * `createRequire(import.meta.url).resolve("@uuaid/pillar")` follows the
 * package's own "." export (`./src/index.mjs`) and gives us its absolute
 * path; `dirname` of that is Pillar's `src/` directory — the root every file
 * path in {@link PILLAR_FILES} is relative to. `supportsSubpathExports` is
 * probed by reading the SAME `package.json`'s `exports` field, never
 * inferred from the version string.
 */
export function resolvePillar(opts: ResolvePillarOptions = {}): ResolvePillarResult {
  let root: string;
  if (opts.root) {
    root = opts.root;
  } else {
    const require = createRequire(import.meta.url);
    const indexPath = require.resolve("@uuaid/pillar");
    root = path.dirname(indexPath);
  }
  const packageJsonPath = path.join(root, "..", "package.json");
  if (!existsSync(packageJsonPath)) {
    throw new Error(`pillar-bridge: cannot read version — ${packageJsonPath} does not exist`);
  }
  const pkg = JSON.parse(readFileSync(packageJsonPath, "utf-8")) as { version?: string; exports?: unknown };
  if (!pkg.version) {
    throw new Error(`pillar-bridge: ${packageJsonPath} has no "version" field`);
  }
  const exportsMap =
    pkg.exports && typeof pkg.exports === "object" && !Array.isArray(pkg.exports)
      ? (pkg.exports as Record<string, unknown>)
      : null;
  const supportsSubpathExports = exportsMap !== null && REQUIRED_EXPORT_SUBPATHS.every((k) => k in exportsMap);
  return { root, version: pkg.version, supportsSubpathExports };
}

function sha256File(absPath: string): string {
  return createHash("sha256").update(readFileSync(absPath)).digest("hex");
}

/**
 * Hash-assert every file in `files` (paths relative to `root`) against
 * {@link pinnedPillarHashes} for `version`. Callers pass the FULL walked
 * import closure (`walkImportGraph(...).visited`, made root-relative), not
 * just the entry files — a visited file with no pinned entry at all comes
 * back with `expected: undefined`, which never matches a real hash, so an
 * unrecognized transitive import fails closed exactly like a tampered one
 * (RT-2026-08-28-01 F1). Throws {@link PillarHashMismatchError} on any
 * mismatch (including an entirely unpinned version) unless
 * `ESIG_PILLAR_ALLOW_UNPINNED=1`, in which case it prints a loud warning to
 * stderr, fires `onAudit({action:"pillar.unpinned_allowed", version,
 * files})` (`files` = the mismatched relative paths) if given, and returns
 * normally.
 */
export function assertPillarHashes(
  root: string,
  version: string,
  files: readonly string[],
  onAudit?: PillarAuditCallback
): void {
  const pinned = pinnedPillarHashes[version];
  const mismatches: Array<{ file: string; expected: string | undefined; actual: string }> = [];
  for (const file of files) {
    const actual = sha256File(path.join(root, file));
    const expected = pinned?.[file];
    if (actual !== expected) mismatches.push({ file, expected, actual });
  }
  if (mismatches.length === 0) return;
  if (process.env.ESIG_PILLAR_ALLOW_UNPINNED === "1") {
    console.error(
      `[esig-pillar-bridge] WARNING: @uuaid/pillar@${version} does not match any pinned hash ` +
        `(ESIG_PILLAR_ALLOW_UNPINNED=1 set — proceeding anyway, UNVERIFIED build):\n` +
        mismatches.map((m) => `  ${m.file}: expected ${m.expected ?? "<no pin>"}, got ${m.actual}`).join("\n")
    );
    onAudit?.({
      action: "pillar.unpinned_allowed",
      version,
      files: mismatches.map((m) => m.file),
    });
    return;
  }
  throw new PillarHashMismatchError(mismatches);
}

/**
 * Import one of {@link PILLAR_FILES} — via a bare subpath specifier
 * (`@uuaid/pillar/envelope`, resolved through Node's own package
 * resolution + `exports` map) when `useSubpath` is true, or via a
 * constructed `file://` URL straight from `root` otherwise. See the file
 * header for why `useSubpath` is forced false whenever `root` was
 * overridden.
 */
async function importPillarFile(root: string, file: PillarFile, useSubpath: boolean): Promise<Record<string, unknown>> {
  if (useSubpath) {
    const specifier = PILLAR_FILE_SUBPATHS[file];
    return (await import(/* @vite-ignore */ specifier)) as Record<string, unknown>;
  }
  const url = pathToFileURL(path.join(root, file)).href;
  return (await import(/* @vite-ignore */ url)) as Record<string, unknown>;
}

let cachedDefaultLoad: Promise<PillarModules> | null = null;

/**
 * Resolve, isolation-check, hash-assert, and import the Pillar modules this
 * bridge needs. Called with no arguments, the result is memoized (the fs
 * walk + hash assert only run once per process). Called with `{ root }`
 * (tests only), it always does a fresh, uncached load.
 */
export async function loadPillar(opts: ResolvePillarOptions = {}): Promise<PillarModules> {
  if (!opts.root && cachedDefaultLoad) return cachedDefaultLoad;
  const promise = doLoadPillar(opts);
  if (!opts.root) cachedDefaultLoad = promise;
  return promise;
}

async function doLoadPillar(opts: ResolvePillarOptions): Promise<PillarModules> {
  const { root, version, supportsSubpathExports } = resolvePillar(opts);

  const { visited, violations } = walkImportGraph(PILLAR_FILES, root);
  if (violations.length > 0) {
    throw new PillarIsolationError(violations);
  }

  // Hash-assert the FULL walked closure, not just the five entry files —
  // any visited file this platform doesn't have a pin for fails closed too
  // (see assertPillarHashes's doc comment).
  const closureFiles = visited.map((abs) => path.relative(root, abs)).sort();
  assertPillarHashes(root, version, closureFiles, opts.onAudit);

  // Subpath imports are only safe when `root` is the real resolved
  // installation — a caller-overridden `root` (test fixtures) would be
  // silently ignored by a bare specifier, which resolves independently
  // through Node's own module resolution. See the file header.
  const useSubpaths = supportsSubpathExports && !opts.root;

  const [envelopeMod, keychainMod, jcsMod, carrierMod] = await Promise.all([
    importPillarFile(root, "net/envelope.mjs", useSubpaths),
    importPillarFile(root, "identity/keychain.mjs", useSubpaths),
    importPillarFile(root, "identity/jcs.mjs", useSubpaths),
    importPillarFile(root, "net/carrier-client.mjs", useSubpaths),
  ]);

  let tier: PillarTierModule | null = null;
  if (existsSync(path.join(root, "identity/tier.mjs"))) {
    const tierMod = await importPillarFile(root, "identity/tier.mjs", useSubpaths);
    tier = tierMod as unknown as PillarTierModule;
  }

  return {
    root,
    version,
    envelope: envelopeMod as unknown as PillarEnvelopeModule,
    Keychain: keychainMod.Keychain as unknown as PillarKeychainCtor,
    jcs: jcsMod.jcs as unknown as (value: unknown) => string,
    CarrierClient: carrierMod.CarrierClient as unknown as PillarCarrierClientCtor,
    tier,
  };
}

/** Reset the memoized default load — test-only escape hatch. */
export function _resetPillarCacheForTests(): void {
  cachedDefaultLoad = null;
}
