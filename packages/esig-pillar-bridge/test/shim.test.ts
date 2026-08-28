import { describe, expect, it } from "vitest";
import { mkdtempSync, cpSync, appendFileSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

import {
  loadPillar,
  resolvePillar,
  walkImportGraph,
  pinnedPillarHashes,
  PILLAR_FILES,
  PillarHashMismatchError,
  PillarIsolationError,
  _resetPillarCacheForTests,
} from "../src/shim.js";
import type { PillarAuditEvent } from "../src/types.js";

const DIST_INDEX = fileURLToPath(new URL("../dist/index.js", import.meta.url));

describe("shim: resolvePillar + loadPillar (real installed @uuaid/pillar)", () => {
  it("resolves the real installed package root/version", () => {
    const { root, version } = resolvePillar();
    expect(existsSync(path.join(root, "net/envelope.mjs"))).toBe(true);
    expect(Object.keys(pinnedPillarHashes)).toContain(version);
  });

  it("loads real alpha.12 from node_modules and the hash assert passes", async () => {
    _resetPillarCacheForTests();
    const pillar = await loadPillar();
    expect(pillar.version).toBe("0.2.0-alpha.12");
    expect(typeof pillar.envelope.seal).toBe("function");
    expect(typeof pillar.envelope.open).toBe("function");
    expect(typeof pillar.envelope.decrypt).toBe("function");
    expect(typeof pillar.envelope.envelopeSha).toBe("function");
    expect(typeof pillar.envelope.keychainSeed).toBe("function");
    expect(typeof pillar.envelope.mkEnvelopeId).toBe("function");
    expect(typeof pillar.Keychain).toBe("function");
    expect(typeof pillar.Keychain._localIdFromKey).toBe("function");
    expect(typeof pillar.jcs).toBe("function");
    expect(typeof pillar.CarrierClient).toBe("function");
    expect(pillar.tier).not.toBeNull();
    expect(pillar.tier?.TIER_DEFAULTS.community.maxBodyBytes).toBe(512 * 1024);
  });

  it("the static import graph over the five files finds no banned module", () => {
    const { root } = resolvePillar();
    const { violations, visited } = walkImportGraph(PILLAR_FILES, root);
    expect(violations).toEqual([]);
    // Sanity: the walk actually traversed something beyond the five entries
    // (e2e.mjs, transitively imported by envelope.mjs).
    expect(visited.length).toBeGreaterThan(PILLAR_FILES.length);
  });

  it("a tampered copy of envelope.mjs (real alpha.12 tree, one file mutated) is refused", async () => {
    const { root, version } = resolvePillar();
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-tamper-"));
    // Mirror the real layout: <tmp>/package.json (version) + <tmp>/src/... (root override).
    cpSync(path.join(root, ".."), tmp, { recursive: true });
    const tamperedRoot = path.join(tmp, "src");
    appendFileSync(path.join(tamperedRoot, "net/envelope.mjs"), "\n// tampered for test\n");

    await expect(loadPillar({ root: tamperedRoot })).rejects.toThrow(PillarHashMismatchError);

    // Confirm the OTHER four (untouched) files still hash-match the pinned
    // table exactly — it is specifically the tampered file that fails, not
    // the whole table (the assert must be per-file, not all-or-nothing).
    for (const file of PILLAR_FILES) {
      const actual = createHash("sha256").update(readFileSync(path.join(tamperedRoot, file))).digest("hex");
      const expected = pinnedPillarHashes[version][file];
      if (file === "net/envelope.mjs") {
        expect(actual).not.toBe(expected);
      } else {
        expect(actual).toBe(expected);
      }
    }
  });

  it("ESIG_PILLAR_ALLOW_UNPINNED=1 downgrades the same tamper to a warning, not a throw", async () => {
    const { root } = resolvePillar();
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-tamper-allow-"));
    cpSync(path.join(root, ".."), tmp, { recursive: true });
    const tamperedRoot = path.join(tmp, "src");
    appendFileSync(path.join(tamperedRoot, "net/envelope.mjs"), "\n// tampered for test\n");

    const prev = process.env.ESIG_PILLAR_ALLOW_UNPINNED;
    process.env.ESIG_PILLAR_ALLOW_UNPINNED = "1";
    try {
      const pillar = await loadPillar({ root: tamperedRoot });
      expect(typeof pillar.envelope.seal).toBe("function");
    } finally {
      if (prev === undefined) delete process.env.ESIG_PILLAR_ALLOW_UNPINNED;
      else process.env.ESIG_PILLAR_ALLOW_UNPINNED = prev;
    }
  });
});

describe("shim: RT-2026-08-28-01 F1 — pin the FULL closure, not just the five entry files", () => {
  it("the pinned table's keys exactly equal the walked closure — for the resolved version, and for alpha.11, alpha.12, and pre-staged alpha.13", () => {
    const { root, version } = resolvePillar();
    const { visited } = walkImportGraph(PILLAR_FILES, root);
    const closureRel = visited.map((v) => path.relative(root, v)).sort();

    // The resolved (installed) version's table matches the real walked closure exactly.
    expect(Object.keys(pinnedPillarHashes[version]).sort()).toEqual(closureRel);

    // All pinned versions declare the SAME file set — they differ only in
    // file CONTENTS (alpha.11→alpha.12: net/carrier-client.mjs; alpha.12→
    // alpha.13 pre-stage: identity/keychain.mjs), never in which files
    // exist in the closure. A future transitive import that lands in one
    // version's table but not another's would fail this before it could
    // fail closed at runtime.
    expect(Object.keys(pinnedPillarHashes["0.2.0-alpha.11"]).sort()).toEqual(closureRel);
    expect(Object.keys(pinnedPillarHashes["0.2.0-alpha.12"]).sort()).toEqual(closureRel);
    expect(Object.keys(pinnedPillarHashes["0.2.0-alpha.13"]).sort()).toEqual(closureRel);
  });

  it("pre-staged alpha.13 = alpha.12 + exactly ONE hash move (identity/keychain.mjs) — the void-if gate for source riding the version bump", () => {
    const v12 = pinnedPillarHashes["0.2.0-alpha.12"];
    const v13 = pinnedPillarHashes["0.2.0-alpha.13"];
    expect(Object.keys(v13).sort()).toEqual(Object.keys(v12).sort());
    expect(Object.keys(v12).filter((f) => v12[f] !== v13[f])).toEqual(["identity/keychain.mjs"]);
    expect(v13["identity/keychain.mjs"]).toBe(
      "0842c925cef3236eefec546e98f72bbbddd58a0f6defc7d7995ecec62badef7e",
    );
  });

  it("a brand-new transitive import with no pinned table entry at all fails closed", async () => {
    const { root } = resolvePillar();
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-new-transitive-"));
    cpSync(path.join(root, ".."), tmp, { recursive: true });
    const tamperedRoot = path.join(tmp, "src");
    // Simulate a hypothetical future Pillar release adding a new transitive
    // file this table has never seen — walkImportGraph will visit it (since
    // one of the five entry files now imports it), but pinnedPillarHashes
    // has no entry for it at all: `expected` comes back `undefined`, which
    // never equals a real `actual` hash, so this must fail exactly like a
    // tampered file — never load unpinned by omission.
    writeFileSync(path.join(tamperedRoot, "identity/brand-new-helper.mjs"), "export const helper = 1;\n");
    appendFileSync(
      path.join(tamperedRoot, "identity/keychain.mjs"),
      '\nimport { helper } from "./brand-new-helper.mjs";\n'
    );

    await expect(loadPillar({ root: tamperedRoot })).rejects.toThrow(PillarHashMismatchError);
  });

  it("a tampered copy of crypto/e2e.mjs — transitively imported by net/envelope.mjs, not itself a PILLAR_FILES entry — is refused (the bug this fixes: the old table only pinned the five entry files and missed this one)", async () => {
    const { root, version } = resolvePillar();
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-tamper-e2e-"));
    cpSync(path.join(root, ".."), tmp, { recursive: true });
    const tamperedRoot = path.join(tmp, "src");
    appendFileSync(path.join(tamperedRoot, "crypto/e2e.mjs"), "\n// tampered e2e.mjs for F1 regression test\n");

    await expect(loadPillar({ root: tamperedRoot })).rejects.toThrow(PillarHashMismatchError);

    // Confirm it is specifically crypto/e2e.mjs that mismatches, and every
    // PILLAR_FILES entry (including net/envelope.mjs, which imports it) is
    // untouched and still hash-matches.
    const actualE2e = createHash("sha256").update(readFileSync(path.join(tamperedRoot, "crypto/e2e.mjs"))).digest("hex");
    expect(actualE2e).not.toBe(pinnedPillarHashes[version]["crypto/e2e.mjs"]);
    for (const file of PILLAR_FILES) {
      const actual = createHash("sha256").update(readFileSync(path.join(tamperedRoot, file))).digest("hex");
      expect(actual).toBe(pinnedPillarHashes[version][file]);
    }
  });
});

describe("shim: RT-2026-08-28-01 F2 — ESIG_PILLAR_ALLOW_UNPINNED=1 is loud AND audited", () => {
  it("fires onAudit with {action:'pillar.unpinned_allowed', version, files} alongside the stderr warning, and only on the bypass path", async () => {
    const { root, version } = resolvePillar();
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-tamper-audit-"));
    cpSync(path.join(root, ".."), tmp, { recursive: true });
    const tamperedRoot = path.join(tmp, "src");
    appendFileSync(path.join(tamperedRoot, "net/envelope.mjs"), "\n// tampered for F2 audit test\n");

    const prev = process.env.ESIG_PILLAR_ALLOW_UNPINNED;
    process.env.ESIG_PILLAR_ALLOW_UNPINNED = "1";
    const events: PillarAuditEvent[] = [];
    try {
      const pillar = await loadPillar({ root: tamperedRoot, onAudit: (e) => events.push(e) });
      expect(typeof pillar.envelope.seal).toBe("function");
    } finally {
      if (prev === undefined) delete process.env.ESIG_PILLAR_ALLOW_UNPINNED;
      else process.env.ESIG_PILLAR_ALLOW_UNPINNED = prev;
    }

    expect(events).toHaveLength(1);
    expect(events[0].action).toBe("pillar.unpinned_allowed");
    expect(events[0].version).toBe(version);
    expect(events[0].files).toEqual(["net/envelope.mjs"]);
  });

  it("does NOT fire onAudit on a normal, clean load (no mismatch to bypass)", async () => {
    _resetPillarCacheForTests();
    const events: PillarAuditEvent[] = [];
    await loadPillar({ onAudit: (e) => events.push(e) });
    expect(events).toHaveLength(0);
  });
});

describe("shim: RT-2026-08-28-01 F3 — subpath exports preferred when supported, file:// fallback otherwise", () => {
  it("resolvePillar reports supportsSubpathExports true for the installed alpha.12 (its package.json really does declare the six subpaths)", () => {
    const { supportsSubpathExports } = resolvePillar();
    expect(supportsSubpathExports).toBe(true);
  });

  it("overriding root forces the file:// route even when the copied package.json declares subpath exports — hash-assert and import always agree on which exact bytes", async () => {
    const { root } = resolvePillar();
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-subpath-override-"));
    cpSync(path.join(root, ".."), tmp, { recursive: true });
    const tamperedRoot = path.join(tmp, "src");
    // A distinguishing, functionally-inert marker — proves the OVERRIDE
    // ROOT's copy was imported, not the real installed package (which a
    // subpath specifier would resolve to, ignoring `root` entirely).
    appendFileSync(
      path.join(tamperedRoot, "net/envelope.mjs"),
      '\nexport const __TEST_ROOT_OVERRIDE_MARKER__ = "from-override-root";\n'
    );

    const prev = process.env.ESIG_PILLAR_ALLOW_UNPINNED;
    process.env.ESIG_PILLAR_ALLOW_UNPINNED = "1"; // the marker changes the hash too — bypass, we're testing routing, not the assert
    try {
      const pillar = await loadPillar({ root: tamperedRoot });
      expect((pillar.envelope as unknown as Record<string, unknown>).__TEST_ROOT_OVERRIDE_MARKER__).toBe("from-override-root");
    } finally {
      if (prev === undefined) delete process.env.ESIG_PILLAR_ALLOW_UNPINNED;
      else process.env.ESIG_PILLAR_ALLOW_UNPINNED = prev;
    }
  });
});

describe("shim: walkImportGraph refuses banned specifiers (synthetic fixture)", () => {
  it("refuses a relative import into a file named mailbox/transport, and a bare libp2p/better-sqlite3 specifier", () => {
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-graph-fixture-"));
    writeFileSync(
      path.join(tmp, "entry-a.mjs"),
      `import { x } from "../mailbox/mailbox.mjs";\nexport const a = 1;\n`
    );
    writeFileSync(path.join(tmp, "entry-b.mjs"), `import "libp2p";\nexport const b = 1;\n`);
    writeFileSync(
      path.join(tmp, "entry-c.mjs"),
      `import Database from "better-sqlite3";\nexport const c = 1;\n`
    );
    writeFileSync(path.join(tmp, "entry-clean.mjs"), `export const clean = 1;\n`);

    const { violations } = walkImportGraph(
      ["entry-a.mjs", "entry-b.mjs", "entry-c.mjs", "entry-clean.mjs"],
      tmp
    );
    const reasons = violations.map((v) => v.reason);
    expect(reasons.some((r) => r.includes("mailbox"))).toBe(true);
    expect(reasons.some((r) => r.includes("libp2p"))).toBe(true);
    expect(reasons.some((r) => r.includes("better-sqlite3"))).toBe(true);
  });

  it("clears a clean synthetic graph", () => {
    const tmp = mkdtempSync(path.join(tmpdir(), "pillar-graph-clean-"));
    writeFileSync(path.join(tmp, "a.mjs"), `import { b } from "./b.mjs";\nexport const a = 1;\n`);
    writeFileSync(path.join(tmp, "b.mjs"), `import { createHash } from "node:crypto";\nexport const b = 1;\n`);
    const { violations, visited } = walkImportGraph(["a.mjs"], tmp);
    expect(violations).toEqual([]);
    expect(visited.length).toBe(2);
  });
});

describe("shim: process isolation (measured, child process)", () => {
  // NOTE: a bare /sqlite/i match against process.report's sharedObjects is
  // NOT sufficient on macOS — every plain node process (zero of our code
  // loaded) already links /usr/lib/libsqlite3.dylib and the private
  // PoirotSQLite framework as OS-level noise, unrelated to better-sqlite3's
  // native addon (measured live on this machine: `node -e
  // "console.log(process.report.getReport().sharedObjects.filter(s=>/sqlite/i.test(s)))"`
  // with NO imports at all prints exactly those two paths). The correct
  // measurement is a DIFFERENCE against a baseline child process, not a
  // bare pattern match — this is the same "state what the instrument can
  // physically record" discipline as any other negative-evidence claim.
  function sharedObjectsOf(script: string): string[] {
    const wrapped = `
      (${script.trim()})().then(() => {
        process.stdout.write(JSON.stringify(process.report.getReport().sharedObjects || []));
      }).catch((err) => {
        process.stderr.write(String((err && err.stack) || err));
        process.exit(1);
      });
    `;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", wrapped], {
      encoding: "utf-8",
      timeout: 20_000,
    });
    if (result.status !== 0) {
      throw new Error(`child process failed (status ${result.status}): ${result.stderr}`);
    }
    return JSON.parse(result.stdout.trim());
  }

  it("importing the built shim loads no NEW shared object matching better-sqlite3 or libp2p, beyond baseline OS noise", () => {
    if (!existsSync(DIST_INDEX)) {
      throw new Error(`dist not built at ${DIST_INDEX} — run "npm run build -w @e-sig/pillar-bridge" first`);
    }
    const baseline = sharedObjectsOf("async () => {}");
    const withShim = sharedObjectsOf(
      `async () => { const mod = await import(${JSON.stringify(pathToFileURL(DIST_INDEX).href)}); await mod.loadPillar(); }`
    );
    const baselineSet = new Set(baseline);
    const newlyLoaded = withShim.filter((s) => !baselineSet.has(s));

    const newSqlite = newlyLoaded.filter((s) => /sqlite/i.test(s));
    const newLibp2p = newlyLoaded.filter((s) => /libp2p/i.test(s));
    expect(newSqlite, `newly-loaded shared objects beyond baseline: ${JSON.stringify(newlyLoaded)}`).toEqual([]);
    expect(newLibp2p, `newly-loaded shared objects beyond baseline: ${JSON.stringify(newlyLoaded)}`).toEqual([]);

    // Sanity: the baseline itself DOES carry the macOS system sqlite noise —
    // proving the filter above is discriminating on NEW objects, not
    // vacuously passing because nothing was ever measured (§4.12 class).
    if (process.platform === "darwin") {
      expect(baseline.some((s) => /sqlite/i.test(s))).toBe(true);
    }
  });
});
