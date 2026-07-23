// scripts/publish-preflight.mjs — release gate + idempotent publisher for publish.yml.
//
// Why this exists: the release workflow publishes seven packages sequentially.
// OIDC trusted publishing cannot FIRST-publish a new package name (npm only
// lets you configure a trusted publisher on an existing package), so a release
// containing a never-published name used to fail mid-chain and leave the
// registry inconsistent (early packages at the new version, later ones absent).
//
// Modes:
//   node scripts/publish-preflight.mjs
//     Preflight only. Fails BEFORE anything is published if:
//       - any publishable workspace name does not exist on its registry
//         (needs a one-time manual publish + trusted-publisher setup), or
//       - a prerelease version has no explicit publishConfig.tag (would be
//         installed by default as `latest`), or
//       - no workspace has a new version to publish (forgotten version bump —
//         a release that publishes nothing is treated as a mistake), or
//       - the registry cannot be reached (never publish blind).
//   node scripts/publish-preflight.mjs --publish
//     Re-runs the same checks, then publishes each package whose current
//     version is not yet on the registry, dependencies first. Versions that
//     are already live are SKIPPED, so re-running the workflow after a
//     partial failure converges instead of dying on EPUBLISHCONFLICT.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_REGISTRY = "https://registry.npmjs.org";

/** Expand root package.json `workspaces` globs (supports "dir/*" and literal dirs). */
function expandWorkspaceGlobs(rootDir, globs) {
  const dirs = [];
  for (const glob of globs) {
    if (glob.endsWith("/*")) {
      const base = join(rootDir, glob.slice(0, -2));
      if (!existsSync(base)) continue;
      for (const entry of readdirSync(base, { withFileTypes: true })) {
        if (entry.isDirectory()) dirs.push(join(base, entry.name));
      }
    } else {
      dirs.push(join(rootDir, glob));
    }
  }
  return dirs;
}

/** Stable topological order: intra-workspace dependencies before dependents. */
export function topoSort(pkgs) {
  const byName = new Map(pkgs.map((p) => [p.name, p]));
  const sorted = [];
  const visiting = new Set();
  const done = new Set();
  const visit = (pkg) => {
    if (done.has(pkg.name)) return;
    if (visiting.has(pkg.name)) return; // cycle — keep input order for the rest
    visiting.add(pkg.name);
    for (const dep of pkg.workspaceDeps) {
      const target = byName.get(dep);
      if (target) visit(target);
    }
    visiting.delete(pkg.name);
    done.add(pkg.name);
    sorted.push(pkg);
  };
  for (const pkg of [...pkgs].sort((a, b) => a.name.localeCompare(b.name))) visit(pkg);
  return sorted;
}

/**
 * Discover publishable workspace packages (private ones excluded), in
 * publish order (dependencies first). Reads the root `workspaces` globs so a
 * future package is picked up automatically — no hand-maintained list.
 */
export function discoverPackages(rootDir) {
  const root = JSON.parse(readFileSync(join(rootDir, "package.json"), "utf8"));
  const pkgs = [];
  for (const dir of expandWorkspaceGlobs(rootDir, root.workspaces ?? [])) {
    const manifestPath = join(dir, "package.json");
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.private === true) continue;
    pkgs.push({
      name: manifest.name,
      version: manifest.version,
      registry: (manifest.publishConfig?.registry ?? DEFAULT_REGISTRY).replace(/\/$/, ""),
      publishTag: manifest.publishConfig?.tag,
      workspaceDeps: [], // filled below, once all names are known
      manifest,
    });
  }
  const names = new Set(pkgs.map((p) => p.name));
  for (const pkg of pkgs) {
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
      for (const dep of Object.keys(pkg.manifest[field] ?? {})) {
        if (names.has(dep)) pkg.workspaceDeps.push(dep);
      }
    }
  }
  return topoSort(pkgs);
}

/** Dist-tag for a package, or an error string. Prereleases MUST be explicit. */
export function distTagFor(pkg) {
  if (pkg.publishTag) return { tag: pkg.publishTag };
  if (pkg.version.includes("-")) {
    return {
      error:
        `${pkg.name}@${pkg.version} is a prerelease but has no publishConfig.tag — ` +
        `it would be published as "latest". Set publishConfig.tag in its package.json.`,
    };
  }
  return { tag: "latest" };
}

/** Fetch registry state for one package name: { exists, versions:Set } */
export async function fetchRegistryState(pkg, fetchImpl = fetch) {
  const res = await fetchImpl(`${pkg.registry}/${encodeURIComponent(pkg.name)}`, {
    headers: { accept: "application/vnd.npm.install-v1+json" }, // abbreviated doc
  });
  if (res.status === 404) return { exists: false, versions: new Set() };
  if (!res.ok) {
    throw new Error(`registry check for ${pkg.name} failed: HTTP ${res.status}`);
  }
  const doc = await res.json();
  return { exists: true, versions: new Set(Object.keys(doc.versions ?? {})) };
}

/**
 * Compute the publish plan. Returns { errors: string[], actions: [{pkg, action, tag?, reason}] }.
 * Any error means: publish NOTHING.
 */
export function planPublishes(pkgs, registryStates) {
  const errors = [];
  const actions = [];
  for (const pkg of pkgs) {
    const state = registryStates.get(pkg.name);
    const { tag, error } = distTagFor(pkg);
    if (error) errors.push(error);
    if (!state.exists) {
      errors.push(
        `${pkg.name} does not exist on ${pkg.registry} — OIDC trusted publishing cannot ` +
          `first-publish a new name. Publish it once manually (npm publish from the package ` +
          `dir with a granular token), configure its Trusted Publisher ` +
          `(vmvtech / esig-suite / publish.yml), then re-run this workflow.`,
      );
      continue;
    }
    if (state.versions.has(pkg.version)) {
      actions.push({ pkg, action: "skip", reason: `${pkg.version} already on registry` });
    } else {
      actions.push({ pkg, action: "publish", tag, reason: `${pkg.version} is new` });
    }
  }
  if (errors.length === 0 && !actions.some((a) => a.action === "publish")) {
    errors.push(
      "Nothing to publish: every workspace version is already on the registry. " +
        "Did you forget to bump versions before releasing?",
    );
  }
  return { errors, actions };
}

async function computePlan(rootDir) {
  const pkgs = discoverPackages(rootDir);
  const states = new Map();
  await Promise.all(
    pkgs.map(async (pkg) => states.set(pkg.name, await fetchRegistryState(pkg))),
  );
  return planPublishes(pkgs, states);
}

function printPlan({ errors, actions }) {
  for (const { pkg, action, tag, reason } of actions) {
    const tagNote = action === "publish" && tag !== "latest" ? ` (tag: ${tag})` : "";
    console.log(`  ${action === "publish" ? "→ publish" : "· skip   "} ${pkg.name}@${pkg.version}${tagNote} — ${reason}`);
  }
  for (const error of errors) console.error(`\n✗ ${error}`);
}

async function main() {
  const publishMode = process.argv.includes("--publish");
  const rootDir = process.cwd();
  const plan = await computePlan(rootDir);
  console.log(publishMode ? "Publish plan:" : "Preflight publish plan:");
  printPlan(plan);
  if (plan.errors.length > 0) {
    console.error("\nPreflight FAILED — nothing was published.");
    process.exit(1);
  }
  if (!publishMode) {
    console.log("\nPreflight OK.");
    return;
  }
  for (const { pkg, action, tag } of plan.actions) {
    if (action !== "publish") continue;
    const args = ["publish", "-w", pkg.name, "--access", "public"];
    // The explicit --tag flag is LOAD-BEARING, not belt-and-braces: npm ignores
    // a workspace's publishConfig.tag when publishing via `npm publish -w`
    // (verified on npm 10.9.3 and 11.5.1 — dry-run shows "tag latest" for
    // @e-sig/uaid-exch despite publishConfig.tag "preview"). Without this flag
    // the preview package would be published as `latest`.
    if (tag !== "latest") args.push("--tag", tag);
    console.log(`\n$ npm ${args.join(" ")}`);
    const res = spawnSync("npm", args, { stdio: "inherit" });
    if (res.status !== 0) {
      console.error(
        `\n✗ publish of ${pkg.name}@${pkg.version} failed (exit ${res.status}). ` +
          "Fix the cause and re-run this workflow: already-published packages will be " +
          "skipped and the remaining ones published.",
      );
      process.exit(res.status ?? 1);
    }
  }
  console.log("\nAll packages published (or already current).");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`\n✗ ${err.message ?? err}`);
    console.error("Preflight FAILED — nothing was published.");
    process.exit(1);
  });
}
