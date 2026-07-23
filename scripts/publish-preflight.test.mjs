// Unit tests for scripts/publish-preflight.mjs — the release gate that keeps
// publish.yml from half-publishing a release. No network: registry access is
// exercised through an injected fetch stub, discovery through tmp fixtures.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  discoverPackages,
  topoSort,
  distTagFor,
  fetchRegistryState,
  planPublishes,
} from "./publish-preflight.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function writeManifest(dir, manifest) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
}

describe("discoverPackages", () => {
  let fixture;

  beforeAll(() => {
    fixture = mkdtempSync(join(tmpdir(), "preflight-"));
    writeManifest(fixture, {
      name: "fixture-root",
      private: true,
      workspaces: ["packages/*", "examples/app"],
    });
    writeManifest(join(fixture, "packages/a"), {
      name: "@fix/a",
      version: "1.0.0",
      peerDependencies: { "@fix/b": "^1.0.0", "left-pad": "^1.0.0" },
    });
    writeManifest(join(fixture, "packages/b"), {
      name: "@fix/b",
      version: "2.0.0",
      publishConfig: { registry: "https://registry.example.com/", tag: "next" },
    });
    writeManifest(join(fixture, "packages/secret"), {
      name: "@fix/secret",
      version: "0.0.1",
      private: true,
    });
    mkdirSync(join(fixture, "packages/not-a-package"), { recursive: true });
    writeManifest(join(fixture, "examples/app"), {
      name: "fixture-app",
      version: "0.0.0",
      private: true,
    });
  });

  afterAll(() => rmSync(fixture, { recursive: true, force: true }));

  it("finds public workspace packages, deps first; skips private and non-packages", () => {
    const pkgs = discoverPackages(fixture);
    expect(pkgs.map((p) => p.name)).toEqual(["@fix/b", "@fix/a"]); // a peer-depends on b
  });

  it("only records intra-workspace deps as edges", () => {
    const a = discoverPackages(fixture).find((p) => p.name === "@fix/a");
    expect(a.workspaceDeps).toEqual(["@fix/b"]); // left-pad is external — not an edge
  });

  it("honors publishConfig registry (trailing slash stripped) and tag", () => {
    const b = discoverPackages(fixture).find((p) => p.name === "@fix/b");
    expect(b.registry).toBe("https://registry.example.com");
    expect(b.publishTag).toBe("next");
  });

  it("real repo: discovers exactly the 7 @e-sig packages, core first, quickstart excluded", () => {
    const names = discoverPackages(repoRoot).map((p) => p.name);
    expect(names[0]).toBe("@e-sig/core"); // everything else peer-depends on core
    expect(names).toHaveLength(7);
    expect(new Set(names)).toEqual(
      new Set([
        "@e-sig/core",
        "@e-sig/supabase",
        "@e-sig/react",
        "@e-sig/uuaid",
        "@e-sig/uaid-exch",
        "@e-sig/worm",
        "@e-sig/hsm-pkcs11",
      ]),
    );
  });
});

describe("topoSort", () => {
  const pkg = (name, deps = []) => ({ name, workspaceDeps: deps });

  it("orders dependencies before dependents", () => {
    const sorted = topoSort([pkg("c", ["b"]), pkg("b", ["a"]), pkg("a")]);
    expect(sorted.map((p) => p.name)).toEqual(["a", "b", "c"]);
  });

  it("terminates on cycles instead of hanging", () => {
    const sorted = topoSort([pkg("a", ["b"]), pkg("b", ["a"])]);
    expect(sorted.map((p) => p.name).sort()).toEqual(["a", "b"]);
  });
});

describe("distTagFor", () => {
  it("uses explicit publishConfig.tag", () => {
    expect(distTagFor({ name: "x", version: "0.1.0-preview.1", publishTag: "preview" }))
      .toEqual({ tag: "preview" });
  });

  it("defaults stable versions to latest", () => {
    expect(distTagFor({ name: "x", version: "1.2.3" })).toEqual({ tag: "latest" });
  });

  it("rejects a prerelease without an explicit tag", () => {
    const { error } = distTagFor({ name: "@e-sig/x", version: "1.0.0-rc.1" });
    expect(error).toMatch(/publishConfig\.tag/);
  });
});

describe("fetchRegistryState", () => {
  const pkg = { name: "@e-sig/core", registry: "https://registry.npmjs.org" };
  const response = (status, body) => ({
    status,
    ok: status >= 200 && status < 300,
    json: async () => body,
  });

  it("returns versions for an existing package (scoped name encoded)", async () => {
    let calledUrl;
    const state = await fetchRegistryState(pkg, async (url) => {
      calledUrl = url;
      return response(200, { versions: { "0.6.0": {}, "0.7.0": {} } });
    });
    expect(calledUrl).toBe("https://registry.npmjs.org/%40e-sig%2Fcore");
    expect(state.exists).toBe(true);
    expect(state.versions.has("0.7.0")).toBe(true);
  });

  it("maps 404 to exists:false", async () => {
    const state = await fetchRegistryState(pkg, async () => response(404, {}));
    expect(state).toEqual({ exists: false, versions: new Set() });
  });

  it("throws on other registry failures (never publish blind)", async () => {
    await expect(fetchRegistryState(pkg, async () => response(503, {}))).rejects.toThrow(
      /HTTP 503/,
    );
  });
});

describe("planPublishes", () => {
  const pkg = (name, version, publishTag) => ({
    name,
    version,
    publishTag,
    registry: "https://registry.npmjs.org",
  });
  const state = (exists, versions = []) => ({ exists, versions: new Set(versions) });

  it("errors when a name is missing from the registry (OIDC cannot first-publish)", () => {
    const pkgs = [pkg("@e-sig/core", "0.7.0"), pkg("@e-sig/worm", "0.1.0")];
    const states = new Map([
      ["@e-sig/core", state(true, ["0.6.0"])],
      ["@e-sig/worm", state(false)],
    ]);
    const { errors, actions } = planPublishes(pkgs, states);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/@e-sig\/worm/);
    expect(errors[0]).toMatch(/Trusted Publisher/);
    // core is publishable on its own, but any error must gate the whole run
    expect(actions).toEqual([
      expect.objectContaining({ action: "publish", tag: "latest" }),
    ]);
  });

  it("skips versions that are already live (re-run convergence)", () => {
    const pkgs = [pkg("@e-sig/core", "0.7.0"), pkg("@e-sig/react", "0.2.1")];
    const states = new Map([
      ["@e-sig/core", state(true, ["0.7.0"])], // published before the partial failure
      ["@e-sig/react", state(true, ["0.2.0"])],
    ]);
    const { errors, actions } = planPublishes(pkgs, states);
    expect(errors).toEqual([]);
    expect(actions.map((a) => [a.pkg.name, a.action])).toEqual([
      ["@e-sig/core", "skip"],
      ["@e-sig/react", "publish"],
    ]);
  });

  it("carries the prerelease dist-tag into the publish action", () => {
    const pkgs = [pkg("@e-sig/uaid-exch", "0.1.0-preview.1", "preview")];
    const states = new Map([["@e-sig/uaid-exch", state(true, [])]]);
    const { errors, actions } = planPublishes(pkgs, states);
    expect(errors).toEqual([]);
    expect(actions[0]).toMatchObject({ action: "publish", tag: "preview" });
  });

  it("errors on a prerelease without an explicit tag", () => {
    const pkgs = [pkg("@e-sig/x", "1.0.0-rc.1")];
    const states = new Map([["@e-sig/x", state(true, [])]]);
    const { errors } = planPublishes(pkgs, states);
    expect(errors.some((e) => /publishConfig\.tag/.test(e))).toBe(true);
  });

  it("errors when there is nothing to publish (forgotten version bump)", () => {
    const pkgs = [pkg("@e-sig/core", "0.7.0")];
    const states = new Map([["@e-sig/core", state(true, ["0.7.0"])]]);
    const { errors, actions } = planPublishes(pkgs, states);
    expect(actions).toEqual([expect.objectContaining({ action: "skip" })]);
    expect(errors.some((e) => /Nothing to publish/.test(e))).toBe(true);
  });
});
