// pillar-loader.ts
//
// §17 seams 2-4 (v0.5): `@e-sig/pillar-bridge` is an OPTIONAL peer
// dependency (package.json `peerDependenciesMeta`) — `@e-sig/mcp` never adds
// it to `dependencies` and never statically imports it anywhere. `bin.ts`
// reaches it ONLY through this dynamic, injectable loader so that:
//
//   (a) a server that never sets `ESIG_MCP_DELIVERY=pillar` and never
//       configures `ESIG_PILLAR_SUBSCRIBERS` pays nothing for it — the
//       module is never even touched (`import()` only runs inside `bin.ts`'s
//       `if (pillarNeeded)` branch);
//   (b) an install missing the optional package fails with ONE clear,
//       actionable startup error naming the install command, not a raw
//       `ERR_MODULE_NOT_FOUND` three stack frames deep;
//   (c) tests can inject a fake bridge (test/pillar-seams.test.ts,
//       test/preverified.test.ts) WITHOUT ever importing `@uuaid/pillar` or
//       `@e-sig/pillar-bridge` themselves — exactly the seam the ticket
//       requires ("never import @uuaid/pillar or the bridge package in
//       esig-mcp tests").

/** The loaded Pillar identity — the slice `bin.ts` needs of the bridge's real `PillarIdentity`. */
export interface PillarBridgeIdentity {
  readonly uuaid: string;
  readonly publicKeyHex: string;
}

/** The slice of `@e-sig/pillar-bridge`'s `DeliveryChannel` (types.ts) `bin.ts` needs — kept structural, not a re-export of the bridge's own type. */
export interface PillarBridgeDeliveryChannel {
  deliver(
    meta: { id: string; title: string; expiresAt?: string; message?: string },
    links: Array<{
      signerId: string;
      name: string;
      email: string;
      url: string;
      pillar?: { uuaid: string; publicKey: string };
    }>,
  ): Promise<Array<{ signerId: string; ok: boolean; detail?: string; messageId?: string }>>;
}

/** The slice of the bridge's `EventSink` (types.ts) `bin.ts` needs. */
export interface PillarBridgeEventSink {
  publish(event: unknown): Promise<void>;
}

/** The slice of the bridge's `IdentityProofSource` (types.ts) `bin.ts` needs. */
export interface PillarBridgeProofSource {
  start(onProof: (event: PillarBridgeIdentityProofEvent) => void): void;
  stop(): void;
}

/** Structurally identical to the bridge's `IdentityProofEvent` (types.ts:100-110) — see identity/proof-source.ts's own copy for why this is duplicated rather than imported. */
export interface PillarBridgeIdentityProofEvent {
  envelopeId: string;
  signerId: string;
  uuaid: string;
  proof: unknown;
  credential?: unknown;
  senderUuaid: string;
  pillarEnvelopeId: string;
}

/**
 * The slice of `@e-sig/pillar-bridge`'s public surface `bin.ts` needs.
 * Deliberately structural (not `import type * as Bridge from
 * "@e-sig/pillar-bridge"`) — a static type-only import would still require
 * the package to be resolvable at every consumer's typecheck/build time,
 * defeating the point of it being an optional peer dependency.
 */
export interface PillarBridgeModule {
  PillarIdentity: {
    load(opts: { home: string; passphrase?: string }): Promise<PillarBridgeIdentity>;
    generate(opts: {
      home: string;
      passphrase?: string;
      uuaidNamespace?: string;
      objectType?: string;
    }): Promise<PillarBridgeIdentity>;
  };
  PillarDelivery: {
    open(opts: { identity: PillarBridgeIdentity; carriers: string[]; timeoutMs?: number }): Promise<PillarBridgeDeliveryChannel>;
  };
  PillarEventSink: {
    open(opts: {
      identity: PillarBridgeIdentity;
      carriers: string[];
      subscribers: Array<{ uuaid: string; publicKey: string }>;
      timeoutMs?: number;
      onReceipt?: (receipt: { uuaid: string; ok: boolean; detail?: string; messageId?: string }) => void;
    }): Promise<PillarBridgeEventSink>;
  };
  PillarProofSource: {
    open(opts: {
      identity: PillarBridgeIdentity;
      carriers: string[];
      home: string;
      waitS?: number;
      timeoutMs?: number;
      onKindCounts?: (counts: Record<string, number>) => void;
    }): Promise<PillarBridgeProofSource>;
  };
}

/** Injectable loader shape — the default resolves the real dynamic `import()`; tests inject a fake module instead (`ESIG_MCP_PILLAR_LOADER_TEST_OVERRIDE` env-var seam below, or a direct function pass-through when calling `wirePillar` in-process). */
export type PillarLoader = () => Promise<PillarBridgeModule>;

const INSTALL_HINT = "npm install @e-sig/pillar-bridge --workspace @e-sig/mcp";

// The specifier is held in a variable, NOT written as a literal inside
// `import(...)`: TypeScript resolves a literal dynamic-import specifier at
// COMPILE time, which turns this optional peer dependency into a hard build
// requirement — `tsc` fails with TS2307 wherever the bridge isn't built yet
// (CI from a clean clone, or any consumer building without it). A non-literal
// specifier keeps the import purely runtime, which is the whole point of an
// optional peer. Verified by a clean-tree build (all dist/ removed) on
// 2026-08-28 after CI run 33138017064 caught exactly this.
const BRIDGE_SPECIFIER = "@e-sig/pillar-bridge";

/**
 * The real loader: `import("@e-sig/pillar-bridge")`. A missing module
 * (`ERR_MODULE_NOT_FOUND` / `MODULE_NOT_FOUND` — the package is an optional
 * peer dependency this package never installs) is rewritten into ONE clear,
 * actionable error naming the install command; any OTHER load-time failure
 * (a corrupt install, an internal error inside the package itself) is
 * rethrown as-is so its real message is never hidden behind a misleading
 * "go install it" hint.
 */
export const defaultPillarLoader: PillarLoader = async () => {
  let mod: PillarBridgeModule;
  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- optional peer dep, never in dependencies
    mod = (await import(BRIDGE_SPECIFIER)) as unknown as PillarBridgeModule;
  } catch {
    throw new Error(
      'ESIG_MCP_DELIVERY="pillar" (or ESIG_PILLAR_SUBSCRIBERS) requires the optional peer dependency ' +
        `"@e-sig/pillar-bridge", which is not installed — install it: \`${INSTALL_HINT}\`.`,
    );
  }
  return mod;
};

/**
 * A loader that always fails exactly like {@link defaultPillarLoader} does
 * when the optional package is genuinely absent — used ONLY by
 * {@link resolvePillarLoader} below when
 * `ESIG_MCP_PILLAR_LOADER_TEST_OVERRIDE=throw` is set. Exists because this
 * monorepo's own workspace hoists every sibling package (including
 * `@e-sig/pillar-bridge`) into the root `node_modules` regardless of
 * whether `@e-sig/mcp` declares it as a dependency — so a real "the module
 * is not installed" state cannot be reproduced in-repo, and this package's
 * own tests are required never to import `@e-sig/pillar-bridge`/
 * `@uuaid/pillar` at all (test/pillar-seams.test.ts injects a fake bridge
 * object directly instead). This override lets `test/bin-cli.test.ts` still
 * exercise `bin.ts`'s REAL startup error-handling path end to end, via a
 * spawned `dist/bin.js` subprocess, without depending on install state.
 */
const throwingPillarLoader: PillarLoader = async () => {
  throw new Error(
    'ESIG_MCP_DELIVERY="pillar" (or ESIG_PILLAR_SUBSCRIBERS) requires the optional peer dependency ' +
      `"@e-sig/pillar-bridge", which is not installed — install it: \`${INSTALL_HINT}\`.`,
  );
};

/** `bin.ts`'s own loader selection — real dynamic import unless the TEST-ONLY override env var above is set. Not documented in `--help`: it exists purely so `bin.ts`'s real startup-failure path is exercisable from a spawned subprocess without installing/uninstalling anything. */
export function resolvePillarLoader(env: Record<string, string | undefined> = process.env): PillarLoader {
  return env.ESIG_MCP_PILLAR_LOADER_TEST_OVERRIDE === "throw" ? throwingPillarLoader : defaultPillarLoader;
}
