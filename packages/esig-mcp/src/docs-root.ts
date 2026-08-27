// docs-root.ts
//
// D6 FIX: `esig_verify_document` / `esig_ingest_document` accept a `path`
// input. A connected agent is untrusted by default (design doc §2) — without
// this, it could hand the server any file the process can read. Confine
// caller-supplied paths to `config.docsRoot` (ESIG_MCP_DOCS_ROOT, default
// "<dataDir>/inbox") before ever touching the filesystem with them.
//
// Three independent checks, in order:
//   1. reject any ".." path segment outright, regardless of where the final
//      resolved position would land — a legitimate caller never needs one;
//   2. resolve relative paths against `root` (never process.cwd()), require
//      absolute paths to already be inside `root`;
//   3. `fs.realpath` both the candidate and `root` and re-check containment
//      on the resolved, symlink-free paths — a symlink placed inside `root`
//      that points outside it must not be a bypass.

import { promises as fs } from "node:fs";
import path from "node:path";

export class PathEscapesRootError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PathEscapesRootError";
  }
}

function isInsideOrEqual(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root + path.sep);
}

/**
 * Resolve a caller-supplied `path` input to an absolute path confined under
 * `root`. Throws {@link PathEscapesRootError} (message always names `root`)
 * on any violation; otherwise returns the resolved, symlink-checked absolute
 * path, safe to pass to `fs.readFile`.
 */
export async function resolveDocPath(root: string, requested: string): Promise<string> {
  if (requested.split(/[/\\]/).includes("..")) {
    throw new PathEscapesRootError(
      `path must not contain ".." segments (confined to ${root}): "${requested}"`,
    );
  }

  const resolved = path.isAbsolute(requested) ? path.resolve(requested) : path.resolve(root, requested);
  if (!isInsideOrEqual(root, resolved)) {
    throw new PathEscapesRootError(`path must resolve inside ${root}, got "${resolved}"`);
  }

  let real: string;
  try {
    real = await fs.realpath(resolved);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new PathEscapesRootError(`path does not exist under ${root}: "${requested}"`);
    }
    throw e;
  }
  // `root` itself may legitimately not exist yet (nothing ingested there
  // yet) — fall back to its plain resolved form rather than failing outright.
  const realRoot = await fs.realpath(root).catch(() => root);
  if (!isInsideOrEqual(realRoot, real)) {
    throw new PathEscapesRootError(`path resolves outside ${root} via a symlink: "${requested}"`);
  }

  return resolved;
}
