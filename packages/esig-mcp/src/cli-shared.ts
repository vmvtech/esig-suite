// cli-shared.ts
//
// Small helpers shared by the `esig-mcp init` and `esig-mcp demo` CLI
// subcommands (design doc §14, cli-init.ts / cli-demo.ts). Kept tiny and
// dependency-free, same rationale as tools/helpers.ts.

import crypto from "node:crypto";
import { promises as fs } from "node:fs";

/**
 * 32 random bytes, base64url-encoded (43 chars, no padding) — well over
 * config.ts's `MIN_PASSPHRASE_LEN` (24). Used by both `init` (written to
 * `.esig-mcp.env`) and `demo` (kept in memory only, for its own temp
 * server).
 */
export function randomPassphrase(): string {
  return crypto.randomBytes(32).toString("base64url");
}

/**
 * A genuinely valid, transparent 1x1 PNG, as a `data:` URL — the same
 * fixture value test/helpers.ts's `PNG_DATA_URL` uses. Core's
 * `assertImageDataUrl` only regex-validates the shape and never decodes
 * pixels, but a real tiny PNG is what `demo`'s printed curl one-liner and
 * `--auto` signature actually claim to be.
 */
export const TINY_PNG_DATA_URL =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

/** `--flag <value>` extraction from an argv slice (already past the subcommand name itself). */
export function flagValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}

/** True iff `p` exists (any type) — used only for the `init` overwrite guard. */
export async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
