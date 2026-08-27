// tools/helpers.ts
//
// Shared result-shaping for every tool in this directory. Kept tiny and
// dependency-free (no @e-sig/core imports) so it can be reused by any tool
// module without pulling in unrelated concerns.

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/**
 * Build a successful tool result. `JSON.parse(JSON.stringify(...))` both
 * guarantees the structured content is plain, serializable data (no class
 * instances, no `Buffer`s leaking through) and satisfies the SDK's
 * `Record<string, unknown>` shape for `structuredContent` without an
 * unchecked type assertion.
 *
 * D5: `content[0]` is a JSON text block MIRRORING `structuredContent` — some
 * MCP clients only ever read `content[]` (never `structuredContent`), and
 * for those a prose-only `content[0]` is unparseable data; `JSON.parse`ing
 * `content[0].text` now always works. The human-readable summary line moves
 * to `content[1]` — still present, still what a human/log skims first, just
 * no longer index 0. When there's no structured `data` at all, there is
 * nothing to mirror, so `content[0]` is the summary (unchanged in that one
 * case).
 */
export function toolResult(summary: string, data?: unknown): CallToolResult {
  const structuredContent =
    data === undefined ? undefined : (JSON.parse(JSON.stringify(data)) as Record<string, unknown>);
  const content: CallToolResult["content"] =
    structuredContent === undefined
      ? [{ type: "text", text: summary }]
      : [
          { type: "text", text: JSON.stringify(structuredContent) },
          { type: "text", text: summary },
        ];
  return {
    content,
    ...(structuredContent !== undefined ? { structuredContent } : {}),
  };
}

/**
 * Build a tool error result. `message` must already be an actionable,
 * user-safe string — callers are responsible for never passing a stack trace
 * or secret material here (see design doc §6 I1; every call site in this
 * package sources `message` from `messageOf()` below, an `EnvelopeError`'s
 * own `.message`, or a literal string this package wrote itself).
 */
export function toolError(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

/** Extract a safe, actionable message from a caught value. Never returns a stack trace. */
export function messageOf(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
