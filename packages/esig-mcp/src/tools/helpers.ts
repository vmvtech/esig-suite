// tools/helpers.ts
//
// Shared result-shaping for every tool in this directory. Kept tiny and
// dependency-free (no @e-sig/core imports) so it can be reused by any tool
// module without pulling in unrelated concerns.

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/**
 * Build a successful tool result: a human-readable summary line (what an
 * agent reads first) plus JSON-safe structured content (what an agent
 * parses). `JSON.parse(JSON.stringify(...))` both guarantees the structured
 * content is plain, serializable data (no class instances, no `Buffer`s
 * leaking through) and satisfies the SDK's `Record<string, unknown>` shape
 * for `structuredContent` without an unchecked type assertion.
 */
export function toolResult(summary: string, data?: unknown): CallToolResult {
  const structuredContent =
    data === undefined ? undefined : (JSON.parse(JSON.stringify(data)) as Record<string, unknown>);
  return {
    content: [{ type: "text", text: summary }],
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
