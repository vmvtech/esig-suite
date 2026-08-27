// sanitize.ts
//
// Strip the obvious script-injection surface from agent-authored envelope
// HTML before it is ever stored or shown to a human signer (I9, T9).
//
// This is DELIBERATELY a defense-in-depth measure, not the primary control:
// the primary control is that the approval page (built by the MCP server
// layer) renders envelope HTML inside a fully sandboxed
// `<iframe sandbox srcdoc>` with no `allow-scripts` / `allow-same-origin` /
// forms, plus a restrictive CSP (docs/architecture/esig-mcp.md §2 T9, §5). A
// sandboxed iframe alone would already stop script execution; this pass
// additionally removes the markup so a signer inspecting "view source" or an
// operator grepping the audit trail never sees it either, and so a future
// change to the rendering surface (e.g. an integrator supplying their own,
// less strict, signing UI per §5) is not silently unprotected.
//
// Regex-based, not a full HTML parser — acceptable here because the goal is
// narrow (remove a small, well-known set of dangerous constructs) and the
// output is never treated as trusted afterwards; it is one of two layers.

export interface SanitizeResult {
  html: string;
  /** What was removed, in removal order (tag names / attribute names / lowercased markers). Empty when nothing matched. */
  removed: string[];
}

const SCRIPT_PAIRED_RE = /<script\b[^>]*>[\s\S]*?<\/script\s*>/gi;
const SCRIPT_VOID_RE = /<script\b[^>]*\/>/gi;
// D4: an opening <script ...> tag with no matching closing tag anywhere in
// the input (e.g. "<script>alert(1)") survives SCRIPT_PAIRED_RE/
// SCRIPT_VOID_RE untouched. There is no way to know where the attacker
// intended the tag to "end", so strip it and everything after it.
const SCRIPT_UNTERMINATED_RE = /<script\b[^>]*>[\s\S]*$/gi;

/** Tags that can execute script or escape the document context entirely. */
const DANGEROUS_TAGS = ["iframe", "object", "embed", "form"] as const;

// `on*="..."` / `on*='...'` / `on*=bareword` event-handler attributes. D4:
// the separator before "on..." is whitespace OR "/" — HTML treats
// `<img/onerror=...>` as a valid tag/attribute boundary exactly like
// `<img onerror=...>`, and a bare `\s` requirement let it through.
// The attribute boundary is a lookbehind, not a consumed character: HTML
// parsers accept `title="x"href=...` (a closing quote as the only separator),
// and consuming that quote would leave the previous attribute unterminated.
const EVENT_ATTR_RE = /(?<=[\s/"'])on[a-z][a-z0-9]*\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;

// Every URL-bearing attribute (optionally namespaced, e.g. `xlink:href`) plus
// `style`, quoted or unquoted. The VALUE is judged after normalisation (see
// isUnsafeUrlValue), not by a literal scheme regex: browsers tolerate leading
// whitespace, embedded tabs/newlines inside the scheme, entity-encoded
// letters (`&#106;avascript:`), and CSS backslash escapes, all of which a
// literal `javascript:` match misses.
const URL_ATTR_RE =
  /(?<=[\s/"'])((?:[a-z]+:)?(?:href|src|srcset|action|formaction|background|poster|data|codebase|dynsrc|lowsrc|style))\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;

const NAMED_ENTITIES: Record<string, string> = {
  colon: ":", tab: "\t", newline: "\n", lpar: "(", rpar: ")", quot: '"', apos: "'", sol: "/",
};

/** Browsers map out-of-range references to U+FFFD; never let attacker digits reach fromCodePoint unguarded. */
function codePointOrReplacement(n: number): string {
  return Number.isFinite(n) && n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : "�";
}

/** Decode the entity/escape forms and drop the whitespace/control bytes browsers ignore inside a URL scheme. */
function normalizeUrlValue(raw: string): string {
  return raw
    .replace(/^["']|["']$/g, "")
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => codePointOrReplacement(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d) => codePointOrReplacement(parseInt(d, 10)))
    .replace(/&(colon|tab|newline|lpar|rpar|quot|apos|sol);/gi, (_, n) => NAMED_ENTITIES[n.toLowerCase()] ?? "")
    .replace(/\\([0-9a-f]{1,6})\s?/gi, (_, h) => codePointOrReplacement(parseInt(h, 16)))
    .replace(/\\([^0-9a-f\r\n])/gi, "$1")
    .replace(/[\s\x00-\x1f\x7f]/g, "")
    .toLowerCase();
}

const UNSAFE_SCHEME_RE = /^(?:javascript|vbscript):|^data:text\/html/;

function isUnsafeUrlValue(attr: string, raw: string): boolean {
  const v = normalizeUrlValue(raw);
  if (attr === "style") return /url\(["']?(?:javascript:|vbscript:|data:text\/html)/.test(v) || v.includes("expression(");
  // srcset carries several comma-separated candidates; judge each.
  return v.split(",").some((part) => UNSAFE_SCHEME_RE.test(part));
}

/** Attribute name from a matched EVENT_ATTR_RE/URL_ATTR_RE run. */
function attrNameFromMatch(m: string): string | undefined {
  return m.split(/\s*=/)[0]?.toLowerCase();
}

/**
 * One pass of the strip pipeline. Never call this directly — a single pass is
 * NOT a safe sanitizer (see `sanitizeEnvelopeHtml`, G2).
 */
function stripOnce(html: string, removed: string[]): string {
  let out = html;

  out = out.replace(SCRIPT_PAIRED_RE, () => {
    removed.push("script");
    return "";
  });
  out = out.replace(SCRIPT_VOID_RE, () => {
    removed.push("script");
    return "";
  });
  out = out.replace(SCRIPT_UNTERMINATED_RE, () => {
    removed.push("script");
    return "";
  });

  for (const tag of DANGEROUS_TAGS) {
    const paired = new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}\\s*>`, "gi");
    out = out.replace(paired, () => {
      removed.push(tag);
      return "";
    });
    // Void/self-closing form (e.g. a bare <embed src="...">, or <iframe ... />).
    const solo = new RegExp(`<${tag}\\b[^>]*\\/?>`, "gi");
    out = out.replace(solo, () => {
      removed.push(tag);
      return "";
    });
  }

  out = out.replace(EVENT_ATTR_RE, (m) => {
    const name = attrNameFromMatch(m);
    if (name) removed.push(name);
    return "";
  });

  out = out.replace(URL_ATTR_RE, (m, attr: string, value: string) => {
    if (!isUnsafeUrlValue(attr.toLowerCase().replace(/^[a-z]+:/, ""), value)) return m;
    const name = attrNameFromMatch(m);
    if (name) removed.push(`${name}=javascript:`);
    return "";
  });

  return out;
}

/**
 * Remove `<script>`, event-handler attributes, `javascript:` URLs, and
 * `<iframe>/<object>/<embed>/<form>` from agent-authored envelope HTML.
 * Deterministic: the same input always produces the same `{html, removed}`.
 *
 * G2 FIX (RedTeam rt-verdict-ESIGMCP-V01-20260826, MEDIUM): a SINGLE pass is
 * not sound. Each construct's strip runs exactly once, in a fixed order, so
 * removing a LATER construct can splice the surrounding fragments into an
 * EARLIER one that has already had its turn — reviving it in the output:
 *
 *   <ifr<form></form>ame src=…>      -> <iframe src=…>   (form stripped last)
 *   <obj<embed/>ect data=…>          -> <object data=…>
 *   <scr<iframe></iframe>ipt>…       -> <script>…        (script runs first)
 *
 * So the pipeline is run to a FIXPOINT instead: repeat until a whole pass
 * changes nothing. Termination is guaranteed — every removal path returns ""
 * for a non-empty match, so a pass that removes anything strictly shortens
 * the string, and the loop exits the moment a pass is a no-op.
 */
export function sanitizeEnvelopeHtml(html: string): SanitizeResult {
  const removed: string[] = [];
  let out = html;

  for (;;) {
    const before = out;
    out = stripOnce(out, removed);
    if (out === before) break;
  }

  return { html: out, removed };
}
