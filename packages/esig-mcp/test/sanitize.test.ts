// sanitize.test.ts — I9, library half (the sandboxed-iframe half lives in the
// server layer a follow-up worker adds).

import { describe, it, expect } from "vitest";
import { sanitizeEnvelopeHtml } from "../dist/index.js";

describe("sanitizeEnvelopeHtml", () => {
  it("strips <script>...</script> blocks", () => {
    const { html, removed } = sanitizeEnvelopeHtml("<p>hi</p><script>alert(1)</script><p>bye</p>");
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain("<p>hi</p>");
    expect(html).toContain("<p>bye</p>");
    expect(removed).toContain("script");
  });

  it("strips a self-closing/void <script/> tag", () => {
    const { html, removed } = sanitizeEnvelopeHtml('<script src="evil.js"/>');
    expect(html).not.toMatch(/<script/i);
    expect(removed).toContain("script");
  });

  it("strips on* event-handler attributes", () => {
    const { html, removed } = sanitizeEnvelopeHtml('<button onclick="alert(1)">go</button>');
    expect(html).not.toMatch(/onclick/i);
    expect(removed).toContain("onclick");
  });

  it("strips javascript: URLs from href/src", () => {
    const { html } = sanitizeEnvelopeHtml('<a href="javascript:alert(1)">x</a><img src="javascript:alert(2)">');
    expect(html).not.toMatch(/javascript:/i);
  });

  it("strips iframe/object/embed/form", () => {
    const input =
      '<iframe src="https://evil.example"></iframe>' +
      '<object data="evil.swf"></object>' +
      '<embed src="evil.swf">' +
      '<form action="/exfiltrate"><input name="x"></form>';
    const { html, removed } = sanitizeEnvelopeHtml(input);
    expect(html).not.toMatch(/<iframe|<object|<embed|<form/i);
    expect(removed).toEqual(expect.arrayContaining(["iframe", "object", "embed", "form"]));
  });

  it("is deterministic for the same input", () => {
    const input = '<p onclick="x()">hi</p><script>y()</script><a href="javascript:z()">l</a>';
    expect(sanitizeEnvelopeHtml(input)).toEqual(sanitizeEnvelopeHtml(input));
  });

  it("leaves benign html completely untouched", () => {
    const input = "<p>Hello <b>world</b>, please review the terms below.</p>";
    const { html, removed } = sanitizeEnvelopeHtml(input);
    expect(html).toBe(input);
    expect(removed).toEqual([]);
  });

  it("is case-insensitive", () => {
    const { html } = sanitizeEnvelopeHtml("<SCRIPT>alert(1)</SCRIPT><DIV ONCLICK=\"x()\">hi</DIV>");
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/onclick/i);
  });

  // D4: three payloads the verifier reproduced as surviving, plus a
  // mixed-case variant.
  it("strips an unterminated <script> with no closing tag", () => {
    const { html, removed } = sanitizeEnvelopeHtml("<p>hi</p><script>alert(1)");
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain("<p>hi</p>");
    expect(removed).toContain("script");
  });

  it("strips an on* attribute separated from the tag name by '/' instead of whitespace", () => {
    const { html, removed } = sanitizeEnvelopeHtml("<img/onerror=alert(1)>");
    expect(html).not.toMatch(/onerror/i);
    expect(removed).toContain("onerror");
  });

  it("strips an unquoted javascript: URL", () => {
    const { html } = sanitizeEnvelopeHtml('<a href=javascript:alert(1)>click</a>');
    expect(html).not.toMatch(/javascript:/i);
  });

  it("strips a mixed-case <ScRiPt> and a mixed-case OnLoad= attribute", () => {
    const { html } = sanitizeEnvelopeHtml('<ScRiPt>alert(1)</ScRiPt><body OnLoad="alert(2)">hi</body>');
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/onload/i);
    expect(html).toContain("hi");
  });

  // Round-2 verifier bypasses: the scheme is judged on the normalised value,
  // not on the literal bytes, so whitespace, control chars, and entities
  // cannot smuggle it past the check.
  it("strips javascript: URLs with leading whitespace, embedded newlines, or entity-encoded letters", () => {
    const input =
      '<a href=" javascript:alert(1)">a</a>' +
      '<a href="java\nscript:alert(2)">b</a>' +
      '<a href="&#106;avascript:alert(3)">c</a>' +
      '<a href="&#x6A;avascript&colon;alert(4)">d</a>';
    const { html, removed } = sanitizeEnvelopeHtml(input);
    expect(html).not.toMatch(/href=/i);
    expect(removed.filter((r) => r === "href=javascript:")).toHaveLength(4);
  });

  it("strips style attributes carrying url(javascript:) or expression()", () => {
    const { html } = sanitizeEnvelopeHtml(
      '<div style="background:url(javascript:alert(1))">x</div><p style="width:expression(alert(2))">y</p>',
    );
    expect(html).not.toMatch(/javascript:|expression\(/i);
    expect(html).toContain("x");
  });

  // Third-round verifier findings.
  it("never throws on out-of-range numeric entities (attacker-controlled digits)", () => {
    const input = '<a href="&#x110000;">a</a><a href="&#99999999999;">b</a>';
    expect(() => sanitizeEnvelopeHtml(input)).not.toThrow();
    expect(sanitizeEnvelopeHtml(input).html).toBe(input);
  });

  it("catches an attribute whose only separator is the previous attribute's closing quote", () => {
    const { html } = sanitizeEnvelopeHtml('<a title="x"href="javascript:alert(1)">a</a><b title="y"onclick="z()">b</b>');
    expect(html).not.toMatch(/javascript:|onclick/i);
    expect(html).toContain('title="x"');
    expect(html).toContain('title="y"');
  });

  it("covers namespaced and other URL-bearing attributes", () => {
    const input =
      '<svg><a xlink:href="javascript:alert(1)">s</a></svg>' +
      '<img srcset="ok.png 1x, javascript:alert(2) 2x">' +
      '<body background="javascript:alert(3)">';
    const { html } = sanitizeEnvelopeHtml(input);
    expect(html).not.toMatch(/javascript:/i);
  });

  it("strips quoted, entity-quoted, and backslash-escaped schemes inside style url()", () => {
    const input =
      '<div style="background:url(&quot;javascript:alert(1)&quot;)">a</div>' +
      "<div style=\"background:url('javascript:alert(2)')\">b</div>" +
      '<div style="background:url(&#34;javascript:alert(3)&#34;)">c</div>' +
      '<div style="background:url(\\6a avascript:alert(4))">d</div>' +
      '<div style="background:url(\\javascript:alert(5))">e</div>' +
      '<div style="width:exp\\ression(alert(6))">f</div>';
    const { html } = sanitizeEnvelopeHtml(input);
    expect(html).not.toMatch(/javascript|6a avascript|ression\(/i);
    expect(html).toContain(">a<");
  });

  it("leaves ordinary URLs and styles alone", () => {
    const input = '<a href="https://e-sig.org/verify">v</a><img src="data:image/png;base64,AAAA"><p style="color:red">t</p>';
    const { html, removed } = sanitizeEnvelopeHtml(input);
    expect(html).toBe(input);
    expect(removed).toEqual([]);
  });
  // G2 (RedTeam rt-verdict-ESIGMCP-V01-20260826, MEDIUM): stripping a tag that
  // comes LATER in the pipeline splices its neighbours together and can revive
  // a construct whose own pass has already run. Reproduced live on dist before
  // the fix; the pipeline now runs to a fixpoint.
  describe("cross-tag mutation (G2) — every strip runs to a fixpoint", () => {
    const REVIVAL_CASES: Array<[string, string]> = [
      ["iframe revived by the form strip", '<ifr<form></form>ame src="https://attacker.example/probe">'],
      ["iframe revived, split elsewhere", '<ifra<form></form>me src="https://attacker.example/probe">'],
      ["object revived by the embed strip", '<obj<embed/>ect data="https://attacker.example/o">'],
      ["embed revived by the form strip", '<emb<form></form>ed src="https://attacker.example/e">'],
      ["script revived by the iframe strip", "<scr<iframe></iframe>ipt>alert(1)</script>"],
      ["script revived by the form strip", "<scr<form></form>ipt>alert(1)</script>"],
      ["nested two deep", "<ifr<obj<embed/>ect></object>ame src=x>"],
    ];

    for (const [name, input] of REVIVAL_CASES) {
      it(`leaves no live tag: ${name}`, () => {
        const { html } = sanitizeEnvelopeHtml(input);
        expect(html).not.toMatch(/<\s*\/?\s*(script|iframe|object|embed|form)\b/i);
      });
    }

    it("is still deterministic and idempotent after the fixpoint loop", () => {
      const input = '<ifr<form></form>ame src="https://attacker.example/probe">x';
      const once = sanitizeEnvelopeHtml(input);
      expect(sanitizeEnvelopeHtml(input)).toEqual(once);
      // A second sanitize of already-sanitized output must be a no-op.
      const twice = sanitizeEnvelopeHtml(once.html);
      expect(twice.html).toBe(once.html);
      expect(twice.removed).toEqual([]);
    });

    it("terminates on adversarially nested revival chains", () => {
      const input = "<scr" + "<form></form>".repeat(200) + "ipt>alert(1)</script>";
      const { html } = sanitizeEnvelopeHtml(input);
      expect(html).not.toMatch(/<\s*script\b/i);
    });
  });
});
