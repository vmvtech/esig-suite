// http.ts
//
// The human-facing approval server (design doc §5 "Approval page (v0.1,
// built-in)", §2 T9, MUST DO item 2). node:http only — same rationale as
// packages/esig-gateway/src/server.ts's header comment: this process holds
// signing keys (mode H's cert + PQ bundle at seal time), and a framework
// dependency is exactly the kind of update surface that process should not
// carry.
//
// Routes: GET /healthz, GET /sign/<token> (renders the approval page), POST
// /sign/<token> (records a drawn signature). Every response — success,
// error, healthz — carries the same security headers; nothing here ever
// writes to stdout (reserved for the MCP stdio transport, see bin.ts).

import crypto from "node:crypto";
import http from "node:http";

import { EnvelopeError as CoreEnvelopeError, type TokenResolution } from "@e-sig/core";

import type { Config } from "./config.js";
import type { EnvelopeService } from "./envelopes.js";
import { EnvelopeConflictError } from "./stores.js";
import { messageOf } from "./tools/helpers.js";

export interface HttpDeps {
  config: Config;
  envelopes: EnvelopeService;
}

// ---------- Security headers (design doc §5 / MUST DO item 2) ----------
//
// Kept as close to the ticket's specified value as possible; the two
// deviations are `connect-src 'self'` and the nonce-based `script-src`.
// Without `connect-src 'self'`, `default-src 'none'` blocks the signature
// pad's own same-origin `fetch()` POST — the ticket's spec for the submit
// step is a JSON body (`{signatureImageDataUrl, consent}`), which a plain
// HTML <form> cannot send (forms only send x-www-form-urlencoded/
// multipart), so `fetch` is not optional here and needs `connect-src`
// explicitly (it does not fall under `form-action`, which only governs
// <form> targets). Every other directive matches the spec verbatim and each
// has a concrete reason: `img-src data:` lets agent-authored HTML embed
// inline images (e.g. a logo) inside the sandboxed iframe without any
// network fetch; `style-src 'unsafe-inline'` is this page's own inline
// <style> (unaffected by the LOW-1 fix below — only script-src changed);
// `frame-src data: blob: 'self'` covers the `srcdoc` iframe (whose
// effective URL is `about:srcdoc`); `form-action 'self'` bounds any future
// plain-form submission to this same origin.
//
// LOW-1 FIX (RedTeam rt-verdict-ESIGMCP-V01-20260826): `script-src
// 'unsafe-inline'` allowed ANY inline script to execute, not just this
// page's own signature-pad script — a strictly weaker control than it needs
// to be (the iframe's own `sandbox` with no `allow-scripts` already stops
// agent-authored envelope HTML from running script regardless, so this
// page's script-src was defense-in-depth for a script this page controls,
// not a load-bearing boundary against agent content). A per-response,
// cryptographically random nonce (`crypto.randomBytes(16).toString("base64")`)
// replaces `'unsafe-inline'` with `'nonce-<n>'`, and the SAME nonce is put on
// the one inline `<script>` this page ever emits (the signature-pad script,
// only present when `resolution.status === "ok"`). A script an attacker
// manages to inject anywhere else on the page (e.g. via a header-injection
// or future template bug) has no way to know the per-request nonce, so it
// cannot execute even though `script-src` is not fully locked to `'none'`.
function cspFor(nonce: string): string {
  return (
    "default-src 'none'; img-src data:; style-src 'unsafe-inline'; " +
    `script-src 'nonce-${nonce}'; connect-src 'self'; frame-src data: blob: 'self'; form-action 'self'`
  );
}

const SECURITY_HEADERS: Record<string, string> = {
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
};

function sendHtml(res: http.ServerResponse, status: number, html: string, csp: string): void {
  const payload = Buffer.from(html, "utf8");
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    "content-security-policy": csp,
    "content-type": "text/html; charset=utf-8",
    "content-length": String(payload.length),
  });
  res.end(payload);
}

function sendJson(res: http.ServerResponse, status: number, body: unknown, csp: string): void {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    "content-security-policy": csp,
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
  });
  res.end(payload);
}

// ---------- Body reading (bounded, same shape as the gateway's readBody) ----------

const MAX_SIGN_BODY_BYTES = 5 * 1024 * 1024; // a 500x160 canvas PNG data URL is a few KB; 5MB is a generous cap

function readBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] ?? NaN);
    if (Number.isFinite(declared) && declared > maxBytes) {
      reject(new Error(`body of ${declared} bytes exceeds the ${maxBytes}-byte cap`));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) {
        reject(new Error(`body exceeded ${maxBytes} bytes`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", (e) => reject(e));
  });
}

// ---------- Per-IP rate limit on /sign (MUST DO item 2) ----------

class IpRateLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  allow(ip: string, now: number = Date.now()): boolean {
    const cutoff = now - this.windowMs;
    const recent = (this.hits.get(ip) ?? []).filter((t) => t > cutoff);
    if (recent.length >= this.limit) {
      this.hits.set(ip, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(ip, recent);
    return true;
  }
}

const SIGN_RATE_LIMIT = 30; // requests
const SIGN_RATE_WINDOW_MS = 60_000; // per minute, per IP

// ---------- Approval page rendering ----------

function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeText(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const GATE_SENTENCES: Record<TokenResolution["status"], string> = {
  ok: "It's your turn to sign.",
  not_your_turn: "Waiting on an earlier signer — you'll be notified when it's your turn.",
  already_signed: "You already signed this envelope.",
  completed: "This envelope is complete — every signer has signed.",
  voided: "This envelope was voided by the sender.",
  expired: "This signing link has expired.",
  invalid: "This signing link is invalid or unknown.",
};

// Vanilla-JS signature pad + consent + submit. Static apart from the CSP
// nonce (LOW-1), so there is nothing here for agent-authored content to
// inject into — the only dynamic content on the page (the envelope HTML)
// lives entirely inside the sandboxed iframe's `srcdoc` attribute, escaped.
// `nonce` is server-generated (`crypto.randomBytes`, never attacker input),
// so it is interpolated directly — the same trust boundary as every other
// server-authored literal in this file's HTML templates.
function signFormHtml(nonce: string): string {
  return `
<div class="row">
  <label><input type="checkbox" id="consent"> I have reviewed the document above and consent to sign electronically.</label>
</div>
<canvas id="pad" width="500" height="160" aria-label="Draw your signature here"></canvas>
<div class="row">
  <button type="button" id="clear">Clear</button>
  <button type="button" id="submit">Sign</button>
</div>
<div id="msg" role="status"></div>
<script nonce="${nonce}">
(function () {
  var canvas = document.getElementById('pad');
  var ctx = canvas.getContext('2d');
  ctx.lineWidth = 2;
  ctx.lineCap = 'round';
  ctx.strokeStyle = '#111';
  var drawing = false;
  var hasInk = false;

  function pos(e) {
    var r = canvas.getBoundingClientRect();
    var t = e.touches && e.touches[0];
    var cx = (t ? t.clientX : e.clientX) - r.left;
    var cy = (t ? t.clientY : e.clientY) - r.top;
    return { x: (cx * canvas.width) / r.width, y: (cy * canvas.height) / r.height };
  }
  function start(e) { drawing = true; hasInk = true; var p = pos(e); ctx.beginPath(); ctx.moveTo(p.x, p.y); e.preventDefault(); }
  function move(e) { if (!drawing) return; var p = pos(e); ctx.lineTo(p.x, p.y); ctx.stroke(); e.preventDefault(); }
  function end() { drawing = false; }

  canvas.addEventListener('mousedown', start);
  canvas.addEventListener('mousemove', move);
  window.addEventListener('mouseup', end);
  canvas.addEventListener('touchstart', start, { passive: false });
  canvas.addEventListener('touchmove', move, { passive: false });
  canvas.addEventListener('touchend', end);

  document.getElementById('clear').addEventListener('click', function () {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    hasInk = false;
  });

  document.getElementById('submit').addEventListener('click', function () {
    var msg = document.getElementById('msg');
    if (!document.getElementById('consent').checked) { msg.textContent = 'Please check the consent box first.'; return; }
    if (!hasInk) { msg.textContent = 'Please draw your signature first.'; return; }
    msg.textContent = 'Submitting…';
    fetch(window.location.pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ signatureImageDataUrl: canvas.toDataURL('image/png'), consent: true }),
    })
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (res) {
        if (res.ok) {
          msg.textContent = res.body.completed ? 'Signed. This envelope is now complete.' : 'Signed. Waiting on other signer(s).';
        } else {
          msg.textContent = (res.body && res.body.error) || 'Sign failed.';
        }
      })
      .catch(function () { msg.textContent = 'Network error — please try again.'; });
  });
})();
</script>`;
}

function page(opts: { title: string; sentence: string; gateClass: "ok" | "blocked"; body: string }): string {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeText(opts.title)}</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #111; background: #fff; }
  h1 { font-size: 1.25rem; }
  .gate { padding: .75rem 1rem; border-radius: 6px; background: #f0f4f8; margin: 1rem 0; }
  .gate.ok { background: #eaf7ea; }
  .gate.blocked { background: #fdeceb; }
  iframe { width: 100%; height: 55vh; border: 1px solid #ccc; border-radius: 6px; background: #fff; }
  canvas { border: 1px solid #999; border-radius: 4px; touch-action: none; width: 100%; max-width: 500px; height: 160px; display: block; margin: .5rem 0; }
  .row { margin: .75rem 0; }
  button { padding: .5rem 1rem; font-size: 1rem; }
  #msg { margin-top: 1rem; font-weight: 600; }
</style>
</head>
<body>
<h1>${escapeText(opts.title)}</h1>
<div class="gate ${opts.gateClass}">${escapeText(opts.sentence)}</div>
${opts.body}
</body>
</html>`;
}

function renderApprovalPage(resolution: TokenResolution, nonce: string): { status: number; html: string } {
  const sentence = GATE_SENTENCES[resolution.status];

  if (resolution.status === "invalid") {
    // No envelope content of any kind — there is none to show, and an
    // invalid/guessed token must not be distinguishable from "exists but
    // you can't see it".
    return { status: 404, html: page({ title: "Signing link not found", sentence, gateClass: "blocked", body: "" }) };
  }

  const { envelope } = resolution;
  // The ONLY place envelope HTML is ever emitted: inside a fully sandboxed
  // iframe (no allow-scripts, no allow-same-origin, no forms) via an
  // HTML-attribute-escaped srcdoc (I9, T9). `envelope.html` is already the
  // sanitize.ts-stripped body set at creation (esig_create_envelope) — this
  // escaping is the second, independent layer.
  const iframe = `<iframe sandbox srcdoc="${escapeAttr(envelope.html)}"></iframe>`;
  const form = resolution.status === "ok" ? signFormHtml(nonce) : "";

  return {
    status: 200,
    html: page({
      title: envelope.title,
      sentence,
      gateClass: resolution.status === "ok" ? "ok" : "blocked",
      body: iframe + form,
    }),
  };
}

// ---------- Sign error -> HTTP status mapping ----------

function statusForSignError(e: unknown): number {
  if (e instanceof EnvelopeConflictError) return 409; // I3: a concurrent signature already won
  if (e instanceof CoreEnvelopeError) {
    switch (e.code) {
      case "invalid_token":
        return 404;
      case "invalid_input":
        return 400;
      case "already_signed":
      case "not_your_turn":
      case "not_signable":
      case "not_complete":
        return 409;
      default:
        return 400;
    }
  }
  return 500;
}

// ---------- Request handler ----------

export function createApprovalRequestHandler(deps: HttpDeps): http.RequestListener {
  const limiter = new IpRateLimiter(SIGN_RATE_LIMIT, SIGN_RATE_WINDOW_MS);

  return async (req, res) => {
    // LOW-1: one fresh nonce per HTTP request/response, never reused across
    // requests (that's the whole point — an attacker who learned a past
    // nonce gains nothing) and never derived from anything request-supplied.
    const nonce = crypto.randomBytes(16).toString("base64");
    const csp = cspFor(nonce);

    try {
      const url = new URL(req.url ?? "/", "http://esig-mcp.invalid");
      const route = url.pathname;

      if (route === "/healthz") {
        if (req.method !== "GET") {
          sendJson(res, 405, { error: "method not allowed" }, csp);
          return;
        }
        sendJson(res, 200, { status: "ok" }, csp);
        return;
      }

      const signMatch = /^\/sign\/([^/]+)$/.exec(route);
      if (!signMatch) {
        sendJson(res, 404, { error: "not found" }, csp);
        return;
      }
      // Never logged (design doc §5 MUST DO item 2): nothing in this
      // function writes `token`, `route`, or `req.url` to any log — the
      // token exists only in this closure and in the calls it makes.
      const token = decodeURIComponent(signMatch[1]);

      const ip = req.socket.remoteAddress ?? "unknown";
      if (!limiter.allow(ip)) {
        sendJson(res, 429, { error: "too many requests to /sign — please wait a moment and try again" }, csp);
        return;
      }

      if (req.method === "GET") {
        const resolution = await deps.envelopes.resolve(token);
        const rendered = renderApprovalPage(resolution, nonce);
        sendHtml(res, rendered.status, rendered.html, csp);
        return;
      }

      if (req.method === "POST") {
        const ctype = String(req.headers["content-type"] ?? "");
        if (!ctype.toLowerCase().startsWith("application/json")) {
          sendJson(res, 415, { error: "content-type must be application/json" }, csp);
          return;
        }

        let parsed: { signatureImageDataUrl?: unknown; consent?: unknown };
        try {
          const raw = await readBody(req, MAX_SIGN_BODY_BYTES);
          parsed = JSON.parse(raw.toString("utf8"));
        } catch (e) {
          sendJson(res, 400, { error: `invalid request body: ${messageOf(e)}` }, csp);
          return;
        }

        if (typeof parsed.signatureImageDataUrl !== "string" || parsed.signatureImageDataUrl.length === 0) {
          sendJson(res, 400, { error: "signatureImageDataUrl (string) is required" }, csp);
          return;
        }
        if (parsed.consent !== true) {
          sendJson(res, 400, { error: "consent must be true" }, csp);
          return;
        }

        try {
          const summary = await deps.envelopes.sign(token, parsed.signatureImageDataUrl);
          sendJson(
            res,
            200,
            {
              status: summary.status,
              envelopeId: summary.envelopeId,
              completed: summary.status === "completed",
              sealedPdf: summary.sealedPdfUrl,
            },
            csp,
          );
        } catch (e) {
          sendJson(res, statusForSignError(e), { error: messageOf(e) }, csp);
        }
        return;
      }

      sendJson(res, 405, { error: "method not allowed" }, csp);
    } catch (e) {
      // Any unexpected failure: a fixed, safe message — never this
      // process's stack trace or an internal detail.
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" }, csp);
      else res.end();
      void e;
    }
  };
}

export function createApprovalServer(deps: HttpDeps): http.Server {
  return http.createServer(createApprovalRequestHandler(deps));
}
