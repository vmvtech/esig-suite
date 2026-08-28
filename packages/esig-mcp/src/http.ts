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
import { derivePhase, getEnvelopeDocument, type EnvelopeService } from "./envelopes.js";
import { stripControlChars } from "./email/templates.js";
import type { IdentityChallengePayload } from "./identity/challenge.js";
import { getEnvelopeIdentityPolicy, IdentityError, type IdentityLevel, type IdentityProofInput } from "./identity/types.js";
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

/**
 * §13: `Content-Disposition` filename for `GET /sign/<token>/document.pdf`,
 * derived from the envelope title. Only `[A-Za-z0-9._ -]` survive (so no
 * quote, backslash, or path separator can ever reach the header value), runs
 * of whitespace collapse to a single underscore, and an empty/all-stripped
 * title falls back to a fixed name rather than an empty filename.
 */
function sanitizeFilename(title: string): string {
  const cleaned = title
    .replace(/[^A-Za-z0-9._ -]+/g, "")
    .trim()
    .replace(/\s+/g, "_")
    .slice(0, 120);
  return cleaned.length > 0 ? cleaned : "document";
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

// D1: shown instead of GATE_SENTENCES.completed for a `completed` envelope
// whose seal step hasn't produced a sealed PDF yet (phase `seal_failed` or
// `awaiting_seal`) — the signature is recorded either way; only the sealed
// artifact is pending.
const SEAL_PENDING_SENTENCE = "Your signature is recorded. The operator will produce the sealed PDF.";

// Vanilla-JS signature pad + consent + submit. Static apart from the CSP
// nonce (LOW-1) and the `identityRequired` boolean (server-computed from
// this envelope's own policy, never attacker input), so there is nothing
// here for agent-authored content to inject into — the only dynamic content
// on the page (the envelope HTML) lives entirely inside the sandboxed
// iframe's `srcdoc` attribute, escaped. `nonce` is server-generated
// (`crypto.randomBytes`, never attacker input), so it is interpolated
// directly — the same trust boundary as every other server-authored literal
// in this file's HTML templates.
//
// §12 MUST DO item 5: "when level > none the submit button requires the
// textarea non-empty" — enforced client-side here (the REAL enforcement is
// server-side, `EnvelopeService.sign()` throwing IdentityError; this is only
// UX so a signer without a proof gets an immediate, specific message instead
// of a generic 403 after drawing their signature).
function signFormHtml(nonce: string, identityRequired: boolean): string {
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
<details class="decline">
  <summary>Decline to sign</summary>
  <div class="row">
    <label for="declineReason">Reason (optional)</label>
    <textarea id="declineReason" rows="2" maxlength="500" placeholder="Why are you declining?"></textarea>
  </div>
  <div class="row">
    <button type="button" id="decline">Decline</button>
  </div>
</details>
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
    var body = { signatureImageDataUrl: canvas.toDataURL('image/png'), consent: true };
    ${
      identityRequired
        ? `
    var idField = document.getElementById('identityProof');
    var idText = idField ? idField.value.trim() : '';
    if (!idText) { msg.textContent = 'This envelope requires an identity proof — paste it in the Identity proof panel above.'; return; }
    try { body.identityProof = JSON.parse(idText); } catch (e) { msg.textContent = 'Identity proof is not valid JSON.'; return; }
    `
        : ""
    }
    msg.textContent = 'Submitting…';
    fetch(window.location.pathname, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
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

  document.getElementById('decline').addEventListener('click', function () {
    var msg = document.getElementById('msg');
    var reasonField = document.getElementById('declineReason');
    var reason = reasonField ? reasonField.value : '';
    msg.textContent = 'Declining…';
    fetch(window.location.pathname + '/decline', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(reason ? { reason: reason } : {}),
    })
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (res) {
        if (res.ok) {
          msg.textContent = 'Declined.';
        } else {
          msg.textContent = (res.body && res.body.error) || 'Decline failed.';
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
  iframe.pdf { height: 70vh; }
  canvas { border: 1px solid #999; border-radius: 4px; touch-action: none; width: 100%; max-width: 500px; height: 160px; display: block; margin: .5rem 0; }
  .row { margin: .75rem 0; }
  button { padding: .5rem 1rem; font-size: 1rem; }
  #msg { margin-top: 1rem; font-weight: 600; }
  details.identity, details.decline { margin: 1rem 0; border: 1px solid #ccc; border-radius: 6px; padding: .5rem 1rem; }
  details.identity summary, details.decline summary { cursor: pointer; font-weight: 600; }
  details.identity textarea, details.decline textarea { width: 100%; box-sizing: border-box; font-family: ui-monospace, monospace; font-size: .8rem; margin: .5rem 0; }
  details.identity label, details.decline label { display: block; font-weight: 600; margin-top: .5rem; }
</style>
</head>
<body>
<h1>${escapeText(opts.title)}</h1>
<div class="gate ${opts.gateClass}">${escapeText(opts.sentence)}</div>
${opts.body}
</body>
</html>`;
}

// §12 MUST DO item 5: "a collapsible 'Identity proof' panel containing the
// challenge JSON (copyable) and a textarea to paste the proof JSON". Only
// rendered when this envelope's effective identity level is above "none"
// AND it's this signer's turn (`resolution.status === "ok"`). `challenge` is
// `undefined` when issuing it failed (e.g. a transient store error) — the
// panel still renders so the signer isn't blocked from seeing WHY, they just
// don't get a pre-filled challenge to copy.
function identityProofPanelHtml(level: IdentityLevel, challenge: IdentityChallengePayload | undefined): string {
  const challengeJson = challenge
    ? escapeText(JSON.stringify(challenge, null, 2))
    : "(could not issue a challenge — reload this page to retry)";
  return `
<details class="identity" open>
  <summary>Identity proof required: ${escapeText(level)}</summary>
  <p>This envelope requires identity level <strong>${escapeText(level)}</strong> before your signature can be recorded. Have your wallet/agent sign the challenge below (an eddsa-jcs-2022 DataIntegrityProof over its exact JSON) and paste the resulting proof JSON below.</p>
  <label for="identityChallenge">Challenge (copyable)</label>
  <textarea id="identityChallenge" readonly rows="8" onclick="this.select()">${challengeJson}</textarea>
  <label for="identityProof">Identity proof JSON (paste here)</label>
  <textarea id="identityProof" rows="8" placeholder='{"uuaid":"...","proof":{...}}'></textarea>
</details>`;
}

function renderApprovalPage(
  resolution: TokenResolution,
  nonce: string,
  challenge: IdentityChallengePayload | undefined,
  requiredLevel: IdentityLevel,
  token: string,
): { status: number; html: string } {
  if (resolution.status === "invalid") {
    // No envelope content of any kind — there is none to show, and an
    // invalid/guessed token must not be distinguishable from "exists but
    // you can't see it".
    const sentence = GATE_SENTENCES.invalid;
    return { status: 404, html: page({ title: "Signing link not found", sentence, gateClass: "blocked", body: "" }) };
  }

  const { envelope } = resolution;
  // §16 "Decline": core's `declineEnvelope` voids the WHOLE envelope, so a
  // declined envelope resolves here exactly like any other sender-voided one
  // (`status: "voided"`) — the declining signer is the only distinguishing
  // signal available. Checked first: it overrides both the generic "voided"
  // sentence below and (for the declining signer specifically) the
  // seal-pending one, since a decline can never coexist with a completion.
  const declinedSigner = resolution.status === "voided" ? envelope.signers.find((s) => s.status === "declined") : undefined;
  // D1: a `completed` envelope whose seal step hasn't produced a sealed PDF
  // yet (phase `seal_failed` or `awaiting_seal`) shows the seal-pending
  // sentence instead of "every signer has signed" — the signature really is
  // recorded either way; only the sealed artifact is pending.
  const sentence = declinedSigner
    ? `This envelope was declined by ${declinedSigner.name}${declinedSigner.declineReason ? `: ${declinedSigner.declineReason}` : "."}`
    : resolution.status === "completed" && derivePhase(envelope) !== "sealed"
      ? SEAL_PENDING_SENTENCE
      : GATE_SENTENCES[resolution.status];
  // §13: a PDF envelope shows the EXACT ingested bytes via a plain,
  // same-origin `<iframe src="/sign/<token>/document.pdf">` — a sandboxed
  // `srcdoc` iframe cannot host a PDF viewer. `frame-src` in `cspFor` above
  // already includes `'self'`, so no CSP change is needed for this to load.
  // For an HTML envelope, this is UNCHANGED and remains the ONLY place
  // envelope HTML is ever emitted: inside a fully sandboxed iframe (no
  // allow-scripts, no allow-same-origin, no forms) via an
  // HTML-attribute-escaped srcdoc (I9, T9). `envelope.html` is already the
  // sanitize.ts-stripped body set at creation (esig_create_envelope) — this
  // escaping is the second, independent layer.
  const doc = getEnvelopeDocument(envelope);
  const iframe = doc
    ? (() => {
        const documentUrl = `/sign/${encodeURIComponent(token)}/document.pdf`;
        return (
          `<iframe class="pdf" src="${escapeAttr(documentUrl)}"></iframe>\n` +
          `<p><a href="${escapeAttr(documentUrl)}" target="_blank" rel="noopener">Open the PDF in a new tab</a></p>\n` +
          `<p>Document sha256: <code>${escapeText(doc.sha256)}</code></p>`
        );
      })()
    : `<iframe sandbox srcdoc="${escapeAttr(envelope.html)}"></iframe>`;
  const identityPanel =
    resolution.status === "ok" && requiredLevel !== "none" ? identityProofPanelHtml(requiredLevel, challenge) : "";
  const form = resolution.status === "ok" ? signFormHtml(nonce, requiredLevel !== "none") : "";

  return {
    status: 200,
    html: page({
      title: envelope.title,
      sentence,
      gateClass: resolution.status === "ok" ? "ok" : "blocked",
      body: iframe + identityPanel + form,
    }),
  };
}

// ---------- Sign error -> HTTP status mapping ----------

function statusForSignError(e: unknown): number {
  if (e instanceof IdentityError) return 403; // §12: identity failure — never a silent downgrade
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

      // §12 MUST DO item 5: GET /sign/<token>/challenge — checked before the
      // plain /sign/<token> route below (its `[^/]+` cannot match a path
      // containing another "/" anyway, but checking the more specific route
      // first keeps the routing readable).
      const challengeMatch = /^\/sign\/([^/]+)\/challenge$/.exec(route);
      if (challengeMatch) {
        if (req.method !== "GET") {
          sendJson(res, 405, { error: "method not allowed" }, csp);
          return;
        }
        const challengeToken = decodeURIComponent(challengeMatch[1]);
        const ip = req.socket.remoteAddress ?? "unknown";
        if (!limiter.allow(ip)) {
          sendJson(res, 429, { error: "too many requests to /sign — please wait a moment and try again" }, csp);
          return;
        }
        const resolution = await deps.envelopes.resolve(challengeToken);
        if (resolution.status === "invalid") {
          sendJson(res, 404, { status: "invalid", error: GATE_SENTENCES.invalid }, csp);
          return;
        }
        if (resolution.status !== "ok") {
          // Same gate states as GET /sign (MUST DO item 5) — informational,
          // no challenge to issue while it isn't this signer's turn (or the
          // envelope is already done/voided/expired).
          sendJson(res, 409, { status: resolution.status, error: GATE_SENTENCES[resolution.status] }, csp);
          return;
        }
        try {
          const challenge = await deps.envelopes.issueIdentityChallenge(resolution.envelope.id, resolution.signer.id);
          sendJson(res, 200, challenge, csp);
        } catch (e) {
          sendJson(res, 400, { error: messageOf(e) }, csp);
        }
        return;
      }

      // §13: GET /sign/<token>/document.pdf — for PDF envelopes only,
      // streams the EXACT ingested bytes (WYSIWYS). Checked before the plain
      // /sign/<token> route below, same reason as /challenge above.
      const documentMatch = /^\/sign\/([^/]+)\/document\.pdf$/.exec(route);
      if (documentMatch) {
        if (req.method !== "GET") {
          sendJson(res, 405, { error: "method not allowed" }, csp);
          return;
        }
        const docToken = decodeURIComponent(documentMatch[1]);
        const ip = req.socket.remoteAddress ?? "unknown";
        if (!limiter.allow(ip)) {
          sendJson(res, 429, { error: "too many requests to /sign — please wait a moment and try again" }, csp);
          return;
        }
        // Any resolvable state except invalid may view the document — the
        // same "envelope is shown for context" policy the HTML iframe
        // already follows for every other gate state (not-your-turn,
        // already-signed, completed, voided, expired all carry an envelope).
        const resolution = await deps.envelopes.resolve(docToken);
        if (resolution.status === "invalid") {
          sendJson(res, 404, { error: GATE_SENTENCES.invalid }, csp);
          return;
        }
        const doc = getEnvelopeDocument(resolution.envelope);
        if (!doc) {
          sendJson(res, 404, { error: "this envelope has no PDF document" }, csp);
          return;
        }
        let bytes: Buffer;
        try {
          bytes = await deps.envelopes.getDocumentBytes(doc.docId);
        } catch (e) {
          sendJson(res, 500, { error: `could not load document: ${messageOf(e)}` }, csp);
          return;
        }
        const filename = `${sanitizeFilename(resolution.envelope.title)}.pdf`;
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          "content-security-policy": csp,
          "content-type": "application/pdf",
          "content-length": String(bytes.length),
          "content-disposition": `inline; filename="${filename}"`,
        });
        res.end(bytes);
        return;
      }

      // §15/§16 "Decline": POST /sign/<token>/decline {reason?} — human-side
      // only (never an MCP tool, same reasoning as signing itself). Checked
      // before the plain /sign/<token> route below, same reason as
      // /challenge and /document.pdf above.
      const declineMatch = /^\/sign\/([^/]+)\/decline$/.exec(route);
      if (declineMatch) {
        if (req.method !== "POST") {
          sendJson(res, 405, { error: "method not allowed" }, csp);
          return;
        }
        const declineToken = decodeURIComponent(declineMatch[1]);
        const ip = req.socket.remoteAddress ?? "unknown";
        if (!limiter.allow(ip)) {
          sendJson(res, 429, { error: "too many requests to /sign — please wait a moment and try again" }, csp);
          return;
        }
        const ctype = String(req.headers["content-type"] ?? "");
        if (!ctype.toLowerCase().startsWith("application/json")) {
          sendJson(res, 415, { error: "content-type must be application/json" }, csp);
          return;
        }
        let parsed: { reason?: unknown };
        try {
          const raw = await readBody(req, MAX_SIGN_BODY_BYTES);
          parsed = raw.length > 0 ? JSON.parse(raw.toString("utf8")) : {};
        } catch (e) {
          sendJson(res, 400, { error: `invalid request body: ${messageOf(e)}` }, csp);
          return;
        }
        let reason: string | undefined;
        if (parsed.reason !== undefined) {
          if (typeof parsed.reason !== "string" || parsed.reason.length > 500) {
            sendJson(res, 400, { error: "reason must be a string of at most 500 characters" }, csp);
            return;
          }
          // Defense in depth (SMTP/log-injection class), same rule create-envelope's `message` applies at rest.
          reason = stripControlChars(parsed.reason) || undefined;
        }
        try {
          const summary = await deps.envelopes.decline(declineToken, reason);
          sendJson(res, 200, { status: summary.status, envelopeId: summary.envelopeId, declined: true }, csp);
        } catch (e) {
          sendJson(res, statusForSignError(e), { error: messageOf(e) }, csp);
        }
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
        // §12: show the required level + a pre-filled challenge whenever
        // it's this signer's turn and this envelope requires identity.
        // `getEnvelopeIdentityPolicy` reads the ALREADY-fetched envelope —
        // no extra store round trip beyond `resolve()` itself.
        let requiredLevel: IdentityLevel = "none";
        let challenge: IdentityChallengePayload | undefined;
        if (resolution.status === "ok") {
          // §16: once per signer (EnvelopeService.recordViewed is idempotent
          // and never throws) — awaited so the event is durably recorded
          // before this response is sent, but a failure here never blocks
          // the page from rendering.
          await deps.envelopes.recordViewed(resolution.envelope.id, resolution.signer.id);
          requiredLevel = getEnvelopeIdentityPolicy(resolution.envelope)?.minLevel ?? "none";
          if (requiredLevel !== "none") {
            try {
              challenge = await deps.envelopes.issueIdentityChallenge(resolution.envelope.id, resolution.signer.id);
            } catch {
              // Non-fatal for page rendering (identityProofPanelHtml handles
              // `undefined`) — the signer can reload to retry.
            }
          }
        }
        const rendered = renderApprovalPage(resolution, nonce, challenge, requiredLevel, token);
        sendHtml(res, rendered.status, rendered.html, csp);
        return;
      }

      if (req.method === "POST") {
        const ctype = String(req.headers["content-type"] ?? "");
        if (!ctype.toLowerCase().startsWith("application/json")) {
          sendJson(res, 415, { error: "content-type must be application/json" }, csp);
          return;
        }

        let parsed: { signatureImageDataUrl?: unknown; consent?: unknown; identityProof?: unknown };
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

        // §12 "Presenting a proof": shape-checked minimally here (uuaid
        // present) — the rest (proof/credential/exchange) is verified inside
        // identity/verify.ts, which never throws anything but IdentityError
        // for a malformed/missing/invalid proof.
        let identityProof: IdentityProofInput | undefined;
        if (parsed.identityProof !== undefined) {
          const raw = parsed.identityProof;
          if (!raw || typeof raw !== "object" || typeof (raw as Record<string, unknown>).uuaid !== "string") {
            sendJson(res, 400, { error: "identityProof.uuaid (string) is required when identityProof is present" }, csp);
            return;
          }
          identityProof = raw as unknown as IdentityProofInput;
        }

        try {
          const summary = await deps.envelopes.sign(token, parsed.signatureImageDataUrl, identityProof);
          // D1(a): a seal failure (or a completed envelope whose seal never
          // ran) is NOT an error — `sign()` never throws for it, and this
          // must not respond 500 either. The signature IS validly recorded;
          // only the sealed PDF is still pending (retryable via
          // esig_reseal).
          if (summary.phase === "seal_failed" || summary.phase === "awaiting_seal") {
            sendJson(
              res,
              202,
              {
                status: "signed",
                envelopeId: summary.envelopeId,
                sealed: false,
                message: "Your signature is recorded. The operator will produce the sealed PDF.",
              },
              csp,
            );
            return;
          }
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
          // §12 MUST DO item 5: "identity failure -> 403 {error, reason}".
          const body: Record<string, unknown> = { error: messageOf(e) };
          if (e instanceof IdentityError) body.reason = e.reason;
          sendJson(res, statusForSignError(e), body, csp);
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
