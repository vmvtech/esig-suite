// email/templates.ts
//
// Renders the signing-notification email (docs/architecture/esig-mcp.md §15
// "Message content"). Anti-phishing / PII minimization by construction: the
// only agent/signer-influenced values are the escaped envelope title and the
// optional sender note (esig_create_envelope's `message`) — never the
// document body, never other signers' details. Every value is HTML-escaped
// for the html part and control-character-stripped everywhere (defense in
// depth against SMTP header injection, independent of transport.ts's own
// stripping of whatever reaches it).

export interface EmailTemplateInput {
  /** Envelope title, shown to the signer. */
  title: string;
  /** The operator's configured from-address display string (ESIG_MCP_EMAIL_FROM) — shown in the body so the signer knows who is asking, separately from the SMTP `From:` header itself (transport.ts). */
  from: string;
  /** Optional sender note (esig_create_envelope's `message`, <= 500 chars). Never the document body, never other signers. */
  note?: string;
  /** The signer's tokenized signing link. */
  url: string;
  /** ISO-8601 envelope expiry, if any. */
  expiresAt?: string;
  /** ESIG_MCP_EMAIL_SUBJECT_PREFIX, if configured. */
  prefix?: string;
}

export interface RenderedEmail {
  subject: string;
  text: string;
  html: string;
}

/** Strip CR/LF/NUL and other C0/DEL control chars — SMTP header injection defense. Exported so envelopes.ts can apply the same rule to `metadata.mcp.message` at rest. */
export function stripControlChars(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\x00-\x1f\x7f]/g, "").trim();
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function renderSigningEmail(input: EmailTemplateInput): RenderedEmail {
  const title = stripControlChars(input.title) || "Untitled document";
  const from = stripControlChars(input.from);
  const note = input.note !== undefined ? stripControlChars(input.note) : undefined;
  const prefix = input.prefix !== undefined ? stripControlChars(input.prefix) : undefined;

  const subject = stripControlChars(`${prefix ? `[${prefix}] ` : ""}Please sign: ${title}`);

  const expiresLine = input.expiresAt ? `This link expires ${input.expiresAt}.` : undefined;

  const text = [
    `You have been asked to sign "${title}".`,
    `From: ${from}`,
    ...(note ? ["", note] : []),
    "",
    `Sign here: ${input.url}`,
    ...(expiresLine ? ["", expiresLine] : []),
  ].join("\n");

  const html = [
    "<div>",
    `<p>You have been asked to sign <strong>${escapeHtml(title)}</strong>.</p>`,
    `<p>From: ${escapeHtml(from)}</p>`,
    ...(note ? [`<p>${escapeHtml(note)}</p>`] : []),
    `<p><a href="${escapeHtml(input.url)}">Sign here</a></p>`,
    ...(expiresLine ? [`<p>${escapeHtml(expiresLine)}</p>`] : []),
    "</div>",
  ].join("\n");

  return { subject, text, html };
}
