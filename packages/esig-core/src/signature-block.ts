// src/lib/integrations/esig/core/signature-block.ts
//
// Phase 21 — portable HTML signature-block rendering for the e-sig pipeline.
// Used by both single-party and multi-party flows. Project-agnostic.

export interface SignatureBlockEntry {
  name: string;
  email: string;
  signatureImageDataUrl: string; // data:image/png;base64,...
  signedAt: Date;
  /** Optional human role label shown above the signature ("Principal investigator", "Witness", ...). */
  roleLabel?: string;
}

/**
 * Render a stack of signature blocks as standalone HTML, suitable for
 * concatenating into a document body before HTML→PDF rendering.
 *
 * Pattern: one signature per row, with name + role + image + timestamp.
 * Plus a trailing audit line tying the PDF back to the platform.
 */
export function renderSignatureBlocksHtml(opts: {
  signers: SignatureBlockEntry[];
  platformLabel?: string;
  platformUrl?: string;
}): string {
  const platform = opts.platformLabel ?? "self-contained e-signature pipeline";
  const url = opts.platformUrl ?? "";
  const rows = opts.signers
    .map(
      (s) => `
  <div class="signature-row">
    ${s.roleLabel ? `<p class="role-label">${escapeHtml(s.roleLabel)}</p>` : ""}
    <p><strong>Signed electronically by:</strong> ${escapeHtml(s.name)}${
      s.email ? ` &lt;${escapeHtml(s.email)}&gt;` : ""
    }</p>
    <img src="${s.signatureImageDataUrl}" alt="Signature of ${escapeHtml(s.name)}">
    <p class="signature-meta">Signed at ${s.signedAt.toISOString()}</p>
  </div>`
    )
    .join("\n");

  return `<div class="signature-block">
  <style>
    .signature-block { margin-top: 64px; border-top: 1px solid #999; padding-top: 16px; }
    .signature-row { margin: 16px 0; padding: 12px 0; border-bottom: 1px dashed #ddd; }
    .signature-row:last-child { border-bottom: none; }
    .signature-row img { display: block; max-height: 96px; margin: 8px 0; }
    .signature-meta { color: #555; font-size: 11px; margin-top: 4px; }
    .role-label { font-style: italic; color: #444; margin: 0 0 4px; }
    .audit-footer { color: #555; font-size: 11px; margin-top: 12px; }
  </style>
  ${rows}
  <p class="audit-footer">
    Cryptographically sealed via the Opendelphi ${platform}${url ? ` (${escapeHtml(url)})` : ""}.
    Any post-signing modification invalidates the signature panel in Adobe Reader / Preview.
  </p>
</div>`;
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
