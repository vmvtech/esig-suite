# Document templates

Six self-contained HTML document templates you can fill in and send through
`@e-sig/core` or the `@e-sig/mcp` server as an envelope: `nda.html` (mutual
NDA), `irb-consent.html` (research informed consent), `dua-mta.html` (data
use / material transfer agreement), `grant-approval.html` (internal
grant/budget approval with a multi-approver chain), `permission-slip.html`
(K-12 field-trip/activity permission slip), and `offer-letter.html`
(employment offer letter).

Each file is a complete, standalone HTML document: inline `<style>` only, no
`<script>`, no external stylesheets/fonts/images, no `<form>`/`<iframe>`/
`<object>`/`<embed>`, and a visible top banner reading `TEMPLATE — not legal
advice; have counsel review before use`. They print cleanly at both US
Letter and A4 sizes. Every file's content area is capped at 6.5in wide so it
fits inside either page size's printable area once margins are applied.

## Placeholder convention

Fields to fill in are mustache-style `{{placeholder_name}}` tokens, e.g.
`{{party_a_name}}` or `{{effective_date}}`. Each template documents its own
full placeholder list in an HTML comment at the top of the file — read that
comment before filling one in. Placeholders are plain text substitution
only: there is no conditional/loop logic, so an unused optional field (e.g.
"Not applicable") should still be filled with literal text rather than left
as `{{...}}`.

## Filling a template and creating an envelope

```js
import { readFile } from "node:fs/promises";
import { createEnvelope } from "@e-sig/core";
// `store` is your own EnvelopeStore implementation (see packages/esig-core's
// EnvelopeStore interface) — e.g. @e-sig/supabase's adapter, or your own.

const fields = { party_a_name: "Acme Inc.", party_b_name: "Beta LLC", /* … */ };
let html = await readFile(new URL("./nda.html", import.meta.url), "utf8");
for (const [k, v] of Object.entries(fields)) html = html.replaceAll(`{{${k}}}`, v);

const { envelope, signingTokens } = await createEnvelope({
  store, tenantId: "acme", title: "Mutual NDA — Acme × Beta", html,
  signers: [{ name: "Ada Lovelace", email: "ada@acme.example", order: 1 },
            { name: "Grace Hopper", email: "grace@beta.example", order: 2 }],
});
```

`signingTokens` is returned exactly once — deliver each token to its signer
out-of-band (email link, etc.); only its hash is persisted.

If you're driving this from an agent instead of application code, do the
same `{{...}}` substitution, then call the MCP server's `esig_create_envelope`
tool with the filled `html` and the same `signers` array (pass `title` and,
if needed, `expiresAt`) — see `packages/esig-mcp/src/tools/create-envelope.ts`.
The MCP path additionally strips `<script>`, event-handler attributes,
`javascript:` URLs, and `<iframe>`/`<object>`/`<embed>`/`<form>` from the HTML
as a defense-in-depth layer before storage
(`packages/esig-mcp/src/sanitize.ts`); none of these templates trigger that
stripping when unmodified. **Core's `createEnvelope` stores the HTML verbatim**
— if you fill placeholders from untrusted input on the core path, sanitize it
yourself first.

For `grant-approval.html`'s multi-approver chain, give each approver an
increasing `order` (1, 2, 3, …) so the chain signs in sequence — order ties
sign in parallel (`packages/esig-core/src/envelope.ts`, `EnvelopeSigner.order`).

## Sealing note

When the last signer signs, the envelope is composed (base HTML + rendered
signature blocks, `composeEnvelopeHtml` in `packages/esig-core/src/envelope.ts`)
and then sealed with one cryptographic signature. **How that seal step
produces a PDF depends on how the envelope was created:**

- **HTML envelopes** (created with `html`, as above) are rendered to PDF with
  headless Chrome at seal time (`renderHtmlToPdf`,
  `packages/esig-core/src/render-pdf.ts`) before signing. This needs a Chrome/
  Chromium binary available on the server doing the sealing — see
  `packages/esig-mcp/src/chrome-preflight.ts` for how the MCP server checks
  for one at startup.
- **PDF envelopes** (created with `docId` from `esig_ingest_document` instead
  of `html`) skip that step entirely: the signer reviews and signs the exact
  ingested PDF bytes, and sealing signs those bytes directly — no Chrome
  needed anywhere on that path.

If you'd rather not depend on Chrome being available, ingest a PDF version of
a filled template and create the envelope with `docId` instead of `html`.

## Legal disclaimer

These are starting-point templates, not legal advice, and not a substitute
for review by qualified counsel (and, for `irb-consent.html`, your
institution's IRB) before use. Requirements vary by jurisdiction, industry,
and document type — employment-offer at-will language, IRB consent
language, and school-district permission-slip policy in particular are all
governed by rules specific to your state/institution that these templates do
not attempt to encode. Have the appropriate reviewer sign off before sending
any of these to a real signer.
