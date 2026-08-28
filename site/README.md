# e-sig.org — site

Static multi-page site for **e-sig** (no build step). Pages: `/` (landing),
`/pricing`, `/why-esig`, `/verify`, `/agents`, `/press`,
`/vs/{docusign,documenso,docuseal}`, `/terms`, `/privacy`, `/legal` — each a
directory with an `index.html` (pretty URLs via the CloudFront function in
`cf-pretty-urls.js`). Shared design system in `assets/site.css` (tokens, VMVONE
fonts, components, scroll-reveal motion) + `assets/site.js`
(IntersectionObserver reveals; content is fully visible without JS).
Self-hosted VMVONE woff2 files live in `fonts/`.
Served privately from S3 through CloudFront with a TLS cert from ACM.

Root machine-readable files: `llms.txt`, `llms-full.txt` (regenerate via
`node scripts/ops/gen-llms-full.mjs` after any page edit), `agent.json`,
`robots.txt`, `sitemap.xml`.

## Deploy

```bash
ESIG_APPROVE_PRODUCTION=1 ./site/finish.sh
```

`finish.sh` is the canonical publisher: it backs up production, publishes the
fail-closed checkout Lambda and URL function, uploads static files without
deleting S3 objects, waits for CloudFront, and hard-fails on live verification.
It never commits or pushes. See the [production runbook](../docs/RUNBOOK-uaid-exch-and-why-esig.md).

`deploy.sh` is a static-files-only helper and does **not** publish edge code.
Its default sync is non-destructive. Set `ESIG_SITE_PRUNE=1` only after a
separate review of obsolete objects. Overridable via env: `ESIG_SITE_BUCKET`,
`ESIG_SITE_DIST`, `ESIG_AWS_CLI`.

## Infrastructure (AWS account 456453427852, us-east-1)

| Piece | Value |
|---|---|
| S3 bucket (private) | `e-sig-org-site-456453427852` |
| CloudFront distribution | `E3SMXIUSEUNZH3` (`d1wy31vfdjs4m.cloudfront.net`) |
| Origin Access Control | `E2WXZVYL8CZ19Y` |
| ACM cert (us-east-1) | `e-sig.org`, `www.e-sig.org` |
| Route 53 zone | `Z0236240WQ558UN63V2O` (alias A/AAAA apex + www → CloudFront) |

The bucket is private; only this CloudFront distribution can read it (OAC + a
bucket policy scoped to the distribution ARN). Use `finish.sh` for production
publishes so static content and edge behavior cannot drift.
