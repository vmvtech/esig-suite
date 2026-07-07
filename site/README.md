# e-sig.org — site

Static multi-page site for **e-sig** (no build step). Pages: `/` (landing),
`/pricing`, `/why-vmv`, `/terms`, `/privacy`, `/legal` — each a directory with an
`index.html` (pretty URLs via the CloudFront function in `cf-pretty-urls.js`).
Shared design system in `assets/site.css` (tokens, VMVONE fonts, components,
scroll-reveal motion) + `assets/site.js` (IntersectionObserver reveals; content is
fully visible without JS). Self-hosted VMVONE woff2 files live in `fonts/`.
Served privately from S3 through CloudFront with a TLS cert from ACM.

## Deploy

```bash
./site/deploy.sh          # aws s3 sync + CloudFront invalidation
```

Overridable via env: `ESIG_SITE_BUCKET`, `ESIG_SITE_DIST`.

## Infrastructure (AWS account 456453427852, us-east-1)

| Piece | Value |
|---|---|
| S3 bucket (private) | `e-sig-org-site-456453427852` |
| CloudFront distribution | `E3SMXIUSEUNZH3` (`d1wy31vfdjs4m.cloudfront.net`) |
| Origin Access Control | `E2WXZVYL8CZ19Y` |
| ACM cert (us-east-1) | `e-sig.org`, `www.e-sig.org` |
| Route 53 zone | `Z0236240WQ558UN63V2O` (alias A/AAAA apex + www → CloudFront) |

The bucket is private; only this CloudFront distribution can read it (OAC + a
bucket policy scoped to the distribution ARN). Edit the page you need and re-run
`deploy.sh`.
