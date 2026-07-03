# e-sig.org — landing page

Static, self-contained landing page for **e-sig** (one `index.html`, no build step,
no external assets). Served privately from S3 through CloudFront with a TLS cert
from ACM.

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
bucket policy scoped to the distribution ARN). Edit `index.html` and re-run
`deploy.sh`.
