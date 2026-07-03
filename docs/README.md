# docs.e-sig.org

Documentation site for **e-sig** — a single self-contained `index.html` (sidebar
nav, scrollspy, dark/light, no build step) matching the e-sig.org brand. Served
privately from S3 through CloudFront with an ACM TLS cert.

Content is authored from the package READMEs (`@e-sig/core` quickstart, signing,
RFC-3161 timestamps, verification, adapters, React UI, compliance). Because the
hosting is generator-agnostic, this page can later be swapped for a full docs
framework (e.g. Fumadocs static export) without touching the bucket, CloudFront,
cert, or DNS.

## Deploy

```bash
./docs/deploy.sh          # aws s3 sync + CloudFront invalidation
```

Overridable via env: `ESIG_DOCS_BUCKET`, `ESIG_DOCS_DIST`.

## Infrastructure (AWS account 456453427852, us-east-1)

| Piece | Value |
|---|---|
| S3 bucket (private) | `e-sig-docs-456453427852` |
| CloudFront distribution | `E2ZGKAD2T1MLHQ` (`dy5lxfd0od97w.cloudfront.net`) |
| Origin Access Control | `E2WXZVYL8CZ19Y` (shared with the landing page) |
| ACM cert (us-east-1) | `docs.e-sig.org` |
| Route 53 zone | `Z0236240WQ558UN63V2O` (alias A/AAAA `docs.e-sig.org` → CloudFront) |
