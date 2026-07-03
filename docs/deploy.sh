#!/usr/bin/env bash
# Deploy the docs.e-sig.org site: sync to S3 (private bucket) + invalidate CloudFront.
#
#   ./docs/deploy.sh
#
set -euo pipefail
BUCKET="${ESIG_DOCS_BUCKET:-e-sig-docs-456453427852}"
DIST="${ESIG_DOCS_DIST:-E2ZGKAD2T1MLHQ}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "→ syncing $DIR to s3://$BUCKET/ …"
aws s3 sync "$DIR" "s3://$BUCKET/" \
  --exclude "deploy.sh" --exclude "README.md" --exclude ".*" \
  --cache-control "public,max-age=300" --delete

echo "→ invalidating CloudFront $DIST …"
aws cloudfront create-invalidation --distribution-id "$DIST" --paths '/*' \
  --query 'Invalidation.Status' --output text

echo "✓ deployed → https://docs.e-sig.org"
