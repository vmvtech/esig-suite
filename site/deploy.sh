#!/usr/bin/env bash
# Deploy the e-sig.org landing page: sync to S3 (private bucket) + invalidate CloudFront.
# Requires AWS credentials with access to the bucket + distribution below.
#
#   ./site/deploy.sh
#
set -euo pipefail
BUCKET="${ESIG_SITE_BUCKET:-e-sig-org-site-456453427852}"
DIST="${ESIG_SITE_DIST:-E3SMXIUSEUNZH3}"
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "→ syncing $DIR to s3://$BUCKET/ …"
aws s3 sync "$DIR" "s3://$BUCKET/" \
  --exclude "deploy.sh" --exclude "README.md" --exclude ".*" \
  --cache-control "public,max-age=300" --delete

echo "→ invalidating CloudFront $DIST …"
aws cloudfront create-invalidation --distribution-id "$DIST" --paths '/*' \
  --query 'Invalidation.Status' --output text

echo "✓ deployed → https://e-sig.org"
