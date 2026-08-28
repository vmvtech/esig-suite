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
AWS_CLI="${ESIG_AWS_CLI:-/opt/homebrew/bin/aws}"

if [[ ! -x "$AWS_CLI" ]]; then
  echo "AWS CLI v2 not found at $AWS_CLI" >&2
  exit 1
fi

SYNC_ARGS=(
  --exclude "deploy.sh"
  --exclude "finish.sh"
  --exclude "cf-pretty-urls.js"
  --exclude "README.md"
  --exclude ".*"
  --cache-control "public,max-age=300"
)
if [[ "${ESIG_SITE_PRUNE:-0}" == "1" ]]; then
  SYNC_ARGS+=(--delete)
fi

echo "→ syncing $DIR to s3://$BUCKET/ …"
"$AWS_CLI" s3 sync "$DIR" "s3://$BUCKET/" "${SYNC_ARGS[@]}"

echo "→ invalidating CloudFront $DIST …"
"$AWS_CLI" cloudfront create-invalidation --distribution-id "$DIST" --paths '/*' \
  --query 'Invalidation.Status' --output text

echo "✓ deployed → https://e-sig.org"
