#!/usr/bin/env bash
# Deploy the docs.e-sig.org site: sync to S3 (private bucket) + invalidate CloudFront.
#
#   ./docs/deploy.sh
#
set -euo pipefail
AWS="${ESIG_AWS_CLI:-/opt/homebrew/bin/aws}"
BUCKET="${ESIG_DOCS_BUCKET:-e-sig-docs-456453427852}"
DIST="${ESIG_DOCS_DIST:-E2ZGKAD2T1MLHQ}"
DIR="$(cd "$(dirname "$0")" && pwd)"

[[ -x "$AWS" ]] || { echo "ERROR: missing AWS CLI v2 executable: $AWS" >&2; exit 1; }
AWS_VERSION=$("$AWS" --version 2>&1)
[[ "$AWS_VERSION" == aws-cli/2.* ]] \
  || { echo "ERROR: AWS CLI v2 required, got: $AWS_VERSION" >&2; exit 1; }

echo "→ syncing $DIR to s3://$BUCKET/ …"
"$AWS" s3 sync "$DIR" "s3://$BUCKET/" \
  --exclude "*" \
  --include "index.html" \
  --include "blog/*" \
  --cache-control "public,max-age=300" --delete

echo "→ invalidating CloudFront $DIST …"
"$AWS" cloudfront create-invalidation --distribution-id "$DIST" --paths '/*' \
  --query 'Invalidation.Status' --output text

echo "✓ deployed → https://docs.e-sig.org"
