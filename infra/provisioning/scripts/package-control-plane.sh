#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
AWS_BIN=${AWS_BIN:-/opt/homebrew/bin/aws}
AWS_REGION=${AWS_REGION:-us-east-1}
ARTIFACT_PREFIX=${ARTIFACT_PREFIX:-e-sig/cloud-provisioning}
OUTPUT_TEMPLATE=${OUTPUT_TEMPLATE:-"$ROOT_DIR/infra/provisioning/packaged-template.yaml"}

: "${ARTIFACT_BUCKET:?Set ARTIFACT_BUCKET to a private, versioned deployment bucket.}"

if [[ ! -x "$AWS_BIN" ]]; then
  echo "AWS CLI v2 not found at $AWS_BIN." >&2
  exit 1
fi

npm run bundle -w @e-sig/cloud-provisioning

customer_digest=$(shasum -a 256 \
  "$ROOT_DIR/infra/provisioning/customer-stack.yaml" | awk '{print $1}')
customer_key="$ARTIFACT_PREFIX/customer-stack/$customer_digest.yaml"

"$AWS_BIN" s3 cp \
  "$ROOT_DIR/infra/provisioning/customer-stack.yaml" \
  "s3://$ARTIFACT_BUCKET/$customer_key" \
  --region "$AWS_REGION" \
  --only-show-errors

"$AWS_BIN" cloudformation package \
  --template-file "$ROOT_DIR/infra/provisioning/template.yaml" \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --s3-prefix "$ARTIFACT_PREFIX/control-plane" \
  --output-template-file "$OUTPUT_TEMPLATE" \
  --region "$AWS_REGION"

printf 'PACKAGED_TEMPLATE=%s\n' "$OUTPUT_TEMPLATE"
printf 'CUSTOMER_STACK_TEMPLATE_URL=https://s3.%s.amazonaws.com/%s/%s\n' \
  "$AWS_REGION" "$ARTIFACT_BUCKET" "$customer_key"
