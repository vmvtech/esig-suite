#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
AWS_BIN=${AWS_BIN:-/opt/homebrew/bin/aws}
AWS_REGION=${AWS_REGION:-us-east-1}
STACK_NAME=${STACK_NAME:-esig-cloud-provisioning-staging}
PACKAGED_TEMPLATE=${PACKAGED_TEMPLATE:-"$ROOT_DIR/infra/provisioning/packaged-template.yaml"}
EXECUTE_CHANGESET=${EXECUTE_CHANGESET:-0}

: "${STRIPE_WEBHOOK_SECRET_ARN:?Set STRIPE_WEBHOOK_SECRET_ARN to an existing Secrets Manager ARN.}"

if [[ ! -x "$AWS_BIN" ]]; then
  echo "AWS CLI v2 not found at $AWS_BIN." >&2
  exit 1
fi
if [[ ! -f "$PACKAGED_TEMPLATE" ]]; then
  echo "Packaged template not found: $PACKAGED_TEMPLATE" >&2
  echo "Run package-control-plane.sh first." >&2
  exit 1
fi

deploy_args=(
  cloudformation deploy
  --template-file "$PACKAGED_TEMPLATE"
  --stack-name "$STACK_NAME"
  --region "$AWS_REGION"
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND
  --no-fail-on-empty-changeset
  --parameter-overrides
  "StripeWebhookSecretArn=$STRIPE_WEBHOOK_SECRET_ARN"
  "OperationalWorkerEnabled=false"
  --tags
  "e-sig:managed-by=cloud-provisioning"
  "e-sig:environment=staging"
)

if [[ "$EXECUTE_CHANGESET" != 1 ]]; then
  deploy_args+=(--no-execute-changeset)
fi

"$AWS_BIN" "${deploy_args[@]}"
