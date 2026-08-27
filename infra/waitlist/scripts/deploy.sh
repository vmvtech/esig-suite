#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
AWS_BIN=${AWS_BIN:-/opt/homebrew/bin/aws}
NPM_BIN=${NPM_BIN:-$(command -v npm || true)}
NODE_BIN=${NODE_BIN:-$(command -v node || true)}
AWS_REGION=${AWS_REGION:-us-east-1}
BOOTSTRAP_STACK_NAME=${BOOTSTRAP_STACK_NAME:-esig-waitlist-artifacts}
STACK_NAME=${STACK_NAME:-esig-waitlist-production}
ARTIFACT_PREFIX=${ARTIFACT_PREFIX:-e-sig/waitlist-api}
BOOTSTRAP_ONLY=${BOOTSTRAP_ONLY:-0}
EXECUTE_CHANGESET=${EXECUTE_CHANGESET:-0}
WAITLIST_NOTIFIER_ENABLED=${WAITLIST_NOTIFIER_ENABLED:-}
WAITLIST_READER_ENABLED=${WAITLIST_READER_ENABLED:-false}
WAITLIST_READER_PRINCIPAL_ARN=${WAITLIST_READER_PRINCIPAL_ARN:-}
WAITLIST_BROKER_QUEUE_URL=${WAITLIST_BROKER_QUEUE_URL:-}
WAITLIST_BROKER_QUEUE_ARN=${WAITLIST_BROKER_QUEUE_ARN:-}
WAITLIST_BROKER_KMS_KEY_ARN=${WAITLIST_BROKER_KMS_KEY_ARN:-}
APPROVED_BROKER_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/633740007231/esig-mail-enqueue-standard.fifo
APPROVED_BROKER_QUEUE_ARN=arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard.fifo
APPROVED_PRODUCER_ROLE_ARN=arn:aws:iam::456453427852:role/esig-waitlist-production-mail-producer
ACTIVATION_PROOF_READ_INVOCATION_TYPE=waitlist-activation-proof-read-v1
BROKER_KMS_KEY_ARN_PATTERN='^arn:aws:kms:us-east-1:633740007231:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
READER_PRINCIPAL_ARN_PATTERN='^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$'

if [[ ! -x "$AWS_BIN" ]]; then
  echo "AWS CLI v2 not found at $AWS_BIN." >&2
  exit 1
fi
if [[ -z "$NPM_BIN" || ! -x "$NPM_BIN" ]]; then
  echo "npm not found." >&2
  exit 1
fi
if [[ -z "$NODE_BIN" || ! -x "$NODE_BIN" ]]; then
  echo "node not found." >&2
  exit 1
fi
if [[ "$AWS_REGION" != "us-east-1" ]]; then
  echo "AWS_REGION must be us-east-1 for the pinned producer deployment." >&2
  exit 1
fi
if [[ "$BOOTSTRAP_ONLY" != "0" && "$BOOTSTRAP_ONLY" != "1" ]]; then
  echo "BOOTSTRAP_ONLY must be 0 or 1." >&2
  exit 1
fi
if [[ "$EXECUTE_CHANGESET" != "0" && "$EXECUTE_CHANGESET" != "1" ]]; then
  echo "EXECUTE_CHANGESET must be 0 or 1." >&2
  exit 1
fi
if [[ -n "$WAITLIST_NOTIFIER_ENABLED" && "$WAITLIST_NOTIFIER_ENABLED" != "true" && "$WAITLIST_NOTIFIER_ENABLED" != "false" ]]; then
  echo "WAITLIST_NOTIFIER_ENABLED must be empty, true, or false." >&2
  exit 1
fi
if [[ "$WAITLIST_READER_ENABLED" != "true" && "$WAITLIST_READER_ENABLED" != "false" ]]; then
  echo "WAITLIST_READER_ENABLED must be true or false." >&2
  exit 1
fi
if [[ "$WAITLIST_READER_ENABLED" == "true" ]]; then
  if [[ ! "$WAITLIST_READER_PRINCIPAL_ARN" =~ $READER_PRINCIPAL_ARN_PATTERN ]]; then
    echo "WAITLIST_READER_PRINCIPAL_ARN must be one exact non-root IAM role ARN." >&2
    exit 1
  fi
elif [[ -n "$WAITLIST_READER_PRINCIPAL_ARN" ]]; then
  echo "WAITLIST_READER_PRINCIPAL_ARN must be empty while the reader is disabled." >&2
  exit 1
fi
if [[ "$WAITLIST_NOTIFIER_ENABLED" == "true" ]]; then
  if [[ "$WAITLIST_BROKER_QUEUE_URL" != "$APPROVED_BROKER_QUEUE_URL" ]]; then
    echo "WAITLIST_BROKER_QUEUE_URL must be the approved Standard-lane FIFO URL." >&2
    exit 1
  fi
  if [[ "$WAITLIST_BROKER_QUEUE_ARN" != "$APPROVED_BROKER_QUEUE_ARN" ]]; then
    echo "WAITLIST_BROKER_QUEUE_ARN must be the approved Standard-lane FIFO ARN." >&2
    exit 1
  fi
  if [[ ! "$WAITLIST_BROKER_KMS_KEY_ARN" =~ $BROKER_KMS_KEY_ARN_PATTERN ]]; then
    echo "WAITLIST_BROKER_KMS_KEY_ARN must be the exact Standard-account broker CMK ARN." >&2
    exit 1
  fi
elif [[ -n "$WAITLIST_BROKER_KMS_KEY_ARN" && ! "$WAITLIST_BROKER_KMS_KEY_ARN" =~ $BROKER_KMS_KEY_ARN_PATTERN ]]; then
  echo "WAITLIST_BROKER_KMS_KEY_ARN is invalid." >&2
  exit 1
fi

if [[ "$BOOTSTRAP_ONLY" == "1" ]]; then
  "$AWS_BIN" cloudformation deploy \
    --template-file "$ROOT_DIR/infra/waitlist/artifact-bootstrap.yaml" \
    --stack-name "$BOOTSTRAP_STACK_NAME" \
    --region "$AWS_REGION" \
    --no-fail-on-empty-changeset \
    --tags \
    "e-sig:managed-by=waitlist-api" \
    "e-sig:environment=production"
fi

artifact_bucket=$(
  "$AWS_BIN" cloudformation describe-stacks \
    --stack-name "$BOOTSTRAP_STACK_NAME" \
    --region "$AWS_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='ArtifactBucketName'].OutputValue | [0]" \
    --output text 2>/dev/null || true
)

if [[ -z "$artifact_bucket" || "$artifact_bucket" == "None" ]]; then
  echo "Artifact bootstrap stack is absent. Run once with BOOTSTRAP_ONLY=1; application deployment never bootstraps implicitly." >&2
  exit 1
fi

public_access=$(
  "$AWS_BIN" s3api get-public-access-block \
    --bucket "$artifact_bucket" \
    --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
    --output text \
    --region "$AWS_REGION"
)
if [[ "$public_access" != $'True\tTrue\tTrue\tTrue' ]]; then
  echo "Artifact bucket must have all four S3 public-access blocks enabled." >&2
  exit 1
fi

versioning=$(
  "$AWS_BIN" s3api get-bucket-versioning \
    --bucket "$artifact_bucket" \
    --query Status \
    --output text \
    --region "$AWS_REGION"
)
if [[ "$versioning" != "Enabled" ]]; then
  echo "Artifact bucket versioning must be Enabled." >&2
  exit 1
fi

encryption=$(
  "$AWS_BIN" s3api get-bucket-encryption \
    --bucket "$artifact_bucket" \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
    --output text \
    --region "$AWS_REGION"
)
if [[ "$encryption" != "AES256" && "$encryption" != "aws:kms" ]]; then
  echo "Artifact bucket default encryption is not enabled." >&2
  exit 1
fi

bucket_policy_json=$(
  "$AWS_BIN" s3api get-bucket-policy \
    --bucket "$artifact_bucket" \
    --query Policy \
    --output text \
    --region "$AWS_REGION"
)
# shellcheck disable=SC2016 # JavaScript is intentionally single-quoted for the shell.
tls_policy_ok=$(
  BUCKET_POLICY_JSON="$bucket_policy_json" "$NODE_BIN" -e '
    const bucket = process.argv[1];
    const policy = JSON.parse(process.env.BUCKET_POLICY_JSON || "{}");
    const statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
    const bucketSuffix = `:s3:::${bucket}`;
    const ok = statements.filter(Boolean).some((statement) => {
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
      const principal = statement.Principal;
      const principalIsAll = principal === "*" || (principal && principal.AWS === "*");
      const secureTransport = statement.Condition && statement.Condition.Bool &&
        statement.Condition.Bool["aws:SecureTransport"];
      return statement.Effect === "Deny" && principalIsAll &&
        actions.some((action) => action === "s3:*" || action === "*") &&
        resources.some((resource) => typeof resource === "string" && resource.endsWith(bucketSuffix)) &&
        resources.some((resource) => typeof resource === "string" && resource.endsWith(`${bucketSuffix}/*`)) &&
        String(secureTransport).toLowerCase() === "false";
    });
    process.stdout.write(ok ? "true" : "false");
  ' "$artifact_bucket"
)
if [[ "$tls_policy_ok" != "true" ]]; then
  echo "Artifact bucket policy must deny insecure transport for the bucket and its objects." >&2
  exit 1
fi

if [[ "$BOOTSTRAP_ONLY" == "1" ]]; then
  printf 'ARTIFACT_BUCKET=%s\n' "$artifact_bucket"
  exit 0
fi

release_dir=$(mktemp -d "${TMPDIR:-/tmp}/esig-waitlist-release.XXXXXX")
chmod 700 "$release_dir"
trap 'rm -rf "$release_dir"' EXIT

build_dir="$release_dir/build"
mkdir -m 700 "$build_dir"
cp "$ROOT_DIR/infra/waitlist/template.yaml" "$build_dir/template.yaml"
cp "$ROOT_DIR/infra/waitlist/package.json" "$build_dir/package.json"
cp "$ROOT_DIR/infra/waitlist/package-lock.json" "$build_dir/package-lock.json"
cp -R "$ROOT_DIR/infra/waitlist/src" "$build_dir/src"

"$NPM_BIN" ci \
  --omit=dev \
  --ignore-scripts \
  --no-audit \
  --no-fund \
  --prefix "$build_dir"

read_activation_proof_receipt() {
  local function_name=$1
  local response_file=$2
  local invocation_metadata

  : >"$response_file"
  chmod 600 "$response_file"
  invocation_metadata=$(
    "$AWS_BIN" lambda invoke \
      --function-name "$function_name" \
      --invocation-type RequestResponse \
      --cli-binary-format raw-in-base64-out \
      --payload "{\"invocationType\":\"$ACTIVATION_PROOF_READ_INVOCATION_TYPE\"}" \
      --region "$AWS_REGION" \
      --output json \
      "$response_file"
  )

  INVOCATION_METADATA="$invocation_metadata" "$NODE_BIN" -e '
    const fs = require("node:fs");
    try {
      const metadata = JSON.parse(process.env.INVOCATION_METADATA || "{}");
      const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const keys = Object.keys(value).sort().join(",");
      const generation = typeof value.proofGeneration === "string" ? value.proofGeneration : "";
      const order = typeof value.proofOrder === "string" ? value.proofOrder : "";
      const generationMatch = /^([0-9]{39}):[0-9]{20}:[0-9]{20}:[a-f0-9]{64}$/.exec(generation);
      const sequenceNumber = generationMatch ? BigInt(generationMatch[1]) : 0n;
      const ok = metadata.StatusCode === 200 && !metadata.FunctionError &&
        keys === "proofDigest,proofGeneration,proofOrder,status" &&
        value.status === "proof-verified" && /^[a-f0-9]{64}$/.test(value.proofDigest || "") &&
        generationMatch && sequenceNumber > 0n && sequenceNumber <= ((1n << 128n) - 1n) &&
        order === `${generation}:01`;
      if (!ok) process.exit(1);
      process.stdout.write(JSON.stringify({
        status: value.status,
        proofDigest: value.proofDigest,
        proofGeneration: generation,
        proofOrder: order,
      }));
    } catch { process.exit(1); }
  ' "$response_file"
}

activation_preflight=not-approved
reader_activation_preflight=not-approved
if [[ "$WAITLIST_READER_ENABLED" == "true" ]]; then
  waitlist_table_name=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistTableName'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )
  outbox_table_name=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistNotificationOutboxTableName'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )
  opaque_id_writer_version=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistOpaqueIdWriterVersion'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )
  submission_id_index_name=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistSubmissionIdIndexName'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )

  if [[ -z "$waitlist_table_name" || "$waitlist_table_name" == "None" || -z "$outbox_table_name" || "$outbox_table_name" == "None" || "$opaque_id_writer_version" != "opaque-id-random-v1" || "$submission_id_index_name" != "submission-id-index" ]]; then
    echo "Reader activation blocked: deploy the random-v1 writer and submission ID index with the reader disabled first." >&2
    exit 1
  fi

  backfill_result=$(
    AWS_REGION="$AWS_REGION" \
    WAITLIST_TABLE_NAME="$waitlist_table_name" \
    WAITLIST_OUTBOX_TABLE_NAME="$outbox_table_name" \
    "$NODE_BIN" "$build_dir/src/backfill-outbox.js"
  )
  backfill_verified=$(
    BACKFILL_RESULT="$backfill_result" "$NODE_BIN" -e '
      try {
        const value = JSON.parse(process.env.BACKFILL_RESULT || "");
        const keys = Object.keys(value).sort().join(",");
        const ok = keys === "eligible,passes,status" && value.status === "verified" &&
          Number.isInteger(value.passes) && value.passes >= 1 && value.passes <= 3 &&
          Number.isInteger(value.eligible) && value.eligible >= 0;
        process.stdout.write(ok ? "true" : "false");
      } catch { process.stdout.write("false"); }
    '
  )
  if [[ "$backfill_verified" != "true" ]]; then
    echo "Reader activation blocked: opaque random-v1 ID migration did not converge." >&2
    exit 1
  fi
  reader_activation_preflight=opaque-ids-verified
fi

if [[ "$WAITLIST_NOTIFIER_ENABLED" == "true" ]]; then
  current_notifier_enabled=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Parameters[?ParameterKey=='WaitlistNotifierEnabled'].ParameterValue | [0]" \
      --output text 2>/dev/null || true
  )
  notifier_function_name=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistNotifierFunctionName'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )
  notifier_role_arn=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistNotifierRoleArn'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )
  deployed_broker_kms_key_arn=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistBrokerKmsKeyArn'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )
  if [[ -z "$notifier_function_name" || "$notifier_function_name" == "None" || "$notifier_role_arn" != "$APPROVED_PRODUCER_ROLE_ARN" || "$deployed_broker_kms_key_arn" != "$WAITLIST_BROKER_KMS_KEY_ARN" ]]; then
    echo "Notifier activation blocked: deploy the proof-reader-capable notifier, exact producer role, and broker CMK with its mapping disabled first." >&2
    exit 1
  fi
  if ! activation_proof_receipt=$(
    read_activation_proof_receipt \
      "$notifier_function_name" \
      "$release_dir/activation-proof-before.json"
  ); then
    echo "Notifier activation blocked: exact lane proof is invalid, stale, or incomplete." >&2
    exit 1
  fi

  if [[ "$current_notifier_enabled" != "true" ]]; then
    waitlist_table_name=$(
      "$AWS_BIN" cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='WaitlistTableName'].OutputValue | [0]" \
        --output text 2>/dev/null || true
    )
    outbox_table_name=$(
      "$AWS_BIN" cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='WaitlistNotificationOutboxTableName'].OutputValue | [0]" \
        --output text 2>/dev/null || true
    )
    outbox_writer_version=$(
      "$AWS_BIN" cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='WaitlistOutboxWriterVersion'].OutputValue | [0]" \
        --output text 2>/dev/null || true
    )
    outbox_stream_arn=$(
      "$AWS_BIN" cloudformation describe-stacks \
        --stack-name "$STACK_NAME" --region "$AWS_REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='WaitlistNotificationOutboxStreamArn'].OutputValue | [0]" --output text 2>/dev/null || true
    )
    if [[ -z "$waitlist_table_name" || "$waitlist_table_name" == "None" || -z "$outbox_table_name" || "$outbox_table_name" == "None" || "$outbox_writer_version" != "metadata-outbox-v1" || -z "$outbox_stream_arn" || "$outbox_stream_arn" == "None" || -z "$notifier_function_name" || "$notifier_function_name" == "None" || "$notifier_role_arn" != "$APPROVED_PRODUCER_ROLE_ARN" || "$deployed_broker_kms_key_arn" != "$WAITLIST_BROKER_KMS_KEY_ARN" ]]; then
      echo "Deploy the canary-ready metadata-outbox-v1 handler, disabled notifier mapping, and exact broker CMK first." >&2
      exit 1
    fi

    mapping_state=$(
      "$AWS_BIN" lambda list-event-source-mappings \
        --function-name "$notifier_function_name" \
        --event-source-arn "$outbox_stream_arn" \
        --region "$AWS_REGION" \
        --query "join(',', EventSourceMappings[].State)" \
        --output text
    )
    if [[ "$mapping_state" != "Disabled" ]]; then
      echo "Notifier activation blocked: exactly one deployed event-source mapping must still be Disabled." >&2
      exit 1
    fi

    backfill_result=$(
      AWS_REGION="$AWS_REGION" \
      WAITLIST_TABLE_NAME="$waitlist_table_name" \
      WAITLIST_OUTBOX_TABLE_NAME="$outbox_table_name" \
      "$NODE_BIN" "$build_dir/src/backfill-outbox.js"
    )
    backfill_verified=$(
      BACKFILL_RESULT="$backfill_result" "$NODE_BIN" -e '
        try {
          const value = JSON.parse(process.env.BACKFILL_RESULT || "");
          const keys = Object.keys(value).sort().join(",");
          const ok = keys === "eligible,passes,status" && value.status === "verified" &&
            Number.isInteger(value.passes) && value.passes >= 1 && value.passes <= 3 &&
            Number.isInteger(value.eligible) && value.eligible >= 0;
          process.stdout.write(ok ? "true" : "false");
        } catch { process.stdout.write("false"); }
      '
    )
    if [[ "$backfill_verified" != "true" ]]; then
      echo "Notifier activation blocked: metadata-only outbox backfill did not verify zero missing records." >&2
      exit 1
    fi

    replay_result=$(
      AWS_REGION="$AWS_REGION" \
      WAITLIST_OUTBOX_TABLE_NAME="$outbox_table_name" \
      WAITLIST_OUTBOX_STREAM_ARN="$outbox_stream_arn" \
      WAITLIST_NOTIFIER_FUNCTION_NAME="$notifier_function_name" \
      "$NODE_BIN" "$build_dir/src/replay-outbox.js"
    )
    replay_verified=$(
      REPLAY_RESULT="$replay_result" "$NODE_BIN" -e '
        try {
          const value = JSON.parse(process.env.REPLAY_RESULT || "");
          const keys = Object.keys(value).sort().join(",");
          const ok = keys === "eligible,passes,replayed,status" && value.status === "verified" &&
            Number.isInteger(value.passes) && value.passes >= 1 && value.passes <= 3 &&
            Number.isInteger(value.eligible) && value.eligible >= 0 &&
            Number.isInteger(value.replayed) && value.replayed >= value.eligible;
          process.stdout.write(ok ? "true" : "false");
        } catch { process.stdout.write("false"); }
      '
    )
    if [[ "$replay_verified" != "true" ]]; then
      echo "Notifier activation blocked: direct notifier backlog replay did not verify every eligible row." >&2
      exit 1
    fi

    if ! activation_proof_receipt_after_replay=$(
      read_activation_proof_receipt \
        "$notifier_function_name" \
        "$release_dir/activation-proof-after.json"
    ); then
      echo "Notifier activation blocked: lane proof expired or changed during backlog replay." >&2
      exit 1
    fi
    if [[ "$activation_proof_receipt_after_replay" != "$activation_proof_receipt" ]]; then
      echo "Notifier activation blocked: lane proof expired or changed during backlog replay." >&2
      exit 1
    fi
    unset activation_proof_receipt_after_replay
  fi

  unset activation_proof_receipt
  activation_preflight=proof-and-backfill-verified
fi

packaged_template="$release_dir/packaged-template.yaml"
"$AWS_BIN" cloudformation package \
  --template-file "$build_dir/template.yaml" \
  --s3-bucket "$artifact_bucket" \
  --s3-prefix "$ARTIFACT_PREFIX" \
  --output-template-file "$packaged_template" \
  --region "$AWS_REGION"
chmod 400 "$packaged_template"

packaged_sha256=$(shasum -a 256 "$packaged_template" | awk '{print $1}')
printf 'PACKAGED_TEMPLATE_SHA256=%s\n' "$packaged_sha256"

parameter_overrides=(
  "ProductionRetentionDays=180"
  "SmokeTestTtlHours=24"
  "WafRateLimit=50"
  "WaitlistReaderEnabled=$WAITLIST_READER_ENABLED"
)

if [[ "$WAITLIST_READER_ENABLED" == "true" ]]; then
  parameter_overrides+=(
    "WaitlistReaderPrincipalArn=$WAITLIST_READER_PRINCIPAL_ARN"
    "WaitlistReaderActivationPreflight=$reader_activation_preflight"
  )
else
  parameter_overrides+=(
    "WaitlistReaderPrincipalArn=not-configured"
    "WaitlistReaderActivationPreflight=not-approved"
  )
fi

if [[ -n "$WAITLIST_NOTIFIER_ENABLED" ]]; then
  parameter_overrides+=("WaitlistNotifierEnabled=$WAITLIST_NOTIFIER_ENABLED")
fi
if [[ -n "$WAITLIST_BROKER_KMS_KEY_ARN" ]]; then
  parameter_overrides+=("WaitlistBrokerKmsKeyArn=$WAITLIST_BROKER_KMS_KEY_ARN")
fi
if [[ "$WAITLIST_NOTIFIER_ENABLED" == "true" ]]; then
  parameter_overrides+=(
    "WaitlistBrokerQueueUrl=$WAITLIST_BROKER_QUEUE_URL"
    "WaitlistBrokerQueueArn=$WAITLIST_BROKER_QUEUE_ARN"
    "WaitlistNotifierActivationPreflight=$activation_preflight"
  )
elif [[ "$WAITLIST_NOTIFIER_ENABLED" == "false" ]]; then
  parameter_overrides+=("WaitlistNotifierActivationPreflight=not-approved")
fi

deploy_args=(
  cloudformation deploy
  --template-file "$packaged_template"
  --stack-name "$STACK_NAME"
  --region "$AWS_REGION"
  --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
  --no-fail-on-empty-changeset
  --parameter-overrides
  "${parameter_overrides[@]}"
  --tags
  "e-sig:managed-by=waitlist-api"
  "e-sig:environment=production"
)

if [[ "$EXECUTE_CHANGESET" != "1" ]]; then
  deploy_args+=(--no-execute-changeset)
fi

"$AWS_BIN" "${deploy_args[@]}"

if [[ "$EXECUTE_CHANGESET" == "1" ]]; then
  waitlist_api_url=$(
    "$AWS_BIN" cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --region "$AWS_REGION" \
      --query "Stacks[0].Outputs[?OutputKey=='WaitlistApiUrl'].OutputValue | [0]" \
      --output text
  )
  printf 'WAITLIST_API_URL=%s\n' "$waitlist_api_url"
fi
