#!/usr/bin/env bash
# provision-worm-bucket.sh — create an S3 bucket ready for @e-sig/worm.
#
# Creates a bucket with:
#   * Object Lock ENABLED at creation (can only be set at creation time),
#   * bucket versioning ENABLED (Object Lock requires it; enabling Object
#     Lock at creation turns it on, we assert it explicitly anyway),
#   * a DEFAULT retention rule (mode + days) applied to any object written
#     without explicit retention — a safety net under WormPdfStorageStore,
#     which always sets retention explicitly and atomically per put,
#   * full public-access block (these are compliance records, never public).
#
# NON-DESTRUCTIVE: bails immediately if the bucket already exists. It never
# modifies, reconfigures, or deletes an existing bucket.
#
# Usage:
#   ./provision-worm-bucket.sh <bucket-name> [region] [retention-days] [mode]
#
#   bucket-name     required, globally unique
#   region          default: us-east-1
#   retention-days  default: 2555 (~7 years, matches @e-sig/worm's default)
#   mode            COMPLIANCE (default) or GOVERNANCE
#
# COMPLIANCE mode is the 17a-4 posture: once written, NO principal — the
# account root included — can shorten the retention or delete the locked
# object version until retain-until passes. Test with GOVERNANCE (bypassable
# via s3:BypassGovernanceRetention) before you commit to COMPLIANCE.
#
# Requires AWS CLI v2 with credentials that can create buckets.

set -euo pipefail

# This machine's AWS CLI v2 lives here (bare `aws` may resolve to v1).
AWS=/opt/homebrew/bin/aws

BUCKET="${1:?usage: provision-worm-bucket.sh <bucket-name> [region] [retention-days] [mode]}"
REGION="${2:-us-east-1}"
RETENTION_DAYS="${3:-2555}"
MODE="${4:-COMPLIANCE}"

case "$MODE" in
  COMPLIANCE|GOVERNANCE) ;;
  *) echo "error: mode must be COMPLIANCE or GOVERNANCE (got '$MODE')" >&2; exit 1 ;;
esac
if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || [ "$RETENTION_DAYS" -lt 1 ]; then
  echo "error: retention-days must be an integer >= 1 (got '$RETENTION_DAYS')" >&2
  exit 1
fi

# --- Non-destructive guard: refuse to touch an existing bucket. -------------
# head-bucket succeeds only for a bucket this identity can reach; if it
# succeeds, the bucket exists — bail. (If the name is taken by ANOTHER
# account, head-bucket fails but create-bucket below fails too, so we still
# never mutate anything.)
if "$AWS" s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  echo "error: bucket '$BUCKET' already exists — refusing to touch it (non-destructive script)." >&2
  exit 1
fi

echo "Creating bucket '$BUCKET' in $REGION with Object Lock enabled..."
if [ "$REGION" = "us-east-1" ]; then
  # us-east-1 rejects a LocationConstraint.
  "$AWS" s3api create-bucket \
    --bucket "$BUCKET" \
    --region "$REGION" \
    --object-lock-enabled-for-bucket
else
  "$AWS" s3api create-bucket \
    --bucket "$BUCKET" \
    --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=$REGION" \
    --object-lock-enabled-for-bucket
fi

echo "Ensuring versioning is enabled (Object Lock requires it)..."
"$AWS" s3api put-bucket-versioning \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --versioning-configuration Status=Enabled

echo "Setting default retention: $MODE, $RETENTION_DAYS days..."
"$AWS" s3api put-object-lock-configuration \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --object-lock-configuration "{\"ObjectLockEnabled\":\"Enabled\",\"Rule\":{\"DefaultRetention\":{\"Mode\":\"$MODE\",\"Days\":$RETENTION_DAYS}}}"

echo "Blocking all public access..."
"$AWS" s3api put-public-access-block \
  --bucket "$BUCKET" \
  --region "$REGION" \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo
echo "Done. Verification:"
"$AWS" s3api get-object-lock-configuration --bucket "$BUCKET" --region "$REGION"
echo
echo "Wire it up:  new WormPdfStorageStore(s3, { bucket: \"$BUCKET\", mode: \"$MODE\", retentionDays: $RETENTION_DAYS })"
