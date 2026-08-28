#!/usr/bin/env bash
# Canonical production publisher for e-sig.org.
#
# This publishes the fail-closed checkout Lambda first, then the URL-rewrite
# function, then static site files. It never commits, pushes, publishes npm
# packages, deletes S3 objects, or contacts Stripe.
#
#   ESIG_APPROVE_PRODUCTION=1 ./site/finish.sh

set -euo pipefail

REPO="/Volumes/X/VMV/esig-suite"
AWS="${ESIG_AWS_CLI:-/opt/homebrew/bin/aws}"
BUCKET="${ESIG_SITE_BUCKET:-e-sig-org-site-456453427852}"
DIST="${ESIG_SITE_DIST:-E3SMXIUSEUNZH3}"
CF_FN="esig-pretty-urls"
LAMBDA_FN="esig-checkout"
EXPECTED_ACCOUNT="456453427852"
WAITLIST_URL="https://e-sig.org/pricing?waitlist=1#cloud-waitlist"
BACKUP_BASE="${ESIG_BACKUP_BASE:-/Volumes/S/Claude-Backups}"

say() { printf '\n→ %s\n' "$*"; }
ok() { printf '  ✓ %s\n' "$*"; }
die() { printf '  ERROR: %s\n' "$*" >&2; exit 1; }

if [[ "${ESIG_APPROVE_PRODUCTION:-0}" != "1" ]]; then
  die "production publish requires ESIG_APPROVE_PRODUCTION=1"
fi

for cmd in "$AWS" jq zip curl git shasum rg tar awk grep cmp; do
  if [[ "$cmd" == */* ]]; then
    [[ -x "$cmd" ]] || die "missing executable: $cmd"
  else
    command -v "$cmd" >/dev/null || die "missing executable: $cmd"
  fi
done

cd "$REPO"

# --exclude of this script is load-bearing: the pattern literal on this line
# lives inside site/, so an unexcluded recursive grep self-matches and dies
# on every run (caught by the blind verifier before it ever shipped).
! grep -rqiE --exclude="finish.sh" "CAIQ|SIG Core|@e-sig/enterprise|Helm chart" site \
  || die "site copy claims artifacts that do not exist in the repo"

ACCOUNT=$("$AWS" sts get-caller-identity --query Account --output text)
[[ "$ACCOUNT" == "$EXPECTED_ACCOUNT" ]] || die "wrong AWS account: $ACCOUNT"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP_DIR="${ESIG_BACKUP_DIR:-$BACKUP_BASE/esig-site-publish-$STAMP}"
mkdir -p "$BACKUP_DIR/site-before"
chmod 700 "$BACKUP_DIR"

SOURCE_HEAD=$(git rev-parse HEAD)
SOURCE_ARCHIVE="$BACKUP_DIR/source-published.tar"
tar -cf "$SOURCE_ARCHIVE" site infra/lambda-checkout
SOURCE_SHA=$(shasum -a 256 "$SOURCE_ARCHIVE" | awk '{print $1}')
git status --short > "$BACKUP_DIR/source-status.txt"

say "backing up current production state"
"$AWS" s3 sync "s3://$BUCKET/" "$BACKUP_DIR/site-before/" --only-show-errors
"$AWS" cloudfront get-distribution-config --id "$DIST" > "$BACKUP_DIR/distribution.before.json"
"$AWS" cloudfront get-function --name "$CF_FN" --stage LIVE \
  "$BACKUP_DIR/cf-pretty-urls.before.js" > "$BACKUP_DIR/cf-function.before.json"
OLD_CHECKOUT_ARN=$(jq -r '
  [.DistributionConfig.CacheBehaviors.Items[]?
   | select(.PathPattern == "/api/checkout*")
   | .LambdaFunctionAssociations.Items[]?
   | select(.EventType == "viewer-request")
   | .LambdaFunctionARN]
  | if length == 1 then .[0] else empty end
' "$BACKUP_DIR/distribution.before.json")
[[ -n "$OLD_CHECKOUT_ARN" ]] || die "expected exactly one /api/checkout* viewer-request Lambda"
DEFAULT_CF_ARN=$(jq -r '
  [.DistributionConfig.DefaultCacheBehavior.FunctionAssociations.Items[]?
   | select(.EventType == "viewer-request")
   | .FunctionARN]
  | if length == 1 then .[0] else empty end
' "$BACKUP_DIR/distribution.before.json")
[[ "$DEFAULT_CF_ARN" == *":function/$CF_FN" ]] \
  || die "default behavior is not associated with $CF_FN"
"$AWS" lambda get-function-configuration --region us-east-1 \
  --function-name "$LAMBDA_FN" --qualifier "${OLD_CHECKOUT_ARN##*:}" \
  > "$BACKUP_DIR/lambda-checkout.before.json"
ok "backup: $BACKUP_DIR"

if rg -q 'STRIPE_SECRET_KEY|api\.stripe\.com' infra/lambda-checkout/index.js; then
  die "checkout package still contains Stripe execution code"
fi

say "publishing fail-closed checkout Lambda"
LAMBDA_ZIP="$BACKUP_DIR/esig-checkout-waitlist.zip"
(cd infra/lambda-checkout && zip -q -X "$LAMBDA_ZIP" index.js)
"$AWS" lambda update-function-code --region us-east-1 \
  --function-name "$LAMBDA_FN" --zip-file "fileb://$LAMBDA_ZIP" --publish \
  > "$BACKUP_DIR/lambda-checkout.new.json"
"$AWS" lambda wait function-updated-v2 --region us-east-1 --function-name "$LAMBDA_FN"
NEW_CHECKOUT_ARN=$(jq -r '.FunctionArn' "$BACKUP_DIR/lambda-checkout.new.json")
NEW_CHECKOUT_VERSION=$(jq -r '.Version' "$BACKUP_DIR/lambda-checkout.new.json")
[[ "$NEW_CHECKOUT_VERSION" != "\$LATEST" && -n "$NEW_CHECKOUT_VERSION" ]] \
  || die "Lambda did not publish an immutable version"

DIST_ETAG=$(jq -r '.ETag' "$BACKUP_DIR/distribution.before.json")
jq --arg arn "$NEW_CHECKOUT_ARN" '
  (.DistributionConfig.CacheBehaviors.Items[]
   | select(.PathPattern == "/api/checkout*")
   | .LambdaFunctionAssociations.Items[]
   | select(.EventType == "viewer-request")
   | .LambdaFunctionARN) = $arn
  | .DistributionConfig
' "$BACKUP_DIR/distribution.before.json" > "$BACKUP_DIR/distribution.checkout-new.json"

"$AWS" cloudfront update-distribution --id "$DIST" --if-match "$DIST_ETAG" \
  --distribution-config "file://$BACKUP_DIR/distribution.checkout-new.json" \
  > "$BACKUP_DIR/distribution.checkout-update.json"
"$AWS" cloudfront wait distribution-deployed --id "$DIST"
ok "checkout behavior: $OLD_CHECKOUT_ARN → $NEW_CHECKOUT_ARN"

CHECKOUT_PROBE=$(curl -sS --max-time 30 -o /dev/null \
  -w '%{http_code}|%{redirect_url}' \
  'https://e-sig.org/api/checkout?plan=cloud_starter&interval=monthly')
[[ "$CHECKOUT_PROBE" == "302|$WAITLIST_URL" ]] \
  || die "checkout did not fail closed: $CHECKOUT_PROBE"
ok "legacy checkout redirects to waitlist"

say "uploading static site without deleting objects"
"$AWS" s3 sync "$REPO/site" "s3://$BUCKET/" \
  --exclude deploy.sh --exclude finish.sh --exclude cf-pretty-urls.js \
  --exclude README.md --exclude '.*' \
  --cache-control 'public,max-age=300' --only-show-errors
INVALIDATION_ID=$("$AWS" cloudfront create-invalidation --distribution-id "$DIST" \
  --paths '/*' --query 'Invalidation.Id' --output text)
"$AWS" cloudfront wait invalidation-completed --distribution-id "$DIST" --id "$INVALIDATION_ID"
ok "static site uploaded; invalidation $INVALIDATION_ID completed"

[[ "$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' 'https://e-sig.org/why-esig')" == "200" ]] \
  || die "new trust-route target is not live; refusing to publish its redirect"
PRE_EDGE_PRICING=$(curl -sS --max-time 30 'https://e-sig.org/pricing')
grep -q 'No checkout yet' <<< "$PRE_EDGE_PRICING" \
  || die "waitlist page is not live; refusing to publish redirects"

say "publishing URL and private-file edge rules"
"$AWS" cloudfront describe-function --name "$CF_FN" --stage DEVELOPMENT \
  > "$BACKUP_DIR/cf-function.development-before.json"
CF_DEV_ETAG=$(jq -r '.ETag' "$BACKUP_DIR/cf-function.development-before.json")
"$AWS" cloudfront update-function --name "$CF_FN" --if-match "$CF_DEV_ETAG" \
  --function-config 'Comment=e-sig pretty URLs and legacy safety redirects,Runtime=cloudfront-js-2.0' \
  --function-code "fileb://$REPO/site/cf-pretty-urls.js" \
  > "$BACKUP_DIR/cf-function.updated.json"
CF_UPDATED_ETAG=$(jq -r '.ETag' "$BACKUP_DIR/cf-function.updated.json")
"$AWS" cloudfront publish-function --name "$CF_FN" --if-match "$CF_UPDATED_ETAG" \
  > "$BACKUP_DIR/cf-function.published.json"
CF_STATUS="IN_PROGRESS"
for _ in $(seq 1 30); do
  CF_STATUS=$("$AWS" cloudfront describe-function --name "$CF_FN" --stage LIVE \
    --query 'FunctionSummary.Status' --output text)
  [[ "$CF_STATUS" == "DEPLOYED" ]] && break
  sleep 2
done
[[ "$CF_STATUS" == "DEPLOYED" ]] || die "LIVE CloudFront function did not reach DEPLOYED"
"$AWS" cloudfront get-function --name "$CF_FN" --stage LIVE \
  "$BACKUP_DIR/cf-pretty-urls.live.js" > "$BACKUP_DIR/cf-function.live.json"
cmp -s "$REPO/site/cf-pretty-urls.js" "$BACKUP_DIR/cf-pretty-urls.live.js" \
  || die "LIVE CloudFront function code does not match the release source"
CF_LIVE_ETAG=$(jq -r '.ETag' "$BACKUP_DIR/cf-function.live.json")
ok "CloudFront function is DEPLOYED with matching code at $CF_LIVE_ETAG"

say "verifying exact live behavior"
fetch_code() {
  curl -sS --max-time 30 -o /dev/null -w '%{http_code}' "$1"
}
fetch_redirect() {
  curl -sS --max-time 30 -o /dev/null -w '%{http_code}|%{redirect_url}' "$1"
}

[[ "$(fetch_code 'https://e-sig.org/')" == "200" ]] || die "homepage is not 200"
[[ "$(fetch_code 'https://e-sig.org/pricing')" == "200" ]] || die "pricing is not 200"
[[ "$(fetch_code 'https://e-sig.org/why-esig')" == "200" ]] || die "why-esig is not 200"

for extra_path in verify agents press llms.txt llms-full.txt agent.json robots.txt sitemap.xml; do
  [[ "$(fetch_code "https://e-sig.org/$extra_path")" == "200" ]] \
    || die "$extra_path is not 200"
done

for old_path in why-vmv why-vmv/ why-vmv/index.html; do
  [[ "$(fetch_redirect "https://e-sig.org/$old_path")" == '301|https://e-sig.org/why-esig' ]] \
    || die "$old_path does not redirect to /why-esig"
done

for private_path in README.md deploy.sh finish.sh cf-pretty-urls.js; do
  [[ "$(fetch_code "https://e-sig.org/$private_path")" == "404" ]] \
    || die "$private_path is still publicly served"
done

for plan in cloud_starter cloud_team cloud_scale addon_hipaa_baa addon_hsm_signer addon_21cfr_part11 addon_uuaid_ent addon_worm; do
  [[ "$(fetch_redirect "https://e-sig.org/api/checkout?plan=$plan")" == "302|$WAITLIST_URL" ]] \
    || die "legacy checkout plan $plan did not redirect to the waitlist"
done

PRICING_HTML=$(curl -sS --max-time 30 'https://e-sig.org/pricing')
grep -q 'No checkout yet' <<< "$PRICING_HTML" || die "waitlist notice missing"
grep -q 'Join Starter waitlist' <<< "$PRICING_HTML" || die "waitlist CTA missing"
grep -q 'id="cloud-waitlist-form"' <<< "$PRICING_HTML" || die "hosted waitlist form missing"
if grep -q '/api/checkout' <<< "$PRICING_HTML"; then
  die "pricing still contains a checkout link"
fi
if grep -q 'mailto:' <<< "$PRICING_HTML"; then
  die "pricing still contains a mailto CTA"
fi
WAITLIST_ENDPOINT=$(sed -n 's/.*id="cloud-waitlist-form"[^>]*data-endpoint="\([^"]*\)".*/\1/p' <<< "$PRICING_HTML" | head -1)
[[ "$WAITLIST_ENDPOINT" == https://*.execute-api.us-east-1.amazonaws.com/*/waitlist ]] \
  || die "waitlist API endpoint missing or unexpected: $WAITLIST_ENDPOINT"
WAITLIST_SMOKE_BODY=$(jq -cn --arg email "release-$STAMP@example.com" \
  '{offer:"shared_starter",email:$email,consent:true,website:"",source:"pricing"}')
WAITLIST_SMOKE_RESPONSE=$(curl -sS --max-time 30 -w '\n%{http_code}' \
  -H 'Origin: https://e-sig.org' -H 'Content-Type: application/json' \
  --data "$WAITLIST_SMOKE_BODY" "$WAITLIST_ENDPOINT")
WAITLIST_SMOKE_CODE=${WAITLIST_SMOKE_RESPONSE##*$'\n'}
WAITLIST_SMOKE_JSON=${WAITLIST_SMOKE_RESPONSE%$'\n'*}
[[ "$WAITLIST_SMOKE_CODE" == "202" ]] || die "waitlist API smoke returned $WAITLIST_SMOKE_CODE"
[[ "$(jq -r '.status // empty' <<< "$WAITLIST_SMOKE_JSON")" == "accepted" ]] \
  || die "waitlist API smoke did not return accepted"
WHY_HTML=$(curl -sS --max-time 30 'https://e-sig.org/why-esig')
grep -q 'e-sig trust stack' <<< "$WHY_HTML" || die "e-sig trust heading missing"
if grep -Eq 'Why VMV|VMV trust stack' <<< "$WHY_HTML"; then
  die "legacy trust branding still visible"
fi

jq -n \
  --arg published_at "$STAMP" \
  --arg source_head "$SOURCE_HEAD" \
  --arg source_sha "$SOURCE_SHA" \
  --arg backup_dir "$BACKUP_DIR" \
  --arg pre_publish_checkout_arn "$OLD_CHECKOUT_ARN" \
  --arg safe_checkout_arn "$NEW_CHECKOUT_ARN" \
  --arg cf_live_etag "$CF_LIVE_ETAG" \
  --arg invalidation_id "$INVALIDATION_ID" \
  '{published_at:$published_at,source_head:$source_head,source_sha:$source_sha,backup_dir:$backup_dir,pre_publish_checkout_arn:$pre_publish_checkout_arn,safe_checkout_arn:$safe_checkout_arn,cf_live_etag:$cf_live_etag,invalidation_id:$invalidation_id,verified:true}' \
  > "$BACKUP_DIR/release-manifest.json"

ok "published and verified: https://e-sig.org"
ok "release evidence: $BACKUP_DIR/release-manifest.json"
ok "safe checkout ARN to retain during rollback: $NEW_CHECKOUT_ARN"
ok "pre-publish checkout ARN is audit evidence only; never restore it: $OLD_CHECKOUT_ARN"
