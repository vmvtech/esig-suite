#!/usr/bin/env bash
# Finish tonight's e-sig.org deploy: publish /pricing, attach the CloudFront
# pretty-URL function to the distribution, deploy files, verify.
#
# Idempotent: safe to re-run. Handles the "function already exists / already
# published / already attached" states without erroring out.
#
#   ./finish.sh
set -eo pipefail

REPO="/Volumes/X/VMV/esig-suite"
DIST="E3SMXIUSEUNZH3"
FN="esig-pretty-urls"
FN_FILE="$REPO/site/cf-pretty-urls.js"

cd "$REPO"

say() { printf '\n\033[36m→ %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m✓ %s\033[0m\n'  "$*"; }
warn() { printf '  \033[33m! %s\033[0m\n'  "$*"; }

# ─────────────────────────────────────────────────────────────
# 1. Commit + push, if there's anything to commit
# ─────────────────────────────────────────────────────────────
say "committing pricing + CF function"
git add site/pricing/ site/cf-pretty-urls.js 2>/dev/null || true
if git diff --cached --quiet; then
  ok "nothing to commit — already staged in a prior run"
else
  git -c user.email='builder@vmvtech.com' -c user.name='VMV Builder' \
    commit -m "site: add /pricing page + CloudFront pretty-urls function"
  ok "committed"
fi
git push 2>&1 | tail -3

# ─────────────────────────────────────────────────────────────
# 2. Deploy static files to S3 + invalidate cache
# ─────────────────────────────────────────────────────────────
say "deploying site to S3"
./site/deploy.sh

# ─────────────────────────────────────────────────────────────
# 3. Ensure the CloudFront function exists at the LIVE stage
# ─────────────────────────────────────────────────────────────
say "ensuring CloudFront function '$FN' is LIVE"

# Read current state of the function (DEVELOPMENT stage).
if aws cloudfront describe-function --name "$FN" --stage DEVELOPMENT \
     > /tmp/fn-dev.json 2>/dev/null; then
  FN_EXISTS=1
  FN_DEV_ETAG=$(jq -r '.ETag' /tmp/fn-dev.json)
else
  FN_EXISTS=0
fi

if [ "$FN_EXISTS" = "0" ]; then
  # Create it fresh
  aws cloudfront create-function \
    --name "$FN" \
    --function-config "Comment=Append /index.html for subdirectories,Runtime=cloudfront-js-2.0" \
    --function-code "fileb://$FN_FILE" \
    > /tmp/fn-created.json
  FN_DEV_ETAG=$(jq -r '.ETag' /tmp/fn-created.json)
  ok "created (dev stage)"
else
  # Already exists — update the DEVELOPMENT copy to match our file, in case
  # cf-pretty-urls.js has changed since last run.
  aws cloudfront update-function \
    --name "$FN" \
    --if-match "$FN_DEV_ETAG" \
    --function-config "Comment=Append /index.html for subdirectories,Runtime=cloudfront-js-2.0" \
    --function-code "fileb://$FN_FILE" \
    > /tmp/fn-updated.json
  FN_DEV_ETAG=$(jq -r '.ETag' /tmp/fn-updated.json)
  ok "updated (dev stage)"
fi

# Publish DEVELOPMENT -> LIVE. This is a no-op if LIVE already matches; the
# error path only triggers if the DEV ETag is stale, and we just fetched it.
if aws cloudfront publish-function \
     --name "$FN" \
     --if-match "$FN_DEV_ETAG" \
     > /tmp/fn-published.json 2>&1; then
  ok "published to LIVE"
else
  # Likely already published at this exact code hash — verify and move on.
  if grep -q 'InvalidIfMatchVersion\|CannotPublishFunction' /tmp/fn-published.json 2>/dev/null; then
    warn "publish returned $(cat /tmp/fn-published.json | head -1) — assuming LIVE matches, continuing"
  else
    cat /tmp/fn-published.json
    exit 1
  fi
fi

FN_ARN=$(aws cloudfront describe-function --name "$FN" --stage LIVE \
           --query 'FunctionSummary.FunctionMetadata.FunctionARN' --output text)
ok "LIVE ARN: $FN_ARN"

# ─────────────────────────────────────────────────────────────
# 4. Attach the function to the default cache behavior (idempotent)
# ─────────────────────────────────────────────────────────────
say "checking distribution attachment"
aws cloudfront get-distribution-config --id "$DIST" > /tmp/dist.json
DIST_ETAG=$(jq -r '.ETag' /tmp/dist.json)

ALREADY_ATTACHED=$(jq -r --arg arn "$FN_ARN" '
  (.DistributionConfig.DefaultCacheBehavior.FunctionAssociations.Items // [])
  | any(.FunctionARN == $arn and .EventType == "viewer-request")
' /tmp/dist.json)

if [ "$ALREADY_ATTACHED" = "true" ]; then
  ok "function already attached to viewer-request — no update needed"
else
  say "attaching function to default cache behavior"
  jq --arg arn "$FN_ARN" '
    .DistributionConfig.DefaultCacheBehavior.FunctionAssociations = {
      Quantity: 1,
      Items: [ { FunctionARN: $arn, EventType: "viewer-request" } ]
    }
    | .DistributionConfig
  ' /tmp/dist.json > /tmp/dist-new.json

  aws cloudfront update-distribution \
    --id "$DIST" \
    --if-match "$DIST_ETAG" \
    --distribution-config file:///tmp/dist-new.json \
    --query 'Distribution.Status' --output text
  ok "distribution update submitted (will show InProgress → Deployed)"
fi

# ─────────────────────────────────────────────────────────────
# 5. Poll until the distribution is Deployed
# ─────────────────────────────────────────────────────────────
say "waiting for distribution to reach Deployed (~3–8 min)"
for i in $(seq 1 30); do
  STATUS=$(aws cloudfront get-distribution --id "$DIST" --query 'Distribution.Status' --output text)
  printf '  [%02d/30] status=%s\r' "$i" "$STATUS"
  if [ "$STATUS" = "Deployed" ]; then
    printf '\n'
    ok "Deployed"
    break
  fi
  sleep 20
done

# ─────────────────────────────────────────────────────────────
# 6. Smoke-check the routes
# ─────────────────────────────────────────────────────────────
say "verifying URLs"
for u in "https://e-sig.org/" \
         "https://e-sig.org/pricing" "https://e-sig.org/pricing/" \
         "https://e-sig.org/why-vmv" "https://e-sig.org/why-vmv/"; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Cache-Control: no-cache' "$u")
  [ "$code" = "200" ] && ok "$code $u" || warn "$code $u"
done

say "confirming page content"
if curl -sS "https://e-sig.org/pricing" | grep -q 'Pay only for what'; then
  ok "/pricing serving the new page"
else
  warn "/pricing not serving new content yet — CloudFront still propagating; try again in 2 min"
fi
if curl -sS "https://e-sig.org/why-vmv" | grep -q 'Verify your vendor'; then
  ok "/why-vmv serving Verify-your-vendor"
else
  warn "/why-vmv not serving new content yet — CloudFront still propagating; try again in 2 min"
fi

printf '\n\033[32m✓ done\033[0m\n'
