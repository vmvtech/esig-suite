# Production publish runbook

**Status:** current as of 2026-08-27
**Growth direction:** [OSS-first 90-day playbook](growth/90-day-playbook.md)

This runbook publishes the e-sig.org static site, the e-sig trust-route rules,
and the fail-closed Cloud checkout redirect. It does not commit, push, publish
npm packages, delete S3 objects, or contact Stripe.

The previous Stripe-seeding instructions are retired. Do not enable or seed a
public checkout until every item in the playbook's Cloud checkout provisioning
gate has evidence and sign-off.

## 1. Local gate

```bash
cd /Volumes/X/VMV/esig-suite
git diff --check
bash -n site/deploy.sh site/finish.sh
npm run build
npm test
npm run smoke
```

Also run the checkout Lambda and CloudFront function probes described in the
current release evidence. Stop if any legacy checkout URL can reach a payment
processor or any trust route exposes the retired brand.

The pricing/checkout release-evidence gate lives at
`scripts/checkout-gate.test.mjs` (covered by `npm test` above via
`test:scripts`, and runnable on its own):

```bash
npx vitest run scripts/checkout-gate.test.mjs
```

It asserts the checkout Lambda always redirects to the Cloud waitlist and that
the pricing page's offer names and list prices haven't drifted underneath it.

## 2. Content-parity gate

Site copy must never claim an artifact that doesn't exist in the repo, and the
agent-facing surface must stay in sync with what actually ships:

```bash
! grep -rqiE "CAIQ|SIG Core|@e-sig/enterprise|Helm chart" site \
  || echo "FAIL: site copy claims artifacts that do not exist in the repo"
```

`site/finish.sh` runs this same anchored check automatically before every
publish and fails closed; this is the same gate run by hand for review.

Also confirm the site mentions the agent-driven-signing surface before
publishing — `@e-sig/mcp` and the `esig verify` CLI should each appear on at
least `/pricing`, `/agents`, and `/llms.txt`:

```bash
grep -l '@e-sig/mcp' site/pricing/index.html site/agents/index.html site/llms.txt
grep -l 'esig verify' site/agents/index.html site/llms.txt
```

## 3. Review the static upload

```bash
/opt/homebrew/bin/aws s3 sync site s3://e-sig-org-site-456453427852/ \
  --exclude deploy.sh --exclude finish.sh --exclude cf-pretty-urls.js \
  --exclude README.md --exclude '.*' \
  --cache-control public,max-age=300 --dryrun
```

The dry run must contain uploads only. Production publishing is intentionally
non-pruning because bucket versioning is disabled.

## 4. Publish

```bash
cd /Volumes/X/VMV/esig-suite
ESIG_APPROVE_PRODUCTION=1 ./site/finish.sh
```

The canonical publisher runs in this order:

1. runs the content-parity guard (section 2 above) and verifies the expected
   AWS account, then creates a local production backup;
2. publishes an immutable, secret-free Lambda@Edge version that redirects all
   old checkout URLs to the waitlist;
3. updates the `/api/checkout*` CloudFront behavior and waits for deployment;
4. uploads site files without `--delete`, invalidates CloudFront, and proves the
   waitlist and new trust-route target are live;
5. publishes the pretty-URL, trust-route, and private-file edge rules;
6. hard-fails unless the live homepage, pricing, trust route, legacy redirects,
   private-file blocks, machine-readable endpoints (llms.txt, llms-full.txt,
   agent.json, robots.txt, sitemap.xml, /verify, /agents, /press), and every
   old checkout plan behave exactly as expected.

The final output identifies `release-manifest.json`, the pre-publish backup,
the immutable safe waitlist Lambda ARN, and the prior checkout ARN as audit-only
evidence. Record that evidence — together with the `scripts/checkout-gate.test.mjs`
result from section 1 — with the release decision.

## 5. Rollback

Keep the release manifest's `safe_checkout_arn` associated with
`/api/checkout*` during every rollback. The `pre_publish_checkout_arn` and the
checkout association inside `distribution.before.json` are audit evidence only;
restoring either would re-enable unsafe paid checkout.

Use `cf-pretty-urls.before.js` and `site-before/` only for the affected
non-checkout surfaces, and preserve the safe checkout association when building
any CloudFront rollback config. Re-fetch the current CloudFront ETag before an
update. Restoring S3 with deletion is destructive and requires a separate
reviewed decision; the normal publisher never does it.
