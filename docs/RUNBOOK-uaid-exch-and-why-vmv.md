# Runbook — commands you run to finish the ship

Everything below runs on your Mac (not from Perplexity Computer, which is
network-isolated). Each block is a single copy-paste. All three can run in any
order.

---

## 1. Deploy `/why-vmv` to e-sig.org

```bash
cd /Volumes/X/VMV/esig-suite
./site/deploy.sh
```

Publishes the new `site/why-vmv/index.html` to
`s3://e-sig-org-site-456453427852/why-vmv/` and invalidates CloudFront
`E3SMXIUSEUNZH3`. Live at `https://e-sig.org/why-vmv` a couple of minutes later.
Also refreshes the home page cache.

## 2. Seed Stripe live products

```bash
cd /Volumes/X/VMV/esig-suite
npm i --no-save stripe
STRIPE_SECRET_KEY="$(awk -F= '/^STRIPE_SECRET_KEY_VMVTECH=/{print $2}' /Users/z/FiDz/keyz/APSI.txt)" \
  node scripts/seed-stripe.mjs
```

The seeder is **idempotent**. It creates each product only if its `metadata.plan_key`
is not already in your account, and creates each price only if its `lookup_key` is
not already there. Safe to re-run.

Expected output — one line per plan and add-on:

```
✓ cloud_starter      — $19/mo · $190/yr · overage $0.20/env
✓ cloud_team         — $49/mo · $490/yr · overage $0.20/env
✓ cloud_scale        — $79/mo · $790/yr · overage $0.20/env
✓ business           — $299/mo · $2990/yr
✓ addon_hipaa_baa    — $500/mo · $5000/yr
✓ addon_hsm_signer   — $800/mo · $8000/yr
✓ addon_eidas_qes    — $1500/mo · $15000/yr
✓ addon_21cfr_part11 — $1200/mo · $12000/yr
✓ addon_uuaid_ent    — $500/mo · $5000/yr
✓ addon_worm         — $300/mo · $3000/yr
done. verify: https://dashboard.stripe.com/products
```

If you want a dry-run first, swap the env var:

```bash
STRIPE_SECRET_KEY="$(awk -F= '/^STRIPE_SECRET_KEY_TEST_VMVTECH=/{print $2}' /Users/z/FiDz/keyz/APSI.txt)" \
  node scripts/seed-stripe.mjs
```

Then verify at `https://dashboard.stripe.com/test/products` and re-run with the live key.

## 3. Push branches for review

Two feature branches are ready locally:

```bash
# esig-suite: @e-sig/uaid-exch preview package + /why-vmv site
cd /Volumes/X/VMV/esig-suite
git push -u origin feat/uaid-exch-package

# iaaso: ADR-006 doctrine proposal (Exchange profile)
cd /Volumes/X/VMV/iaaso
git push -u origin proposals/adr-006-exchange-profile
```

Both are safe to open as PRs. Neither modifies existing behavior:
- iaaso branch adds `proposals/ADR-006-exchange-profile.md`, nothing else.
- esig-suite branch adds `packages/esig-uaid-exch/` (a new package on
  `0.1.0-preview.0`) and `site/why-vmv/`.

---

## What DID NOT happen tonight

The Perplexity Computer sandbox has network egress disabled — I couldn't:

- Install npm packages (Stripe seeder needs `npm i stripe`).
- Hit `api.stripe.com` or `api.uuaid.org`.
- Run `site/deploy.sh` (needs AWS credentials + S3/CloudFront).
- Push branches to GitHub.

Everything above is local commits. The three commands in this runbook take
about 60 seconds total on your Mac to make everything live.

## What's still queued

Two of the four deliverables from the earlier plan are staged in the sandbox
but not yet landed anywhere, because they belong outside `/Volumes/X/VMV`:

- **DSalvus Assurance Package generator** (`cmd/assurance/`). Landing target:
  `/Volumes/X/dsalvus/cmd/assurance/`. Read-only from this sandbox.
- **`vmvtech.com/stack` marketing page**. Landing target: the vmvtech.com repo
  (not in this workspace). HTML + PDF are ready in the previous session's zip.

Widen the sandbox to include `/Volumes/X/dsalvus` (and wherever vmvtech.com
lives) and I'll land those the same way in a follow-up session.
