---
type: reference
title: Fail-Closed Checkout Redirect
created: 2026-09-28
tags:
  - esig
  - checkout
  - infrastructure
related:
  - '[[90-day-playbook]]'
  - '[[GAPS-AND-TODOS]]'
---

# Fail-closed checkout redirect

[`index.js`](index.js) is an 18-line Lambda@Edge handler that unconditionally returns a `302 Found` response to `https://e-sig.org/pricing?waitlist=1#cloud-waitlist` with `Cache-Control: no-store`. It keeps existing checkout links fail-closed while paid Cloud provisioning is not proven end to end.

Two repository gates protect that behavior:

- [`scripts/checkout-gate.test.mjs`](../../scripts/checkout-gate.test.mjs) asserts the exact redirect and confirms the public pricing page does not link to `/api/checkout`.
- [`site/finish.sh`](../../site/finish.sh) checks at line 87 for the literal `STRIPE_SECRET_KEY` and `api.stripe.com` patterns before packaging and publishing the Lambda.

Restore paid checkout only after one release candidate passes every item in the [Cloud checkout provisioning gate](../../docs/growth/90-day-playbook.md#cloud-checkout-provisioning-gate) in a production-like environment and links the evidence from the release record. If any gate item fails, the same playbook requires checkout to remain redirected to the waitlist.
