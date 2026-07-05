// Lambda@Edge — /api/checkout
// Runs on CloudFront viewer-request events for path /api/checkout.
// Maps ?plan=<slug>&interval=<monthly|yearly> to a real Stripe Checkout Session
// and returns a 302 redirect to the hosted Checkout URL.
//
// Deployed in us-east-1. Environment variables are NOT supported on Lambda@Edge —
// the Stripe live key is baked into the constant below at deploy time by the
// deploy script (which pulls STRIPE_SECRET_KEY_VMVTECH from ~/FiDz/keyz/APSI.txt).
// The key is never printed, never committed to git, never logged.
//
// Price lookup: uses Stripe price `lookup_keys` — configured in the seeder as
//   {plan}_monthly | {plan}_yearly   (recurring subscription line)
//   {plan}_overage_env               (metered per-envelope line, cloud tiers only)
// Business tier is subscription-only (no metered line).
// Add-ons are single-item monthly subscriptions.
//
// No external npm deps — uses Node's built-in https + querystring.

'use strict';

const https = require('https');
const querystring = require('querystring');

// ⇩ Deploy script rewrites this line with the live secret before zipping.
const STRIPE_SECRET_KEY = 'REPLACE_AT_DEPLOY';

// Plans that get a metered per-envelope overage line item.
const CLOUD_PLANS = new Set(['cloud_starter', 'cloud_team', 'cloud_scale']);

// Business is a single-item subscription (no overage line).
const BUSINESS_PLANS = new Set(['business']);

// Add-ons: single-item subscription, monthly-only (interval forced to monthly).
const ADDON_PLANS = new Set([
  'addon_hipaa_baa',
  'addon_hsm_signer',
  'addon_eidas_qes',
  'addon_21cfr_part11',
  'addon_uuaid_ent',
  'addon_worm',
]);

const SUCCESS_URL = 'https://e-sig.org/pricing?checkout=success&session_id={CHECKOUT_SESSION_ID}';
const CANCEL_URL = 'https://e-sig.org/pricing?checkout=cancel';

function stripeRequest(path, formBody) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: 'POST',
        hostname: 'api.stripe.com',
        path,
        headers: {
          Authorization: 'Bearer ' + STRIPE_SECRET_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(formBody),
          'Stripe-Version': '2024-06-20',
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
            else reject(new Error('stripe_' + res.statusCode + '_' + (parsed.error && parsed.error.code || 'unknown')));
          } catch (e) {
            reject(new Error('stripe_parse_error'));
          }
        });
      }
    );
    req.on('error', (e) => reject(new Error('stripe_network_' + e.code)));
    req.write(formBody);
    req.end();
  });
}

// Resolve a Stripe price ID from a lookup_key.
async function resolvePriceId(lookupKey) {
  const q = querystring.stringify({ 'lookup_keys[]': lookupKey, active: 'true', limit: 1 });
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: 'GET',
        hostname: 'api.stripe.com',
        path: '/v1/prices?' + q,
        headers: {
          Authorization: 'Bearer ' + STRIPE_SECRET_KEY,
          'Stripe-Version': '2024-06-20',
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            const p = JSON.parse(data);
            if (p.data && p.data.length > 0) resolve(p.data[0].id);
            else reject(new Error('price_not_found_' + lookupKey));
          } catch (e) {
            reject(new Error('price_lookup_parse_error'));
          }
        });
      }
    );
    req.on('error', (e) => reject(new Error('price_lookup_network_' + e.code)));
    req.end();
  });
}

function redirectResponse(url) {
  return {
    status: '302',
    statusDescription: 'Found',
    headers: {
      location: [{ key: 'Location', value: url }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
    },
  };
}

function errorResponse(code, message) {
  return {
    status: String(code),
    statusDescription: 'Bad Request',
    headers: {
      'content-type': [{ key: 'Content-Type', value: 'text/plain; charset=utf-8' }],
      'cache-control': [{ key: 'Cache-Control', value: 'no-store' }],
    },
    body: message + '\n',
  };
}

exports.handler = async (event) => {
  const req = event.Records[0].cf.request;
  const qs = querystring.parse(req.querystring || '');
  const plan = String(qs.plan || '').toLowerCase();
  let interval = String(qs.interval || 'monthly').toLowerCase();

  if (!plan) return errorResponse(400, 'missing plan');

  const isCloud = CLOUD_PLANS.has(plan);
  const isBusiness = BUSINESS_PLANS.has(plan);
  const isAddon = ADDON_PLANS.has(plan);

  if (!isCloud && !isBusiness && !isAddon) return errorResponse(400, 'unknown plan');
  if (interval !== 'monthly' && interval !== 'yearly') interval = 'monthly';
  if (isAddon) interval = 'monthly'; // add-ons are month-only

  try {
    // Resolve subscription price
    const subLookup = plan + '_' + interval;
    const subPriceId = await resolvePriceId(subLookup);

    // Build line_items[]
    const lineItems = [{ price: subPriceId, quantity: 1 }];

    if (isCloud) {
      const meteredLookup = plan + '_overage_env';
      try {
        const meteredPriceId = await resolvePriceId(meteredLookup);
        lineItems.push({ price: meteredPriceId }); // no quantity for metered
      } catch (e) {
        // If metered price not seeded, proceed with subscription only rather than fail hard.
      }
    }

    // Build application/x-www-form-urlencoded body for Stripe Checkout
    const form = new URLSearchParams();
    form.append('mode', 'subscription');
    form.append('success_url', SUCCESS_URL);
    form.append('cancel_url', CANCEL_URL);
    form.append('allow_promotion_codes', 'true');
    form.append('billing_address_collection', 'auto');
    form.append('client_reference_id', plan + '_' + interval);
    form.append('metadata[plan]', plan);
    form.append('metadata[interval]', interval);
    form.append('metadata[source]', 'e-sig.org/pricing');
    lineItems.forEach((li, i) => {
      form.append('line_items[' + i + '][price]', li.price);
      if (li.quantity !== undefined) form.append('line_items[' + i + '][quantity]', String(li.quantity));
    });

    const session = await stripeRequest('/v1/checkout/sessions', form.toString());
    if (!session.url) return errorResponse(502, 'checkout_session_missing_url');
    return redirectResponse(session.url);
  } catch (e) {
    return errorResponse(502, 'checkout_error: ' + e.message);
  }
};
