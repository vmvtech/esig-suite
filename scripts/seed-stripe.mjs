#!/usr/bin/env node
/**
 * esig-suite — Stripe product/price seeder
 *
 * Usage:
 *   npm i stripe
 *   STRIPE_SECRET_KEY=sk_test_... node scripts/seed-stripe.mjs
 *
 * Idempotent: uses metadata.plan_key on Product and lookup_key on Price.
 * Safe to re-run. Prices are immutable in Stripe — this script will not
 * silently change a live price. If you want to raise prices, deprecate
 * the old lookup_key and issue a new one (e.g. cloud_team_monthly_v2).
 */

import Stripe from "stripe";

if (!process.env.STRIPE_SECRET_KEY) {
  console.error("STRIPE_SECRET_KEY missing");
  process.exit(1);
}
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
});

// ---------- Plan catalog ----------
const PLANS = [
  {
    key: "cloud_starter",
    name: "esig Cloud — Starter",
    description:
      "Managed hosting: 100 envelopes/mo, 1 user, $0.20/env overage. Managed Postgres audit chain, S3 storage, verify page, email delivery.",
    monthly: 1900,
    yearly: 19000,
    envelopesIncluded: 100,
    seats: 1,
  },
  {
    key: "cloud_team",
    name: "esig Cloud — Team",
    description:
      "Managed hosting for growing teams: 500 envelopes/mo, 5 users, $0.20/env overage. Everything in Starter + webhooks, SDK support.",
    monthly: 4900,
    yearly: 49000,
    envelopesIncluded: 500,
    seats: 5,
  },
  {
    key: "cloud_scale",
    name: "esig Cloud — Scale",
    description:
      "Managed hosting at volume: 1,500 envelopes/mo, 15 users, $0.20/env overage. Higher rate limits, priority queue.",
    monthly: 7900,
    yearly: 79000,
    envelopesIncluded: 1500,
    seats: 15,
  },
  {
    key: "business",
    name: "esig Business (self-hosted)",
    description:
      "Self-host with a vendor relationship: signed invoice, DPA, W-9, priority Slack Connect support, quarterly patches, enterprise adapter packages.",
    monthly: 29900,
    yearly: 299000,
    envelopesIncluded: null, // self-hosted; no metering by us
    seats: null,
  },
];

const OVERAGE_UNIT_CENTS = "20"; // $0.20/envelope over included allocation

const ADDONS = [
  {
    key: "addon_hipaa_baa",
    name: "HIPAA BAA + Healthcare Runbook",
    description:
      "Business Associate Agreement + healthcare-specific runbooks: PHI handling, breach notification, minimum necessary, disposal.",
    monthly: 50000,
    yearly: 500000,
  },
  {
    key: "addon_hsm_signer",
    name: "HSM Signer (PKCS#11)",
    description:
      "Cryptographic key material stored in FIPS 140-2 Level 3 HSM. Supports AWS CloudHSM, YubiHSM, or on-prem PKCS#11.",
    monthly: 80000,
    yearly: 800000,
  },
  {
    key: "addon_eidas_qes",
    name: "eIDAS Qualified Electronic Signature Integration",
    description:
      "Integration with an eIDAS Qualified Trust Service Provider for EU QES-grade signatures.",
    monthly: 150000,
    yearly: 1500000,
  },
  {
    key: "addon_21cfr_part11",
    name: "21 CFR Part 11 Compliance Pack",
    description:
      "FDA 21 CFR Part 11 compliance package: validated build, IQ/OQ/PQ documentation, audit trail requirements, controlled release.",
    monthly: 120000,
    yearly: 1200000,
  },
  {
    key: "addon_uuaid_ent",
    name: "Agent-Signed Documents (UUAID Enterprise)",
    description:
      "Enterprise-grade agent identity attribution: signed AI-agent identity in audit log, Polygon-anchored chain-head, revocation lists.",
    monthly: 50000,
    yearly: 500000,
  },
  {
    key: "addon_worm",
    name: "WORM Archival (Object-Lock)",
    description:
      "Write-Once-Read-Many archival: S3 Object Lock or Glacier Vault Lock for signed PDFs and audit rows. FINRA / SEC 17a-4 compatible.",
    monthly: 30000,
    yearly: 300000,
  },
];

// ---------- Helpers ----------
async function upsertProduct({ key, name, description, seats, envelopesIncluded }) {
  const search = await stripe.products.search({
    query: `metadata['plan_key']:'${key}'`,
    limit: 1,
  });
  const metadata = {
    plan_key: key,
    envelopes_included: envelopesIncluded == null ? "custom" : String(envelopesIncluded),
    seats: seats == null ? "custom" : String(seats),
  };
  if (search.data[0]) {
    const p = search.data[0];
    if (p.name !== name || p.description !== description) {
      await stripe.products.update(p.id, { name, description, metadata });
    }
    return p;
  }
  return stripe.products.create({ name, description, metadata });
}

async function upsertLicensedPrice({ product, lookup_key, unit_amount, interval }) {
  const list = await stripe.prices.list({ lookup_keys: [lookup_key], limit: 1 });
  if (list.data[0]) return list.data[0];
  return stripe.prices.create({
    product: product.id,
    lookup_key,
    currency: "usd",
    unit_amount,
    recurring: { interval, usage_type: "licensed" },
    nickname: lookup_key,
  });
}

async function upsertMeteredPrice({ product, lookup_key, unit_amount_decimal }) {
  const list = await stripe.prices.list({ lookup_keys: [lookup_key], limit: 1 });
  if (list.data[0]) return list.data[0];
  return stripe.prices.create({
    product: product.id,
    lookup_key,
    currency: "usd",
    billing_scheme: "per_unit",
    unit_amount_decimal,
    recurring: {
      interval: "month",
      usage_type: "metered",
      aggregate_usage: "sum",
    },
    nickname: lookup_key,
  });
}

// ---------- Run ----------
console.log("Seeding esig-suite plans in Stripe…\n");

for (const p of PLANS) {
  const product = await upsertProduct(p);
  await upsertLicensedPrice({
    product,
    lookup_key: `${p.key}_monthly`,
    unit_amount: p.monthly,
    interval: "month",
  });
  await upsertLicensedPrice({
    product,
    lookup_key: `${p.key}_yearly`,
    unit_amount: p.yearly,
    interval: "year",
  });
  if (p.envelopesIncluded != null) {
    await upsertMeteredPrice({
      product,
      lookup_key: `${p.key}_overage_env`,
      unit_amount_decimal: OVERAGE_UNIT_CENTS,
    });
  }
  console.log(`✓ ${p.key.padEnd(18)} — $${(p.monthly / 100).toFixed(0)}/mo · $${(p.yearly / 100).toFixed(0)}/yr${p.envelopesIncluded != null ? ` · overage $${(Number(OVERAGE_UNIT_CENTS) / 100).toFixed(2)}/env` : ""}`);
}

console.log("\nSeeding add-ons…\n");
for (const a of ADDONS) {
  const product = await upsertProduct({
    key: a.key,
    name: a.name,
    description: a.description,
    envelopesIncluded: null,
    seats: null,
  });
  await upsertLicensedPrice({
    product,
    lookup_key: `${a.key}_monthly`,
    unit_amount: a.monthly,
    interval: "month",
  });
  await upsertLicensedPrice({
    product,
    lookup_key: `${a.key}_yearly`,
    unit_amount: a.yearly,
    interval: "year",
  });
  console.log(`✓ ${a.key.padEnd(22)} — $${(a.monthly / 100).toFixed(0)}/mo · $${(a.yearly / 100).toFixed(0)}/yr`);
}

console.log("\nDone. Verify at https://dashboard.stripe.com/products");
console.log(
  "\nNext step: wire the Checkout route (see esig-monetize/api/checkout.ts)"
);
