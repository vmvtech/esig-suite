import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const { ALLOWED_OFFERS } = require("../infra/waitlist/src/handler.js");

const readSiteFile = (path) =>
  readFile(new URL(`../site/${path}/index.html`, import.meta.url), "utf8");

describe("pricing waitlist form", () => {
  it("routes every commercial offer to the hosted form instead of email or checkout", async () => {
    const pricing = await readSiteFile("pricing");
    const offers = [
      ["Join Starter waitlist", "shared_starter"],
      ["Join Team waitlist", "shared_team"],
      ["Join Scale waitlist", "shared_scale"],
      ["Talk to us", "business"],
      ["Join Dedicated waitlist", "dedicated"],
      ["HIPAA BAA + Healthcare Runbook", "addon_hipaa_baa"],
      ["HSM Signer (PKCS#11)", "addon_hsm_signer"],
      ["eIDAS QES Integration", "addon_eidas_qes"],
      ["21 CFR Part 11", "addon_21cfr_part11"],
      ["UUAID Enterprise (agent-signed docs)", "addon_uuaid_ent"],
      ["WORM Archival (Object-Lock)", "addon_worm"],
    ];

    expect(pricing).not.toContain("mailto:");
    expect(pricing).not.toContain("/api/checkout");

    expect([...ALLOWED_OFFERS].sort()).toEqual(
      offers.map(([, offer]) => offer).sort(),
    );

    for (const [label, offer] of offers) {
      expect(pricing).toContain(label);
      expect(pricing).toContain(
        `href="#waitlist-form" data-waitlist-offer="${offer}"`,
      );
      expect(pricing).toContain(`<option value="${offer}">`);
    }
  });

  it("collects only the documented fields and exposes an injectable API endpoint", async () => {
    const pricing = await readSiteFile("pricing");

    expect(pricing).toContain(
      'id="cloud-waitlist-form" data-endpoint="https://e998xqnsrd.execute-api.us-east-1.amazonaws.com/Prod/waitlist"',
    );
    expect(pricing).not.toContain("__ESIG_WAITLIST_API_URL__");
    expect(pricing).toContain('name="email"');
    expect(pricing).toContain('name="name"');
    expect(pricing).toContain('name="company"');
    expect(pricing).toContain('name="useCase"');
    expect(pricing).toContain('name="expectedMonthlyEnvelopes"');
    expect(pricing).toContain('name="offer"');
    expect(pricing).toContain('name="consent"');
    expect(pricing).toContain('name="website"');
    expect(pricing).toContain('aria-live="polite"');
    expect(pricing).toContain("sales@e-sig.org");
    expect(pricing).toContain("source: 'pricing'");
    expect(pricing).not.toContain("smokeTest");
    expect(pricing).not.toContain("already_joined");
    expect(pricing).toContain("response.status !== 202");
    expect(pricing).toContain("body.status !== 'accepted'");
    expect(pricing).toContain("about this specific preview or commercial-offer request");
    expect(pricing).toContain("not consent to unrelated marketing");
    expect(pricing).toContain("fetch(endpoint");
  });

  it("documents first-party waitlist collection without claiming email-only intake", async () => {
    const [privacy, terms] = await Promise.all([
      readSiteFile("privacy"),
      readSiteFile("terms"),
    ]);

    expect(privacy).toContain("waitlist form");
    expect(privacy).toContain("selected offer");
    expect(privacy).toContain("expected monthly volume");
    expect(privacy).toContain("automatically deleted by time-to-live (TTL) within 180 days");
    expect(privacy).toContain("retained separately rather than extending the waitlist record's TTL");
    expect(privacy).toContain("@example.com");
    expect(privacy).toContain("automatically deleted by TTL within 24 hours");
    expect(privacy).toContain("Intake does not verify email ownership");
    expect(privacy).toContain("contact permission is stored as asserted and unverified");
    expect(privacy).toContain("not proof of identity, email ownership");
    expect(privacy).toContain("not proof of identity, email ownership, or consent to unrelated marketing");
    expect(privacy).not.toContain("waitlist links open an email");
    expect(terms).toContain("waitlist form");
    expect(terms).not.toContain("no forms");
  });
});
