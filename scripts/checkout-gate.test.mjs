import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const { handler } = require("../infra/lambda-checkout/index.js");

describe("public checkout release gate", () => {
  it("always redirects to the Cloud waitlist without caching", async () => {
    const response = await handler({ request: { method: "POST" } });

    expect(response).toEqual({
      status: "302",
      statusDescription: "Found",
      headers: {
        location: [
          {
            key: "Location",
            value: "https://e-sig.org/pricing?waitlist=1#cloud-waitlist",
          },
        ],
        "cache-control": [{ key: "Cache-Control", value: "no-store" }],
      },
    });
  });

  it("keeps both shared and dedicated offers on the waitlist at the accepted list prices", async () => {
    const pricing = await readFile(
      new URL("../site/pricing/index.html", import.meta.url),
      "utf8",
    );

    expect(pricing).toContain("Shared Cloud Starter");
    expect(pricing).toContain('data-price-monthly="$79"');
    expect(pricing).toContain('data-price-monthly="$199"');
    expect(pricing).toContain('data-price-monthly="$499"');
    expect(pricing).toContain("Dedicated Cloud · private preview");
    expect(pricing).toContain("from $30k");
    expect(pricing).toContain("$5k setup");
    expect(pricing).toContain("Join Dedicated waitlist");
    expect(pricing).not.toContain("/api/checkout");
  });
});
