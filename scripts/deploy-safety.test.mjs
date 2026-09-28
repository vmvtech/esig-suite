import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

describe("deployment script safety", () => {
  let docsDeploy;
  let docsIndex;
  let siteFinish;

  beforeAll(async () => {
    [docsDeploy, docsIndex, siteFinish] = await Promise.all([
      readFile(new URL("../docs/deploy.sh", import.meta.url), "utf8"),
      readFile(new URL("../docs/index.html", import.meta.url), "utf8"),
      readFile(new URL("../site/finish.sh", import.meta.url), "utf8"),
    ]);
  });

  it("publishes only the public docs allowlist with AWS CLI v2", () => {
    const includes = [...docsDeploy.matchAll(/--include "([^"]+)"/g)].map(
      (match) => match[1],
    );

    expect(docsDeploy).toContain('AWS="${ESIG_AWS_CLI:-/opt/homebrew/bin/aws}"');
    expect(docsDeploy).toContain('[[ "$AWS_VERSION" == aws-cli/2.* ]]');
    expect(docsDeploy).toContain('--exclude "*"');
    expect(includes).toEqual(["index.html", "blog/*"]);
    expect(docsDeploy).toMatch(/--cache-control [^\n]+ --delete/);
  });

  it("has no local HTML asset path outside the docs allowlist", () => {
    const localReferences = [
      ...docsIndex.matchAll(/(?:src|href)="([^"]+)"/g),
    ]
      .map((match) => match[1])
      .filter((reference) => !/^(?:https?:|data:|mailto:|#)/.test(reference));

    const outsideAllowlist = localReferences.filter(
      (reference) => reference !== "index.html" && !reference.startsWith("blog/"),
    );

    expect(outsideAllowlist).toEqual([]);
  });

  it("waits at least ten minutes for CloudFront with ten-second polling", () => {
    expect(siteFinish).toContain("CF_WAIT_TIMEOUT_SECONDS=600");
    expect(siteFinish).toContain("CF_WAIT_INTERVAL_SECONDS=10");
    expect(siteFinish).toContain("CF_WAIT_ELAPSED=$((SECONDS - CF_WAIT_STARTED))");
    expect(siteFinish).toContain("CloudFront function status: %s (%ss elapsed)");
    expect(siteFinish).toContain(
      "((CF_WAIT_ELAPSED >= CF_WAIT_TIMEOUT_SECONDS)) && break",
    );
    expect(siteFinish).toMatch(
      /\[\[ "\$CF_STATUS" == "DEPLOYED" \]\] \|\| die "LIVE CloudFront function did not reach DEPLOYED"/,
    );
  });
});
