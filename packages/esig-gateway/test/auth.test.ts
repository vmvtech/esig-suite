// Authentication tests: the JWT contract HP-001 has to satisfy, the JWKS
// cache, the replay cache, and Envoy XFCC parsing. Runs against ../dist.

import crypto from "node:crypto";
import { describe, it, expect } from "vitest";

import { generateSelfSignedCert } from "@e-sig/core";

import { JwksCache, ReplayCache, verifyJwt, parseXfcc, GatewayError } from "../dist/index.js";
import type { JwtAuthConfig } from "../dist/index.js";

const CFG: JwtAuthConfig = {
  issuer: "https://pdp.vmvtech.io",
  audience: "esig-assurance-gateway",
  maxLifetimeSec: 600,
  clockSkewSec: 60,
  requiredScope: "esig:sign",
};

const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });

function jwkOf(key: crypto.KeyObject, kid: string, alg: string): Record<string, unknown> {
  return { ...(key.export({ format: "jwk" }) as Record<string, unknown>), kid, alg, use: "sig" };
}

const JWKS = new JwksCache(undefined, {
  keys: [jwkOf(rsa.publicKey, "rsa-1", "RS256"), jwkOf(ec.publicKey, "ec-1", "ES256")],
});

let jtiCounter = 0;

function mint(
  over: Record<string, unknown> = {},
  opts: { alg?: "RS256" | "ES256" | "none"; kid?: string; key?: crypto.KeyObject; tamper?: boolean } = {},
): string {
  const alg = opts.alg ?? "RS256";
  const kid = opts.kid ?? (alg === "ES256" ? "ec-1" : "rsa-1");
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg, kid, typ: "JWT" };
  const claims = {
    iss: CFG.issuer,
    aud: CFG.audience,
    sub: "spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance",
    iat: nowSec,
    exp: nowSec + 300,
    jti: `jti-${++jtiCounter}`,
    scope: "esig:sign",
    ...over,
  };
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signingInput = `${b64(header)}.${b64(claims)}`;
  if (alg === "none") return `${signingInput}.`;
  const key = opts.key ?? (alg === "ES256" ? ec.privateKey : rsa.privateKey);
  const sig =
    alg === "ES256"
      ? crypto.sign("sha256", Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" })
      : crypto.sign("sha256", Buffer.from(signingInput), key);
  const encoded = opts.tamper ? Buffer.from(sig.map((b, i) => (i === 0 ? b ^ 0xff : b))) : sig;
  return `${signingInput}.${encoded.toString("base64url")}`;
}

async function expectRejected(token: string, replay = new ReplayCache()): Promise<GatewayError> {
  try {
    await verifyJwt(token, CFG, JWKS, replay);
  } catch (e) {
    expect(e).toBeInstanceOf(GatewayError);
    return e as GatewayError;
  }
  throw new Error("expected the token to be rejected");
}

describe("verifyJwt — accepted", () => {
  it("accepts a well-formed RS256 token", async () => {
    const claims = await verifyJwt(mint(), CFG, JWKS, new ReplayCache());
    expect(claims.sub).toBe("spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance");
  });

  it("accepts ES256 (raw r||s, not DER)", async () => {
    const claims = await verifyJwt(mint({}, { alg: "ES256" }), CFG, JWKS, new ReplayCache());
    expect(claims.sub).toBeTruthy();
  });

  it("accepts an array aud containing the configured audience", async () => {
    const claims = await verifyJwt(mint({ aud: ["other", CFG.audience] }), CFG, JWKS, new ReplayCache());
    expect(claims.aud).toContain(CFG.audience);
  });

  it("accepts the scp alias for scope", async () => {
    const claims = await verifyJwt(mint({ scope: undefined, scp: ["esig:sign"] }), CFG, JWKS, new ReplayCache());
    expect(claims.sub).toBeTruthy();
  });

  it("surfaces the optional tenant claim", async () => {
    const claims = await verifyJwt(mint({ tenant: "acme-health" }), CFG, JWKS, new ReplayCache());
    expect(claims.tenant).toBe("acme-health");
  });
});

describe("verifyJwt — rejected", () => {
  it('rejects alg "none"', async () => {
    const e = await expectRejected(mint({}, { alg: "none" }));
    expect(e.code).toBe("unauthenticated");
  });

  it("rejects a tampered signature", async () => {
    await expectRejected(mint({}, { tamper: true }));
  });

  it("rejects a token signed by an unknown key", async () => {
    const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    await expectRejected(mint({}, { key: other.privateKey }));
  });

  it("rejects alg/key-type confusion (ES256 header over the RSA kid)", async () => {
    await expectRejected(mint({}, { alg: "ES256", kid: "rsa-1", key: rsa.privateKey }));
  });

  it("rejects an unknown kid", async () => {
    await expectRejected(mint({}, { kid: "nope" }));
  });

  it("rejects a wrong issuer", async () => {
    await expectRejected(mint({ iss: "https://evil.example" }));
  });

  it("rejects a wrong audience", async () => {
    await expectRejected(mint({ aud: "some-other-service" }));
  });

  it("rejects a missing scope", async () => {
    await expectRejected(mint({ scope: "read:stuff" }));
  });

  it("rejects an expired token", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    await expectRejected(mint({ iat: nowSec - 900, exp: nowSec - 600 }));
  });

  it("rejects a token whose lifetime exceeds the configured maximum", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    await expectRejected(mint({ iat: nowSec, exp: nowSec + 86_400 }));
  });

  it("rejects a missing jti", async () => {
    await expectRejected(mint({ jti: undefined }));
  });

  it("rejects a replayed jti", async () => {
    const replay = new ReplayCache();
    const token = mint();
    await verifyJwt(token, CFG, JWKS, replay);
    const e = await expectRejected(token, replay);
    expect(e.code).toBe("unauthenticated");
  });

  it("does not burn a jti on a token rejected for another reason", async () => {
    // A rejected-for-audience token must not consume its jti — otherwise an
    // attacker can pre-burn a legitimate credential's jti.
    const replay = new ReplayCache();
    const jti = "shared-jti";
    await expectRejected(mint({ aud: "wrong", jti }), replay);
    const claims = await verifyJwt(mint({ jti }), CFG, JWKS, replay);
    expect(claims.jti).toBe(jti);
  });

  it("rejects a malformed token", async () => {
    await expectRejected("not.a.jwt");
    await expectRejected("onlyonepart");
  });
});

describe("ReplayCache", () => {
  it("allows a jti again once it has expired", () => {
    const c = new ReplayCache();
    const t0 = 1_000_000;
    c.use("a", t0 + 100, t0);
    expect(() => c.use("a", t0 + 100, t0 + 50)).toThrow();
    expect(() => c.use("a", t0 + 300, t0 + 200)).not.toThrow();
  });
});

describe("JwksCache", () => {
  it("selects a single key when the token carries no kid", async () => {
    const cache = new JwksCache(undefined, { keys: [jwkOf(rsa.publicKey, "solo", "RS256")] });
    await expect(cache.get(undefined)).resolves.toMatchObject({ kid: "solo" });
  });

  it("refuses to guess when several keys are present and no kid is given", async () => {
    await expect(JWKS.get(undefined)).rejects.toBeInstanceOf(GatewayError);
  });

  it("fetches from a JWKS URI and caches the result", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return new Response(JSON.stringify({ keys: [jwkOf(rsa.publicKey, "remote", "RS256")] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const cache = new JwksCache("https://pdp.invalid/jwks", undefined, 300_000, 30_000, fetchImpl);
    await cache.get("remote");
    await cache.get("remote");
    expect(calls).toBe(1);
  });

  it("does not refetch on every unknown kid (egress amplification guard)", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return new Response(JSON.stringify({ keys: [jwkOf(rsa.publicKey, "remote", "RS256")] }), {
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const cache = new JwksCache("https://pdp.invalid/jwks", undefined, 300_000, 30_000, fetchImpl);
    for (let i = 0; i < 5; i++) {
      await expect(cache.get(`unknown-${i}`)).rejects.toBeInstanceOf(GatewayError);
    }
    // One initial load; the cooldown suppresses the rest.
    expect(calls).toBe(1);
  });
});

describe("parseXfcc", () => {
  it("extracts the SPIFFE URI SAN", () => {
    const { uris } = parseXfcc(
      'By=spiffe://vmvtech.io/ns/esig/sa/gateway;Hash=abc;URI=spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance',
    );
    expect(uris).toEqual(["spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance"]);
  });

  it("computes the SHA-256 fingerprint of a URL-encoded PEM Cert element", () => {
    const { certPem, fingerprint } = selfSignedFixture();
    const { fingerprints } = parseXfcc(`Cert=${encodeURIComponent(certPem)}`);
    expect(fingerprints).toEqual([fingerprint]);
  });

  it("ignores Subject= (spoofable across intermediates)", () => {
    const { uris, fingerprints } = parseXfcc('Subject="CN=totally-trusted"');
    expect(uris).toEqual([]);
    expect(fingerprints).toEqual([]);
  });
});

/** A throwaway self-signed cert, for the XFCC fingerprint test. */
function selfSignedFixture(): { certPem: string; fingerprint: string } {
  // Reuse core's issuer rather than hand-rolling ASN.1 here.
  const cert = generateSelfSignedCert({ subjectName: "XFCC Fixture" });
  const der = Buffer.from(
    cert.certPem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  return { certPem: cert.certPem, fingerprint: crypto.createHash("sha256").update(der).digest("hex") };
}
