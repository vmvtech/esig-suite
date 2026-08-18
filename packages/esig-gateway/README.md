# @e-sig/assurance-gateway

A small internal signing service in front of [`@e-sig/core`](../esig-core).
It renders a caller-supplied HTML document to PDF, signs it, and returns the
bytes. It holds signing keys, so it is **private-reachability only** — never
internet-facing.

Built for the DSalvus Assurance monthly evidence dossier
(`HANDOFF-dsalvus-assurance-gateway.md` in the repo root); the wire contract is
frozen by the dsalvus client at `internal/assurance/sign.go`.

```
POST /v1/sign   { tenant, cert_alias, html_base64, purpose, timestamp }
             -> { signed_pdf_base64, cert_fingerprint, timestamped }
GET  /healthz   liveness  — process only, touches no dependency
GET  /ready     readiness — tenant registry, cert store, TSA, JWKS
```

---

## The signature it produces

The dsalvus design note says *"Ed25519 through the @e-sig/core PKCS#7 wrapper."*
Ed25519-**in**-PKCS#7 is not what core produces and should not be: `PemSigner`
is RSASSA-PKCS1-v1_5/SHA-256 end to end, `ExternalSignerKeyType` admits only
`rsa-2048|3072|4096`, and no mainstream PDF reader validates an EdDSA
`SignerInfo`. Such a signature would verify in our tooling and nowhere else —
the opposite of what a reassurance artifact needs.

What this gateway emits instead satisfies the intent literally *and* verifies in
Acrobat:

| Layer | What | Why |
|---|---|---|
| 1 | **Hybrid seal — Ed25519 + ML-DSA-65** (FIPS 204) over SHA-256 of the pre-signature PDF, embedded as an append-only incremental update | the Ed25519 the design asked for, plus post-quantum |
| 2 | **PAdES / PKCS#7 detached, RSA-2048**, `/SubFilter ETSI.CAdES.detached`, applied on top so its `/ByteRange` covers layer 1 | every PDF reader validates this |
| 3 | **RFC-3161 timestamp token** → CAdES-T (optional, configurable as required) | authoritative time, not the caller's clock |

So Ed25519 is present and is cryptographically covered by the PKCS#7 signature.
Verify both layers with core's `verifyDocument(pdf, { requirePq: true })`; verify
the classical layer alone with `verifyPdfSignature(pdf)` or any PDF reader.

Every response is **self-verified before it is returned** — the gateway never
hands back a PDF whose own signature does not verify.

---

## Contract notes (deltas from the handoff, none breaking)

- **`purpose`** must be 1–120 printable ASCII characters. It reaches the PDF
  signature dictionary `/Reason`; core escapes dictionary strings as of 0.7.0,
  this is the caller-side half of that defence. dsalvus' default
  `dsalvus-assurance-package` passes.
- **`timestamp`** is recorded as a *claim* (`metadata.client_timestamp`) and is
  freshness-checked (±15 min by default). It never becomes the signing time —
  a client-controlled signing time would let a caller backdate a signed dossier.
- **`html_base64`** must be canonical standard base64.
  `Buffer.from(s,"base64")` silently discards garbage, which would let a
  corrupted payload be signed as though it were the dossier.
- **Additive response fields** — `audit_id`, `signed_at`, `pq_seal`,
  `tsa_error`, `transitional_auth`. Go's `encoding/json` ignores unknown fields,
  so these need no dsalvus release. The three contractual fields are unchanged.
- **Unknown tenant, unknown alias and not-permitted all return the same 403 and
  the same body.** A distinguishable "no such tenant" makes the registry
  enumerable by an authenticated caller. Operator logs distinguish them.

---

## Tenants: `(tenant, cert_alias)` is the identity

Core's `CertStore` is keyed by a single `tenantId`. A (tenant, alias) pair is
addressed as `` `${tenant}/${alias}` ``, and both components are constrained to
`^[a-z0-9][a-z0-9._-]{0,63}$` — `/` is excluded, so the encoding is injective
and no two distinct pairs can collide onto one signing key.

The registry is an **explicit allowlist with no wildcard and no create-on-first-
sight path** (`ESIG_GATEWAY_TENANTS` → a JSON file, e.g. a mounted ConfigMap).
An unregistered tenant or alias is rejected; it is never provisioned. See
[`deploy/tenants.example.json`](deploy/tenants.example.json).

```jsonc
{
  "tenant": "dsalvus-pilot",
  "aliases": ["assurance-signer"],       // no wildcard
  "subjectName": "DSalvus Assurance",    // X.509 CN, printable ASCII only
  "callers": ["spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance"],
  "reason": "DSalvus monthly assurance evidence dossier",
  "pqSeal": true,                        // default
  "uuaid": "uuaid:foundation:agent:…"    // optional seal-bound assertion
}
```

`uuaid` is a **claim by the seal key**, not proof of identity — the reverse
binding (UUAID → key) lives in the UUAID registry and is not established here.
See the identity-model note at the top of `core/src/pq-seal.ts` before relying
on it in an assurance narrative.

---

## Authentication — what HP-001 must wire

`ESIG_GATEWAY_AUTH_MODE` is **required**; the gateway refuses to start without
it. Recommended: `mtls+jwt`. The two halves answer different questions —

- **mTLS**: *is this connection from a workload the mesh vouches for?*
- **JWT**: *did the PDP authorise THIS workload to sign for THIS tenant, now?*

A mesh certificate alone proves membership, not authorisation, and is long-lived
relative to a monthly batch. A bearer token alone is replayable by anything that
can reach the port.

### The JWT contract

| Claim | Requirement |
|---|---|
| `alg` | `RS256` \| `PS256` \| `ES256` — asymmetric only, pinned before key lookup (no `none`, no HS\*) |
| `iss` | exactly `ESIG_GATEWAY_JWT_ISSUER` |
| `aud` | exactly `ESIG_GATEWAY_JWT_AUDIENCE` (string, or a member of the array form) |
| `sub` | the workload identity — this is the value that must appear in a tenant's `callers` |
| `exp`, `iat` | required; `exp - iat` ≤ `ESIG_GATEWAY_JWT_MAX_LIFETIME_SEC` (default 600) |
| `nbf` | optional, honoured when present |
| `jti` | required and single-use — a replay inside the token lifetime is rejected |
| `scope` / `scp` | must contain `ESIG_GATEWAY_JWT_SCOPE` (default `esig:sign`) |
| `tenant` | **optional but recommended** — when present it must equal the request body `tenant`, which is how the PDP mints a credential scoped to one tenant rather than to every tenant a workload is listed against |

Keys come from `ESIG_GATEWAY_JWKS_URI` (cached 5 min; an unknown `kid` triggers
at most one refetch per 30 s, so random-kid tokens cannot amplify egress onto
the PDP).

**Identity binding — the PDP must mint `sub` identical to the cert URI-SAN.**
In `mtls+jwt` mode the caller is matched against a tenant's `callers` list by
the JWT `sub`, and the mTLS peer is matched separately against
`ESIG_GATEWAY_MTLS_SPIFFE_IDS`. For the assurance workload the same string must
appear verbatim in **both** — e.g.
`spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance` is the URI-SAN on the
mesh-issued cert *and* the `sub` HP-001 mints. The gateway does not
cross-check the two lists against each other; if they diverge, one half
authenticates and the other does not, and the failure surfaces as a 403 with no
hint that the cause is a config split. Record the SPIFFE string once and put it
in both places.

### mTLS

`ESIG_GATEWAY_MTLS_SOURCE=socket` terminates TLS in-process with
`requestCert + rejectUnauthorized` — an unverified peer never reaches the
handler, and no proxy header has to be trusted. `=xfcc` accepts Envoy's
`x-forwarded-client-cert` instead; only use it behind a proxy that strips the
header from inbound traffic. Identity is matched against
`ESIG_GATEWAY_MTLS_SPIFFE_IDS` (URI SAN) or `ESIG_GATEWAY_MTLS_FINGERPRINTS`
(cert SHA-256) — a verified chain alone does not say *which* workload is calling.
`Subject=` in XFCC is deliberately ignored; it is spoofable across intermediates.

**The default is `socket`, not neutral.** An unset `ESIG_GATEWAY_MTLS_SOURCE`
resolves to `socket`, which needs `ESIG_GATEWAY_TLS_KEY` / `_TLS_CERT` /
`_TLS_CLIENT_CA` set. It fails closed at boot rather than mis-authenticating a
peer — but a mesh-sidecar deployment that forgets to set `=xfcc` will not
start. Set the mode deliberately.

### Transitional API key

`ESIG_GATEWAY_AUTH_MODE=api-key` additionally requires
`ESIG_GATEWAY_ALLOW_TRANSITIONAL_AUTH=1`. Credentials are
`Authorization: Bearer <keyId>.<secret>` from `ESIG_GATEWAY_API_KEYS`
(≥32-char secrets, injected from Secrets Manager). Every audit row signed this
way carries `transitional_auth: true`, and the response carries it too — the
pilot's weaker posture is visible in the evidence trail a year later, not only
in a startup log line.

> **Open item on the dsalvus side.** `internal/assurance/sign.go` sends **no
> credential today** — no `Authorization` header, and `cmd/assurance/main.go`
> passes no `HTTPClient`. mTLS via a mesh sidecar works with no Go change; a
> JWT or API key needs either a `RoundTripper` in `SignerConfig.HTTPClient` at
> the call site, or a small client change. Flagged, not assumed.

---

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `ESIG_GATEWAY_TENANTS` | ✔ | — | path to the tenant registry JSON |
| `ESIG_GATEWAY_KEY_PASSPHRASE` | ✔ | — | ≥24 chars; wraps keys at rest. From Secrets Manager, never baked into the image |
| `ESIG_GATEWAY_STATE_DIR` | ✔ | — | cert store, PQ bundles, audit NDJSON |
| `ESIG_GATEWAY_AUTH_MODE` | ✔ | — | `mtls+jwt` \| `mtls` \| `jwt` \| `api-key` |
| `ESIG_GATEWAY_HOST` / `_PORT` | | `0.0.0.0` / `8443` | |
| `ESIG_GATEWAY_TLS_KEY` / `_TLS_CERT` / `_TLS_CLIENT_CA` | | — | required for `MTLS_SOURCE=socket` |
| `ESIG_GATEWAY_TSA_URLS` | | — | comma-separated, tried in order |
| `ESIG_GATEWAY_TSA_REQUIRED` | | `0` | `1` = a TSA failure fails the sign |
| `ESIG_GATEWAY_TSA_TIMEOUT_MS` | | `8000` | |
| `ESIG_GATEWAY_MAX_BODY_BYTES` | | `12582912` | |
| `ESIG_GATEWAY_MAX_CONCURRENT_SIGNS` | | `2` | each in-flight sign holds a Chromium process |
| `ESIG_GATEWAY_SIGN_DEADLINE_MS` | | `25000` | below the client's 30 s, so we fail before it does |
| `ESIG_GATEWAY_MAX_CLIENT_SKEW_SEC` | | `900` | `0` disables |
| `ESIG_CHROME_PATH` | | image default | `/usr/bin/chromium` in the container |
| `ESIG_GATEWAY_WORM_BUCKET` | | — | S3 Object Lock bucket for sign-time WORM archival. Unset = archival stays off (destinations dsalvus-side). Requires `@aws-sdk/client-s3` in the container image. |

`ESIG_GATEWAY_TSA_REQUIRED=1` matters more than it looks: the only thing dsalvus
sees is a boolean `timestamped`, so a silent CAdES-T → CAdES-B downgrade is
invisible until someone audits a dossier a year later. Set it where the
assurance narrative claims trusted timestamps.

---

## Key custody

**Pilot** — self-issued certs from core's `ensureActiveCert`, private keys
AES-256-GCM wrapped at rest under `ESIG_GATEWAY_KEY_PASSPHRASE` (scrypt KDF,
core `cert-issuer.ts`). The passphrase is injected at runtime; no key material
and no secret is in the image or the repo.

**Upgrade path** — core's `ExternalSigner` seam keeps the private key out of the
process entirely, and [`@e-sig/hsm-pkcs11`](../esig-hsm-pkcs11)'s `Pkcs11Signer`
implements it (`CKM_SHA256_RSA_PKCS`). Wiring it is a per-tenant swap of
`keyPem`/`certPem` for `externalSigner` in `sign.ts`. **This is a seam, not a
shipped configuration** — there is no env-driven PKCS#11 bootstrap yet, because
there is no HSM (or SoftHSM2 token) to point it at. Stated plainly rather than
claimed.

---

## Persistence and scale

The pilot uses core's filesystem stores plus `FsPqKeyStore` (this package —
core ships no filesystem `PqKeyStore`). Core documents these as **single-process**:
read-modify-write with atomic replace, which serialises within one process only.

**Therefore the pilot runs at replica count 1.** Two replicas sharing a volume
can both mint a "first" cert for one tenant and one loses the
single-active-per-tenant race. Within a process, `KeyedMutex` serialises
`ensureActiveCert` / `ensureActivePqKeys` per `(tenant, alias)` so the same race
cannot happen across concurrent requests.

Scaling out is a constructor swap in `createGateway` — `@e-sig/supabase`'s
adapters, or a small DynamoDB conditional-write store, behind the same
interfaces. Nothing else changes.

### Archival

`signDocument()`'s storage-first shape is deliberately **not** used: the frozen
contract needs the signed *bytes* back, and handoff §6 leaves archival custody
an open owner decision. Sign-time archival is wired through
`createGateway(config, { archive })` and auto-created when
`ESIG_GATEWAY_WORM_BUCKET` is set — the gateway creates a
`WormPdfStorageStore` (S3 Object Lock, COMPLIANCE retention, 2555 days) from the
configured bucket and an injected S3 client. When the bucket is unset, archival
stays off and destinations stay dsalvus-side.

#### Owner decision (2026-08-17): WORM sign-time archive = ON (wired)

The owner accepted sign-time WORM archival as the deployment default. The code
is wired: set `ESIG_GATEWAY_WORM_BUCKET=esig-assurance-worm-<env>` and ensure
`@aws-sdk/client-s3` is in the container image (the gateway loads it dynamically
at startup — it is not a hard dependency). The S3 client picks up credentials
from the ECS task role automatically. A missing SDK or unreachable bucket fails
at startup, not on the first dossier.

**Bucket provisioning** (route to infra) — the spec below is unchanged from the
original handoff response:

- name: `esig-assurance-worm-<env>` — one per environment, tenant-partitioned by
  key prefix, **not** one per tenant. Object Lock must be enabled **at creation**
  (cannot be added later). Bucket versioning on (Object Lock requires it).
- region: the lane's primary compliance region.

**Retention** — per-`PutObject`, atomic: `ObjectLockMode=COMPLIANCE`,
`RetainUntilDate=now+2555d` (~7 years). No conflicting bucket-level default.
In COMPLIANCE mode even account root cannot shorten or delete before the date.

**Object key layout** — `<tenant>/<cert_alias>/<signedAt-UTC>.pdf`.

**IAM — gateway task role, puts only:**
```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject", "s3:PutObjectTagging"],
  "Resource": "arn:aws:s3:::esig-assurance-worm-<env>/<tenant>/*"
}
```

No Get/Delete/PutObjectRetention/BypassGovernanceRetention/PutBucket*. Read/export
is a separate auditor role.

**Note for HP-001:** the archive is code-complete. The infra-side items are the
bucket creation + task-role attachment. The gateway reads the bucket from
`ESIG_GATEWAY_WORM_BUCKET` and loads the S3 SDK dynamically; until the bucket
exists and the role is attached, keep the env var unset and archival stays off.

---

## Running it

```bash
# from the repo root
npm run build -w @e-sig/core && npm run build -w @e-sig/assurance-gateway
npm test  -w @e-sig/assurance-gateway     # 59 tests, no Chromium needed

ESIG_GATEWAY_TENANTS=packages/esig-gateway/deploy/tenants.example.json \
ESIG_GATEWAY_STATE_DIR=/var/lib/esig-gateway \
ESIG_GATEWAY_KEY_PASSPHRASE="$(openssl rand -hex 24)" \
ESIG_GATEWAY_AUTH_MODE=api-key \
ESIG_GATEWAY_ALLOW_TRANSITIONAL_AUTH=1 \
ESIG_GATEWAY_API_KEYS="dsalvus-pilot:$(openssl rand -hex 24)" \
  node packages/esig-gateway/dist/bin.js
```

Container (build from the repo root — the gateway is a workspace package):

```bash
docker build -f packages/esig-gateway/Dockerfile -t esig-assurance-gateway:dev .
```

Release builds pin the base by digest: `--build-arg NODE_IMAGE=node:22-bookworm-slim@sha256:…`.
The image runs as `node` (uid 1000), needs a writable `/tmp` (Chromium) and a
volume at `ESIG_GATEWAY_STATE_DIR`; everything else can be read-only.

### Test coverage

`npm test -w @e-sig/assurance-gateway` maps to the handoff's acceptance criteria:
signed-PDF verification (§7.1), both seal layers, tamper detection and the audit
row (§7.2), every fail-closed rejection (§7.3), `/healthz` + `/ready` including
required-vs-optional TSA behaviour (§7.4), and the full JWT/JWKS/replay/XFCC
suite. The HTML→PDF renderer is injectable, so CI needs no Chromium — the tests
use the repo's `scripts/sample-unsigned.pdf` fixture, the same trick core's own
PQ tests use.
