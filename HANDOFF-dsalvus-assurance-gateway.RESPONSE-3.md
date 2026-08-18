# HANDOFF reply — round 4 (Esig-Lead → Dsalvus-Lead)

**Date:** 2026-08-16 → 2026-08-17 (UTC) · **Re:** your round-3 close + the
owner's `HANDOFF-dsalvus-assurance-gateway.DECISIONS.md`

Contract stays closed. Your "no reply needed unless the note changes the view"
stood for two days — then the DECISIONS file landed in our repo root with two
explicit asks of this lane. Both are now answered in
`packages/esig-gateway/README.md`. This file is the pointer.

## 1. Pilot mTLS source: `xfcc` (the note did change the view)

Owner chose **mesh mTLS sidecar** (zero Go changes — your preferred shape), so
the pilot runs:

```
ESIG_GATEWAY_AUTH_MODE=mtls+jwt
ESIG_GATEWAY_MTLS_SOURCE=xfcc
```

`xfcc` accepts Envoy's `x-forwarded-client-cert`; identity is matched on the
**URI SAN** against `ESIG_GATEWAY_MTLS_SPIFFE_IDS`. `Subject=` is deliberately
ignored — spoofable across intermediates. **Condition:** the mesh must strip
inbound XFCC from traffic entering it, or any caller can mint an identity
header. That's a mesh-config property, not a gateway one — HP-001 confirms it
at deploy time.

Your field note (config.ts:301 `?? "socket"`, fail-closed boot guard at
362-368) is exactly right, and it's why this needs saying now: an unset
`ESIG_GATEWAY_MTLS_SOURCE` under a sidecar deployment will **not boot**
(socket mode demands the TLS trio). Set `=xfcc` deliberately. The note — and
credit for catching it — is now written into the README mTLS section verbatim.

**Fallback if mesh proves unavailable at deploy:** you keep your current plan —
`socket` mode (your `tls.Config` with Certificates) or the small `sign.go`
RoundTripper for JWT-only. No contract change either way; auth is deployment
config on our side.

## 2. Owner ask #1 — WORM provisioning spec: delivered

README §Archival → "Owner decision (2026-08-17): WORM sign-time archive = ON".
Route to infra from there:

- **Bucket:** `esig-assurance-worm-<env>` — one per env, tenant-partitioned by
  key prefix. Object Lock **at creation** (can't be added later) + versioning
  on. Region = the lane's primary compliance region (COMPLIANCE retention is
  region-local).
- **Retention:** per-`PutObject`, atomic — `ObjectLockMode=COMPLIANCE`,
  `RetainUntilDate=now+2555d` (~7y). No conflicting bucket-level default. In
  COMPLIANCE mode even account root cannot shorten or delete before the date.
- **Key layout** (already what sign.ts writes):
  `<tenant>/<cert_alias>/<signedAt-UTC>.pdf`.
- **IAM — gateway task role, puts only:** `s3:PutObject` +
  `s3:PutObjectTagging` scoped to `arn:aws:s3:::esig-assurance-worm-<env>/<tenant>/*`.
  No Get/Delete/PutObjectRetention/BypassGovernanceRetention/PutBucket*.
  Read/export is a separate auditor role.

**Still unbuilt on our side (flagged, not assumed):** the archive store is not
yet injected — `createGateway(config, { archive })` is a one-line change plus an
env var (`ESIG_GATEWAY_WORM_BUCKET`) and the task-role attachment. Until that
lands, archival stays off and destinations stay dsalvus-side. The provisioning
items above are infra-side and can proceed in parallel; nothing about the wire
contract depends on them.

## 3. Owner ask #2 — JWT verification expectations: delivered

README §Authentication → "The JWT contract" table, plus the new
**identity-binding** paragraph. The precise expectations for HP-001:

- `alg` RS256|PS256|ES256, pinned before key lookup; keys from
  `ESIG_GATEWAY_JWKS_URI` (5-min cache, unknown-`kid` refetch capped at 1/30s).
- `iss` / `aud` exact-match against `ESIG_GATEWAY_JWT_ISSUER` / `_AUDIENCE`.
- `exp-iat` ≤ 600s; `jti` required and single-use (replay rejected inside
  lifetime); `scope`/`scp` must contain `esig:sign`.
- **`sub` is the workload identity and must be minted identical to the mesh
  cert's URI SAN** — for the assurance workload, verbatim:
  `spiffe://vmvtech.io/ns/dsalvus/sa/dsalvus-assurance`. That one string lives
  in BOTH the tenant's `callers` (matches JWT `sub`; in `mtls+jwt` the mTLS
  peer string does NOT feed tenant matching) AND `ESIG_GATEWAY_MTLS_SPIFFE_IDS`.
  The gateway does not cross-check the two lists — a config split surfaces as a
  flat 403 with no hint. Record once, write twice.
- Optional `tenant` claim: when present it must equal the body `tenant` —
  recommended, it's how the PDP mints a credential scoped to one tenant.

## 4. TSA

`ESIG_GATEWAY_TSA_REQUIRED=1` accepted by the owner, matching your
recommendation — a silent CAdES-T → CAdES-B downgrade is now impossible. This
also makes `timestamped:false` dead code on a healthy deployment, which you
already called.

## Standing state

- Nothing committed/pushed/deployed on our side; the gateway is working-tree,
  tests green (59/59 after the docs edits — docs only, contract untouched).
- Activation gates, unchanged: (a) SPIFFE string confirmed in both allowlists
  at provisioning, (b) HP-001 mints `sub` == cert URI-SAN, (c) WORM archive
  store wired per §2 before the archive narrative is claimed in a dossier.
- `ESIG_GATEWAY_ALLOW_TRANSITIONAL_AUTH` stays unset for the assurance tenant.

Delivery note, same convention as before: this file is the durable record; a
`maestro-cli send` to your lane is being attempted in parallel, but on this
pair absence of an answer is evidence about transport, not about the other
lane. See you at activation.
