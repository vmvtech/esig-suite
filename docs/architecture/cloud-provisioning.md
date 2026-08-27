# e-sig Cloud provisioning architecture

**Status:** Implemented locally; real staging proof pending  
**Date:** 2026-08-04  
**Checkout state:** Disabled; all public checkout routes must continue to redirect to the waitlist.

## Understanding and scope

e-sig Cloud will automate two commercial deployment modes behind the existing
waitlist gate:

1. **Shared Cloud** — one Supabase project and one AWS control plane, with
   tenant isolation enforced by PostgreSQL row-level security and tenant-scoped
   storage paths.
2. **Dedicated Cloud** — a separate Supabase project and a separate AWS
   CloudFormation data-plane stack for one customer.

A successful provisioning run creates an organization, owner membership, plan
entitlement, hashed API credential, storage namespace, and activation record.
It must be safe under duplicate and out-of-order Stripe events, retryable after
partial failure, and reversible without deleting immutable signing evidence.

### Commercial defaults

| Offer | List price | Included envelopes | Users |
| --- | ---: | ---: | ---: |
| Shared Starter | $79/month | 100 | 1 |
| Shared Team | $199/month | 500 | 5 |
| Shared Scale | $499/month | 1,500 | 15 |
| Dedicated Cloud | From $30,000/year + $5,000 setup | 1,500 | Contract |

The previous $19/$49/$79 targets may be used only as a 90-day founding-preview
discount with best-effort support. They are not the support-backed list price.

### Planning cost and margin estimate

These are planning ranges, not accounting promises. They assume US domestic-card
pricing, low-volume serverless traffic, pooled email delivery, no included custom
integration work, and support kept inside the stated envelope. Recalculate from
real bills after the first five design partners.

| Offer | Revenue | Estimated direct platform COGS | Platform gross margin | COGS including support reserve | Contribution margin |
| --- | ---: | ---: | ---: | ---: | ---: |
| Shared Starter | $79/month | $7–$14 | 82–91% | $22–$39 | 51–72% |
| Shared Team | $199/month | $16–$31 | 84–92% | $46–$91 | 54–77% |
| Shared Scale | $499/month | $40–$80 | 84–92% | $115–$230 | 54–77% |
| Dedicated Cloud | $2,500/month equivalent | $75–$300 | 88–97% | $575–$1,200 | 52–77% |
| Dedicated setup | $5,000 once | n/a | n/a | $1,800–$3,500 delivery labor | 30–64% |

The shared base cost is pooled across tenants. The dedicated range assumes one
Supabase production project plus the customer's retained AWS data plane; a
Supabase Team/Enterprise requirement, HIPAA add-on, private networking, premium
support, or unusually high storage/egress is pass-through or separately quoted.
At the $30,000/year floor, dedicated support must stay below roughly eight loaded
hours per month to preserve a 60% contribution margin. Custom work is never
absorbed into the subscription.

Pricing inputs checked on 2026-08-04: Supabase Pro starts at $25/month and
additional projects at $10/month; Stripe standard US domestic cards are 2.9% +
$0.30; Postmark Basic starts at $15/month for 10,000 emails; AWS Lambda and SQS
include one million monthly requests in their free tiers, API Gateway HTTP APIs
start around $1/million requests, and each customer-managed KMS key is $1/month.
See [Supabase pricing](https://supabase.com/pricing),
[Stripe pricing](https://stripe.com/pricing),
[Postmark pricing](https://postmarkapp.com/pricing/),
[AWS Lambda pricing](https://aws.amazon.com/lambda/pricing/),
[AWS API Gateway pricing](https://aws.amazon.com/api-gateway/pricing/),
[AWS SQS pricing](https://aws.amazon.com/sqs/pricing/), and
[AWS KMS pricing](https://aws.amazon.com/kms/pricing/).

## Non-functional defaults

- Region: AWS `us-east-1`; Supabase project region selected to match.
- Scale: private-preview workloads through 1,500 envelopes/month per tenant.
- Availability: no paid SLA during private preview.
- Recovery: retry transient failures with bounded exponential backoff; route
  exhausted jobs to a dead-letter queue and alarm.
- Security: secrets are references to AWS Secrets Manager entries, never
  template parameters, logs, event records, or repository content.
- Privacy: operational logs contain opaque IDs and state transitions only—no
  documents, signer data, API keys, payment details, or email message bodies.
- Ownership: one operational team; every failed job exposes a safe replay path.

## Architecture

```text
Stripe test/live events
        |
        v
API Gateway HTTP API
        |
        v
Webhook Lambda -- signature + event-id conditional write --> DynamoDB ledger
        |                                                        |
        +-------------------- accepted event --------------------+
                                 |
                                 v
                            SQS + DLQ
                                 |
                                 v
                         Provisioning worker
                          /               \
                         v                 v
             Shared Supabase RPC    Dedicated provider
             + tenant namespace     + Supabase project
                                    + customer AWS stack
```

The webhook does only three things before returning `2xx`: preserve and verify
the raw Stripe body, claim the event ID conditionally, and enqueue the event.
All network provisioning happens in the worker.

## Durable state

The control-plane table uses a composite key and stores four record types:

- `EVENT#<stripe_event_id>` — immutable idempotency claim and payload digest.
- `ORDER#<subscription_id>` — customer, plan, deployment mode, billing state,
  and a monotonic compare-and-swap version.
- `JOB#<subscription_id>` — provisioning state, completed steps, attempt count,
  lease, last safe error code, and retry time.
- `RESOURCE#<subscription_id>#<kind>` — opaque downstream identifiers used for
  resume and compensation.
- `CREDENTIAL_HANDOFF#<activation_id>` — the authoritative pending, published,
  or revoked pointer to one immutable credential secret generation. It contains
  identifiers and fencing metadata only, never plaintext or a credential hash.

Billing states are `pending`, `active`, `past_due`, `canceled`, and `refunded`.
Provisioning states are `queued`, `running`, `ready`, `failed`, `compensating`,
and `disabled`. Every order write uses its monotonic version as the conditional
write token, so a stale worker cannot overwrite newer metadata or regress a
terminal state. Each independently ordered Stripe aggregate tracks the latest
accepted event creation time; older events may fill missing identifiers but
cannot resurrect a canceled or refunded subscription.

## Provisioning contract

Every provider implements idempotent operations keyed by subscription ID:

1. create or resolve the tenant;
2. create or resolve the owner membership;
3. apply the plan entitlement;
4. create one API key, persist only its SHA-256 hash, and expose plaintext once;
5. create the tenant storage namespace;
6. configure activation/email metadata;
7. mark the tenant ready.

Compensation runs completed steps in reverse. It revokes credentials, disables
new signing, and quarantines partial resources. It never deletes audit rows,
signed documents, or retention-locked objects. `past_due` uses a reversible
suspension operation: it revokes the active credential and disables signing
without deleting the tenant or pausing its dedicated Supabase project. A later
paid event resumes the same tenant, rotates a fresh credential, and requires the
normal ready proof. Cancellation and refund remain irreversible terminal paths.

### Shared provider

One security-definer PostgreSQL function performs the organization, membership,
entitlement, credential-hash, and provisioning-record writes transactionally.
RLS membership reads from the real membership table; the current deny-all stub
is replaced only when that schema is applied. Storage paths remain tenant-ID
prefixed. Ready and terminal billing transitions lock the same tenant rows, so
a stale ready attempt cannot resurrect a canceled or past-due tenant.

### Dedicated provider

The worker creates or resumes a Supabase project through the Management API,
then creates a customer CloudFormation stack containing a KMS key, private
versioned S3 bucket, tenant queue/DLQ, and parameterized outputs. Project and
stack names are deterministic, so retries discover rather than duplicate them.
Deletion is never an automatic compensation step; failed stacks are disabled
and surfaced for reviewed cleanup. A dedicated tenant remains `provisioning`
until migrations 0001–0004 match their SHA-256 ledger, the tenant/account RPC
returns valid proof, and the explicit ready RPC succeeds.

Supabase currently documents the Management API SQL-query request but not a
stable successful-response schema. The adapter therefore requires a narrow row
decoder supplied by deployment composition. The operational worker must remain
disabled until that decoder is proven against a real staging project.

### Credential handoff and worker serialization

Each subscription has one persisted execution lease with a monotonic fencing
token. A second worker defers while the lease is live; an expired owner can be
replaced, but cannot renew or release its successor's lease. The default lease
is ten minutes, longer than the five-minute Lambda timeout, and active work
renews it while provider effects and credential delivery are in flight.

Credential plaintext is never written to DynamoDB, tenant tables, resource
records, logs, or exceptions. Before a provider may create or rotate a
credential, the worker creates a pending DynamoDB handoff pointer bound to the
activation lifecycle and current lease fencing token. It then creates one
generation-specific Secrets Manager secret with `CreateSecret` only. Publishing
the pointer is a fenced DynamoDB transaction: a delayed expired worker cannot
replace a newer worker's pointer or make its revoked credential current.

Retries verify the exact immutable secret named by the published pointer; they
never discover a credential through `AWSCURRENT`, list order, or timestamps. If
publication cannot be verified, a new fence must rotate and publish a new
credential. A paid-recovery retry that already has a verified publication reuses
the persisted resumed provider snapshot; it must not invoke resume and rotate a
second time. Publication names, IDs, tags, and version tokens derive only from
non-secret lifecycle, fence, and credential identifiers—not credential
plaintext or its digest. Suspension and terminal compensation revoke the
authoritative pointer before revoking provider access. This proves durable
storage, not that the intended customer retrieved it; checkout still requires a
separate customer acknowledgment/login proof. A commit-unknown provider effect
with no snapshot uses deterministic discovery and compensation without creating
new resources.

## Webhook policy

Accepted event families:

- `checkout.session.completed`
- `invoice.paid`
- `invoice.payment_failed`
- `customer.subscription.created|updated|deleted`
- `charge.refunded`

Unknown event types are acknowledged and recorded as ignored. Invalid
signatures return `400`; temporary store/queue failures return `500` so Stripe
retries. Duplicate valid events return `200` without another queue message.

## Testing and release gates

The implementation must prove:

- valid, invalid, stale, and malformed Stripe signatures;
- ten concurrent duplicate deliveries create one event claim and one job;
- relevant event permutations converge to the same final state;
- fault injection after every provisioning step resumes without duplication;
- compensation revokes access but preserves immutable evidence;
- both shared and dedicated providers converge on retry;
- `past_due` suspends both providers, and a later paid event resumes the same
  tenant with a new credential while terminal states remain disabled;
- delayed expired workers cannot publish or repoint a stale credential after a
  successor has taken the lease;
- pending-write, immutable-secret commit-unknown, publish-before-checkpoint, and
  exact retry paths converge without exposing plaintext;
- cancellation and refund disable signing and API credentials;
- cleanup is idempotent and reports retention-blocked resources honestly;
- the CloudFormation template validates and grants least-privilege access;
- root build/test/smoke remains green;
- the public checkout route still redirects to the waitlist after all tests.

Production checkout may be restored only after a real Stripe test-mode event,
real shared tenant, real dedicated staging stack, owner login, first envelope,
verification, cancellation, and cleanup are evidenced. This implementation does
not itself authorize that restoration.

## Decision log

| Date | Decision | Rationale |
| --- | --- | --- |
| 2026-08-04 | Offer shared and dedicated provisioning | Covers low-cost adoption and isolation-sensitive buyers without forcing one topology on both. |
| 2026-08-04 | Use a regional webhook plus SQS worker | Stripe can be acknowledged quickly while long provisioning remains retryable. |
| 2026-08-04 | Keep one control-plane event ledger | Centralizes idempotency and recovery across both providers. |
| 2026-08-04 | Use transactional SQL for shared provisioning | Prevents partially created shared tenants and keeps RLS authoritative. |
| 2026-08-04 | Use deterministic names for dedicated resources | Retries converge on existing resources instead of duplicating them. |
| 2026-08-04 | Never auto-delete immutable evidence | Cancellation and compensation must preserve legal/audit records. |
| 2026-08-04 | Keep checkout fail-closed | Provisioning code and tests are necessary but not sufficient to accept payment. |

## Implementation sequence

1. Pure event reducer, idempotency model, job state machine, and fault-injected tests.
2. Shared SQL migration and provider client.
3. Dedicated Supabase/AWS provider and customer-stack template.
4. DynamoDB/SQS adapters, webhook/worker handlers, and control-plane template.
5. Integration harness, deployment validation, staging proof, and adversarial review.
