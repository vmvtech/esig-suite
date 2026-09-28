---
type: reference
title: Cloud Provisioning Control Plane
created: 2026-09-28
tags:
  - esig
  - provisioning
  - infrastructure
related:
  - '[[GAPS-AND-TODOS]]'
  - '[[90-day-playbook]]'
---

# Cloud provisioning control plane

`@e-sig/cloud-provisioning` is the private, fail-closed control plane for e-sig Cloud. Its [Stripe webhook handler](src/handlers/webhook.ts) verifies and normalizes billing events, claims them in the event ledger, and queues accepted events. The [worker](src/handlers/worker.ts) reduces those events into durable order and job state, then runs the [shared or dedicated provider graph](src/runtime.ts).

The exported worker entry point deliberately returns every record as a batch failure until a deployer binds an explicit store, provider driver, and credential handoff. This prevents a partially configured deployment from acknowledging paid work; see [`src/handlers/worker.ts`](src/handlers/worker.ts).

## Tests

Run the three root-level provisioning checks from the repository root; the command names are defined in the root [`package.json`](../../package.json).

| Command | Coverage |
| --- | --- |
| `npm run test:provisioning` | Vitest unit and integration suites for the package |
| `npm run test:provisioning:supabase` | Supabase PostgreSQL migration and pgTAP checks |
| `npm run test:provisioning:templates` | CloudFormation template validation |

Template validation covers [`template.yaml`](template.yaml) and [`customer-stack.yaml`](customer-stack.yaml). [`scripts/validate-templates.sh`](scripts/validate-templates.sh) uses an installed `cfn-lint` when available and otherwise runs `cfn-lint==1.53.3` through `uvx`; it exits if neither path exists.

> [!WARNING]
> The Supabase test is not a valid local gate on Apple-silicon Macs: the AMD64 database image fails under QEMU inside its own GraphQL event trigger after readiness. Use the native CI run as the consumer-path result. This operational caveat comes from the non-versioned fleet handoff at `/Volumes/X/VMV/esig-suite/.maestro/handoff.md` risk 4, not from a file included in every clone.

Package-local build, bundle, and watch commands are listed in [`infra/provisioning/package.json`](package.json). Packaging and deployment remain separate, explicit operations in [`scripts/package-control-plane.sh`](scripts/package-control-plane.sh) and [`scripts/deploy-control-plane.sh`](scripts/deploy-control-plane.sh).
