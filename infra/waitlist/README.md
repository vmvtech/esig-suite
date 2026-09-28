---
type: reference
title: Waitlist Intake and Notification Pipeline
created: 2026-09-28
tags:
  - esig
  - waitlist
  - infrastructure
related:
  - '[[GAPS-AND-TODOS]]'
  - '[[90-day-playbook]]'
---

# Waitlist intake and notification pipeline

The waitlist API accepts pricing-form submissions and persists them through the [Lambda handler](src/handler.js). For production submissions, the handler writes the submission and a metadata-only notification outbox row in one conditional DynamoDB transaction, so neither half can be acknowledged alone.

When explicitly enabled after the deployment preflight, the outbox table's DynamoDB stream invokes the [notifier](src/notifier.js); the mapping is disabled by default in [`template.yaml`](template.yaml). The notifier validates the exact outbox shape and forwards an idempotent `waitlist.submitted` event to the approved cross-account SQS FIFO broker. The broker payload contains the opaque submission ID and sales metadata but not the submitter's email address.

> [!IMPORTANT]
> No confirmation email is sent to the submitter today. Double opt-in, the signed verification link, and submitter email delivery are deferred to GAPS-05 MSG-05 in [`docs/GAPS-AND-TODOS.md`](../../docs/GAPS-AND-TODOS.md).

## Infrastructure and deployment

[`template.yaml`](template.yaml) defines the API, DynamoDB submission and outbox tables, Lambda functions, stream mapping, retention settings, and broker permissions. [`scripts/deploy.sh`](scripts/deploy.sh) packages that template and keeps reader/notifier activation behind its explicit preflight checks; change-set execution is opt-in.

Run the workspace tests from the repository root:

```bash
npm run test -w @e-sig/waitlist-api
```

The workspace name and test command come from [`package.json`](package.json).

## Smoke submissions

Use only `@example.com` addresses for smoke submissions. [`src/handler.js`](src/handler.js) classifies that domain as `smoke_test`, applies the short smoke-test retention window, and does not create a production notification outbox row. Production submissions use the normal retention class and metadata-only outbox path.
