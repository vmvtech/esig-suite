import type { SQSEvent, SQSBatchResponse, SQSRecord } from "aws-lambda";

import {
  ACCEPTED_STRIPE_EVENT_TYPES,
  BILLING_STATES,
  DEPLOYMENT_MODES,
  PLAN_CATALOG,
  type DeploymentMode,
  type NormalizedStripeEvent,
  type OneTimeCredentialHandoff,
  type ProvisioningDriver,
} from "../domain.js";
import type { ProvisioningStore } from "../memory-store.js";
import {
  processClaimedStripeEvent,
  runProvisioningJob,
} from "../orchestrator.js";

export interface ProvisioningWorkerDependencies {
  readonly store: ProvisioningStore;
  /**
   * Deployment composition seam. The deployer must resolve an idempotent pure
   * driver for the persisted order mode, normally using cached secret
   * references and provider adapters outside this handler. No provider-secret
   * JSON shape is invented or parsed here.
   */
  readonly driverFor: (
    mode: DeploymentMode,
  ) => ProvisioningDriver | Promise<ProvisioningDriver>;
  /** Required for any driver that can create a one-time plaintext credential. */
  readonly credentialHandoff?: OneTimeCredentialHandoff;
  readonly now?: () => number;
}

export type ProvisioningWorkerHandler = (
  event: SQSEvent,
) => Promise<SQSBatchResponse>;

interface StripeEventQueueEnvelope {
  readonly version: 1;
  readonly kind: "stripe-event";
  readonly event: AcceptedNormalizedStripeEvent;
}

type AcceptedNormalizedStripeEvent = Exclude<
  NormalizedStripeEvent,
  { readonly type: "ignored" }
>;

/**
 * Compose this factory only after runtime provider credentials and drivers
 * have an explicit deployment contract. It imports and invokes the pure
 * orchestrator; AWS SDK and provider construction remain adapter concerns.
 */
export function createProvisioningWorkerHandler(
  dependencies: ProvisioningWorkerDependencies,
): ProvisioningWorkerHandler {
  const now = dependencies.now ?? Date.now;

  return async (event) => {
    const batchItemFailures: SQSBatchResponse["batchItemFailures"] = [];

    for (let index = 0; index < event.Records.length; index += 1) {
      const record = event.Records[index]!;
      try {
        await processRecord(record, dependencies, now);
      } catch {
        // Stop at the first FIFO failure. Returning this record and every later
        // record prevents Lambda from acknowledging work out of queue order if
        // the deployment batch size is raised above one.
        batchItemFailures.push(
          ...event.Records.slice(index).map((failedRecord) => ({
            itemIdentifier: failedRecord.messageId,
          })),
        );
        break;
      }
    }

    return { batchItemFailures };
  };
}

async function processRecord(
  record: SQSRecord,
  dependencies: ProvisioningWorkerDependencies,
  now: () => number,
): Promise<void> {
  const event = parseQueueEnvelope(record.body).event;
  const transition = await processClaimedStripeEvent(dependencies.store, event);

  if (transition.status === "ignored" || transition.job === undefined) return;

  const order = transition.order ?? (await dependencies.store.getOrder(event.subscriptionId));
  if (order?.mode === undefined) throw new Error("PROVISIONING_ORDER_NOT_FOUND");

  const driver = await dependencies.driverFor(order.mode);
  const result = await runProvisioningJob({
    store: dependencies.store,
    driver,
    subscriptionId: event.subscriptionId,
    now: now(),
    ...(dependencies.credentialHandoff === undefined
      ? {}
      : { credentialHandoff: dependencies.credentialHandoff }),
  });

  if (result.status !== "ready" && result.status !== "disabled") {
    throw new Error(`PROVISIONING_${result.status.toUpperCase()}`);
  }
}

function parseQueueEnvelope(body: string): StripeEventQueueEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    throw new Error("INVALID_QUEUE_MESSAGE");
  }

  if (!isRecord(value) || value.version !== 1 || value.kind !== "stripe-event") {
    throw new Error("INVALID_QUEUE_MESSAGE");
  }
  if (!isNormalizedAcceptedEvent(value.event)) {
    throw new Error("INVALID_QUEUE_MESSAGE");
  }

  return value as unknown as StripeEventQueueEnvelope;
}

function isNormalizedAcceptedEvent(
  value: unknown,
): value is AcceptedNormalizedStripeEvent {
  if (!isRecord(value)) return false;
  if (
    typeof value.eventId !== "string" ||
    value.eventId.length === 0 ||
    typeof value.createdAt !== "number" ||
    !Number.isSafeInteger(value.createdAt) ||
    value.createdAt < 0 ||
    typeof value.payloadDigest !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.payloadDigest) ||
    typeof value.subscriptionId !== "string" ||
    value.subscriptionId.length === 0 ||
    !isOneOf(value.type, ACCEPTED_STRIPE_EVENT_TYPES)
  ) {
    return false;
  }

  if (!optionalString(value.customerId) || !optionalString(value.ownerSubject)) {
    return false;
  }
  if (value.mode !== undefined && !isOneOf(value.mode, DEPLOYMENT_MODES)) {
    return false;
  }
  if (
    value.plan !== undefined &&
    (typeof value.plan !== "string" || !Object.hasOwn(PLAN_CATALOG, value.plan))
  ) {
    return false;
  }

  const needsBillingState =
    value.type === "customer.subscription.created" ||
    value.type === "customer.subscription.updated";
  if (needsBillingState) {
    return (
      value.billingState !== "refunded" &&
      isOneOf(value.billingState, BILLING_STATES)
    );
  }
  return value.billingState === undefined;
}

function optionalString(value: unknown): boolean {
  return value === undefined || (typeof value === "string" && value.length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isOneOf<const Value extends string>(
  value: unknown,
  allowed: readonly Value[],
): value is Value {
  return typeof value === "string" && allowed.includes(value as Value);
}

/**
 * Deliberately non-operational Lambda entrypoint. Until deployment code binds
 * createProvisioningWorkerHandler to a Dynamo store and provider driverFor
 * implementation, every record is retained for retry/DLQ and no external call
 * is attempted. This prevents a partially configured deploy from acknowledging
 * paid orders or guessing a secret schema.
 */
export const handler: ProvisioningWorkerHandler = async (event) => ({
  batchItemFailures: event.Records.map((record) => ({
    itemIdentifier: record.messageId,
  })),
});

// Ship the explicitly configured composition factory in the worker artifact
// without installing it as the Lambda handler. This embeds the exact dedicated
// migration sources while preserving the fail-closed default export above.
export {
  createProvisioningRuntime,
  type ProvisioningRuntime,
  type ProvisioningRuntimeConfig,
} from "../runtime.js";
