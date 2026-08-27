import type Stripe from "stripe";

import {
  ACCEPTED_STRIPE_EVENT_TYPES,
  type BillingState,
  type DeploymentMode,
  type NormalizedStripeEvent,
  type PlanId,
} from "../domain.js";

const acceptedTypes: ReadonlySet<string> = new Set(ACCEPTED_STRIPE_EVENT_TYPES);

export function normalizeStripeEvent(
  event: Stripe.Event,
  payloadDigest: string,
): NormalizedStripeEvent {
  const object = asRecord(event.data.object);
  const metadata = asRecord(object.metadata);
  const subscriptionId = resolveSubscriptionId(event.type, object, metadata);
  const base = {
    eventId: event.id,
    createdAt: event.created,
    payloadDigest,
  } as const;

  if (!acceptedTypes.has(event.type) || subscriptionId === undefined) {
    return {
      ...base,
      type: "ignored",
      originalType: event.type,
      ...optional("subscriptionId", subscriptionId),
    };
  }

  const customerId = identifier(object.customer) ?? stringValue(metadata.customer_id);
  const ownerSubject =
    stringValue(metadata.owner_subject) ?? stringValue(metadata.ownerSubject);
  const mode = deploymentMode(metadata.deployment_mode ?? metadata.mode);
  const plan = planId(metadata.plan ?? metadata.plan_id);
  const order = {
    subscriptionId,
    ...optional("customerId", customerId),
    ...optional("ownerSubject", ownerSubject),
    ...optional("mode", mode),
    ...optional("plan", plan),
  };

  switch (event.type) {
    case "customer.subscription.created":
    case "customer.subscription.updated":
      return {
        ...base,
        ...order,
        type: event.type,
        billingState: subscriptionBillingState(stringValue(object.status)),
      };
    case "checkout.session.completed":
    case "invoice.paid":
    case "invoice.payment_failed":
    case "customer.subscription.deleted":
    case "charge.refunded":
      return { ...base, ...order, type: event.type };
    default:
      return {
        ...base,
        type: "ignored",
        originalType: event.type,
        ...optional("subscriptionId", subscriptionId),
      };
  }
}

function resolveSubscriptionId(
  eventType: string,
  object: Record<string, unknown>,
  metadata: Record<string, unknown>,
): string | undefined {
  if (eventType.startsWith("customer.subscription.")) {
    return stringValue(object.id);
  }

  return (
    identifier(object.subscription) ??
    identifier(asRecord(asRecord(object.parent).subscription_details).subscription) ??
    stringValue(metadata.subscription_id) ??
    stringValue(metadata.subscriptionId)
  );
}

function subscriptionBillingState(status: string | undefined): Exclude<BillingState, "refunded"> {
  switch (status) {
    case "active":
    case "trialing":
      return "active";
    case "past_due":
    case "paused":
    case "unpaid":
      return "past_due";
    case "canceled":
    case "incomplete_expired":
      return "canceled";
    default:
      return "pending";
  }
}

function deploymentMode(value: unknown): DeploymentMode | undefined {
  return value === "shared" || value === "dedicated" ? value : undefined;
}

function planId(value: unknown): PlanId | undefined {
  return value === "starter" || value === "team" || value === "scale" ? value : undefined;
}

function identifier(value: unknown): string | undefined {
  return stringValue(value) ?? stringValue(asRecord(value).id);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};
}

function optional<Key extends string, Value>(
  key: Key,
  value: Value | undefined,
): { [Property in Key]?: Value } {
  return value === undefined ? {} : ({ [key]: value } as { [Property in Key]: Value });
}
