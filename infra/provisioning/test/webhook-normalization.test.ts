import type Stripe from "stripe";
import { describe, expect, it } from "vitest";

import { normalizeStripeEvent } from "../src/handlers/normalize-stripe-event.js";

describe("Stripe event normalization", () => {
  it("extracts only provisioning metadata from a paid invoice", () => {
    const event = stripeEvent("invoice.paid", {
      parent: { subscription_details: { subscription: "sub_123" } },
      customer: "cus_123",
      metadata: {
        owner_subject: "owner_123",
        deployment_mode: "dedicated",
        plan: "scale",
      },
      customer_email: "must-not-enter-queue@example.test",
      payment_intent: "pi_secret_payment_object",
    });

    const normalized = normalizeStripeEvent(event, "a".repeat(64));

    expect(normalized).toEqual({
      eventId: "evt_123",
      type: "invoice.paid",
      createdAt: 1_785_844_800,
      payloadDigest: "a".repeat(64),
      subscriptionId: "sub_123",
      customerId: "cus_123",
      ownerSubject: "owner_123",
      mode: "dedicated",
      plan: "scale",
    });
    expect(JSON.stringify(normalized)).not.toContain("customer_email");
    expect(JSON.stringify(normalized)).not.toContain("payment_intent");
  });

  it("maps subscription status to the domain billing state", () => {
    const normalized = normalizeStripeEvent(
      stripeEvent("customer.subscription.updated", {
        id: "sub_123",
        customer: "cus_123",
        status: "past_due",
        metadata: {},
      }),
      "b".repeat(64),
    );

    expect(normalized).toMatchObject({
      type: "customer.subscription.updated",
      subscriptionId: "sub_123",
      billingState: "past_due",
    });
  });

  it("acknowledges unknown or malformed accepted events as ignored", () => {
    expect(
      normalizeStripeEvent(stripeEvent("payment_intent.succeeded", {}), "c".repeat(64)),
    ).toMatchObject({ type: "ignored", originalType: "payment_intent.succeeded" });
    expect(
      normalizeStripeEvent(stripeEvent("invoice.paid", {}), "d".repeat(64)),
    ).toMatchObject({ type: "ignored", originalType: "invoice.paid" });
  });
});

function stripeEvent(type: string, object: Record<string, unknown>): Stripe.Event {
  return {
    id: "evt_123",
    object: "event",
    api_version: "2026-07-29.basil",
    created: 1_785_844_800,
    data: { object },
    livemode: false,
    pending_webhooks: 1,
    request: null,
    type,
  } as unknown as Stripe.Event;
}
