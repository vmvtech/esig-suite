import { describe, expect, expectTypeOf, it } from "vitest";

import {
  DEDICATED_OFFER,
  PLAN_CATALOG,
  PROVISIONING_STEPS,
  SafeProvisioningError,
  deterministicJobId,
  deterministicTenantId,
  sanitizeProvisioningError,
  type DeploymentMode,
  type NormalizedStripeEvent,
  type PlanId,
} from "../src/domain.js";
import {
  completeProvisioningStep,
  createProvisioningJob,
  failProvisioningAttempt,
  reduceBillingEvent,
  startProvisioningAttempt,
} from "../src/state-machine.js";

const digest = (character: string): string => character.repeat(64);

const checkoutEvent = (
  overrides: Partial<NormalizedStripeEvent> = {},
): NormalizedStripeEvent => ({
  eventId: "evt_checkout",
  type: "checkout.session.completed",
  createdAt: 100,
  payloadDigest: digest("a"),
  subscriptionId: "sub_checkout",
  customerId: "cus_checkout",
  ownerSubject: "owner_checkout",
  mode: "shared",
  plan: "team",
  ...overrides,
} as NormalizedStripeEvent);

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length < 2) return [Array.from(values)];

  return values.flatMap((value, index) =>
    permutations(values.filter((_, candidate) => candidate !== index)).map(
      (tail) => [value, ...tail],
    ),
  );
}

describe("commercial domain", () => {
  it("locks the accepted shared plan limits and support-backed prices", () => {
    expect(PLAN_CATALOG).toEqual({
      starter: {
        id: "starter",
        monthlyPriceCents: 7_900,
        includedEnvelopes: 100,
        includedUsers: 1,
      },
      team: {
        id: "team",
        monthlyPriceCents: 19_900,
        includedEnvelopes: 500,
        includedUsers: 5,
      },
      scale: {
        id: "scale",
        monthlyPriceCents: 49_900,
        includedEnvelopes: 1_500,
        includedUsers: 15,
      },
    });
    expect(DEDICATED_OFFER).toEqual({
      annualPriceCentsFrom: 3_000_000,
      setupFeeCents: 500_000,
      includedEnvelopes: 1_500,
      includedUsers: "contract",
    });
    expectTypeOf<PlanId>().toEqualTypeOf<"starter" | "team" | "scale">();
    expectTypeOf<DeploymentMode>().toEqualTypeOf<"shared" | "dedicated">();
  });

  it("derives stable opaque tenant and job identifiers without exposing Stripe IDs", () => {
    const shared = deterministicTenantId("sub_sensitive_123", "shared");
    const dedicated = deterministicTenantId("sub_sensitive_123", "dedicated");
    const job = deterministicJobId("sub_sensitive_123");

    expect(shared).toBe(deterministicTenantId("sub_sensitive_123", "shared"));
    expect(shared).toMatch(
      /^[a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
    );
    expect(dedicated).toMatch(
      /^[a-f0-9]{8}-[a-f0-9]{4}-5[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
    );
    expect(job).toMatch(/^job_[a-f0-9]{24}$/);
    expect(shared).not.toBe(dedicated);
    expect(`${shared}${dedicated}${job}`).not.toContain("sub_sensitive_123");
  });
});

describe("billing reducer", () => {
  it("converges for every relevant event permutation", () => {
    const events: readonly NormalizedStripeEvent[] = [
      checkoutEvent(),
      {
        eventId: "evt_failed",
        type: "invoice.payment_failed",
        createdAt: 110,
        payloadDigest: digest("b"),
        subscriptionId: "sub_checkout",
      },
      {
        eventId: "evt_paid",
        type: "invoice.paid",
        createdAt: 120,
        payloadDigest: digest("c"),
        subscriptionId: "sub_checkout",
      },
      {
        eventId: "evt_deleted",
        type: "customer.subscription.deleted",
        createdAt: 130,
        payloadDigest: digest("d"),
        subscriptionId: "sub_checkout",
      },
      {
        eventId: "evt_refunded",
        type: "charge.refunded",
        createdAt: 140,
        payloadDigest: digest("e"),
        subscriptionId: "sub_checkout",
      },
    ];

    const finalOrders = permutations(events).map((orderedEvents) =>
      orderedEvents.reduce(
        (order, event) => reduceBillingEvent(order, event).order,
        undefined as ReturnType<typeof reduceBillingEvent>["order"],
      ),
    );

    for (const order of finalOrders) {
      expect(order).toMatchObject({
        subscriptionId: "sub_checkout",
        customerId: "cus_checkout",
        ownerSubject: "owner_checkout",
        mode: "shared",
        plan: "team",
        billingState: "refunded",
        latestEventCreatedAt: 140,
      });
    }
  });

  it("lets stale events fill missing identifiers without regressing billing", () => {
    const paid = reduceBillingEvent(undefined, {
      eventId: "evt_paid_first",
      type: "invoice.paid",
      createdAt: 200,
      payloadDigest: digest("f"),
      subscriptionId: "sub_stale",
    }).order;

    const reduced = reduceBillingEvent(
      paid,
      checkoutEvent({
        eventId: "evt_checkout_stale",
        createdAt: 100,
        subscriptionId: "sub_stale",
        customerId: "cus_filled",
        ownerSubject: "owner_filled",
        mode: "dedicated",
        plan: "scale",
      }),
    );

    expect(reduced.disposition).toBe("stale_metadata_filled");
    expect(reduced.order).toMatchObject({
      billingState: "active",
      customerId: "cus_filled",
      ownerSubject: "owner_filled",
      mode: "dedicated",
      plan: "scale",
      latestEventCreatedAt: 200,
    });
  });

  it("never resurrects canceled or refunded subscriptions", () => {
    const canceled = reduceBillingEvent(undefined, {
      eventId: "evt_cancel",
      type: "customer.subscription.deleted",
      createdAt: 100,
      payloadDigest: digest("1"),
      subscriptionId: "sub_terminal",
    }).order;
    const canceledThenNewerPaid = reduceBillingEvent(canceled, {
      eventId: "evt_paid_newer",
      type: "invoice.paid",
      createdAt: 500,
      payloadDigest: digest("2"),
      subscriptionId: "sub_terminal",
    }).order;
    const refunded = reduceBillingEvent(canceledThenNewerPaid, {
      eventId: "evt_refund_older",
      type: "charge.refunded",
      createdAt: 50,
      payloadDigest: digest("3"),
      subscriptionId: "sub_terminal",
    }).order;
    const refundedThenActive = reduceBillingEvent(refunded, {
      eventId: "evt_active_latest",
      type: "customer.subscription.updated",
      createdAt: 1_000,
      payloadDigest: digest("4"),
      subscriptionId: "sub_terminal",
      billingState: "active",
    }).order;

    expect(canceledThenNewerPaid?.billingState).toBe("canceled");
    expect(refunded?.billingState).toBe("refunded");
    expect(refundedThenActive?.billingState).toBe("refunded");
  });
});

describe("provisioning job state machine", () => {
  it("enforces ordered, idempotent checkpoints and reaches ready", () => {
    const order = reduceBillingEvent(undefined, {
      eventId: "evt_ready",
      type: "invoice.paid",
      createdAt: 100,
      payloadDigest: digest("5"),
      subscriptionId: "sub_ready",
      customerId: "cus_ready",
      ownerSubject: "owner_ready",
      mode: "shared",
      plan: "starter",
    }).order;
    if (!order) throw new Error("test fixture did not create an order");

    let job = startProvisioningAttempt(
      createProvisioningJob(order, {
        maxAttempts: 3,
        baseDelayMs: 100,
        maxDelayMs: 250,
      }),
      0,
    );

    expect(() => completeProvisioningStep(job, PROVISIONING_STEPS[1])).toThrow(
      "INVALID_STEP_ORDER",
    );

    for (const step of PROVISIONING_STEPS) {
      job = completeProvisioningStep(job, step);
      expect(completeProvisioningStep(job, step)).toEqual(job);
    }

    expect(job.state).toBe("ready");
    expect(job.completedSteps).toEqual(PROVISIONING_STEPS);
  });

  it("uses bounded exponential retry delays and stops at max attempts", () => {
    const order = reduceBillingEvent(undefined, {
      eventId: "evt_retry",
      type: "invoice.paid",
      createdAt: 100,
      payloadDigest: digest("6"),
      subscriptionId: "sub_retry",
      customerId: "cus_retry",
      ownerSubject: "owner_retry",
      mode: "dedicated",
      plan: "scale",
    }).order;
    if (!order) throw new Error("test fixture did not create an order");
    const policy = { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 150 };

    let job = startProvisioningAttempt(createProvisioningJob(order, policy), 0);
    job = failProvisioningAttempt(
      job,
      { code: "PROVIDER_UNAVAILABLE", retryable: true },
      1_000,
    );
    expect(job).toMatchObject({
      state: "failed",
      attempt: 1,
      nextRetryAt: 1_100,
      retryExhausted: false,
    });

    job = startProvisioningAttempt(job, 1_100);
    job = failProvisioningAttempt(
      job,
      { code: "PROVIDER_UNAVAILABLE", retryable: true },
      2_000,
    );
    expect(job.nextRetryAt).toBe(2_150);

    job = startProvisioningAttempt(job, 2_150);
    job = failProvisioningAttempt(
      job,
      { code: "PROVIDER_UNAVAILABLE", retryable: true },
      3_000,
    );
    expect(job).toMatchObject({
      state: "failed",
      attempt: 3,
      retryExhausted: true,
      lastErrorCode: "PROVIDER_UNAVAILABLE",
    });
    expect(job.nextRetryAt).toBeUndefined();
  });

  it("persists only allow-listed safe error codes", () => {
    const unknown = sanitizeProvisioningError(
      new Error("provider leaked sk_live_do-not-persist"),
    );
    const known = sanitizeProvisioningError(
      new SafeProvisioningError("PROVIDER_UNAVAILABLE", true),
    );
    const forged = sanitizeProvisioningError({
      safeCode: "sk_live_forged",
      retryable: true,
      message: "secret provider response",
    });

    expect(unknown).toEqual({ code: "UNEXPECTED_FAILURE", retryable: false });
    expect(known).toEqual({ code: "PROVIDER_UNAVAILABLE", retryable: true });
    expect(forged).toEqual({ code: "UNEXPECTED_FAILURE", retryable: false });
    expect(JSON.stringify({ unknown, known, forged })).not.toContain("sk_live");
  });

  it("rejects malformed normalized events and unsupported dedicated tiers safely", () => {
    expect(() =>
      reduceBillingEvent(undefined, {
        ...checkoutEvent(),
        payloadDigest: "not-a-sha256",
      }),
    ).toThrow("INVALID_EVENT");

    const unsupportedDedicatedOrder = reduceBillingEvent(undefined, {
      eventId: "evt_dedicated_starter",
      type: "invoice.paid",
      createdAt: 100,
      payloadDigest: digest("7"),
      subscriptionId: "sub_dedicated_starter",
      customerId: "cus_dedicated_starter",
      ownerSubject: "owner_dedicated_starter",
      mode: "dedicated",
      plan: "starter",
    }).order;
    if (!unsupportedDedicatedOrder) {
      throw new Error("test fixture did not create an order");
    }

    expect(() => createProvisioningJob(unsupportedDedicatedOrder)).toThrow(
      "INVALID_ORDER",
    );
  });
});
