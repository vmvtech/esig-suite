import {
  DEFAULT_RETRY_POLICY,
  PROVISIONING_STEPS,
  SafeProvisioningError,
  assertRetryPolicy,
  deterministicJobId,
  deterministicTenantId,
  isProvisionableOrder,
  type BillingState,
  type EventCursor,
  type NormalizedStripeEvent,
  type OrderRecord,
  type ProvisioningJob,
  type ProvisioningStep,
  type RetryPolicy,
  type SafeFailure,
} from "./domain.js";

export type BillingReductionDisposition =
  | "ignored"
  | "created"
  | "applied"
  | "stale"
  | "stale_metadata_filled"
  | "terminal_preserved";

export interface BillingReduction {
  readonly disposition: BillingReductionDisposition;
  readonly order: OrderRecord | undefined;
}

const STATE_PRECEDENCE: Readonly<Record<BillingState, number>> = {
  pending: 1,
  active: 2,
  past_due: 3,
  canceled: 4,
  refunded: 5,
};

function desiredBillingState(event: NormalizedStripeEvent): BillingState | undefined {
  switch (event.type) {
    case "ignored":
      return undefined;
    case "checkout.session.completed":
      return "pending";
    case "invoice.paid":
      return "active";
    case "invoice.payment_failed":
      return "past_due";
    case "customer.subscription.created":
    case "customer.subscription.updated":
      return event.billingState;
    case "customer.subscription.deleted":
      return "canceled";
    case "charge.refunded":
      return "refunded";
  }
}

function validateEvent(event: NormalizedStripeEvent): void {
  if (
    event.eventId.length === 0 ||
    !Number.isSafeInteger(event.createdAt) ||
    event.createdAt < 0 ||
    !/^[a-f0-9]{64}$/.test(event.payloadDigest) ||
    (event.type !== "ignored" && event.subscriptionId.length === 0)
  ) {
    throw new SafeProvisioningError("INVALID_EVENT");
  }
}

function compareCursor(left: EventCursor, right: EventCursor): number {
  if (left.createdAt !== right.createdAt) {
    return left.createdAt - right.createdAt;
  }
  if (left.precedence !== right.precedence) {
    return left.precedence - right.precedence;
  }
  return left.eventId.localeCompare(right.eventId);
}

function eventCursor(
  event: Exclude<NormalizedStripeEvent, { readonly type: "ignored" }>,
  state: BillingState,
): EventCursor {
  return {
    createdAt: event.createdAt,
    precedence: STATE_PRECEDENCE[state],
    eventId: event.eventId,
  };
}

function isLatestAcceptedEvent(
  current: OrderRecord,
  event: Exclude<NormalizedStripeEvent, { readonly type: "ignored" }>,
): boolean {
  return (
    event.createdAt > current.latestEventCreatedAt ||
    (event.createdAt === current.latestEventCreatedAt &&
      event.eventId.localeCompare(current.latestEventId) > 0)
  );
}

function mergeMetadata(
  current: OrderRecord,
  event: Exclude<NormalizedStripeEvent, { readonly type: "ignored" }>,
  mayReplacePlan: boolean,
): Pick<OrderRecord, "customerId" | "ownerSubject" | "mode" | "plan"> {
  return {
    // Subscription identity and deployment topology are immutable once known.
    customerId: current.customerId ?? event.customerId,
    ownerSubject: current.ownerSubject ?? event.ownerSubject,
    mode: current.mode ?? event.mode,
    plan:
      mayReplacePlan && event.plan !== undefined
        ? event.plan
        : current.plan ?? event.plan,
  };
}

function metadataWasFilled(current: OrderRecord, next: OrderRecord): boolean {
  return (
    (current.customerId === undefined && next.customerId !== undefined) ||
    (current.ownerSubject === undefined && next.ownerSubject !== undefined) ||
    (current.mode === undefined && next.mode !== undefined) ||
    (current.plan === undefined && next.plan !== undefined)
  );
}

/**
 * Reduces one already-verified, normalized event. Terminal states dominate
 * timestamps, which makes delivery permutations converge and prevents a later
 * active event from resurrecting a canceled or refunded subscription.
 */
export function reduceBillingEvent(
  current: OrderRecord | undefined,
  event: NormalizedStripeEvent,
): BillingReduction {
  validateEvent(event);
  const desired = desiredBillingState(event);
  if (event.type === "ignored" || desired === undefined) {
    return { disposition: "ignored", order: current };
  }

  const cursor = eventCursor(event, desired);
  if (current === undefined) {
    return {
      disposition: "created",
      order: {
        version: 0,
        subscriptionId: event.subscriptionId,
        customerId: event.customerId,
        ownerSubject: event.ownerSubject,
        mode: event.mode,
        plan: event.plan,
        billingState: desired,
        latestEventCreatedAt: event.createdAt,
        latestEventId: event.eventId,
        stateCursor: cursor,
      },
    };
  }

  if (current.subscriptionId !== event.subscriptionId) {
    throw new SafeProvisioningError("INVALID_EVENT");
  }

  const acceptedIsLatest = isLatestAcceptedEvent(current, event);
  const currentIsTerminal =
    current.billingState === "canceled" || current.billingState === "refunded";
  const desiredIsTerminal = desired === "canceled" || desired === "refunded";
  const metadata = mergeMetadata(
    current,
    event,
    acceptedIsLatest && !currentIsTerminal && !desiredIsTerminal,
  );
  let billingState = current.billingState;
  let stateCursor = current.stateCursor;
  let terminalPreserved = false;

  if (current.billingState === "refunded") {
    terminalPreserved = desired !== "refunded";
  } else if (desired === "refunded") {
    billingState = "refunded";
    stateCursor = cursor;
  } else if (current.billingState === "canceled") {
    terminalPreserved = desired !== "canceled";
  } else if (desired === "canceled") {
    billingState = "canceled";
    stateCursor = cursor;
  } else if (compareCursor(cursor, current.stateCursor) > 0) {
    billingState = desired;
    stateCursor = cursor;
  }

  const next: OrderRecord = {
    ...current,
    ...metadata,
    billingState,
    stateCursor,
    latestEventCreatedAt: acceptedIsLatest
      ? event.createdAt
      : current.latestEventCreatedAt,
    latestEventId: acceptedIsLatest ? event.eventId : current.latestEventId,
  };

  if (terminalPreserved) {
    return { disposition: "terminal_preserved", order: next };
  }
  if (!acceptedIsLatest && metadataWasFilled(current, next)) {
    return { disposition: "stale_metadata_filled", order: next };
  }
  if (!acceptedIsLatest && compareCursor(cursor, current.stateCursor) <= 0) {
    return { disposition: "stale", order: next };
  }
  return { disposition: "applied", order: next };
}

export function createProvisioningJob(
  order: OrderRecord,
  retryPolicy: RetryPolicy = DEFAULT_RETRY_POLICY,
): ProvisioningJob {
  assertRetryPolicy(retryPolicy);
  if (!isProvisionableOrder(order)) {
    throw new SafeProvisioningError("INVALID_ORDER");
  }

  return {
    version: 0,
    jobId: deterministicJobId(order.subscriptionId),
    subscriptionId: order.subscriptionId,
    tenantId: deterministicTenantId(order.subscriptionId, order.mode),
    activationGeneration: 0,
    state: "queued",
    operation: "provisioning",
    completedSteps: [],
    compensatedSteps: [],
    attempt: 0,
    retryPolicy: { ...retryPolicy },
    retryExhausted: false,
  };
}

function validTime(value: number): boolean {
  return Number.isFinite(value) && value >= 0;
}

export function startProvisioningAttempt(
  job: ProvisioningJob,
  now: number,
): ProvisioningJob {
  if (!validTime(now)) {
    throw new SafeProvisioningError("INVALID_STATE");
  }
  if (job.state === "running") return job;
  if (job.state === "compensating" && job.attempt > 0) return job;
  if (job.state === "ready" || job.state === "disabled") {
    throw new SafeProvisioningError("INVALID_STATE");
  }
  if (
    job.state === "failed" &&
    (job.retryExhausted ||
      job.nextRetryAt === undefined ||
      now < job.nextRetryAt)
  ) {
    throw new SafeProvisioningError("INVALID_STATE");
  }

  return {
    ...job,
    state: job.operation === "provisioning" ? "running" : "compensating",
    attempt: job.attempt + 1,
    retryExhausted: false,
    nextRetryAt: undefined,
    lastErrorCode: undefined,
  };
}

export function nextProvisioningStep(
  job: ProvisioningJob,
): ProvisioningStep | undefined {
  return PROVISIONING_STEPS[job.completedSteps.length];
}

export function completeProvisioningStep(
  job: ProvisioningJob,
  step: ProvisioningStep,
): ProvisioningJob {
  if (job.completedSteps.includes(step)) return job;
  if (
    job.state !== "running" ||
    job.operation !== "provisioning" ||
    nextProvisioningStep(job) !== step
  ) {
    throw new SafeProvisioningError("INVALID_STEP_ORDER");
  }

  const completedSteps = [...job.completedSteps, step];
  return {
    ...job,
    completedSteps,
    state:
      completedSteps.length === PROVISIONING_STEPS.length ? "ready" : "running",
  };
}

export function retryDelayMs(job: ProvisioningJob): number {
  const exponent = Math.max(0, Math.min(job.attempt - 1, 30));
  return Math.min(
    job.retryPolicy.maxDelayMs,
    job.retryPolicy.baseDelayMs * 2 ** exponent,
  );
}

export function failProvisioningAttempt(
  job: ProvisioningJob,
  failure: SafeFailure,
  now: number,
): ProvisioningJob {
  if (
    !validTime(now) ||
    (job.state !== "running" && job.state !== "compensating") ||
    job.attempt < 1
  ) {
    throw new SafeProvisioningError("INVALID_STATE");
  }

  const canRetry = failure.retryable && job.attempt < job.retryPolicy.maxAttempts;
  return {
    ...job,
    state: "failed",
    lastErrorCode: failure.code,
    retryExhausted: !canRetry,
    nextRetryAt: canRetry ? now + retryDelayMs(job) : undefined,
  };
}

export function beginCompensation(
  job: ProvisioningJob,
  observedResourceSteps: readonly ProvisioningStep[] = [],
  operation: "suspension" | "compensation" = "compensation",
): ProvisioningJob {
  const furthestObservedIndex = [...job.completedSteps, ...observedResourceSteps]
    .map((step) => PROVISIONING_STEPS.indexOf(step))
    .reduce((furthest, index) => Math.max(furthest, index), -1);
  const completedSteps = PROVISIONING_STEPS.slice(0, furthestObservedIndex + 1);

  if (job.operation === operation) {
    const discoveredNewEffects = completedSteps.some(
      (step) => !job.completedSteps.includes(step),
    );
    if (!discoveredNewEffects) return job;
    const fullyCompensated = completedSteps.every((step) =>
      job.compensatedSteps.includes(step),
    );
    return {
      ...job,
      completedSteps,
      state: fullyCompensated ? "disabled" : "compensating",
      attempt: 0,
      retryExhausted: false,
      nextRetryAt: undefined,
      lastErrorCode: undefined,
    };
  }

  if (completedSteps.length === 0) {
    return {
      ...job,
      state: "disabled",
      operation,
      attempt: 0,
      retryExhausted: false,
      nextRetryAt: undefined,
      lastErrorCode: undefined,
    };
  }

  return {
    ...job,
    state: "compensating",
    operation,
    completedSteps,
    compensatedSteps: [],
    attempt: 0,
    retryExhausted: false,
    nextRetryAt: undefined,
    lastErrorCode: undefined,
  };
}

export function nextCompensationStep(
  job: ProvisioningJob,
): ProvisioningStep | undefined {
  return [...job.completedSteps]
    .reverse()
    .find((step) => !job.compensatedSteps.includes(step));
}

export function completeCompensationStep(
  job: ProvisioningJob,
  step: ProvisioningStep,
): ProvisioningJob {
  if (job.compensatedSteps.includes(step)) return job;
  if (
    job.state !== "compensating" ||
    job.operation === "provisioning" ||
    nextCompensationStep(job) !== step
  ) {
    throw new SafeProvisioningError("INVALID_STEP_ORDER");
  }

  const compensatedSteps = [...job.compensatedSteps, step];
  const fullyCompensated = job.completedSteps.every((completedStep) =>
    compensatedSteps.includes(completedStep),
  );
  return {
    ...job,
    compensatedSteps,
    state: fullyCompensated ? "disabled" : "compensating",
  };
}

/** Starts a distinct paid activation while retaining the same tenant identity. */
export function resumeProvisioningJob(job: ProvisioningJob): ProvisioningJob {
  if (job.operation !== "suspension") {
    throw new SafeProvisioningError("INVALID_STATE");
  }
  return {
    ...job,
    activationGeneration: (job.activationGeneration ?? 0) + 1,
    state: "queued",
    operation: "provisioning",
    completedSteps: [],
    compensatedSteps: [],
    attempt: 0,
    retryExhausted: false,
    nextRetryAt: undefined,
    lastErrorCode: undefined,
  };
}
