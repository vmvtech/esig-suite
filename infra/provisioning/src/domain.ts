import { createHash } from "node:crypto";

export const DEPLOYMENT_MODES = ["shared", "dedicated"] as const;
export type DeploymentMode = (typeof DEPLOYMENT_MODES)[number];

export const PLAN_CATALOG = {
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
} as const;

export type PlanId = keyof typeof PLAN_CATALOG;
export type PlanDefinition = (typeof PLAN_CATALOG)[PlanId];

export const DEDICATED_OFFER = {
  annualPriceCentsFrom: 3_000_000,
  setupFeeCents: 500_000,
  includedEnvelopes: 1_500,
  includedUsers: "contract",
} as const;

export const BILLING_STATES = [
  "pending",
  "active",
  "past_due",
  "canceled",
  "refunded",
] as const;
export type BillingState = (typeof BILLING_STATES)[number];
export type NonRefundedBillingState = Exclude<BillingState, "refunded">;

export const PROVISIONING_STATES = [
  "queued",
  "running",
  "ready",
  "failed",
  "compensating",
  "disabled",
] as const;
export type ProvisioningState = (typeof PROVISIONING_STATES)[number];

export const PROVISIONING_STEPS = [
  "resolve_tenant",
  "owner_membership",
  "plan_entitlement",
  "api_credential",
  "storage_namespace",
  "activation_metadata",
  "mark_ready",
] as const;
export type ProvisioningStep = (typeof PROVISIONING_STEPS)[number];

export const ACCEPTED_STRIPE_EVENT_TYPES = [
  "checkout.session.completed",
  "invoice.paid",
  "invoice.payment_failed",
  "customer.subscription.created",
  "customer.subscription.updated",
  "customer.subscription.deleted",
  "charge.refunded",
] as const;
export type AcceptedStripeEventType =
  (typeof ACCEPTED_STRIPE_EVENT_TYPES)[number];

interface NormalizedStripeEventBase {
  readonly eventId: string;
  readonly createdAt: number;
  /** Lowercase SHA-256 of the verified raw request body. */
  readonly payloadDigest: string;
}

interface NormalizedOrderMetadata {
  readonly subscriptionId: string;
  readonly customerId?: string;
  readonly ownerSubject?: string;
  readonly mode?: DeploymentMode;
  readonly plan?: PlanId;
}

type FixedStateStripeEvent = NormalizedStripeEventBase &
  NormalizedOrderMetadata & {
    readonly type: Exclude<
      AcceptedStripeEventType,
      "customer.subscription.created" | "customer.subscription.updated"
    >;
    readonly billingState?: never;
  };

type StatusBearingStripeEvent = NormalizedStripeEventBase &
  NormalizedOrderMetadata & {
    readonly type:
      | "customer.subscription.created"
      | "customer.subscription.updated";
    readonly billingState: NonRefundedBillingState;
  };

export interface IgnoredStripeEvent extends NormalizedStripeEventBase {
  readonly type: "ignored";
  readonly originalType: string;
  readonly subscriptionId?: string;
}

/**
 * Provider-neutral event data produced only after Stripe signature validation.
 * Raw request bodies, payment data, e-mail addresses, and signer data do not
 * belong in this model.
 */
export type NormalizedStripeEvent =
  | FixedStateStripeEvent
  | StatusBearingStripeEvent
  | IgnoredStripeEvent;

export interface EventCursor {
  readonly createdAt: number;
  readonly precedence: number;
  readonly eventId: string;
}

export interface OrderRecord {
  /** Monotonic optimistic-lock token. Stores increment it on every update. */
  readonly version: number;
  readonly subscriptionId: string;
  readonly customerId?: string;
  readonly ownerSubject?: string;
  readonly mode?: DeploymentMode;
  readonly plan?: PlanId;
  readonly billingState: BillingState;
  readonly latestEventCreatedAt: number;
  readonly latestEventId: string;
  /** Cursor of the event that currently determines billingState. */
  readonly stateCursor: EventCursor;
}

export type ProvisioningIdentity = OrderRecord & {
  readonly customerId: string;
  readonly ownerSubject: string;
  readonly mode: DeploymentMode;
  readonly plan: PlanId;
};

export type ProvisionableOrder = ProvisioningIdentity & {
  readonly billingState: "active";
};

export interface RetryPolicy {
  readonly maxAttempts: number;
  readonly baseDelayMs: number;
  readonly maxDelayMs: number;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = Object.freeze({
  maxAttempts: 5,
  baseDelayMs: 1_000,
  maxDelayMs: 60_000,
});

/**
 * A durable, renewable execution lease serializes all effects for one
 * subscription. The fencing token changes on every expired-lease takeover so
 * a stale worker cannot renew or release a newer owner's lease.
 */
export interface JobExecutionLease {
  readonly subscriptionId: string;
  readonly ownerId: string;
  readonly fencingToken: number;
  readonly expiresAt: number;
}

export type JobExecutionLeaseClaimResult =
  | { readonly status: "acquired"; readonly lease: JobExecutionLease }
  | { readonly status: "held" };

// Longer than the control-plane Lambda's five-minute hard timeout. If a
// heartbeat cannot run, Lambda termination still precedes lease takeover.
export const DEFAULT_EXECUTION_LEASE_DURATION_MS = 10 * 60_000;

export type ProvisioningOperation =
  | "provisioning"
  | "suspension"
  | "compensation";

export interface ProvisioningJob {
  /** Monotonic optimistic-lock token. Stores increment it on every update. */
  readonly version: number;
  readonly jobId: string;
  readonly subscriptionId: string;
  readonly tenantId: string;
  /** Increments for every paid recovery so handoff receipts cannot cross activations. */
  readonly activationGeneration?: number;
  readonly state: ProvisioningState;
  readonly operation: ProvisioningOperation;
  readonly completedSteps: readonly ProvisioningStep[];
  readonly compensatedSteps: readonly ProvisioningStep[];
  readonly attempt: number;
  readonly retryPolicy: RetryPolicy;
  readonly retryExhausted: boolean;
  readonly nextRetryAt?: number;
  readonly lastErrorCode?: SafeErrorCode;
}

export interface ProvisioningQueueMessage {
  readonly subscriptionId: string;
  readonly jobId: string;
}

export interface EventClaim {
  readonly eventId: string;
  readonly eventType: string;
  readonly createdAt: number;
  readonly payloadDigest: string;
  readonly subscriptionId?: string;
}

export type EventClaimResult =
  | { readonly status: "claimed"; readonly claim: EventClaim }
  | { readonly status: "duplicate"; readonly claim: EventClaim }
  | { readonly status: "conflict"; readonly claim: EventClaim };

export type MutableResourceStatus =
  | "active"
  | "revoked"
  | "disabled"
  | "quarantined";

export type ResourceRecord =
  | {
      readonly resourceKey: string;
      readonly subscriptionId: string;
      readonly step: ProvisioningStep;
      readonly kind: string;
      readonly opaqueId: string;
      readonly retention: "mutable";
      readonly status: MutableResourceStatus;
    }
  | {
      readonly resourceKey: string;
      readonly subscriptionId: string;
      readonly step: ProvisioningStep;
      readonly kind: string;
      readonly opaqueId: string;
      readonly retention: "immutable_evidence";
      readonly status: "retained";
    };

export interface StepResourceInput {
  readonly kind: string;
  readonly opaqueId: string;
  readonly retention: "mutable" | "immutable_evidence";
}

export interface StepExecutionInput {
  readonly step: ProvisioningStep;
  readonly order: ProvisionableOrder;
  readonly job: ProvisioningJob;
  readonly resources: readonly ResourceRecord[];
  readonly stepResources: readonly ResourceRecord[];
  readonly credentialHandoffCompleted: boolean;
}

export interface StepExecutionResult {
  readonly resources?: readonly StepResourceInput[];
  /** Ephemeral output handed to OneTimeCredentialHandoff; never persisted/logged. */
  readonly oneTimeCredential?: {
    readonly id: string;
    readonly plaintext: string;
  };
}

export interface ResourceDisposition {
  readonly resourceKey: string;
  readonly status: Exclude<MutableResourceStatus, "active">;
}

export interface StepCompensationInput
  extends Omit<StepExecutionInput, "order"> {
  readonly order: ProvisioningIdentity;
}

export interface StepCompensationResult {
  /** Provider lifecycle snapshot created by suspend/terminal-disable effects. */
  readonly resources?: readonly StepResourceInput[];
  readonly dispositions?: readonly ResourceDisposition[];
}

export interface ProvisioningDriver {
  readonly mode: DeploymentMode;
  /** Declare before effects when the API-credential step can emit plaintext. */
  readonly requiresCredentialHandoff?: boolean;
  executeStep(input: StepExecutionInput): Promise<StepExecutionResult>;
  compensateStep(
    input: StepCompensationInput,
  ): Promise<StepCompensationResult>;
}

export interface OneTimeCredentialHandoffInput {
  readonly handoffId: string;
  readonly jobId: string;
  readonly subscriptionId: string;
  readonly activationGeneration: number;
  readonly publicationGeneration: number;
  readonly fencingToken: number;
  readonly credential: {
    readonly id: string;
    readonly plaintext: string;
  };
}

export interface CredentialSecretPublication {
  readonly secretId: string;
  readonly publicationId: string;
  readonly credentialId: string;
}

export type CredentialHandoffState = "pending" | "published" | "revoked";

/** Authoritative publication pointer. It never contains plaintext or a credential hash. */
export interface CredentialHandoffPointer {
  readonly handoffId: string;
  readonly subscriptionId: string;
  readonly jobId: string;
  readonly activationGeneration: number;
  readonly publicationGeneration: number;
  readonly fencingToken: number;
  readonly state: CredentialHandoffState;
  readonly secretId?: string;
  readonly publicationId?: string;
  readonly credentialId?: string;
}

export interface CredentialHandoffMutationInput {
  readonly pointer: CredentialHandoffPointer;
  readonly lease: JobExecutionLease;
  readonly now: number;
}

/**
 * Immutable secret-publication boundary. The durable authoritative pointer is
 * owned by ProvisioningStore; this adapter may only create or verify secrets.
 */
export interface OneTimeCredentialHandoff {
  describePublication(
    input: OneTimeCredentialHandoffInput,
  ): CredentialSecretPublication;
  createImmutable(
    input: OneTimeCredentialHandoffInput,
  ): Promise<CredentialSecretPublication>;
  verifyPublication(pointer: CredentialHandoffPointer): Promise<boolean>;
}

export const SAFE_ERROR_CODES = [
  "INVALID_EVENT",
  "INVALID_ORDER",
  "INVALID_STATE",
  "INVALID_STEP_ORDER",
  "MODE_MISMATCH",
  "STORE_CONFLICT",
  "PROVIDER_UNAVAILABLE",
  "PROVIDER_INVALID_REQUEST",
  "PROVIDER_AUTH_FAILED",
  "PROVIDER_RATE_LIMITED",
  "PROVIDER_CONFLICT",
  "PROVIDER_NOT_FOUND",
  "PROVIDER_TRANSIENT",
  "PROVIDER_TIMEOUT",
  "PROVIDER_RESPONSE_INVALID",
  "PROVIDER_RESOURCE_FAILED",
  "CREDENTIAL_HANDOFF_REQUIRED",
  "CREDENTIAL_REISSUE_REQUIRED",
  "COMPENSATION_FAILED",
  "UNEXPECTED_FAILURE",
] as const;
export type SafeErrorCode = (typeof SAFE_ERROR_CODES)[number];

const safeErrorCodeSet: ReadonlySet<string> = new Set(SAFE_ERROR_CODES);

export interface SafeFailure {
  readonly code: SafeErrorCode;
  readonly retryable: boolean;
}

export class SafeProvisioningError extends Error {
  readonly safeCode: SafeErrorCode;
  readonly code: SafeErrorCode;
  readonly retryable: boolean;

  constructor(code: SafeErrorCode, retryable = false) {
    super(code);
    this.name = "SafeProvisioningError";
    this.safeCode = code;
    this.code = code;
    this.retryable = retryable;
  }
}

export function isSafeErrorCode(value: unknown): value is SafeErrorCode {
  return typeof value === "string" && safeErrorCodeSet.has(value);
}

export function sanitizeProvisioningError(error: unknown): SafeFailure {
  if (error instanceof SafeProvisioningError) {
    return { code: error.safeCode, retryable: error.retryable };
  }

  if (typeof error === "object" && error !== null) {
    const candidate = error as {
      readonly code?: unknown;
      readonly safeCode?: unknown;
      readonly retryable?: unknown;
    };
    const code = isSafeErrorCode(candidate.safeCode)
      ? candidate.safeCode
      : isSafeErrorCode(candidate.code)
        ? candidate.code
        : undefined;
    if (code !== undefined) {
      return { code, retryable: candidate.retryable === true };
    }
  }

  return { code: "UNEXPECTED_FAILURE", retryable: false };
}

function digestIdentifier(namespace: string, value: string): string {
  if (value.length === 0) {
    throw new SafeProvisioningError("INVALID_ORDER");
  }
  return createHash("sha256")
    .update(`e-sig-cloud:v1:${namespace}:${value}`, "utf8")
    .digest("hex")
    .slice(0, 24);
}

export function deterministicTenantId(
  subscriptionId: string,
  mode: DeploymentMode,
): string {
  if (subscriptionId.length === 0) {
    throw new SafeProvisioningError("INVALID_ORDER");
  }
  // Stable private namespace; mode remains part of the name to prevent a
  // shared and dedicated deployment for one subscription from colliding.
  const namespace = Buffer.from(
    "6f5f1dfae2295aeda58b31447728f1c2".replaceAll("-", ""),
    "hex",
  );
  const bytes = createHash("sha1")
    .update(namespace)
    .update(`e-sig-cloud:v1:tenant:${mode}:${subscriptionId}`, "utf8")
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function deterministicJobId(subscriptionId: string): string {
  return `job_${digestIdentifier("job", subscriptionId)}`;
}

export function deterministicResourceKey(
  subscriptionId: string,
  step: ProvisioningStep,
  kind: string,
  opaqueId: string,
): string {
  return `resource_${digestIdentifier(
    `resource:${step}:${kind}`,
    `${subscriptionId}:${opaqueId}`,
  )}`;
}

export function deterministicCredentialHandoffId(
  subscriptionId: string,
  activationGeneration = 0,
): string {
  const identity =
    activationGeneration === 0
      ? subscriptionId
      : `${subscriptionId}:activation:${activationGeneration}`;
  return `handoff_${digestIdentifier("credential-handoff", identity)}`;
}

export function isProvisionableOrder(
  order: OrderRecord,
): order is ProvisionableOrder {
  return (
    order.billingState === "active" &&
    hasProvisioningIdentity(order) &&
    (order.mode === "shared" || order.plan === "scale")
  );
}

export function hasProvisioningIdentity(
  order: OrderRecord,
): order is ProvisioningIdentity {
  return (
    order.customerId !== undefined &&
    order.customerId.length > 0 &&
    order.ownerSubject !== undefined &&
    order.ownerSubject.length > 0 &&
    order.mode !== undefined &&
    order.plan !== undefined
  );
}

export function assertRetryPolicy(policy: RetryPolicy): void {
  if (
    !Number.isSafeInteger(policy.maxAttempts) ||
    policy.maxAttempts < 1 ||
    !Number.isSafeInteger(policy.baseDelayMs) ||
    policy.baseDelayMs < 0 ||
    !Number.isSafeInteger(policy.maxDelayMs) ||
    policy.maxDelayMs < policy.baseDelayMs
  ) {
    throw new SafeProvisioningError("INVALID_STATE");
  }
}
