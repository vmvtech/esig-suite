import { randomUUID } from "node:crypto";

import {
  DEFAULT_EXECUTION_LEASE_DURATION_MS,
  DEFAULT_RETRY_POLICY,
  SafeProvisioningError,
  deterministicCredentialHandoffId,
  deterministicResourceKey,
  hasProvisioningIdentity,
  isProvisionableOrder,
  sanitizeProvisioningError,
  type EventClaim,
  type CredentialHandoffPointer,
  type JobExecutionLease,
  type NormalizedStripeEvent,
  type OneTimeCredentialHandoff,
  type OrderRecord,
  type ProvisioningDriver,
  type ProvisioningJob,
  type ProvisioningOperation,
  type ProvisioningIdentity,
  type ProvisionableOrder,
  type ProvisioningQueueMessage,
  type ProvisioningStep,
  type ResourceRecord,
  type RetryPolicy,
  type StepExecutionResult,
} from "./domain.js";
import type { ProvisioningStore } from "./memory-store.js";
import {
  beginCompensation,
  completeCompensationStep,
  completeProvisioningStep,
  createProvisioningJob,
  failProvisioningAttempt,
  nextCompensationStep,
  nextProvisioningStep,
  reduceBillingEvent,
  resumeProvisioningJob,
  startProvisioningAttempt,
} from "./state-machine.js";

export type EventProcessingStatus =
  | "claimed"
  | "duplicate"
  | "conflict"
  | "ignored";

export interface EventProcessingResult {
  readonly status: EventProcessingStatus;
  readonly order?: OrderRecord;
  readonly job?: ProvisioningJob;
  /** Present only when this transition needs one worker wake-up. */
  readonly queueMessage?: ProvisioningQueueMessage;
}

function eventClaim(event: NormalizedStripeEvent): EventClaim {
  return {
    eventId: event.eventId,
    eventType: event.type === "ignored" ? event.originalType : event.type,
    createdAt: event.createdAt,
    payloadDigest: event.payloadDigest,
    subscriptionId: event.subscriptionId,
  };
}

function queueMessage(job: ProvisioningJob): ProvisioningQueueMessage {
  return { subscriptionId: job.subscriptionId, jobId: job.jobId };
}

function isTerminalBilling(order: OrderRecord): boolean {
  return order.billingState === "canceled" || order.billingState === "refunded";
}

class JobVersionConflict extends Error {}

async function saveUpdatedJob(
  store: ProvisioningStore,
  current: ProvisioningJob,
  next: ProvisioningJob,
): Promise<ProvisioningJob> {
  try {
    return await store.putJob(next, current.version);
  } catch (error: unknown) {
    if (sanitizeProvisioningError(error).code === "STORE_CONFLICT") {
      throw new JobVersionConflict();
    }
    throw error;
  }
}

async function transitionToCompensation(
  store: ProvisioningStore,
  initialJob: ProvisioningJob,
  operation: "suspension" | "compensation" = "compensation",
): Promise<ProvisioningJob> {
  let current = initialJob;
  for (let conflict = 0; conflict < 3; conflict += 1) {
    const resources = await store.listResources(current.subscriptionId);
    const potentiallyInFlightStep =
      current.operation === "provisioning" &&
      (current.state === "running" || current.state === "failed")
        ? nextProvisioningStep(current)
        : undefined;
    const next = beginCompensation(
      current,
      [
        ...resources.map((resource) => resource.step),
        ...(potentiallyInFlightStep === undefined ? [] : [potentiallyInFlightStep]),
      ],
      operation,
    );
    if (next === current) return current;
    try {
      return await saveUpdatedJob(store, current, next);
    } catch (error: unknown) {
      if (!(error instanceof JobVersionConflict)) throw error;
      const latest = await store.getJob(current.subscriptionId);
      if (latest === undefined) {
        throw new SafeProvisioningError("STORE_CONFLICT");
      }
      current = latest;
    }
  }
  throw new SafeProvisioningError("STORE_CONFLICT", true);
}

/**
 * Conditional-claim convenience path for tests or adapters where claiming and
 * reduction happen in one process. Webhook-first systems should conditionally
 * claim before enqueue and call processClaimedStripeEvent in the worker.
 */
export async function processStripeEvent(
  store: ProvisioningStore,
  event: NormalizedStripeEvent,
  retryPolicy: RetryPolicy = DEFAULT_RETRY_POLICY,
): Promise<EventProcessingResult> {
  const claim = await store.claimEvent(eventClaim(event));
  if (claim.status !== "claimed") {
    if (event.type === "ignored") return { status: claim.status };
    return {
      status: claim.status,
      order: await store.getOrder(event.subscriptionId),
      job: await store.getJob(event.subscriptionId),
    };
  }
  return processClaimedStripeEvent(store, event, retryPolicy);
}

const ORDER_CAS_ATTEMPTS = 4;

async function reduceAndStoreOrder(
  store: ProvisioningStore,
  event: NormalizedStripeEvent,
): Promise<OrderRecord | undefined> {
  let current =
    event.type === "ignored"
      ? undefined
      : await store.getOrder(event.subscriptionId);

  for (let attempt = 0; attempt < ORDER_CAS_ATTEMPTS; attempt += 1) {
    const reduction = reduceBillingEvent(current, event);
    if (reduction.order === undefined) return undefined;
    try {
      return await store.putOrder(reduction.order, current?.version);
    } catch (error: unknown) {
      if (sanitizeProvisioningError(error).code !== "STORE_CONFLICT") {
        throw error;
      }
      if (attempt === ORDER_CAS_ATTEMPTS - 1) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      current = await store.getOrder(reduction.order.subscriptionId);
    }
  }
  throw new SafeProvisioningError("STORE_CONFLICT", true);
}

/** Apply an event whose immutable EVENT# claim was written before enqueue. */
export async function processClaimedStripeEvent(
  store: ProvisioningStore,
  event: NormalizedStripeEvent,
  retryPolicy: RetryPolicy = DEFAULT_RETRY_POLICY,
): Promise<EventProcessingResult> {
  if (event.type === "ignored") return { status: "ignored" };

  const order = await reduceAndStoreOrder(store, event);
  if (order === undefined) return { status: "ignored" };

  const existingJob = await store.getJob(event.subscriptionId);
  if (order.billingState === "past_due" || isTerminalBilling(order)) {
    if (existingJob === undefined) return { status: "claimed", order };
    const operation = order.billingState === "past_due" ? "suspension" : "compensation";
    const job = await transitionToCompensation(store, existingJob, operation);
    const shouldQueue =
      job.state === "compensating" && existingJob.state !== "compensating";
    return {
      status: "claimed",
      order,
      job,
      queueMessage: shouldQueue ? queueMessage(job) : undefined,
    };
  }

  if (!isProvisionableOrder(order)) {
    return { status: "claimed", order, job: existingJob };
  }

  if (existingJob !== undefined) {
    if (existingJob.operation === "suspension") {
      const resumed = resumeProvisioningJob(existingJob);
      const stored = await saveUpdatedJob(store, existingJob, resumed);
      return {
        status: "claimed",
        order,
        job: stored,
        queueMessage: queueMessage(stored),
      };
    }
    return { status: "claimed", order, job: existingJob };
  }

  const job = createProvisioningJob(order, retryPolicy);
  let storedJob: ProvisioningJob;
  try {
    storedJob = await store.putJob(job);
  } catch (error: unknown) {
    if (sanitizeProvisioningError(error).code !== "STORE_CONFLICT") throw error;
    const concurrentJob = await store.getJob(order.subscriptionId);
    if (concurrentJob === undefined) throw error;
    return { status: "claimed", order, job: concurrentJob };
  }
  return {
    status: "claimed",
    order,
    job: storedJob,
    queueMessage: queueMessage(storedJob),
  };
}

export type ProvisioningRunStatus =
  | "ready"
  | "disabled"
  | "failed"
  | "deferred"
  | "exhausted"
  | "not_found";

export interface ProvisioningRunResult {
  readonly status: ProvisioningRunStatus;
  readonly job?: ProvisioningJob;
}

export interface RunProvisioningJobInput {
  readonly store: ProvisioningStore;
  readonly driver: ProvisioningDriver;
  readonly subscriptionId: string;
  readonly now: number;
  /** Stable only for this invocation; generated when omitted. */
  readonly executionOwnerId?: string;
  /** Wall-clock lease duration. Active workers renew it while effects await. */
  readonly executionLeaseDurationMs?: number;
  /** Injectable wall clock for deterministic lease tests. */
  readonly executionLeaseClock?: () => number;
  /** Required before any driver declared to emit a one-time credential runs. */
  readonly credentialHandoff?: OneTimeCredentialHandoff;
  /** Fault-injection/checkpoint hook. Runs after effects, before job checkpoint. */
  readonly afterStep?: (
    step: ProvisioningStep,
    operation: ProvisioningOperation,
  ) => void | Promise<void>;
}

class JobExecutionLeaseLost extends Error {}

class JobExecutionLeaseGuard {
  readonly #store: ProvisioningStore;
  readonly #durationMs: number;
  readonly #clock: () => number;
  #lease: JobExecutionLease;
  #heartbeat?: ReturnType<typeof setInterval>;
  #renewal?: Promise<void>;
  #lost = false;
  #closed = false;

  constructor(
    store: ProvisioningStore,
    lease: JobExecutionLease,
    durationMs: number,
    clock: () => number,
  ) {
    this.#store = store;
    this.#lease = lease;
    this.#durationMs = durationMs;
    this.#clock = clock;
  }

  start(): void {
    const intervalMs = Math.max(1, Math.floor(this.#durationMs / 3));
    this.#heartbeat = setInterval(() => {
      void this.#renew().catch(() => undefined);
    }, intervalMs);
    this.#heartbeat.unref?.();
  }

  async assertOwned(): Promise<void> {
    if (this.#lost || this.#closed) throw new JobExecutionLeaseLost();
    await this.#renew();
    if (this.#lost || this.#closed) throw new JobExecutionLeaseLost();
  }

  async fence(): Promise<{ lease: JobExecutionLease; now: number }> {
    await this.assertOwned();
    return { lease: { ...this.#lease }, now: this.#clock() };
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#heartbeat !== undefined) clearInterval(this.#heartbeat);
    await this.#renewal?.catch(() => undefined);
    await this.#store.releaseJobExecutionLease(this.#lease);
  }

  async #renew(): Promise<void> {
    if (this.#lost || this.#closed) throw new JobExecutionLeaseLost();
    if (this.#renewal !== undefined) return this.#renewal;
    const renewal = this.#store
      .renewJobExecutionLease(
        this.#lease,
        this.#clock(),
        this.#durationMs,
      )
      .then((lease) => {
        this.#lease = lease;
      })
      .catch(() => {
        this.#lost = true;
        throw new JobExecutionLeaseLost();
      })
      .finally(() => {
        if (this.#renewal === renewal) this.#renewal = undefined;
      });
    this.#renewal = renewal;
    return renewal;
  }
}

type LeasedRunProvisioningJobInput = RunProvisioningJobInput & {
  readonly executionLease: JobExecutionLeaseGuard;
};

function resourceInputIsSafe(resource: {
  readonly kind: string;
  readonly opaqueId: string;
}): boolean {
  return (
    /^[a-z0-9][a-z0-9_.:-]{0,127}$/i.test(resource.kind) &&
    resource.opaqueId.length > 0 &&
    resource.opaqueId.length <= 512 &&
    !/[\r\n\0]/.test(resource.opaqueId)
  );
}

async function persistStepResources(
  store: ProvisioningStore,
  job: ProvisioningJob,
  step: ProvisioningStep,
  result: StepExecutionResult,
): Promise<void> {
  for (const resource of result.resources ?? []) {
    if (!resourceInputIsSafe(resource)) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    const common = {
      resourceKey: deterministicResourceKey(
        job.subscriptionId,
        step,
        resource.kind,
        resource.opaqueId,
      ),
      subscriptionId: job.subscriptionId,
      step,
      kind: resource.kind,
      opaqueId: resource.opaqueId,
    } as const;
    const record: ResourceRecord =
      resource.retention === "immutable_evidence"
        ? { ...common, retention: "immutable_evidence", status: "retained" }
        : { ...common, retention: "mutable", status: "active" };
    await store.putResource(record);
  }
}

const CREDENTIAL_HANDOFF_KIND = "credential_handoff_receipt";

function hasCredentialHandoffReceipt(
  resources: readonly ResourceRecord[],
  job: ProvisioningJob,
): boolean {
  const expectedHandoffId = deterministicCredentialHandoffId(
    job.subscriptionId,
    job.activationGeneration ?? 0,
  );
  return resources.some(
    (resource) =>
      resource.step === "api_credential" &&
      resource.kind === CREDENTIAL_HANDOFF_KIND &&
      resource.opaqueId === expectedHandoffId &&
      resource.retention === "mutable" &&
      resource.status === "active",
  );
}

async function persistCredentialHandoffReceipt(
  store: ProvisioningStore,
  job: ProvisioningJob,
  handoffId: string,
): Promise<void> {
  await store.putResource({
    resourceKey: deterministicResourceKey(
      job.subscriptionId,
      "api_credential",
      CREDENTIAL_HANDOFF_KIND,
      handoffId,
    ),
    subscriptionId: job.subscriptionId,
    step: "api_credential",
    kind: CREDENTIAL_HANDOFF_KIND,
    opaqueId: handoffId,
    retention: "mutable",
    status: "active",
  });
}

function pointerMatchesJob(
  pointer: CredentialHandoffPointer,
  job: ProvisioningJob,
): boolean {
  return (
    pointer.subscriptionId === job.subscriptionId &&
    pointer.jobId === job.jobId &&
    pointer.activationGeneration === (job.activationGeneration ?? 0) &&
    pointer.handoffId ===
      deterministicCredentialHandoffId(
        job.subscriptionId,
        job.activationGeneration ?? 0,
      )
  );
}

interface PreparedCredentialHandoff {
  readonly completed: boolean;
  readonly pointer?: CredentialHandoffPointer;
}

async function prepareCredentialHandoff(
  input: LeasedRunProvisioningJobInput,
  job: ProvisioningJob,
  step: ProvisioningStep,
  handoffCompleted: boolean,
): Promise<PreparedCredentialHandoff> {
  if (step !== "api_credential" || !input.driver.requiresCredentialHandoff) {
    return { completed: handoffCompleted };
  }
  // A local receipt is only a checkpoint cache. An incomplete API step must
  // always re-verify the authoritative fenced pointer and immutable secret.
  if (input.credentialHandoff === undefined) {
    throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
  }
  const handoffId = deterministicCredentialHandoffId(
    job.subscriptionId,
    job.activationGeneration ?? 0,
  );
  let pointer = await input.store.getCredentialHandoffPointer(
    job.subscriptionId,
    handoffId,
  );
  if (pointer !== undefined && !pointerMatchesJob(pointer, job)) {
    throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
  }
  if (
    pointer !== undefined &&
    pointer.state !== "revoked" &&
    pointer.secretId !== undefined &&
    pointer.publicationId !== undefined &&
    pointer.credentialId !== undefined
  ) {
    const verified = await input.credentialHandoff.verifyPublication(pointer);
    if (verified) {
      if (pointer.state === "pending") {
        const fence = await input.executionLease.fence();
        pointer = await input.store.publishCredentialHandoff({
          pointer,
          ...fence,
        });
      }
      await persistCredentialHandoffReceipt(input.store, job, handoffId);
      return { completed: true, pointer };
    }
  }
  if (pointer?.state === "revoked") {
    throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
  }

  const fence = await input.executionLease.fence();
  const next: CredentialHandoffPointer = {
    handoffId,
    subscriptionId: job.subscriptionId,
    jobId: job.jobId,
    activationGeneration: job.activationGeneration ?? 0,
    publicationGeneration: (pointer?.publicationGeneration ?? -1) + 1,
    fencingToken: fence.lease.fencingToken,
    state: "pending",
  };
  pointer = await input.store.beginCredentialHandoff(
    next,
    fence.lease,
    fence.now,
    pointer?.publicationGeneration,
  );
  return { completed: false, pointer };
}

async function publishCredentialIfNeeded(
  input: LeasedRunProvisioningJobInput,
  job: ProvisioningJob,
  step: ProvisioningStep,
  prepared: PreparedCredentialHandoff,
  result: StepExecutionResult,
): Promise<void> {
  if (result.oneTimeCredential !== undefined && step !== "api_credential") {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
  if (step !== "api_credential" || !input.driver.requiresCredentialHandoff) return;
  if (prepared.completed) {
    if (result.oneTimeCredential !== undefined) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    return;
  }
  if (input.credentialHandoff === undefined || prepared.pointer === undefined) {
    throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
  }

  if (result.oneTimeCredential !== undefined) {
    const publicationInput = {
        handoffId: prepared.pointer.handoffId,
        jobId: job.jobId,
        subscriptionId: job.subscriptionId,
        activationGeneration: job.activationGeneration ?? 0,
        publicationGeneration: prepared.pointer.publicationGeneration,
        fencingToken: prepared.pointer.fencingToken,
        credential: result.oneTimeCredential,
      } as const;
    const descriptor = input.credentialHandoff.describePublication(publicationInput);
    let fence = await input.executionLease.fence();
    const bound = await input.store.bindCredentialHandoff(
      { pointer: prepared.pointer, ...fence },
      descriptor,
    );
    const created = await input.credentialHandoff.createImmutable(publicationInput);
    if (
      created.secretId !== descriptor.secretId ||
      created.publicationId !== descriptor.publicationId ||
      created.credentialId !== descriptor.credentialId
    ) {
      throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
    }
    fence = await input.executionLease.fence();
    await input.store.publishCredentialHandoff({ pointer: bound, ...fence });
    await persistCredentialHandoffReceipt(
      input.store,
      job,
      prepared.pointer.handoffId,
    );
    return;
  }
  throw new SafeProvisioningError("CREDENTIAL_REISSUE_REQUIRED", true);
}

async function recoverJobConflict(
  input: LeasedRunProvisioningJobInput,
  conflictsRemaining: number,
): Promise<ProvisioningRunResult> {
  if (conflictsRemaining > 0) {
    return runProvisioningJobInternal(input, conflictsRemaining - 1);
  }
  const latest = await input.store.getJob(input.subscriptionId);
  if (latest === undefined) return { status: "not_found" };
  if (latest.state === "ready") return { status: "ready", job: latest };
  if (latest.state === "disabled") return { status: "disabled", job: latest };
  if (latest.state === "failed" && latest.retryExhausted) {
    return { status: "exhausted", job: latest };
  }
  return { status: "deferred", job: latest };
}

async function runProvisioningSteps(
  input: LeasedRunProvisioningJobInput,
  order: ProvisionableOrder,
  initialJob: ProvisioningJob,
  conflictsRemaining: number,
): Promise<ProvisioningRunResult> {
  let job = initialJob;

  try {
    while (job.state === "running") {
      await input.executionLease.assertOwned();
      const step = nextProvisioningStep(job);
      if (step === undefined) break;
      const resources = await input.store.listResources(job.subscriptionId);
      const stepResources = resources.filter((resource) => resource.step === step);
      const handoffCompleted = hasCredentialHandoffReceipt(stepResources, job);
      if (
        step === "api_credential" &&
        input.driver.requiresCredentialHandoff &&
        !handoffCompleted &&
        input.credentialHandoff === undefined
      ) {
        // Fail before the provider can create plaintext with nowhere safe to go.
        throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
      }
      const prepared = await prepareCredentialHandoff(
        input,
        job,
        step,
        handoffCompleted,
      );
      const result = await input.driver.executeStep({
        step,
        order,
        job,
        resources,
        stepResources,
        credentialHandoffCompleted: prepared.completed,
      });
      await input.executionLease.assertOwned();
      await persistStepResources(input.store, job, step, result);
      await publishCredentialIfNeeded(
        input,
        job,
        step,
        prepared,
        result,
      );
      await input.afterStep?.(step, "provisioning");
      await input.executionLease.assertOwned();
      const next = completeProvisioningStep(job, step);
      job = await saveUpdatedJob(input.store, job, next);
    }
    return { status: job.state === "ready" ? "ready" : "failed", job };
  } catch (error: unknown) {
    if (error instanceof JobExecutionLeaseLost) throw error;
    if (error instanceof JobVersionConflict) {
      return recoverJobConflict(input, conflictsRemaining);
    }
    const failure = sanitizeProvisioningError(error);
    const failed = failProvisioningAttempt(job, failure, input.now);
    try {
      job = await saveUpdatedJob(input.store, job, failed);
      return { status: "failed", job };
    } catch (saveError: unknown) {
      if (saveError instanceof JobVersionConflict) {
        return recoverJobConflict(input, conflictsRemaining);
      }
      throw saveError;
    }
  }
}

async function applyCompensationDispositions(
  store: ProvisioningStore,
  resources: readonly ResourceRecord[],
  dispositions: Awaited<
    ReturnType<ProvisioningDriver["compensateStep"]>
  >["dispositions"],
): Promise<void> {
  const dispositionByKey = new Map(
    (dispositions ?? []).map((disposition) => [
      disposition.resourceKey,
      disposition,
    ]),
  );
  if (dispositionByKey.size !== (dispositions ?? []).length) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }

  for (const disposition of dispositionByKey.values()) {
    if (!resources.some((resource) => resource.resourceKey === disposition.resourceKey)) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
  }

  for (const resource of resources) {
    if (resource.retention === "immutable_evidence") {
      // Intentionally ignore any requested disposition for evidence.
      continue;
    }
    const disposition = dispositionByKey.get(resource.resourceKey);
    if (disposition === undefined) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    const requiredStatus =
      resource.step === "api_credential"
        ? "revoked"
        : resource.step === "plan_entitlement" ||
            resource.step === "activation_metadata" ||
            resource.step === "mark_ready"
          ? "disabled"
          : undefined;
    if (requiredStatus !== undefined && disposition.status !== requiredStatus) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    await store.putResource({ ...resource, status: disposition.status });
  }
}

async function runCompensationSteps(
  input: LeasedRunProvisioningJobInput,
  order: ProvisioningIdentity,
  initialJob: ProvisioningJob,
  conflictsRemaining: number,
): Promise<ProvisioningRunResult> {
  let job = initialJob;

  try {
    while (job.state === "compensating") {
      await input.executionLease.assertOwned();
      const step = nextCompensationStep(job);
      if (step === undefined) break;
      const resources = await input.store.listResources(job.subscriptionId);
      const stepResources = resources.filter((resource) => resource.step === step);
      const handoffId = deterministicCredentialHandoffId(
        job.subscriptionId,
        job.activationGeneration ?? 0,
      );
      const pointer = await input.store.getCredentialHandoffPointer(
        job.subscriptionId,
        handoffId,
      );
      if (pointer !== undefined && pointer.state !== "revoked") {
        if (!pointerMatchesJob(pointer, job)) {
          throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
        }
        const fence = await input.executionLease.fence();
        await input.store.revokeCredentialHandoff({ pointer, ...fence });
      }
      const result = await input.driver.compensateStep({
        step,
        order,
        job,
        resources,
        stepResources,
        credentialHandoffCompleted: hasCredentialHandoffReceipt(stepResources, job),
      });
      await input.executionLease.assertOwned();
      await persistStepResources(input.store, job, step, result);
      await applyCompensationDispositions(
        input.store,
        stepResources,
        result.dispositions,
      );
      await input.afterStep?.(step, "compensation");
      await input.executionLease.assertOwned();
      const next = completeCompensationStep(job, step);
      job = await saveUpdatedJob(input.store, job, next);
    }
    return { status: job.state === "disabled" ? "disabled" : "failed", job };
  } catch (error: unknown) {
    if (error instanceof JobExecutionLeaseLost) throw error;
    if (error instanceof JobVersionConflict) {
      return recoverJobConflict(input, conflictsRemaining);
    }
    const failure = sanitizeProvisioningError(error);
    const failed = failProvisioningAttempt(job, failure, input.now);
    try {
      job = await saveUpdatedJob(input.store, job, failed);
      return { status: "failed", job };
    } catch (saveError: unknown) {
      if (saveError instanceof JobVersionConflict) {
        return recoverJobConflict(input, conflictsRemaining);
      }
      throw saveError;
    }
  }
}

async function runProvisioningJobInternal(
  input: LeasedRunProvisioningJobInput,
  conflictsRemaining: number,
): Promise<ProvisioningRunResult> {
  await input.executionLease.assertOwned();
  const order = await input.store.getOrder(input.subscriptionId);
  let job = await input.store.getJob(input.subscriptionId);
  if (order === undefined || job === undefined) return { status: "not_found" };

  if (order.billingState === "past_due" || isTerminalBilling(order)) {
    try {
      job = await transitionToCompensation(
        input.store,
        job,
        order.billingState === "past_due" ? "suspension" : "compensation",
      );
    } catch (error: unknown) {
      if (sanitizeProvisioningError(error).code === "STORE_CONFLICT") {
        return recoverJobConflict(input, conflictsRemaining);
      }
      throw error;
    }
  }
  if (job.state === "ready") return { status: "ready", job };
  if (job.state === "disabled") return { status: "disabled", job };
  if (job.state === "failed") {
    if (job.retryExhausted) return { status: "exhausted", job };
    if (job.nextRetryAt === undefined || input.now < job.nextRetryAt) {
      return { status: "deferred", job };
    }
  }

  const started = startProvisioningAttempt(job, input.now);
  if (started !== job) {
    try {
      job = await saveUpdatedJob(input.store, job, started);
    } catch (error: unknown) {
      if (error instanceof JobVersionConflict) {
        return recoverJobConflict(input, conflictsRemaining);
      }
      throw error;
    }
  }

  if (input.driver.mode !== order.mode) {
    const failed = failProvisioningAttempt(
      job,
      { code: "MODE_MISMATCH", retryable: false },
      input.now,
    );
    try {
      job = await saveUpdatedJob(input.store, job, failed);
      return { status: "failed", job };
    } catch (error: unknown) {
      if (error instanceof JobVersionConflict) {
        return recoverJobConflict(input, conflictsRemaining);
      }
      throw error;
    }
  }

  if (job.operation === "compensation" || job.operation === "suspension") {
    if (!hasProvisioningIdentity(order)) {
      const failed = failProvisioningAttempt(
        job,
        { code: "INVALID_ORDER", retryable: false },
        input.now,
      );
      try {
        job = await saveUpdatedJob(input.store, job, failed);
        return { status: "failed", job };
      } catch (error: unknown) {
        if (error instanceof JobVersionConflict) {
          return recoverJobConflict(input, conflictsRemaining);
        }
        throw error;
      }
    }
    return runCompensationSteps(input, order, job, conflictsRemaining);
  }
  if (!isProvisionableOrder(order)) {
    const failed = failProvisioningAttempt(
      job,
      { code: "INVALID_ORDER", retryable: false },
      input.now,
    );
    try {
      job = await saveUpdatedJob(input.store, job, failed);
      return { status: "failed", job };
    } catch (error: unknown) {
      if (error instanceof JobVersionConflict) {
        return recoverJobConflict(input, conflictsRemaining);
      }
      throw error;
    }
  }
  return runProvisioningSteps(input, order, job, conflictsRemaining);
}

/** Resume one persisted job. It performs no cloud calls except through driver. */
export async function runProvisioningJob(
  input: RunProvisioningJobInput,
): Promise<ProvisioningRunResult> {
  const leaseDurationMs =
    input.executionLeaseDurationMs ?? DEFAULT_EXECUTION_LEASE_DURATION_MS;
  const clock = input.executionLeaseClock ?? Date.now;
  const claim = await input.store.acquireJobExecutionLease(
    input.subscriptionId,
    input.executionOwnerId ?? randomUUID(),
    clock(),
    leaseDurationMs,
  );
  if (claim.status === "held") return currentRunResult(input.store, input.subscriptionId);

  const guard = new JobExecutionLeaseGuard(
    input.store,
    claim.lease,
    leaseDurationMs,
    clock,
  );
  guard.start();
  try {
    try {
      return await runProvisioningJobInternal(
        { ...input, executionLease: guard },
        2,
      );
    } catch (error: unknown) {
      if (error instanceof JobExecutionLeaseLost) {
        return currentRunResult(input.store, input.subscriptionId);
      }
      throw error;
    }
  } finally {
    await guard.close();
  }
}

async function currentRunResult(
  store: ProvisioningStore,
  subscriptionId: string,
): Promise<ProvisioningRunResult> {
  const job = await store.getJob(subscriptionId);
  if (job === undefined) return { status: "not_found" };
  if (job.state === "ready") return { status: "ready", job };
  if (job.state === "disabled") return { status: "disabled", job };
  if (job.state === "failed" && job.retryExhausted) {
    return { status: "exhausted", job };
  }
  return { status: "deferred", job };
}
