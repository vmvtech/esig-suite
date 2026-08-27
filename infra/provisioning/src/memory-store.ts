import {
  SafeProvisioningError,
  deterministicJobId,
  deterministicResourceKey,
  type EventClaim,
  type EventClaimResult,
  type CredentialHandoffMutationInput,
  type CredentialHandoffPointer,
  type CredentialSecretPublication,
  type JobExecutionLease,
  type JobExecutionLeaseClaimResult,
  type OrderRecord,
  type ProvisioningJob,
  type ResourceRecord,
} from "./domain.js";

/** Durable control-plane operations required by the pure worker domain. */
export interface ProvisioningStore {
  claimEvent(claim: EventClaim): Promise<EventClaimResult>;
  listEventClaims(): Promise<readonly EventClaim[]>;

  getOrder(subscriptionId: string): Promise<OrderRecord | undefined>;
  putOrder(order: OrderRecord, expectedVersion?: number): Promise<OrderRecord>;

  getJob(subscriptionId: string): Promise<ProvisioningJob | undefined>;
  putJob(
    job: ProvisioningJob,
    expectedVersion?: number,
  ): Promise<ProvisioningJob>;

  acquireJobExecutionLease(
    subscriptionId: string,
    ownerId: string,
    now: number,
    leaseDurationMs: number,
  ): Promise<JobExecutionLeaseClaimResult>;
  renewJobExecutionLease(
    lease: JobExecutionLease,
    now: number,
    leaseDurationMs: number,
  ): Promise<JobExecutionLease>;
  releaseJobExecutionLease(lease: JobExecutionLease): Promise<void>;

  getCredentialHandoffPointer(
    subscriptionId: string,
    handoffId: string,
  ): Promise<CredentialHandoffPointer | undefined>;
  beginCredentialHandoff(
    pointer: CredentialHandoffPointer,
    lease: JobExecutionLease,
    now: number,
    expectedPublicationGeneration?: number,
  ): Promise<CredentialHandoffPointer>;
  bindCredentialHandoff(
    input: CredentialHandoffMutationInput,
    publication: CredentialSecretPublication,
  ): Promise<CredentialHandoffPointer>;
  publishCredentialHandoff(
    input: CredentialHandoffMutationInput,
  ): Promise<CredentialHandoffPointer>;
  revokeCredentialHandoff(
    input: CredentialHandoffMutationInput,
  ): Promise<CredentialHandoffPointer>;

  listResources(subscriptionId: string): Promise<readonly ResourceRecord[]>;
  putResource(resource: ResourceRecord): Promise<void>;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

/**
 * Deterministic, side-effect-free test adapter. Map insertion happens before
 * the first await in claimEvent, so concurrent Promise deliveries observe one
 * atomic winner just like a conditional ledger write.
 */
export class InMemoryProvisioningStore implements ProvisioningStore {
  readonly #events = new Map<string, EventClaim>();
  readonly #orders = new Map<string, OrderRecord>();
  readonly #jobs = new Map<string, ProvisioningJob>();
  readonly #executionLeases = new Map<string, JobExecutionLease>();
  readonly #credentialHandoffs = new Map<string, CredentialHandoffPointer>();
  readonly #resources = new Map<string, ResourceRecord>();

  async claimEvent(claim: EventClaim): Promise<EventClaimResult> {
    const existing = this.#events.get(claim.eventId);
    if (existing !== undefined) {
      return {
        status:
          existing.payloadDigest === claim.payloadDigest
            ? "duplicate"
            : "conflict",
        claim: clone(existing),
      };
    }

    const stored = clone(claim);
    this.#events.set(stored.eventId, stored);
    return { status: "claimed", claim: clone(stored) };
  }

  async listEventClaims(): Promise<readonly EventClaim[]> {
    return [...this.#events.values()]
      .sort((left, right) => left.eventId.localeCompare(right.eventId))
      .map(clone);
  }

  async getOrder(subscriptionId: string): Promise<OrderRecord | undefined> {
    const order = this.#orders.get(subscriptionId);
    return order === undefined ? undefined : clone(order);
  }

  async putOrder(
    order: OrderRecord,
    expectedVersion?: number,
  ): Promise<OrderRecord> {
    const existing = this.#orders.get(order.subscriptionId);
    if (
      (existing === undefined &&
        (expectedVersion !== undefined || order.version !== 0)) ||
      (existing !== undefined &&
        (expectedVersion === undefined ||
          expectedVersion !== existing.version ||
          order.version !== expectedVersion))
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    if (
      existing !== undefined &&
      (existing.billingState === "canceled" ||
        existing.billingState === "refunded") &&
      order.billingState !== existing.billingState &&
      !(existing.billingState === "canceled" && order.billingState === "refunded")
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }
    const stored =
      existing === undefined
        ? clone(order)
        : clone({ ...order, version: existing.version + 1 });
    this.#orders.set(order.subscriptionId, stored);
    return clone(stored);
  }

  async getJob(subscriptionId: string): Promise<ProvisioningJob | undefined> {
    const job = this.#jobs.get(subscriptionId);
    return job === undefined ? undefined : clone(job);
  }

  async putJob(
    job: ProvisioningJob,
    expectedVersion?: number,
  ): Promise<ProvisioningJob> {
    if (job.jobId !== deterministicJobId(job.subscriptionId)) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }
    const existing = this.#jobs.get(job.subscriptionId);
    if (
      existing === undefined &&
      (expectedVersion !== undefined || job.version !== 0)
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }
    if (
      existing !== undefined &&
      (existing.jobId !== job.jobId ||
        expectedVersion === undefined ||
        expectedVersion !== existing.version ||
        job.version !== expectedVersion)
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }

    const stored =
      existing === undefined
        ? clone(job)
        : clone({ ...job, version: existing.version + 1 });
    this.#jobs.set(job.subscriptionId, stored);
    return clone(stored);
  }

  async acquireJobExecutionLease(
    subscriptionId: string,
    ownerId: string,
    now: number,
    leaseDurationMs: number,
  ): Promise<JobExecutionLeaseClaimResult> {
    assertLeaseInput(subscriptionId, ownerId, now, leaseDurationMs);
    const existing = this.#executionLeases.get(subscriptionId);
    if (existing !== undefined && existing.expiresAt > now) {
      return { status: "held" };
    }

    const lease: JobExecutionLease = {
      subscriptionId,
      ownerId,
      fencingToken: (existing?.fencingToken ?? 0) + 1,
      expiresAt: now + leaseDurationMs,
    };
    this.#executionLeases.set(subscriptionId, lease);
    return { status: "acquired", lease: clone(lease) };
  }

  async renewJobExecutionLease(
    lease: JobExecutionLease,
    now: number,
    leaseDurationMs: number,
  ): Promise<JobExecutionLease> {
    assertLeaseInput(
      lease.subscriptionId,
      lease.ownerId,
      now,
      leaseDurationMs,
    );
    const existing = this.#executionLeases.get(lease.subscriptionId);
    if (
      existing === undefined ||
      existing.ownerId !== lease.ownerId ||
      existing.fencingToken !== lease.fencingToken ||
      existing.expiresAt <= now
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }

    const renewed = { ...existing, expiresAt: now + leaseDurationMs };
    this.#executionLeases.set(lease.subscriptionId, renewed);
    return clone(renewed);
  }

  async releaseJobExecutionLease(lease: JobExecutionLease): Promise<void> {
    const existing = this.#executionLeases.get(lease.subscriptionId);
    if (
      existing?.ownerId === lease.ownerId &&
      existing.fencingToken === lease.fencingToken
    ) {
      // Preserve the fence counter so a later owner can never reuse a stale
      // token, even if an injected owner ID is accidentally reused.
      this.#executionLeases.set(lease.subscriptionId, {
        ...existing,
        expiresAt: 0,
      });
    }
  }

  async getCredentialHandoffPointer(
    subscriptionId: string,
    handoffId: string,
  ): Promise<CredentialHandoffPointer | undefined> {
    const pointer = this.#credentialHandoffs.get(handoffId);
    if (pointer?.subscriptionId !== subscriptionId) return undefined;
    return clone(pointer);
  }

  async beginCredentialHandoff(
    pointer: CredentialHandoffPointer,
    lease: JobExecutionLease,
    now: number,
    expectedPublicationGeneration?: number,
  ): Promise<CredentialHandoffPointer> {
    this.#assertActiveLease(lease, now);
    const existing = this.#credentialHandoffs.get(pointer.handoffId);
    const validNew =
      existing === undefined &&
      expectedPublicationGeneration === undefined &&
      pointer.publicationGeneration === 0;
    const validReplacement =
      existing !== undefined &&
      expectedPublicationGeneration === existing.publicationGeneration &&
      pointer.publicationGeneration === existing.publicationGeneration + 1 &&
      existing.state !== "revoked";
    if (
      (!validNew && !validReplacement) ||
      pointer.state !== "pending" ||
      pointer.subscriptionId !== lease.subscriptionId ||
      pointer.fencingToken !== lease.fencingToken ||
      pointer.secretId !== undefined ||
      pointer.publicationId !== undefined ||
      pointer.credentialId !== undefined
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    this.#credentialHandoffs.set(pointer.handoffId, clone(pointer));
    return clone(pointer);
  }

  async bindCredentialHandoff(
    input: CredentialHandoffMutationInput,
    publication: CredentialSecretPublication,
  ): Promise<CredentialHandoffPointer> {
    this.#assertActiveLease(input.lease, input.now);
    const existing = this.#credentialHandoffs.get(input.pointer.handoffId);
    if (
      existing === undefined ||
      !samePointerGeneration(existing, input.pointer) ||
      existing.state !== "pending"
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    const bound = {
      ...existing,
      secretId: publication.secretId,
      publicationId: publication.publicationId,
      credentialId: publication.credentialId,
    };
    if (pointerHasPublication(existing) && !samePublication(existing, bound)) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    this.#credentialHandoffs.set(bound.handoffId, clone(bound));
    return clone(bound);
  }

  async publishCredentialHandoff(
    input: CredentialHandoffMutationInput,
  ): Promise<CredentialHandoffPointer> {
    this.#assertActiveLease(input.lease, input.now);
    const existing = this.#credentialHandoffs.get(input.pointer.handoffId);
    if (
      existing === undefined ||
      !samePointerGeneration(existing, input.pointer) ||
      !pointerHasPublication(existing) ||
      !samePublication(existing, input.pointer) ||
      (existing.state !== "pending" && existing.state !== "published")
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    const published = { ...existing, state: "published" as const };
    this.#credentialHandoffs.set(published.handoffId, clone(published));
    return clone(published);
  }

  async revokeCredentialHandoff(
    input: CredentialHandoffMutationInput,
  ): Promise<CredentialHandoffPointer> {
    this.#assertActiveLease(input.lease, input.now);
    const existing = this.#credentialHandoffs.get(input.pointer.handoffId);
    if (existing === undefined || !samePointerGeneration(existing, input.pointer)) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    const revoked = { ...existing, state: "revoked" as const };
    this.#credentialHandoffs.set(revoked.handoffId, clone(revoked));
    return clone(revoked);
  }

  #assertActiveLease(lease: JobExecutionLease, now: number): void {
    const existing = this.#executionLeases.get(lease.subscriptionId);
    if (
      existing?.ownerId !== lease.ownerId ||
      existing.fencingToken !== lease.fencingToken ||
      existing.expiresAt <= now
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
  }

  async listResources(
    subscriptionId: string,
  ): Promise<readonly ResourceRecord[]> {
    return [...this.#resources.values()]
      .filter((resource) => resource.subscriptionId === subscriptionId)
      .sort((left, right) => left.resourceKey.localeCompare(right.resourceKey))
      .map(clone);
  }

  async putResource(resource: ResourceRecord): Promise<void> {
    const expectedKey = deterministicResourceKey(
      resource.subscriptionId,
      resource.step,
      resource.kind,
      resource.opaqueId,
    );
    if (resource.resourceKey !== expectedKey) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }

    const existing = this.#resources.get(resource.resourceKey);
    if (existing !== undefined) {
      const sameIdentity =
        existing.subscriptionId === resource.subscriptionId &&
        existing.step === resource.step &&
        existing.kind === resource.kind &&
        existing.opaqueId === resource.opaqueId &&
        existing.retention === resource.retention;
      if (!sameIdentity) {
        throw new SafeProvisioningError("STORE_CONFLICT");
      }
      if (existing.retention === "immutable_evidence") {
        // Immutable evidence is append-only. Repeated retention writes are safe.
        return;
      }
    }

    this.#resources.set(resource.resourceKey, clone(resource));
  }
}

function samePointerGeneration(
  left: CredentialHandoffPointer | undefined,
  right: CredentialHandoffPointer,
): boolean {
  return (
    left !== undefined &&
    left.handoffId === right.handoffId &&
    left.subscriptionId === right.subscriptionId &&
    left.jobId === right.jobId &&
    left.activationGeneration === right.activationGeneration &&
    left.publicationGeneration === right.publicationGeneration &&
    left.fencingToken === right.fencingToken
  );
}

function pointerHasPublication(
  value: CredentialHandoffPointer,
): value is CredentialHandoffPointer & Required<CredentialSecretPublication> {
  return (
    value.secretId !== undefined &&
    value.publicationId !== undefined &&
    value.credentialId !== undefined
  );
}

function samePublication(
  left: CredentialHandoffPointer,
  right: CredentialHandoffPointer,
): boolean {
  return (
    left.secretId === right.secretId &&
    left.publicationId === right.publicationId &&
    left.credentialId === right.credentialId
  );
}

function assertLeaseInput(
  subscriptionId: string,
  ownerId: string,
  now: number,
  leaseDurationMs: number,
): void {
  if (
    subscriptionId.length === 0 ||
    ownerId.length === 0 ||
    !Number.isSafeInteger(now) ||
    now < 0 ||
    !Number.isSafeInteger(leaseDurationMs) ||
    leaseDurationMs < 1 ||
    now > Number.MAX_SAFE_INTEGER - leaseDurationMs
  ) {
    throw new SafeProvisioningError("INVALID_STATE");
  }
}
