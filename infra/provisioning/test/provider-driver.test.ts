import { describe, expect, it, vi } from "vitest";

import {
  SafeProvisioningError,
  deterministicCredentialHandoffId,
  deterministicResourceKey,
  deterministicTenantId,
  type OneTimeCredentialHandoff,
  type ProvisionableOrder,
  type ProvisioningIdentity,
  type ProvisioningJob,
  type ProvisioningStep,
  type ResourceRecord,
  type StepExecutionInput,
  type StepExecutionResult,
} from "../src/domain.js";
import { InMemoryProvisioningStore } from "../src/memory-store.js";
import {
  processStripeEvent,
  runProvisioningJob,
} from "../src/orchestrator.js";
import {
  PROVIDER_STATE_RESOURCE_KIND,
  ProviderProvisioningDriver,
} from "../src/providers/driver.js";
import { deriveProviderIdentifiers } from "../src/providers/deterministic.js";
import type {
  DedicatedProviderResources,
  ProvisioningProvider,
  ProvisioningRequest,
  SharedProviderResources,
} from "../src/providers/types.js";

const REGION = "us-east-1";
const OWNER = "owner@example.test";
const PLAINTEXT = "one-time-secret-never-persisted";
const REISSUED_PLAINTEXT = "rotated-secret-never-persisted";

function order(
  mode: "shared" | "dedicated",
  subscriptionId = `sub_driver_${mode}`,
): ProvisionableOrder {
  return {
    version: 0,
    subscriptionId,
    customerId: `cus_driver_${mode}`,
    ownerSubject: OWNER,
    mode,
    plan: mode === "shared" ? "team" : "scale",
    billingState: "active",
    latestEventCreatedAt: 1,
    latestEventId: `evt_driver_${mode}`,
    stateCursor: {
      createdAt: 1,
      precedence: 1,
      eventId: `evt_driver_${mode}`,
    },
  };
}

function job(value: ProvisioningIdentity): ProvisioningJob {
  return {
    version: 1,
    jobId: `job_${value.subscriptionId}`,
    subscriptionId: value.subscriptionId,
    tenantId: deterministicTenantId(value.subscriptionId, value.mode),
    state: "running",
    operation: "provisioning",
    completedSteps: [],
    compensatedSteps: [],
    attempt: 1,
    retryPolicy: { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 100 },
    retryExhausted: false,
  };
}

function executionInput(
  step: ProvisioningStep,
  value: ProvisionableOrder,
  resources: readonly ResourceRecord[] = [],
  credentialHandoffCompleted = false,
): StepExecutionInput {
  return {
    step,
    order: value,
    job: job(value),
    resources,
    stepResources: resources.filter((resource) => resource.step === step),
    credentialHandoffCompleted,
  };
}

function persistResult(
  subscriptionId: string,
  step: ProvisioningStep,
  result: StepExecutionResult,
): Array<Extract<ResourceRecord, { readonly retention: "mutable" }>> {
  return (result.resources ?? []).map((resource) => ({
    resourceKey: deterministicResourceKey(
      subscriptionId,
      step,
      resource.kind,
      resource.opaqueId,
    ),
    subscriptionId,
    step,
    kind: resource.kind,
    opaqueId: resource.opaqueId,
    retention: "mutable" as const,
    status: "active" as const,
  }));
}

function sharedResources(
  value: ProvisionableOrder,
  credentialId = "10000000-0000-4000-8000-000000000001",
  status: SharedProviderResources["status"] = "provisioning",
): SharedProviderResources {
  const identifiers = deriveProviderIdentifiers(value.subscriptionId, "shared");
  return {
    mode: "shared",
    subscriptionId: value.subscriptionId,
    tenantId: identifiers.tenantId,
    storageNamespace: identifiers.storageNamespace,
    credentialId,
    status,
  };
}

function dedicatedResources(
  value: ProvisionableOrder,
  status: DedicatedProviderResources["status"] = "provisioning",
): DedicatedProviderResources {
  const identifiers = deriveProviderIdentifiers(
    value.subscriptionId,
    "dedicated",
  );
  return {
    mode: "dedicated",
    subscriptionId: value.subscriptionId,
    tenantId: identifiers.tenantId,
    projectRef: "abcdefghijklmnopqrst",
    projectName: identifiers.projectName,
    stackId:
      "arn:aws:cloudformation:us-east-1:123456789012:stack/esig/stack-id",
    stackName: identifiers.stackName,
    status,
  };
}

function sharedProvider(value: ProvisionableOrder) {
  const initial = sharedResources(value);
  const provider = {
    mode: "shared" as const,
    provision: vi.fn(
      async (_request: ProvisioningRequest, prior?: SharedProviderResources) =>
        prior === undefined
          ? {
              resources: initial,
              created: true,
              oneTimeCredential: {
                id: initial.credentialId,
                plaintext: PLAINTEXT,
              },
            }
          : { resources: prior, created: false },
    ),
    reissueCredential: vi.fn(
      async (_request: ProvisioningRequest, resources: SharedProviderResources) => {
        const rotated = {
          ...resources,
          credentialId: "20000000-0000-4000-8000-000000000002",
        };
        return {
          resources: rotated,
          oneTimeCredential: {
            id: rotated.credentialId,
            plaintext: REISSUED_PLAINTEXT,
          },
        };
      },
    ),
    markReady: vi.fn(
      async (_request: ProvisioningRequest, resources: SharedProviderResources) =>
        ({ ...resources, status: "ready" as const }),
    ),
    resume: vi.fn(
      async (_request: ProvisioningRequest, resources: SharedProviderResources) => {
        const resumed = {
          ...resources,
          credentialId: "30000000-0000-4000-8000-000000000003",
          status: "provisioning" as const,
        };
        return {
          resources: resumed,
          created: false,
          oneTimeCredential: { id: resumed.credentialId, plaintext: REISSUED_PLAINTEXT },
        };
      },
    ),
    suspend: vi.fn(
      async (_request: ProvisioningRequest, resources: SharedProviderResources) =>
        ({ ...resources, status: "suspended" as const }),
    ),
    disable: vi.fn(
      async (_request: ProvisioningRequest, resources: SharedProviderResources) =>
        ({ ...resources, status: "disabled" as const }),
    ),
    compensate: vi.fn(
      async (_request: ProvisioningRequest, resources: SharedProviderResources) =>
        ({ ...resources, status: "disabled" as const }),
    ),
    compensateUnknown: vi.fn(async () => ({
      mode: "shared" as const,
      tenantId: initial.tenantId,
      outcome: "disabled" as const,
    })),
    suspendUnknown: vi.fn(async () => ({
      mode: "shared" as const,
      tenantId: initial.tenantId,
      outcome: "suspended" as const,
    })),
  } satisfies ProvisioningProvider<SharedProviderResources>;
  return { initial, provider };
}

function dedicatedProvider(value: ProvisionableOrder) {
  const initial = dedicatedResources(value);
  const provider = {
    mode: "dedicated" as const,
    provision: vi.fn(
      async (
        _request: ProvisioningRequest,
        prior?: DedicatedProviderResources,
      ) =>
        prior === undefined
          ? {
              resources: initial,
              created: true,
              oneTimeCredential: {
                id: "credential-dedicated-001",
                plaintext: PLAINTEXT,
              },
            }
          : { resources: prior, created: false },
    ),
    reissueCredential: vi.fn(
      async (
        _request: ProvisioningRequest,
        resources: DedicatedProviderResources,
      ) => ({
        resources,
        oneTimeCredential: {
          id: "credential-dedicated-002",
          plaintext: REISSUED_PLAINTEXT,
        },
      }),
    ),
    markReady: vi.fn(
      async (
        _request: ProvisioningRequest,
        resources: DedicatedProviderResources,
      ) => ({ ...resources, status: "ready" as const }),
    ),
    resume: vi.fn(
      async (_request: ProvisioningRequest, resources: DedicatedProviderResources) => ({
        resources: { ...resources, status: "provisioning" as const },
        created: false,
        oneTimeCredential: {
          id: "credential-dedicated-003",
          plaintext: REISSUED_PLAINTEXT,
        },
      }),
    ),
    suspend: vi.fn(
      async (_request: ProvisioningRequest, resources: DedicatedProviderResources) =>
        ({ ...resources, status: "suspended" as const }),
    ),
    disable: vi.fn(
      async (
        _request: ProvisioningRequest,
        resources: DedicatedProviderResources,
      ) => ({ ...resources, status: "disabled" as const }),
    ),
    compensate: vi.fn(
      async (
        _request: ProvisioningRequest,
        resources: DedicatedProviderResources,
      ) => ({ ...resources, status: "disabled" as const }),
    ),
    compensateUnknown: vi.fn(async () => ({
      mode: "dedicated" as const,
      tenantId: initial.tenantId,
      outcome: "absent" as const,
    })),
    suspendUnknown: vi.fn(async () => ({
      mode: "dedicated" as const,
      tenantId: initial.tenantId,
      outcome: "suspended" as const,
    })),
  } satisfies ProvisioningProvider<DedicatedProviderResources>;
  return { initial, provider };
}

class RecoveryReceiptFailureStore extends InMemoryProvisioningStore {
  #targetHandoffId: string | undefined;
  failed = false;

  arm(targetHandoffId: string): void {
    this.#targetHandoffId = targetHandoffId;
  }

  override async putResource(resource: ResourceRecord): Promise<void> {
    if (
      !this.failed &&
      resource.kind === "credential_handoff_receipt" &&
      resource.opaqueId === this.#targetHandoffId
    ) {
      this.failed = true;
      throw new SafeProvisioningError("PROVIDER_TRANSIENT", true);
    }
    return super.putResource(resource);
  }
}

class PublishedCredentialHandoff implements OneTimeCredentialHandoff {
  readonly #publications = new Set<string>();
  createCount = 0;

  describePublication(
    input: Parameters<OneTimeCredentialHandoff["describePublication"]>[0],
  ): ReturnType<OneTimeCredentialHandoff["describePublication"]> {
    const publicationId = `publication_${input.handoffId}_${input.publicationGeneration}_${input.fencingToken}_${input.credential.id}`;
    return {
      secretId: `secret_${publicationId}`,
      publicationId,
      credentialId: input.credential.id,
    };
  }

  async createImmutable(
    input: Parameters<OneTimeCredentialHandoff["createImmutable"]>[0],
  ): ReturnType<OneTimeCredentialHandoff["createImmutable"]> {
    this.createCount += 1;
    const publication = this.describePublication(input);
    this.#publications.add(publication.publicationId);
    return publication;
  }

  async verifyPublication(
    pointer: Parameters<OneTimeCredentialHandoff["verifyPublication"]>[0],
  ): Promise<boolean> {
    return (
      pointer.publicationId !== undefined &&
      this.#publications.has(pointer.publicationId)
    );
  }
}

describe("ProviderProvisioningDriver", () => {
  it("maps the shared atomic boundary only to api_credential and keeps plaintext ephemeral", async () => {
    const value = order("shared");
    const { provider } = sharedProvider(value);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });

    await expect(
      driver.executeStep(executionInput("owner_membership", value)),
    ).resolves.toEqual({});
    expect(provider.provision).not.toHaveBeenCalled();

    const result = await driver.executeStep(
      executionInput("api_credential", value),
    );

    expect(driver.requiresCredentialHandoff).toBe(true);
    expect(provider.provision).toHaveBeenCalledTimes(1);
    expect(provider.provision).toHaveBeenCalledWith(
      {
        subscriptionId: value.subscriptionId,
        customerId: value.customerId,
        ownerSubject: OWNER,
        planCode: "team",
        region: REGION,
      },
      undefined,
    );
    expect(result.oneTimeCredential).toEqual({
      id: "10000000-0000-4000-8000-000000000001",
      plaintext: PLAINTEXT,
    });
    expect(result.resources).toHaveLength(1);
    expect(result.resources?.[0]).toMatchObject({
      kind: PROVIDER_STATE_RESOURCE_KIND,
      retention: "mutable",
    });
    expect(JSON.stringify(result.resources)).not.toContain(PLAINTEXT);
    expect(JSON.stringify(result.resources)).not.toContain(OWNER);
    expect(provider.markReady).not.toHaveBeenCalled();
  });

  it("maps the dedicated provider to the same atomic API boundary", async () => {
    const value = order("dedicated");
    const { provider } = dedicatedProvider(value);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });

    await driver.executeStep(executionInput("resolve_tenant", value));
    await driver.executeStep(executionInput("plan_entitlement", value));
    const result = await driver.executeStep(
      executionInput("api_credential", value),
    );
    await driver.executeStep(executionInput("storage_namespace", value));
    await driver.executeStep(executionInput("activation_metadata", value));

    expect(provider.provision).toHaveBeenCalledTimes(1);
    expect(result.oneTimeCredential?.plaintext).toBe(PLAINTEXT);
    expect(JSON.stringify(result.resources)).not.toContain(PLAINTEXT);
    expect(provider.markReady).not.toHaveBeenCalled();
  });

  it("passes persisted prior and reissues only when the handoff receipt is missing", async () => {
    const value = order("shared", "sub_driver_reissue");
    const { provider } = sharedProvider(value);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });
    const first = await driver.executeStep(
      executionInput("api_credential", value),
    );
    const firstRecords = persistResult(
      value.subscriptionId,
      "api_credential",
      first,
    );

    const reissued = await driver.executeStep(
      executionInput("api_credential", value, firstRecords, false),
    );
    const reissuedRecords = persistResult(
      value.subscriptionId,
      "api_credential",
      reissued,
    );

    expect(provider.provision).toHaveBeenCalledTimes(1);
    expect(provider.reissueCredential).toHaveBeenCalledTimes(1);
    expect(provider.reissueCredential.mock.calls[0]?.[1]).toEqual(
      sharedResources(value),
    );
    expect(reissued.oneTimeCredential?.plaintext).toBe(REISSUED_PLAINTEXT);
    expect(JSON.stringify(reissued.resources)).not.toContain(
      REISSUED_PLAINTEXT,
    );

    await driver.executeStep(
      executionInput(
        "api_credential",
        value,
        [...firstRecords, ...reissuedRecords],
        true,
      ),
    );

    expect(provider.provision).toHaveBeenCalledTimes(2);
    expect(provider.provision.mock.calls[1]?.[1]).toMatchObject({
      credentialId: "20000000-0000-4000-8000-000000000002",
    });
    expect(provider.reissueCredential).toHaveBeenCalledTimes(1);
  });

  it("calls markReady only at mark_ready and checkpoints the ready state", async () => {
    const value = order("dedicated", "sub_driver_mark_ready");
    const { provider } = dedicatedProvider(value);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });
    const provisioned = await driver.executeStep(
      executionInput("api_credential", value),
    );
    const provisionedRecords = persistResult(
      value.subscriptionId,
      "api_credential",
      provisioned,
    );

    await driver.executeStep(
      executionInput("activation_metadata", value, provisionedRecords, true),
    );
    expect(provider.markReady).not.toHaveBeenCalled();

    const ready = await driver.executeStep(
      executionInput("mark_ready", value, provisionedRecords, true),
    );
    expect(provider.markReady).toHaveBeenCalledTimes(1);
    expect(provider.markReady.mock.calls[0]?.[1]).toEqual(
      dedicatedResources(value),
    );
    expect(ready.resources).toHaveLength(1);
    expect(ready).not.toHaveProperty("oneTimeCredential");

    const readyRecords = persistResult(value.subscriptionId, "mark_ready", ready);
    await driver.executeStep(
      executionInput(
        "mark_ready",
        value,
        [...provisionedRecords, ...readyRecords],
        true,
      ),
    );
    expect(provider.markReady.mock.calls[1]?.[1]).toMatchObject({
      status: "ready",
    });
  });

  it("disables known resources before returning valid compensation dispositions", async () => {
    const activeOrder = order("shared", "sub_driver_compensate");
    const canceledOrder: ProvisioningIdentity = {
      ...activeOrder,
      billingState: "canceled",
    };
    const { provider } = sharedProvider(activeOrder);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });
    const provisioned = await driver.executeStep(
      executionInput("api_credential", activeOrder),
    );
    const providerRecords = persistResult(
      activeOrder.subscriptionId,
      "api_credential",
      provisioned,
    );
    const receipt: ResourceRecord = {
      resourceKey: "resource_handoff_receipt",
      subscriptionId: activeOrder.subscriptionId,
      step: "api_credential",
      kind: "credential_handoff_receipt",
      opaqueId: "handoff_receipt",
      retention: "mutable",
      status: "active",
    };

    const result = await driver.compensateStep({
      step: "api_credential",
      order: canceledOrder,
      job: { ...job(canceledOrder), operation: "compensation" },
      resources: [...providerRecords, receipt],
      stepResources: [...providerRecords, receipt],
      credentialHandoffCompleted: true,
    });

    expect(provider.compensate).toHaveBeenCalledTimes(1);
    expect(provider.compensate.mock.calls[0]?.[1]).toEqual(
      sharedResources(activeOrder),
    );
    expect(result.dispositions).toEqual(
      [...providerRecords, receipt].map((resource) => ({
        resourceKey: resource.resourceKey,
        status: "revoked",
      })),
    );

    await driver.compensateStep({
      step: "plan_entitlement",
      order: canceledOrder,
      job: { ...job(canceledOrder), operation: "compensation" },
      resources: providerRecords.map((resource) => ({
        ...resource,
        status: "revoked" as const,
      })),
      stepResources: [],
      credentialHandoffCompleted: true,
    });
    expect(provider.compensate).toHaveBeenCalledTimes(1);
  });

  it("suspends then resumes the same provider identity with a fresh credential", async () => {
    const value = order("shared");
    const { provider } = sharedProvider(value);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });
    const initial = await driver.executeStep(executionInput("api_credential", value));
    const providerResource = initial.resources![0]!;
    const persisted = {
      resourceKey: deterministicResourceKey(
        value.subscriptionId,
        "api_credential",
        providerResource.kind,
        providerResource.opaqueId,
      ),
      subscriptionId: value.subscriptionId,
      step: "api_credential" as const,
      ...providerResource,
      retention: "mutable" as const,
      status: "active" as const,
    };
    const pastDue = { ...value, billingState: "past_due" as const };
    const suspended = await driver.compensateStep({
      ...executionInput("api_credential", value),
      order: pastDue,
      resources: [persisted],
      stepResources: [persisted],
    });
    expect(provider.suspend).toHaveBeenCalledTimes(1);
    expect(suspended.resources).toHaveLength(1);

    const suspendedResource = suspended.resources![0]!;
    const persistedSuspended = {
      resourceKey: deterministicResourceKey(
        value.subscriptionId,
        "api_credential",
        suspendedResource.kind,
        suspendedResource.opaqueId,
      ),
      subscriptionId: value.subscriptionId,
      step: "api_credential" as const,
      ...suspendedResource,
      retention: "mutable" as const,
      status: "active" as const,
    };
    const resumed = await driver.executeStep({
      ...executionInput("api_credential", value),
      job: {
        ...executionInput("api_credential", value).job,
        activationGeneration: 1,
      },
      resources: [persisted, persistedSuspended],
      stepResources: [persisted, persistedSuspended],
      credentialHandoffCompleted: false,
    });
    expect(provider.resume).toHaveBeenCalledTimes(1);
    expect(resumed.oneTimeCredential?.plaintext).toBe(REISSUED_PLAINTEXT);
    expect(resumed.oneTimeCredential?.id).not.toBe(initial.oneTimeCredential?.id);
  });

  it("reuses the persisted paid-recovery snapshot after publish-before-checkpoint", async () => {
    const subscriptionId = "sub_driver_paid_recovery_checkpoint";
    const value = order("shared", subscriptionId);
    const { provider } = sharedProvider(value);
    const driver = new ProviderProvisioningDriver({ provider, region: REGION });
    const store = new RecoveryReceiptFailureStore();
    const credentialHandoff = new PublishedCredentialHandoff();
    const identity = {
      customerId: value.customerId,
      ownerSubject: value.ownerSubject,
      mode: value.mode,
      plan: value.plan,
    } as const;

    await processStripeEvent(
      store,
      {
        eventId: "evt_driver_paid_initial",
        type: "invoice.paid",
        createdAt: 100,
        payloadDigest: "a".repeat(64),
        subscriptionId,
        ...identity,
      },
      { maxAttempts: 5, baseDelayMs: 10, maxDelayMs: 20 },
    );
    await expect(
      runProvisioningJob({
        store,
        driver,
        credentialHandoff,
        subscriptionId,
        now: 0,
      }),
    ).resolves.toMatchObject({ status: "ready" });

    await processStripeEvent(store, {
      eventId: "evt_driver_payment_failed",
      type: "invoice.payment_failed",
      createdAt: 200,
      payloadDigest: "b".repeat(64),
      subscriptionId,
    });
    await expect(
      runProvisioningJob({
        store,
        driver,
        credentialHandoff,
        subscriptionId,
        now: 1_000,
      }),
    ).resolves.toMatchObject({
      status: "disabled",
      job: { operation: "suspension" },
    });

    const recoveryHandoffId = deterministicCredentialHandoffId(
      subscriptionId,
      1,
    );
    store.arm(recoveryHandoffId);
    const recovery = await processStripeEvent(store, {
      eventId: "evt_driver_paid_recovery",
      type: "invoice.paid",
      createdAt: 300,
      payloadDigest: "c".repeat(64),
      subscriptionId,
      ...identity,
    });
    expect(recovery.job).toMatchObject({
      operation: "provisioning",
      activationGeneration: 1,
    });

    const failed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: 2_000,
    });
    expect(failed.status).toBe("failed");
    expect(store.failed).toBe(true);
    expect(provider.resume).toHaveBeenCalledTimes(1);
    expect(
      await store.getCredentialHandoffPointer(
        subscriptionId,
        recoveryHandoffId,
      ),
    ).toMatchObject({ state: "published", activationGeneration: 1 });

    const resumed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: failed.job?.nextRetryAt ?? Number.NaN,
    });
    expect(resumed).toMatchObject({
      status: "ready",
      job: { state: "ready", activationGeneration: 1 },
    });
    expect(provider.resume).toHaveBeenCalledTimes(1);
    expect(credentialHandoff.createCount).toBe(2);
  });

  it.each(["shared", "dedicated"] as const)(
    "uses %s compensateUnknown when the provider snapshot was lost",
    async (mode) => {
      const value = order(mode, `sub_driver_unknown_${mode}`);
      const setup =
        mode === "shared" ? sharedProvider(value) : dedicatedProvider(value);
      const driver = new ProviderProvisioningDriver({
        provider: setup.provider as ProvisioningProvider<
          SharedProviderResources | DedicatedProviderResources
        >,
        region: REGION,
      });
      const canceledOrder: ProvisioningIdentity = {
        ...value,
        billingState: "canceled",
      };

      const result = await driver.compensateStep({
        step: "api_credential",
        order: canceledOrder,
        job: { ...job(canceledOrder), operation: "compensation" },
        resources: [],
        stepResources: [],
        credentialHandoffCompleted: false,
      });

      expect(setup.provider.compensateUnknown).toHaveBeenCalledTimes(1);
      expect(setup.provider.compensate).not.toHaveBeenCalled();
      expect(result).toEqual({ dispositions: [] });
    },
  );
});
