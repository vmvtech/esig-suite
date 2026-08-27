import { describe, expect, it } from "vitest";

import {
  PROVISIONING_STEPS,
  SafeProvisioningError,
  deterministicCredentialHandoffId,
  deterministicJobId,
  deterministicResourceKey,
  type DeploymentMode,
  type NormalizedStripeEvent,
  type OneTimeCredentialHandoff,
  type OrderRecord,
  type ProvisioningDriver,
  type ProvisioningStep,
  type ResourceRecord,
} from "../src/domain.js";
import { InMemoryProvisioningStore } from "../src/memory-store.js";
import {
  processStripeEvent,
  runProvisioningJob,
} from "../src/orchestrator.js";

const digest = (character: string): string => character.repeat(64);

const paidEvent = (
  subscriptionId: string,
  mode: DeploymentMode = "shared",
): NormalizedStripeEvent & {
  readonly type: "invoice.paid";
  readonly subscriptionId: string;
} => ({
  eventId: `evt_paid_${subscriptionId}`,
  type: "invoice.paid",
  createdAt: 100,
  payloadDigest: digest("a"),
  subscriptionId,
  customerId: `cus_${subscriptionId}`,
  ownerSubject: `owner_${subscriptionId}`,
  mode,
  plan: mode === "dedicated" ? "scale" : "team",
});

class DeterministicDriver implements ProvisioningDriver {
  readonly calls: ProvisioningStep[] = [];
  readonly compensationCalls: ProvisioningStep[] = [];
  failEveryExecution = false;
  emitOneTimeCredential = false;

  constructor(readonly mode: DeploymentMode) {}

  get requiresCredentialHandoff(): boolean {
    return this.emitOneTimeCredential;
  }

  async executeStep(
    input: Parameters<ProvisioningDriver["executeStep"]>[0],
  ): ReturnType<ProvisioningDriver["executeStep"]> {
    this.calls.push(input.step);
    if (this.failEveryExecution) {
      throw new SafeProvisioningError("PROVIDER_UNAVAILABLE", true);
    }

    const result: Awaited<ReturnType<ProvisioningDriver["executeStep"]>> = {
      resources: [
        {
          kind: `${input.step}_resource`,
          opaqueId: `opaque_${this.mode}_${input.step}`,
          retention: "mutable",
        },
      ],
    };
    return input.step === "api_credential" &&
      this.emitOneTimeCredential &&
      !input.credentialHandoffCompleted
      ? {
          ...result,
          oneTimeCredential: {
            id: "credential_once",
            plaintext: "plaintext_test_credential",
          },
        }
      : result;
  }

  async compensateStep(
    input: Parameters<ProvisioningDriver["compensateStep"]>[0],
  ): ReturnType<ProvisioningDriver["compensateStep"]> {
    this.compensationCalls.push(input.step);
    return {
      dispositions: input.stepResources.map((resource) => ({
        resourceKey: resource.resourceKey,
        status:
          input.step === "api_credential"
            ? "revoked"
            : input.step === "plan_entitlement" ||
                input.step === "activation_metadata" ||
                input.step === "mark_ready"
              ? "disabled"
              : "quarantined",
      })),
    };
  }
}

class RecordingCredentialHandoff implements OneTimeCredentialHandoff {
  readonly deliveries: string[] = [];
  readonly #publications = new Set<string>();

  describePublication(
    input: Parameters<OneTimeCredentialHandoff["describePublication"]>[0],
  ): ReturnType<OneTimeCredentialHandoff["describePublication"]> {
    return {
      secretId: `secret_${input.handoffId}_${input.publicationGeneration}_${input.fencingToken}`,
      publicationId: `publication_${input.credential.id}_${input.publicationGeneration}_${input.fencingToken}`,
      credentialId: input.credential.id,
    };
  }

  async createImmutable(
    input: Parameters<OneTimeCredentialHandoff["createImmutable"]>[0],
  ): ReturnType<OneTimeCredentialHandoff["createImmutable"]> {
    this.deliveries.push(input.credential.plaintext);
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

class RejectFirstVerificationHandoff extends RecordingCredentialHandoff {
  rejected = false;

  override async verifyPublication(
    pointer: Parameters<OneTimeCredentialHandoff["verifyPublication"]>[0],
  ): Promise<boolean> {
    if (!this.rejected) {
      this.rejected = true;
      return false;
    }
    return super.verifyPublication(pointer);
  }
}

class TwoWriteBarrierStore extends InMemoryProvisioningStore {
  #armed = false;
  #arrivals = 0;
  #releaseFirst!: () => void;
  #firstArrival = Promise.resolve();
  orderWriteAttempts = 0;

  arm(): void {
    this.#armed = true;
    this.#arrivals = 0;
    this.#firstArrival = new Promise<void>((resolve) => {
      this.#releaseFirst = resolve;
    });
  }

  override async putOrder(
    value: OrderRecord,
    expectedVersion?: number,
  ): Promise<OrderRecord> {
    this.orderWriteAttempts += 1;
    if (this.#armed && this.#arrivals < 2) {
      this.#arrivals += 1;
      if (this.#arrivals === 1) {
        await this.#firstArrival;
      } else {
        this.#armed = false;
        this.#releaseFirst();
      }
    }
    return super.putOrder(value, expectedVersion);
  }
}

class FailFirstHandoffReceiptStore extends InMemoryProvisioningStore {
  failed = false;

  override async putResource(resource: ResourceRecord): Promise<void> {
    if (!this.failed && resource.kind === "credential_handoff_receipt") {
      this.failed = true;
      throw new SafeProvisioningError("PROVIDER_TRANSIENT", true);
    }
    return super.putResource(resource);
  }
}

describe("event processing", () => {
  it("claims ten concurrent duplicate deliveries once and queues one job", async () => {
    const store = new InMemoryProvisioningStore();
    const event = paidEvent("sub_concurrent");

    const results = await Promise.all(
      Array.from({ length: 10 }, () => processStripeEvent(store, event)),
    );

    expect(results.filter((result) => result.status === "claimed")).toHaveLength(1);
    expect(results.filter((result) => result.status === "duplicate")).toHaveLength(9);
    expect(results.filter((result) => result.queueMessage !== undefined)).toHaveLength(1);
    expect(await store.listEventClaims()).toHaveLength(1);
    expect(await store.getJob("sub_concurrent")).toMatchObject({
      state: "queued",
      subscriptionId: "sub_concurrent",
    });
  });

  it("detects an event-ID payload conflict without mutating the order", async () => {
    const store = new InMemoryProvisioningStore();
    const accepted = paidEvent("sub_conflict");
    const conflicting = {
      ...accepted,
      payloadDigest: digest("b"),
      type: "invoice.payment_failed" as const,
    };

    await processStripeEvent(store, accepted);
    const before = await store.getOrder("sub_conflict");
    const result = await processStripeEvent(store, conflicting);

    expect(result.status).toBe("conflict");
    expect(await store.getOrder("sub_conflict")).toEqual(before);
    expect(await store.listEventClaims()).toHaveLength(1);
  });

  it("reloads and re-reduces when a stale metadata write loses the order CAS race", async () => {
    const subscriptionId = "sub_order_stale_race";
    const store = new TwoWriteBarrierStore();
    await processStripeEvent(store, {
      eventId: "evt_order_initial",
      type: "checkout.session.completed",
      createdAt: 100,
      payloadDigest: digest("1"),
      subscriptionId,
    });
    store.arm();

    await Promise.all([
      processStripeEvent(store, {
        eventId: "evt_order_stale_metadata",
        type: "checkout.session.completed",
        createdAt: 50,
        payloadDigest: digest("2"),
        subscriptionId,
        customerId: "cus_order_race",
        ownerSubject: "owner_order_race",
        mode: "shared",
        plan: "team",
      }),
      processStripeEvent(store, {
        eventId: "evt_order_paid_latest",
        type: "invoice.paid",
        createdAt: 200,
        payloadDigest: digest("3"),
        subscriptionId,
      }),
    ]);

    expect(await store.getOrder(subscriptionId)).toMatchObject({
      version: 2,
      billingState: "active",
      latestEventId: "evt_order_paid_latest",
      customerId: "cus_order_race",
      ownerSubject: "owner_order_race",
      mode: "shared",
      plan: "team",
    });
    expect(store.orderWriteAttempts).toBe(4);
  });

  it("cannot resurrect a terminal order when cancellation and paid race", async () => {
    const subscriptionId = "sub_order_terminal_race";
    const store = new TwoWriteBarrierStore();
    await processStripeEvent(store, {
      eventId: "evt_terminal_initial",
      type: "invoice.paid",
      createdAt: 100,
      payloadDigest: digest("4"),
      subscriptionId,
    });
    store.arm();

    await Promise.all([
      processStripeEvent(store, {
        eventId: "evt_terminal_cancel",
        type: "customer.subscription.deleted",
        createdAt: 150,
        payloadDigest: digest("5"),
        subscriptionId,
      }),
      processStripeEvent(store, {
        eventId: "evt_terminal_paid_newer",
        type: "invoice.paid",
        createdAt: 200,
        payloadDigest: digest("6"),
        subscriptionId,
      }),
    ]);

    expect(await store.getOrder(subscriptionId)).toMatchObject({
      version: 2,
      billingState: "canceled",
      latestEventId: "evt_terminal_paid_newer",
      stateCursor: { eventId: "evt_terminal_cancel" },
    });
    expect(store.orderWriteAttempts).toBe(4);
  });

  it("records unknown event types as ignored without creating work", async () => {
    const store = new InMemoryProvisioningStore();
    const event: NormalizedStripeEvent = {
      eventId: "evt_ignored",
      type: "ignored",
      originalType: "customer.created",
      createdAt: 100,
      payloadDigest: digest("f"),
    };

    const first = await processStripeEvent(store, event);
    const duplicate = await processStripeEvent(store, event);

    expect(first).toEqual({ status: "ignored" });
    expect(duplicate).toEqual({ status: "duplicate" });
    expect(await store.listEventClaims()).toHaveLength(1);
  });
});

describe("resumable provisioning", () => {
  it.each(["shared", "dedicated"] as const)(
    "converges a %s tenant with the matching typed driver",
    async (mode) => {
      const store = new InMemoryProvisioningStore();
      const event = paidEvent(`sub_${mode}`, mode);
      const driver = new DeterministicDriver(mode);

      await processStripeEvent(store, event);
      const result = await runProvisioningJob({
        store,
        driver,
        subscriptionId: event.subscriptionId,
        now: 0,
      });

      expect(result.status).toBe("ready");
      expect(result.job).toMatchObject({
        state: "ready",
        completedSteps: PROVISIONING_STEPS,
      });
      expect(driver.calls).toEqual(PROVISIONING_STEPS);
      expect(await store.listResources(event.subscriptionId)).toHaveLength(
        PROVISIONING_STEPS.length,
      );
    },
  );

  it("fault-injects after every step and resumes without duplicate resources", async () => {
    for (const faultStep of PROVISIONING_STEPS) {
      const subscriptionId = `sub_fault_${faultStep}`;
      const store = new InMemoryProvisioningStore();
      const driver = new DeterministicDriver("dedicated");
      const event = paidEvent(subscriptionId, "dedicated");
      let injected = false;

      await processStripeEvent(store, event, {
        maxAttempts: 3,
        baseDelayMs: 10,
        maxDelayMs: 20,
      });
      const failed = await runProvisioningJob({
        store,
        driver,
        subscriptionId,
        now: 0,
        afterStep: (step) => {
          if (step === faultStep && !injected) {
            injected = true;
            throw new SafeProvisioningError("PROVIDER_UNAVAILABLE", true);
          }
        },
      });

      expect(failed.status).toBe("failed");
      expect(failed.job?.completedSteps).toEqual(
        PROVISIONING_STEPS.slice(0, PROVISIONING_STEPS.indexOf(faultStep)),
      );

      const resumed = await runProvisioningJob({
        store,
        driver,
        subscriptionId,
        now: failed.job?.nextRetryAt ?? Number.NaN,
      });

      expect(resumed.status).toBe("ready");
      const resources = await store.listResources(subscriptionId);
      expect(resources).toHaveLength(PROVISIONING_STEPS.length);
      expect(new Set(resources.map((resource) => resource.resourceKey)).size).toBe(
        resources.length,
      );
      expect(driver.calls.filter((step) => step === faultStep)).toHaveLength(2);
    }
  });

  it("exhausts retryable failures at the configured bound and stores no error text", async () => {
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    driver.failEveryExecution = true;
    await processStripeEvent(store, paidEvent("sub_exhausted"), {
      maxAttempts: 3,
      baseDelayMs: 10,
      maxDelayMs: 20,
    });

    const first = await runProvisioningJob({
      store,
      driver,
      subscriptionId: "sub_exhausted",
      now: 0,
    });
    const second = await runProvisioningJob({
      store,
      driver,
      subscriptionId: "sub_exhausted",
      now: first.job?.nextRetryAt ?? Number.NaN,
    });
    const third = await runProvisioningJob({
      store,
      driver,
      subscriptionId: "sub_exhausted",
      now: second.job?.nextRetryAt ?? Number.NaN,
    });
    const noFourthAttempt = await runProvisioningJob({
      store,
      driver,
      subscriptionId: "sub_exhausted",
      now: 999_999,
    });

    expect(third.job).toMatchObject({
      state: "failed",
      attempt: 3,
      retryExhausted: true,
      lastErrorCode: "PROVIDER_UNAVAILABLE",
    });
    expect(noFourthAttempt.status).toBe("exhausted");
    expect(driver.calls).toHaveLength(3);
    expect(JSON.stringify(third.job)).not.toContain("message");
  });

  it("compensates a persisted effect even when its job checkpoint never committed", async () => {
    const subscriptionId = "sub_cancel_after_effect";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    await processStripeEvent(store, paidEvent(subscriptionId), {
      maxAttempts: 3,
      baseDelayMs: 10,
      maxDelayMs: 20,
    });

    const failed = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
      afterStep: () => {
        throw new SafeProvisioningError("PROVIDER_UNAVAILABLE", true);
      },
    });
    expect(failed.job?.completedSteps).toEqual([]);
    expect((await store.listResources(subscriptionId))[0]?.status).toBe("active");

    const cancellation = await processStripeEvent(store, {
      eventId: "evt_cancel_after_effect",
      type: "customer.subscription.deleted",
      createdAt: 200,
      payloadDigest: digest("9"),
      subscriptionId,
    });
    expect(cancellation.job).toMatchObject({
      state: "compensating",
      completedSteps: ["resolve_tenant"],
    });

    const compensated = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 1_000,
    });
    expect(compensated.status).toBe("disabled");
    expect(driver.compensationCalls).toEqual(["resolve_tenant"]);
    expect((await store.listResources(subscriptionId))[0]?.status).toBe(
      "quarantined",
    );
  });

  it("hands off one-time plaintext durably before checkpoint and never persists it", async () => {
    const subscriptionId = "sub_credential_handoff";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    const credentialHandoff = new RecordingCredentialHandoff();
    driver.emitOneTimeCredential = true;
    let injected = false;
    await processStripeEvent(store, paidEvent(subscriptionId), {
      maxAttempts: 3,
      baseDelayMs: 10,
      maxDelayMs: 20,
    });

    const failed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: 0,
      afterStep: (step) => {
        if (step === "api_credential" && !injected) {
          injected = true;
          throw new SafeProvisioningError("PROVIDER_UNAVAILABLE", true);
        }
      },
    });
    expect(failed.status).toBe("failed");
    expect(credentialHandoff.deliveries).toEqual(["plaintext_test_credential"]);

    const resumed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: failed.job?.nextRetryAt ?? Number.NaN,
    });
    expect(resumed.status).toBe("ready");
    expect(credentialHandoff.deliveries).toHaveLength(1);
    expect(
      driver.calls.filter((step) => step === "api_credential"),
    ).toHaveLength(2);
    expect(
      (await store.listResources(subscriptionId)).some(
        (resource) => resource.kind === "credential_handoff_receipt",
      ),
    ).toBe(true);
    expect(
      JSON.stringify({
        job: await store.getJob(subscriptionId),
        resources: await store.listResources(subscriptionId),
      }),
    ).not.toContain("plaintext_test_credential");
    expect(resumed).not.toHaveProperty("oneTimeCredentials");
  });

  it("recovers a published pointer before local receipt without rotating again", async () => {
    const subscriptionId = "sub_publish_before_receipt";
    const store = new FailFirstHandoffReceiptStore();
    const driver = new DeterministicDriver("shared");
    const credentialHandoff = new RecordingCredentialHandoff();
    driver.emitOneTimeCredential = true;
    await processStripeEvent(store, paidEvent(subscriptionId), {
      maxAttempts: 3,
      baseDelayMs: 10,
      maxDelayMs: 20,
    });

    const failed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: 0,
    });
    expect(failed.status).toBe("failed");
    expect(credentialHandoff.deliveries).toHaveLength(1);

    const resumed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: failed.job?.nextRetryAt ?? Number.NaN,
    });
    expect(resumed.status).toBe("ready");
    expect(credentialHandoff.deliveries).toHaveLength(1);
  });

  it("ignores a stale lifecycle receipt after the pointer advances", async () => {
    const subscriptionId = "sub_stale_receipt_after_repoint";
    const store = new FailFirstHandoffReceiptStore();
    const driver = new DeterministicDriver("shared");
    const credentialHandoff = new RejectFirstVerificationHandoff();
    driver.emitOneTimeCredential = true;
    await processStripeEvent(store, paidEvent(subscriptionId), {
      maxAttempts: 5,
      baseDelayMs: 10,
      maxDelayMs: 20,
    });

    const first = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: 0,
    });
    expect(first.status).toBe("failed");

    const originalExecute = driver.executeStep.bind(driver);
    let crashAfterRepoint = true;
    driver.executeStep = async (input) => {
      if (input.step === "api_credential" && crashAfterRepoint) {
        crashAfterRepoint = false;
        throw new SafeProvisioningError("PROVIDER_TRANSIENT", true);
      }
      return originalExecute(input);
    };
    const second = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: first.job?.nextRetryAt ?? Number.NaN,
    });
    expect(second.status).toBe("failed");

    const handoffId = deterministicCredentialHandoffId(subscriptionId);
    expect(
      await store.getCredentialHandoffPointer(subscriptionId, handoffId),
    ).toMatchObject({ publicationGeneration: 1, state: "pending" });
    await store.putResource({
      resourceKey: deterministicResourceKey(
        subscriptionId,
        "api_credential",
        "credential_handoff_receipt",
        handoffId,
      ),
      subscriptionId,
      step: "api_credential",
      kind: "credential_handoff_receipt",
      opaqueId: handoffId,
      retention: "mutable",
      status: "active",
    });

    const third = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: second.job?.nextRetryAt ?? Number.NaN,
    });
    expect(third.status).toBe("ready");
    expect(credentialHandoff.deliveries).toHaveLength(2);
    expect(
      await store.getCredentialHandoffPointer(subscriptionId, handoffId),
    ).toMatchObject({ publicationGeneration: 2, state: "published" });
  });

  it("reissues under a new publication generation after an unbound pending crash", async () => {
    const subscriptionId = "sub_pending_crash";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    const credentialHandoff = new RecordingCredentialHandoff();
    driver.emitOneTimeCredential = true;
    const original = driver.executeStep.bind(driver);
    let crash = true;
    driver.executeStep = async (input) => {
      if (input.step === "api_credential" && crash) {
        crash = false;
        throw new SafeProvisioningError("PROVIDER_TRANSIENT", true);
      }
      return original(input);
    };
    await processStripeEvent(store, paidEvent(subscriptionId), {
      maxAttempts: 3,
      baseDelayMs: 10,
      maxDelayMs: 20,
    });

    const failed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: 0,
    });
    const resumed = await runProvisioningJob({
      store,
      driver,
      credentialHandoff,
      subscriptionId,
      now: failed.job?.nextRetryAt ?? Number.NaN,
    });
    const handoffId = deterministicCredentialHandoffId(subscriptionId);
    expect(resumed.status).toBe("ready");
    expect(
      await store.getCredentialHandoffPointer(subscriptionId, handoffId),
    ).toMatchObject({ publicationGeneration: 1, state: "published" });
  });

  it("fences a delayed worker so its orphan secret cannot repoint the current handoff", async () => {
    const store = new InMemoryProvisioningStore();
    const handoff = new RecordingCredentialHandoff();
    const subscriptionId = "sub_fenced_publication";
    const handoffId = deterministicCredentialHandoffId(subscriptionId);
    const leaseA = await store.acquireJobExecutionLease(
      subscriptionId,
      "worker-a",
      0,
      10,
    );
    if (leaseA.status !== "acquired") throw new Error("expected lease A");
    const pointerA = await store.beginCredentialHandoff(
      {
        handoffId,
        subscriptionId,
        jobId: deterministicJobId(subscriptionId),
        activationGeneration: 0,
        publicationGeneration: 0,
        fencingToken: leaseA.lease.fencingToken,
        state: "pending",
      },
      leaseA.lease,
      0,
    );
    const inputA = {
      handoffId,
      subscriptionId,
      jobId: deterministicJobId(subscriptionId),
      activationGeneration: 0,
      publicationGeneration: 0,
      fencingToken: leaseA.lease.fencingToken,
      credential: { id: "credential_a", plaintext: "plaintext_a" },
    };
    const boundA = await store.bindCredentialHandoff(
      { pointer: pointerA, lease: leaseA.lease, now: 0 },
      handoff.describePublication(inputA),
    );

    const leaseB = await store.acquireJobExecutionLease(
      subscriptionId,
      "worker-b",
      11,
      10,
    );
    if (leaseB.status !== "acquired") throw new Error("expected lease B");
    const pointerB = await store.beginCredentialHandoff(
      {
        handoffId,
        subscriptionId,
        jobId: deterministicJobId(subscriptionId),
        activationGeneration: 0,
        publicationGeneration: 1,
        fencingToken: leaseB.lease.fencingToken,
        state: "pending",
      },
      leaseB.lease,
      11,
      0,
    );
    await handoff.createImmutable(inputA);

    await expect(
      store.publishCredentialHandoff({
        pointer: boundA,
        lease: leaseA.lease,
        now: 11,
      }),
    ).rejects.toMatchObject({ safeCode: "STORE_CONFLICT" });
    expect(
      await store.getCredentialHandoffPointer(subscriptionId, handoffId),
    ).toEqual(pointerB);
  });

  it("runs suspension compensation effects to a disabled suspension job", async () => {
    const subscriptionId = "sub_suspension_effect";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    await processStripeEvent(store, paidEvent(subscriptionId));
    await runProvisioningJob({ store, driver, subscriptionId, now: 0 });
    await processStripeEvent(store, {
      eventId: "evt_suspension_failed_payment",
      type: "invoice.payment_failed",
      createdAt: 200,
      payloadDigest: digest("7"),
      subscriptionId,
    });

    const suspended = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 1_000,
    });
    expect(suspended).toMatchObject({
      status: "disabled",
      job: { state: "disabled", operation: "suspension" },
    });
    expect(driver.compensationCalls).toEqual([...PROVISIONING_STEPS].reverse());
  });

  it("uses job CAS so a stale worker cannot overwrite cancellation", async () => {
    const subscriptionId = "sub_cas_cancel";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    let releaseEffect!: () => void;
    let reportStarted!: () => void;
    const effectStarted = new Promise<void>((resolve) => {
      reportStarted = resolve;
    });
    const effectGate = new Promise<void>((resolve) => {
      releaseEffect = resolve;
    });
    const originalExecute = driver.executeStep.bind(driver);
    driver.executeStep = async (input) => {
      if (input.step === "resolve_tenant") {
        reportStarted();
        await effectGate;
      }
      return originalExecute(input);
    };
    await processStripeEvent(store, paidEvent(subscriptionId));

    const staleWorker = runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
    });
    await effectStarted;
    const cancellation = await processStripeEvent(store, {
      eventId: "evt_cancel_during_effect",
      type: "customer.subscription.deleted",
      createdAt: 200,
      payloadDigest: digest("0"),
      subscriptionId,
    });
    expect(cancellation.job).toMatchObject({
      state: "compensating",
      completedSteps: ["resolve_tenant"],
    });
    expect(cancellation.queueMessage).toBeDefined();
    releaseEffect();

    const recovered = await staleWorker;
    expect(recovered.status).toBe("disabled");
    expect(await store.getJob(subscriptionId)).toMatchObject({
      state: "disabled",
      operation: "compensation",
      completedSteps: ["resolve_tenant"],
      compensatedSteps: ["resolve_tenant"],
    });
    expect((await store.listResources(subscriptionId))[0]?.status).toBe(
      "quarantined",
    );
  });

  it("holds a durable lease while credential plaintext is in flight", async () => {
    const subscriptionId = "sub_credential_execution_lease";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    driver.emitOneTimeCredential = true;
    const credentialHandoff = new RecordingCredentialHandoff();
    let releaseCredentialEffect!: () => void;
    let reportCredentialEffect!: () => void;
    const credentialEffectStarted = new Promise<void>((resolve) => {
      reportCredentialEffect = resolve;
    });
    const credentialEffectGate = new Promise<void>((resolve) => {
      releaseCredentialEffect = resolve;
    });
    const originalExecute = driver.executeStep.bind(driver);
    driver.executeStep = async (input) => {
      const result = await originalExecute(input);
      if (input.step === "api_credential") {
        reportCredentialEffect();
        await credentialEffectGate;
      }
      return result;
    };
    await processStripeEvent(store, paidEvent(subscriptionId));
    let leaseClock = 10_000;

    const workerA = runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
      credentialHandoff,
      executionOwnerId: "worker-a",
      executionLeaseDurationMs: 1_000,
      executionLeaseClock: () => leaseClock,
    });
    await credentialEffectStarted;

    leaseClock += 100;
    const workerB = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
      credentialHandoff,
      executionOwnerId: "worker-b",
      executionLeaseDurationMs: 1_000,
      executionLeaseClock: () => leaseClock,
    });

    expect(workerB.status).toBe("deferred");
    expect(
      driver.calls.filter((step) => step === "api_credential"),
    ).toHaveLength(1);
    expect(credentialHandoff.deliveries).toHaveLength(0);

    releaseCredentialEffect();
    await expect(workerA).resolves.toMatchObject({ status: "ready" });
    expect(credentialHandoff.deliveries).toEqual([
      "plaintext_test_credential",
    ]);
  });

  it("recovers an expired lease and fences the stale owner", async () => {
    const subscriptionId = "sub_expired_execution_lease";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    await processStripeEvent(store, paidEvent(subscriptionId));
    const crashedClaim = await store.acquireJobExecutionLease(
      subscriptionId,
      "crashed-worker",
      1_000,
      100,
    );
    expect(crashedClaim.status).toBe("acquired");
    if (crashedClaim.status !== "acquired") throw new Error("unreachable");

    let releaseEffect!: () => void;
    let reportEffect!: () => void;
    const effectStarted = new Promise<void>((resolve) => {
      reportEffect = resolve;
    });
    const effectGate = new Promise<void>((resolve) => {
      releaseEffect = resolve;
    });
    const originalExecute = driver.executeStep.bind(driver);
    driver.executeStep = async (input) => {
      const result = await originalExecute(input);
      if (input.step === "resolve_tenant") {
        reportEffect();
        await effectGate;
      }
      return result;
    };

    const recoveredWorker = runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
      executionOwnerId: "recovery-worker",
      executionLeaseDurationMs: 100,
      executionLeaseClock: () => 1_100,
    });
    await effectStarted;

    await expect(
      store.renewJobExecutionLease(crashedClaim.lease, 1_100, 100),
    ).rejects.toMatchObject({ safeCode: "STORE_CONFLICT" });
    await store.releaseJobExecutionLease(crashedClaim.lease);
    const concurrent = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
      executionOwnerId: "third-worker",
      executionLeaseDurationMs: 100,
      executionLeaseClock: () => 1_101,
    });
    expect(concurrent.status).toBe("deferred");
    expect(driver.calls.filter((step) => step === "resolve_tenant")).toHaveLength(
      1,
    );

    releaseEffect();
    await expect(recoveredWorker).resolves.toMatchObject({ status: "ready" });
  });
});

describe("compensation", () => {
  it("runs completed steps in reverse, disables access, and retains immutable evidence", async () => {
    const subscriptionId = "sub_compensate";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    await processStripeEvent(store, paidEvent(subscriptionId));
    await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 0,
    });

    const evidence: ResourceRecord = {
      resourceKey: deterministicResourceKey(
        subscriptionId,
        "mark_ready",
        "signed_document",
        "opaque_evidence_1",
      ),
      subscriptionId,
      step: "mark_ready",
      kind: "signed_document",
      opaqueId: "opaque_evidence_1",
      retention: "immutable_evidence",
      status: "retained",
    };
    await store.putResource(evidence);

    const cancelResult = await processStripeEvent(store, {
      eventId: "evt_cancel_compensate",
      type: "customer.subscription.deleted",
      createdAt: 200,
      payloadDigest: digest("c"),
      subscriptionId,
    });
    expect(cancelResult.queueMessage).toBeDefined();
    expect(cancelResult.job?.state).toBe("compensating");

    const compensated = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 1_000,
    });

    expect(compensated.status).toBe("disabled");
    expect(driver.compensationCalls).toEqual([...PROVISIONING_STEPS].reverse());
    const resources = await store.listResources(subscriptionId);
    expect(resources.find((resource) => resource.resourceKey === evidence.resourceKey)).toEqual(
      evidence,
    );
    expect(
      resources
        .filter((resource) => resource.retention === "mutable")
        .every((resource) => resource.status !== "active"),
    ).toBe(true);
    expect(
      resources.find((resource) => resource.step === "api_credential")?.status,
    ).toBe("revoked");
    expect(resources.find((resource) => resource.step === "mark_ready")?.status).toBe(
      "disabled",
    );
  });

  it("treats refunds as terminal and runs the same disabling compensation", async () => {
    const subscriptionId = "sub_refunded";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    await processStripeEvent(store, paidEvent(subscriptionId));
    await runProvisioningJob({ store, driver, subscriptionId, now: 0 });

    const refund = await processStripeEvent(store, {
      eventId: "evt_refund_terminal",
      type: "charge.refunded",
      createdAt: 200,
      payloadDigest: digest("8"),
      subscriptionId,
    });
    expect(refund.order?.billingState).toBe("refunded");
    expect(refund.job?.state).toBe("compensating");

    const result = await runProvisioningJob({
      store,
      driver,
      subscriptionId,
      now: 1_000,
    });
    expect(result.status).toBe("disabled");
  });

  it("does not let a later active event resurrect a disabled subscription", async () => {
    const subscriptionId = "sub_no_resurrection";
    const store = new InMemoryProvisioningStore();
    const driver = new DeterministicDriver("shared");
    await processStripeEvent(store, paidEvent(subscriptionId));
    await runProvisioningJob({ store, driver, subscriptionId, now: 0 });
    await processStripeEvent(store, {
      eventId: "evt_cancel_terminal",
      type: "customer.subscription.deleted",
      createdAt: 200,
      payloadDigest: digest("d"),
      subscriptionId,
    });

    const latePaid = await processStripeEvent(store, {
      ...paidEvent(subscriptionId),
      eventId: "evt_paid_after_cancel",
      createdAt: 300,
      payloadDigest: digest("e"),
      customerId: "cus_wrong_identity",
      ownerSubject: "owner_wrong_identity",
      mode: "dedicated",
      plan: "scale",
    });

    expect(latePaid.order).toMatchObject({
      billingState: "canceled",
      customerId: `cus_${subscriptionId}`,
      ownerSubject: `owner_${subscriptionId}`,
      mode: "shared",
    });
    expect(latePaid.queueMessage).toBeUndefined();
    await runProvisioningJob({ store, driver, subscriptionId, now: 1_000 });
    expect((await store.getJob(subscriptionId))?.state).toBe("disabled");
  });
});
