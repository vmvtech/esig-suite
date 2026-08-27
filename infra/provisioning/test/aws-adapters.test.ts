import { createHash } from "node:crypto";

import { GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { SendMessageCommand } from "@aws-sdk/client-sqs";
import {
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { describe, expect, it, vi } from "vitest";

import { DynamoEventLedger } from "../src/aws/dynamo-event-ledger.js";
import { DynamoProvisioningStore } from "../src/aws/dynamo-provisioning-store.js";
import { SqsProvisioningQueue } from "../src/aws/provisioning-queue.js";
import { SecretsManagerSecretCache } from "../src/aws/secret-cache.js";
import {
  deterministicJobId,
  deterministicResourceKey,
  type OrderRecord,
  type ProvisioningJob,
  type ResourceRecord,
} from "../src/domain.js";

const now = new Date("2026-08-04T12:00:00.000Z");

describe("DynamoEventLedger", () => {
  it("claims an event with one conditional single-table write and a delivery lease", async () => {
    const send = vi.fn().mockResolvedValue({});
    const ledger = new DynamoEventLedger({ send } as never, "control-plane", {
      now: () => now,
      token: () => "delivery-token",
      leaseSeconds: 60,
    });

    await expect(
      ledger.claimEvent({
        eventId: "evt_123",
        eventType: "invoice.paid",
        eventCreated: 1_785_844_800,
        payloadDigest: "abc123",
        shouldEnqueue: true,
      }),
    ).resolves.toEqual({ outcome: "deliver", deliveryToken: "delivery-token" });

    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(PutCommand);
    expect(command.input).toMatchObject({
      TableName: "control-plane",
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      Item: {
        pk: "EVENT#evt_123",
        sk: "EVENT",
        recordType: "EVENT",
        deliveryStatus: "pending",
        deliveryLeaseOwner: "delivery-token",
      },
    });
  });

  it("does not reacquire a live delivery lease for a concurrent duplicate", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(conditionalFailure())
      .mockResolvedValueOnce({
        Item: {
          pk: "EVENT#evt_123",
          sk: "EVENT",
          payloadDigest: "abc123",
          deliveryStatus: "pending",
          deliveryLeaseExpiresAt: Math.floor(now.getTime() / 1_000) + 30,
        },
      });
    const ledger = new DynamoEventLedger({ send } as never, "control-plane", {
      now: () => now,
    });

    await expect(
      ledger.claimEvent({
        eventId: "evt_123",
        eventType: "invoice.paid",
        eventCreated: 1,
        payloadDigest: "abc123",
        shouldEnqueue: true,
      }),
    ).resolves.toEqual({ outcome: "in-flight" });

    expect(send.mock.calls[0]![0]).toBeInstanceOf(PutCommand);
    expect(send.mock.calls[1]![0]).toBeInstanceOf(GetCommand);
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("reacquires an expired delivery lease for safe FIFO retry", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(conditionalFailure())
      .mockResolvedValueOnce({
        Item: {
          pk: "EVENT#evt_123",
          sk: "EVENT",
          payloadDigest: "abc123",
          deliveryStatus: "pending",
          deliveryLeaseExpiresAt: Math.floor(now.getTime() / 1_000) - 1,
        },
      })
      .mockResolvedValueOnce({});
    const ledger = new DynamoEventLedger({ send } as never, "control-plane", {
      now: () => now,
      token: () => "retry-token",
    });

    await expect(
      ledger.claimEvent({
        eventId: "evt_123",
        eventType: "invoice.paid",
        eventCreated: 1,
        payloadDigest: "abc123",
        shouldEnqueue: true,
      }),
    ).resolves.toEqual({ outcome: "deliver", deliveryToken: "retry-token" });

    const command = send.mock.calls[2]![0];
    expect(command).toBeInstanceOf(UpdateCommand);
    expect(command.input.ConditionExpression).toContain("deliveryLeaseExpiresAt <= :now");
  });

  it("records unsupported event types as ignored without a delivery lease", async () => {
    const send = vi.fn().mockResolvedValue({});
    const ledger = new DynamoEventLedger({ send } as never, "control-plane", {
      now: () => now,
    });

    await expect(
      ledger.claimEvent({
        eventId: "evt_unknown",
        eventType: "radar.early_fraud_warning.created",
        eventCreated: 1,
        payloadDigest: "digest",
        shouldEnqueue: false,
      }),
    ).resolves.toEqual({ outcome: "ignored" });

    expect(send.mock.calls[0]![0].input.Item).toMatchObject({ deliveryStatus: "ignored" });
    expect(send.mock.calls[0]![0].input.Item).not.toHaveProperty("deliveryLeaseOwner");
  });

  it("marks enqueue completion only for the current lease owner", async () => {
    const send = vi.fn().mockResolvedValue({});
    const ledger = new DynamoEventLedger({ send } as never, "control-plane", {
      now: () => now,
    });

    await ledger.markEnqueued("evt_123", "delivery-token");

    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(UpdateCommand);
    expect(command.input).toMatchObject({
      Key: { pk: "EVENT#evt_123", sk: "EVENT" },
      ConditionExpression: "deliveryStatus = :pending AND deliveryLeaseOwner = :owner",
    });
  });

  it("rejects a reused Stripe event ID with a different verified payload", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(conditionalFailure())
      .mockResolvedValueOnce({
        Item: {
          pk: "EVENT#evt_123",
          sk: "EVENT",
          payloadDigest: "different",
          deliveryStatus: "enqueued",
        },
      });
    const ledger = new DynamoEventLedger({ send } as never, "control-plane", {
      now: () => now,
    });

    await expect(
      ledger.claimEvent({
        eventId: "evt_123",
        eventType: "invoice.paid",
        eventCreated: 1,
        payloadDigest: "abc123",
        shouldEnqueue: true,
      }),
    ).rejects.toThrow("payload digest conflict");
  });
});

describe("SecretsManagerSecretCache", () => {
  it("fetches a JSON-wrapped webhook secret once per warm cache", async () => {
    const send = vi.fn().mockResolvedValue({
      SecretString: JSON.stringify({ webhookSecret: "whsec_test" }),
    });
    const cache = new SecretsManagerSecretCache({ send } as never, "secret-arn");

    await expect(Promise.all([cache.get(), cache.get()])).resolves.toEqual([
      "whsec_test",
      "whsec_test",
    ]);
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]![0]).toBeInstanceOf(GetSecretValueCommand);
  });

  it("does not cache a transient Secrets Manager failure", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(new Error("temporary"))
      .mockResolvedValueOnce({ SecretString: "whsec_recovered" });
    const cache = new SecretsManagerSecretCache({ send } as never, "secret-arn");

    await expect(cache.get()).rejects.toThrow("temporary");
    await expect(cache.get()).resolves.toBe("whsec_recovered");
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("refreshes a warm secret after the bounded cache TTL", async () => {
    let clock = 10_000;
    const send = vi
      .fn()
      .mockResolvedValueOnce({ SecretString: "whsec_first" })
      .mockResolvedValueOnce({ SecretString: "whsec_rotated" });
    const cache = new SecretsManagerSecretCache({ send } as never, "secret-arn", {
      ttlMs: 1_000,
      now: () => clock,
    });

    await expect(cache.get()).resolves.toBe("whsec_first");
    clock += 999;
    await expect(cache.get()).resolves.toBe("whsec_first");
    clock += 1;
    await expect(cache.get()).resolves.toBe("whsec_rotated");
    expect(send).toHaveBeenCalledTimes(2);
  });
});

describe("SqsProvisioningQueue", () => {
  it("uses the Stripe event ID as the FIFO deduplication key", async () => {
    const send = vi.fn().mockResolvedValue({});
    const queue = new SqsProvisioningQueue({ send } as never, "queue-url");
    const event = normalizedEvent();

    await queue.enqueue(event);

    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(SendMessageCommand);
    expect(command.input).toMatchObject({
      QueueUrl: "queue-url",
      MessageDeduplicationId: "evt_123",
      MessageGroupId: `subscription-${createHash("sha256")
        .update("sub_123")
        .digest("hex")}`,
    });
    expect(JSON.parse(command.input.MessageBody)).toMatchObject({
      version: 1,
      kind: "stripe-event",
      event: { eventId: "evt_123", type: "invoice.paid" },
    });
  });

  it("rejects an accepted queue event without a subscription ID", async () => {
    const send = vi.fn();
    const queue = new SqsProvisioningQueue({ send } as never, "queue-url");

    await expect(
      queue.enqueue({
        ...normalizedEvent(),
        subscriptionId: undefined,
      } as never),
    ).rejects.toThrow("requires a subscription ID");
    expect(send).not.toHaveBeenCalled();
  });
});

describe("DynamoProvisioningStore", () => {
  it("uses an immutable conditional EVENT claim and classifies a matching duplicate", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(conditionalFailure())
      .mockResolvedValueOnce({
        Item: {
          pk: "EVENT#evt_123",
          sk: "EVENT",
          recordType: "EVENT",
          eventId: "evt_123",
          eventType: "invoice.paid",
          createdAt: 1_785_844_800,
          payloadDigest: "a".repeat(64),
          subscriptionId: "sub_123",
        },
      });
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(
      store.claimEvent({
        eventId: "evt_123",
        eventType: "invoice.paid",
        createdAt: 1_785_844_800,
        payloadDigest: "a".repeat(64),
        subscriptionId: "sub_123",
      }),
    ).resolves.toMatchObject({ status: "duplicate" });

    expect(send.mock.calls[0]![0]).toBeInstanceOf(PutCommand);
    expect(send.mock.calls[0]![0].input).toMatchObject({
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      Item: { pk: "EVENT#evt_123", sk: "EVENT", recordType: "EVENT" },
    });
    expect(send.mock.calls[1]![0]).toBeInstanceOf(GetCommand);
  });

  it("writes ORDER and JOB records under deterministic subscription keys", async () => {
    const send = vi.fn().mockResolvedValue({});
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");
    const order = orderRecord();
    const job: ProvisioningJob = {
      version: 0,
      jobId: deterministicJobId("sub_123"),
      subscriptionId: "sub_123",
      tenantId: "tenant_shared_123",
      state: "queued",
      operation: "provisioning",
      completedSteps: [],
      compensatedSteps: [],
      attempt: 0,
      retryPolicy: { maxAttempts: 5, baseDelayMs: 1_000, maxDelayMs: 60_000 },
      retryExhausted: false,
    };

    await store.putOrder(order);
    await expect(store.putJob(job)).resolves.toEqual(job);

    expect(send.mock.calls[0]![0]).toBeInstanceOf(PutCommand);
    expect(send.mock.calls[0]![0].input.Item).toMatchObject({
      pk: "SUBSCRIPTION#sub_123",
      sk: "ORDER#sub_123",
      recordType: "ORDER",
      version: 0,
    });
    expect(send.mock.calls[1]![0]).toBeInstanceOf(PutCommand);
    expect(send.mock.calls[1]![0].input.Item).toMatchObject({
      pk: "SUBSCRIPTION#sub_123",
      sk: "JOB#sub_123",
      recordType: "JOB",
      jobId: deterministicJobId("sub_123"),
      version: 0,
    });
  });

  it("increments ORDER version only when its persisted CAS token matches", async () => {
    const send = vi.fn().mockResolvedValue({});
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");
    const order = { ...orderRecord(), version: 4 };

    await expect(store.putOrder(order, 4)).resolves.toEqual({
      ...order,
      version: 5,
    });

    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(PutCommand);
    expect(command.input).toMatchObject({
      ConditionExpression: "#version = :expectedVersion",
      ExpressionAttributeNames: { "#version": "version" },
      ExpressionAttributeValues: { ":expectedVersion": 4 },
      Item: { version: 5 },
    });
  });

  it("rejects a stale ORDER write when DynamoDB loses the version race", async () => {
    const send = vi.fn().mockRejectedValue(conditionalFailure());
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(store.putOrder({ ...orderRecord(), version: 2 }, 2)).rejects.toMatchObject({
      safeCode: "STORE_CONFLICT",
      retryable: true,
    });
  });

  it("changes the authoritative handoff pointer only in a live-lease transaction", async () => {
    const send = vi.fn().mockResolvedValue({});
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");
    const lease = {
      subscriptionId: "sub_123",
      ownerId: "worker-a",
      fencingToken: 7,
      expiresAt: 20_000,
    };
    const pointer = {
      handoffId: "handoff_123",
      subscriptionId: "sub_123",
      jobId: deterministicJobId("sub_123"),
      activationGeneration: 2,
      publicationGeneration: 0,
      fencingToken: 7,
      state: "pending" as const,
    };

    await expect(
      store.beginCredentialHandoff(pointer, lease, 10_000),
    ).resolves.toEqual(pointer);

    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(TransactWriteCommand);
    expect(command.input.TransactItems?.[0]?.ConditionCheck).toMatchObject({
      Key: {
        pk: "SUBSCRIPTION#sub_123",
        sk: "JOB_EXECUTION_LEASE#sub_123",
      },
      ConditionExpression:
        "ownerId = :leaseOwner AND fencingToken = :leaseFence AND expiresAt > :now",
      ExpressionAttributeValues: {
        ":leaseOwner": "worker-a",
        ":leaseFence": 7,
        ":now": 10_000,
      },
    });
    expect(command.input.TransactItems?.[1]?.Put?.Item).toMatchObject({
      sk: "CREDENTIAL_HANDOFF#handoff_123",
      recordType: "CREDENTIAL_HANDOFF",
      state: "pending",
    });
    expect(JSON.stringify(command.input)).not.toContain("plaintext");
  });

  it("increments a JOB version only when the persisted CAS token matches", async () => {
    const send = vi.fn().mockResolvedValue({});
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");
    const job: ProvisioningJob = {
      version: 4,
      jobId: deterministicJobId("sub_123"),
      subscriptionId: "sub_123",
      tenantId: "tenant_shared_123",
      state: "running",
      operation: "provisioning",
      completedSteps: ["resolve_tenant"],
      compensatedSteps: [],
      attempt: 1,
      retryPolicy: { maxAttempts: 5, baseDelayMs: 1_000, maxDelayMs: 60_000 },
      retryExhausted: false,
    };

    await expect(store.putJob(job, 4)).resolves.toEqual({ ...job, version: 5 });

    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(PutCommand);
    expect(command.input).toMatchObject({
      ConditionExpression: "jobId = :jobId AND #version = :expectedVersion",
      ExpressionAttributeNames: { "#version": "version" },
      ExpressionAttributeValues: {
        ":jobId": deterministicJobId("sub_123"),
        ":expectedVersion": 4,
      },
      Item: { version: 5 },
    });
  });

  it("rejects a stale JOB write when DynamoDB loses the version race", async () => {
    const send = vi.fn().mockRejectedValue(conditionalFailure());
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");
    const job: ProvisioningJob = {
      version: 2,
      jobId: deterministicJobId("sub_123"),
      subscriptionId: "sub_123",
      tenantId: "tenant_shared_123",
      state: "running",
      operation: "provisioning",
      completedSteps: [],
      compensatedSteps: [],
      attempt: 1,
      retryPolicy: { maxAttempts: 5, baseDelayMs: 1_000, maxDelayMs: 60_000 },
      retryExhausted: false,
    };

    await expect(store.putJob(job, 2)).rejects.toMatchObject({
      safeCode: "STORE_CONFLICT",
      retryable: true,
    });
  });

  it("atomically acquires an expired execution lease with a new fence", async () => {
    const send = vi.fn().mockResolvedValue({
      Attributes: {
        pk: "SUBSCRIPTION#sub_123",
        sk: "JOB_EXECUTION_LEASE#sub_123",
        recordType: "JOB_EXECUTION_LEASE",
        subscriptionId: "sub_123",
        ownerId: "worker-a",
        fencingToken: 2,
        expiresAt: 11_000,
      },
    });
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(
      store.acquireJobExecutionLease("sub_123", "worker-a", 10_000, 1_000),
    ).resolves.toEqual({
      status: "acquired",
      lease: {
        subscriptionId: "sub_123",
        ownerId: "worker-a",
        fencingToken: 2,
        expiresAt: 11_000,
      },
    });

    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(UpdateCommand);
    expect(command.input).toMatchObject({
      Key: {
        pk: "SUBSCRIPTION#sub_123",
        sk: "JOB_EXECUTION_LEASE#sub_123",
      },
      ConditionExpression: "attribute_not_exists(pk) OR expiresAt <= :now",
      ExpressionAttributeValues: {
        ":ownerId": "worker-a",
        ":expiresAt": 11_000,
        ":now": 10_000,
        ":zero": 0,
        ":one": 1,
      },
      ReturnValues: "ALL_NEW",
    });
  });

  it("defers when another worker owns a live execution lease", async () => {
    const send = vi.fn().mockRejectedValue(conditionalFailure());
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(
      store.acquireJobExecutionLease("sub_123", "worker-b", 10_000, 1_000),
    ).resolves.toEqual({ status: "held" });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("renews and releases an execution lease only for its fencing owner", async () => {
    const lease = {
      subscriptionId: "sub_123",
      ownerId: "worker-a",
      fencingToken: 3,
      expiresAt: 11_000,
    } as const;
    const send = vi
      .fn()
      .mockResolvedValueOnce({
        Attributes: {
          pk: "SUBSCRIPTION#sub_123",
          sk: "JOB_EXECUTION_LEASE#sub_123",
          recordType: "JOB_EXECUTION_LEASE",
          ...lease,
          expiresAt: 11_500,
        },
      })
      .mockResolvedValueOnce({});
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(
      store.renewJobExecutionLease(lease, 10_500, 1_000),
    ).resolves.toEqual({ ...lease, expiresAt: 11_500 });
    await store.releaseJobExecutionLease({ ...lease, expiresAt: 11_500 });

    const renew = send.mock.calls[0]![0];
    expect(renew).toBeInstanceOf(UpdateCommand);
    expect(renew.input).toMatchObject({
      ConditionExpression:
        "ownerId = :ownerId AND fencingToken = :fencingToken AND expiresAt > :now",
      ExpressionAttributeValues: {
        ":ownerId": "worker-a",
        ":fencingToken": 3,
        ":expiresAt": 11_500,
        ":now": 10_500,
      },
    });
    const release = send.mock.calls[1]![0];
    expect(release).toBeInstanceOf(UpdateCommand);
    expect(release.input).toMatchObject({
      UpdateExpression: "SET expiresAt = :releasedAt",
      ConditionExpression: "ownerId = :ownerId AND fencingToken = :fencingToken",
      ExpressionAttributeValues: {
        ":ownerId": "worker-a",
        ":fencingToken": 3,
        ":releasedAt": 0,
      },
    });
  });

  it("maps an expired or superseded lease renewal to retryable conflict", async () => {
    const send = vi.fn().mockRejectedValue(conditionalFailure());
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(
      store.renewJobExecutionLease(
        {
          subscriptionId: "sub_123",
          ownerId: "stale-worker",
          fencingToken: 1,
          expiresAt: 10_000,
        },
        10_000,
        1_000,
      ),
    ).rejects.toMatchObject({
      safeCode: "STORE_CONFLICT",
      retryable: true,
    });
  });

  it("paginates RESOURCE records and hydrates storage keys away", async () => {
    const first = resourceRecord("bucket-z");
    const second = resourceRecord("bucket-a");
    const send = vi
      .fn()
      .mockResolvedValueOnce({
        Items: [storedResource(first)],
        LastEvaluatedKey: {
          pk: "SUBSCRIPTION#sub_123",
          sk: `RESOURCE#${first.resourceKey}`,
        },
      })
      .mockResolvedValueOnce({ Items: [storedResource(second)] });
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await expect(store.listResources("sub_123")).resolves.toEqual(
      [first, second].sort((left, right) =>
        left.resourceKey.localeCompare(right.resourceKey),
      ),
    );

    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(QueryCommand);
    expect(command.input).toMatchObject({
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: {
        ":pk": "SUBSCRIPTION#sub_123",
        ":prefix": "RESOURCE#",
      },
      ConsistentRead: true,
    });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1]![0].input.ExclusiveStartKey).toEqual({
      pk: "SUBSCRIPTION#sub_123",
      sk: `RESOURCE#${first.resourceKey}`,
    });
  });

  it("never rewrites an existing immutable-evidence resource", async () => {
    const resource = resourceRecord("signed-envelope");
    const send = vi.fn().mockResolvedValueOnce({
      Item: {
        pk: "SUBSCRIPTION#sub_123",
        sk: `RESOURCE#${resource.resourceKey}`,
        recordType: "RESOURCE",
        ...resource,
      },
    });
    const store = new DynamoProvisioningStore({ send } as never, "control-plane");

    await store.putResource(resource);

    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]![0]).toBeInstanceOf(GetCommand);
  });
});

function normalizedEvent() {
  return {
    eventId: "evt_123",
    createdAt: 1_785_844_800,
    payloadDigest: "digest",
    type: "invoice.paid",
    subscriptionId: "sub_123",
  } as const;
}

function conditionalFailure(): Error {
  return Object.assign(new Error("duplicate"), {
    name: "ConditionalCheckFailedException",
  });
}

function orderRecord(): OrderRecord {
  return {
    version: 0,
    subscriptionId: "sub_123",
    customerId: "cus_123",
    ownerSubject: "owner_123",
    mode: "shared",
    plan: "starter",
    billingState: "active",
    latestEventCreatedAt: 1_785_844_800,
    latestEventId: "evt_123",
    stateCursor: {
      createdAt: 1_785_844_800,
      precedence: 2,
      eventId: "evt_123",
    },
  };
}

function resourceRecord(opaqueId: string): ResourceRecord {
  return {
    resourceKey: deterministicResourceKey(
      "sub_123",
      "storage_namespace",
      "signed-document",
      opaqueId,
    ),
    subscriptionId: "sub_123",
    step: "storage_namespace",
    kind: "signed-document",
    opaqueId,
    retention: "immutable_evidence",
    status: "retained",
  };
}

function storedResource(resource: ResourceRecord): Record<string, unknown> {
  return {
    pk: `SUBSCRIPTION#${resource.subscriptionId}`,
    sk: `RESOURCE#${resource.resourceKey}`,
    recordType: "RESOURCE",
    ...resource,
  };
}
