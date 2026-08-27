import type { SQSEvent } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";

import {
  PROVISIONING_STEPS,
  SafeProvisioningError,
  type ProvisioningDriver,
} from "../src/domain.js";
import { InMemoryProvisioningStore } from "../src/memory-store.js";
import {
  createProvisioningWorkerHandler,
  handler as failClosedHandler,
} from "../src/handlers/worker.js";

describe("provisioning SQS worker adapter", () => {
  it("passes a verified normalized event through the pure orchestrator and injected driver", async () => {
    const store = new InMemoryProvisioningStore();
    const executeStep = vi.fn<ProvisioningDriver["executeStep"]>(async (input) =>
      input.step === "api_credential"
        ? {
            oneTimeCredential: {
              id: "credential_123",
              plaintext: "ephemeral-test-value",
            },
          }
        : {},
    );
    const driver: ProvisioningDriver = {
      mode: "shared",
      requiresCredentialHandoff: true,
      executeStep,
      compensateStep: vi.fn().mockResolvedValue({}),
    };
    const driverFor = vi.fn().mockReturnValue(driver);
    const credentialHandoff = {
      describePublication: vi.fn((input) => ({
        secretId: `secret_${input.handoffId}`,
        publicationId: `publication_${input.fencingToken}`,
        credentialId: input.credential.id,
      })),
      createImmutable: vi.fn(async (input) => ({
        secretId: `secret_${input.handoffId}`,
        publicationId: `publication_${input.fencingToken}`,
        credentialId: input.credential.id,
      })),
      verifyPublication: vi.fn().mockResolvedValue(false),
    };
    const worker = createProvisioningWorkerHandler({
      store,
      driverFor,
      credentialHandoff,
      now: () => 1_785_844_800_000,
    });

    await expect(worker(queueEvent(queueBody()))).resolves.toEqual({
      batchItemFailures: [],
    });

    expect(driverFor).toHaveBeenCalledWith("shared");
    expect(executeStep).toHaveBeenCalledTimes(PROVISIONING_STEPS.length);
    expect(credentialHandoff.createImmutable).toHaveBeenCalledWith(
      expect.objectContaining({
        subscriptionId: "sub_123",
        credential: { id: "credential_123", plaintext: "ephemeral-test-value" },
      }),
    );
    await expect(store.getJob("sub_123")).resolves.toMatchObject({ state: "ready" });
  });

  it("reports invalid input and retryable orchestration failures by message ID", async () => {
    const store = new InMemoryProvisioningStore();
    const driver: ProvisioningDriver = {
      mode: "shared",
      executeStep: vi
        .fn()
        .mockRejectedValue(new SafeProvisioningError("PROVIDER_TRANSIENT", true)),
      compensateStep: vi.fn().mockResolvedValue({}),
    };
    const worker = createProvisioningWorkerHandler({
      store,
      driverFor: () => driver,
      now: () => 1_785_844_800_000,
    });
    const event = queueEvent("not-json", queueBody());

    await expect(worker(event)).resolves.toEqual({
      batchItemFailures: [
        { itemIdentifier: "message-1" },
        { itemIdentifier: "message-2" },
      ],
    });
    expect(driver.executeStep).not.toHaveBeenCalled();
  });

  it("keeps the default deployment entrypoint fail-closed without calling AWS or providers", async () => {
    await expect(failClosedHandler(queueEvent(queueBody(), queueBody()))).resolves.toEqual({
      batchItemFailures: [
        { itemIdentifier: "message-1" },
        { itemIdentifier: "message-2" },
      ],
    });
  });
});

function queueBody(): string {
  return JSON.stringify({
    version: 1,
    kind: "stripe-event",
    event: {
      eventId: "evt_123",
      type: "invoice.paid",
      createdAt: 1_785_844_800,
      payloadDigest: "a".repeat(64),
      subscriptionId: "sub_123",
      customerId: "cus_123",
      ownerSubject: "owner_123",
      mode: "shared",
      plan: "starter",
    },
  });
}

function queueEvent(...bodies: string[]): SQSEvent {
  return {
    Records: bodies.map((body, index) => ({
      messageId: `message-${index + 1}`,
      receiptHandle: `receipt-${index + 1}`,
      body,
      attributes: {
        ApproximateReceiveCount: "1",
        SentTimestamp: "1785844800000",
        SenderId: "sender",
        ApproximateFirstReceiveTimestamp: "1785844800000",
      },
      messageAttributes: {},
      md5OfBody: "md5",
      eventSource: "aws:sqs",
      eventSourceARN: "arn:aws:sqs:us-east-1:123456789012:queue.fifo",
      awsRegion: "us-east-1",
    })),
  } as SQSEvent;
}
