import { createHash } from "node:crypto";

import { SendMessageCommand, type SQSClient } from "@aws-sdk/client-sqs";

import type { NormalizedStripeEvent } from "../domain.js";

export type AcceptedNormalizedStripeEvent = Exclude<
  NormalizedStripeEvent,
  { readonly type: "ignored" }
>;

export interface ProvisioningQueueMessage {
  version: 1;
  kind: "stripe-event";
  event: AcceptedNormalizedStripeEvent;
}

export class SqsProvisioningQueue {
  readonly #client: Pick<SQSClient, "send">;
  readonly #queueUrl: string;

  constructor(client: Pick<SQSClient, "send">, queueUrl: string) {
    if (!queueUrl) throw new Error("SQS queue URL is required");
    this.#client = client;
    this.#queueUrl = queueUrl;
  }

  async enqueue(event: AcceptedNormalizedStripeEvent): Promise<void> {
    const subscriptionId = (event as { readonly subscriptionId?: unknown })
      .subscriptionId;
    if (typeof subscriptionId !== "string" || subscriptionId.length === 0) {
      throw new Error("Accepted provisioning event requires a subscription ID");
    }
    const message: ProvisioningQueueMessage = {
      version: 1,
      kind: "stripe-event",
      event,
    };

    await this.#client.send(
      new SendMessageCommand({
        QueueUrl: this.#queueUrl,
        MessageBody: JSON.stringify(message),
        MessageDeduplicationId: event.eventId,
        MessageGroupId: subscriptionMessageGroup(subscriptionId),
      }),
    );
  }
}

function subscriptionMessageGroup(subscriptionId: string): string {
  const digest = createHash("sha256").update(subscriptionId, "utf8").digest("hex");
  return `subscription-${digest}`;
}
