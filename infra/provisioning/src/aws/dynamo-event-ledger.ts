import { randomUUID } from "node:crypto";

import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import {
  GetCommand,
  type GetCommandOutput,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

export interface EventClaimInput {
  eventId: string;
  eventType: string;
  eventCreated: number;
  payloadDigest: string;
  subscriptionId?: string;
  shouldEnqueue: boolean;
}

export type EventClaimResult =
  | { outcome: "deliver"; deliveryToken: string }
  | { outcome: "duplicate" }
  | { outcome: "in-flight" }
  | { outcome: "ignored" };

interface EventLedgerItem {
  pk: string;
  sk: "EVENT";
  recordType: "EVENT";
  eventId: string;
  eventType: string;
  createdAt: number;
  payloadDigest: string;
  subscriptionId?: string;
  claimedAt: string;
  deliveryStatus: "pending" | "enqueued" | "ignored";
  deliveryLeaseOwner?: string;
  deliveryLeaseExpiresAt?: number;
}

export interface DynamoEventLedgerOptions {
  leaseSeconds?: number;
  now?: () => Date;
  token?: () => string;
}

export class DynamoEventLedger {
  readonly #client: Pick<DynamoDBDocumentClient, "send">;
  readonly #tableName: string;
  readonly #leaseSeconds: number;
  readonly #now: () => Date;
  readonly #token: () => string;

  constructor(
    client: Pick<DynamoDBDocumentClient, "send">,
    tableName: string,
    options: DynamoEventLedgerOptions = {},
  ) {
    if (!tableName) throw new Error("DynamoDB table name is required");

    this.#client = client;
    this.#tableName = tableName;
    this.#leaseSeconds = options.leaseSeconds ?? 60;
    this.#now = options.now ?? (() => new Date());
    this.#token = options.token ?? randomUUID;
  }

  async claimEvent(input: EventClaimInput): Promise<EventClaimResult> {
    const now = this.#now();
    const nowSeconds = Math.floor(now.getTime() / 1_000);
    const deliveryToken = this.#token();
    const item: EventLedgerItem = {
      pk: eventKey(input.eventId),
      sk: "EVENT",
      recordType: "EVENT",
      eventId: input.eventId,
      eventType: input.eventType,
      createdAt: input.eventCreated,
      payloadDigest: input.payloadDigest,
      ...(input.subscriptionId === undefined
        ? {}
        : { subscriptionId: input.subscriptionId }),
      claimedAt: now.toISOString(),
      deliveryStatus: input.shouldEnqueue ? "pending" : "ignored",
      ...(input.shouldEnqueue
        ? {
            deliveryLeaseOwner: deliveryToken,
            deliveryLeaseExpiresAt: nowSeconds + this.#leaseSeconds,
          }
        : {}),
    };

    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: item,
          ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
        }),
      );

      return input.shouldEnqueue
        ? { outcome: "deliver", deliveryToken }
        : { outcome: "ignored" };
    } catch (error) {
      if (!isConditionalCheckFailure(error)) throw error;
    }

    const existing = await this.#getEvent(input.eventId);
    if (!existing) {
      throw new Error(`Event claim disappeared: ${input.eventId}`);
    }
    if (existing.payloadDigest !== input.payloadDigest) {
      throw new Error("Stripe event payload digest conflict");
    }
    if (existing.deliveryStatus === "enqueued" || existing.deliveryStatus === "ignored") {
      return { outcome: "duplicate" };
    }
    if ((existing.deliveryLeaseExpiresAt ?? 0) > nowSeconds) {
      return { outcome: "in-flight" };
    }

    try {
      await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: { pk: eventKey(input.eventId), sk: "EVENT" },
          UpdateExpression:
            "SET deliveryLeaseOwner = :owner, deliveryLeaseExpiresAt = :expires",
          ConditionExpression:
            "deliveryStatus = :pending AND (attribute_not_exists(deliveryLeaseExpiresAt) OR deliveryLeaseExpiresAt <= :now)",
          ExpressionAttributeValues: {
            ":owner": deliveryToken,
            ":expires": nowSeconds + this.#leaseSeconds,
            ":pending": "pending",
            ":now": nowSeconds,
          },
        }),
      );
      return { outcome: "deliver", deliveryToken };
    } catch (error) {
      if (isConditionalCheckFailure(error)) return { outcome: "in-flight" };
      throw error;
    }
  }

  async markEnqueued(eventId: string, deliveryToken: string): Promise<void> {
    await this.#client.send(
      new UpdateCommand({
        TableName: this.#tableName,
        Key: { pk: eventKey(eventId), sk: "EVENT" },
        UpdateExpression:
          "SET deliveryStatus = :enqueued, enqueuedAt = :enqueuedAt REMOVE deliveryLeaseOwner, deliveryLeaseExpiresAt",
        ConditionExpression: "deliveryStatus = :pending AND deliveryLeaseOwner = :owner",
        ExpressionAttributeValues: {
          ":enqueued": "enqueued",
          ":enqueuedAt": this.#now().toISOString(),
          ":pending": "pending",
          ":owner": deliveryToken,
        },
      }),
    );
  }

  async #getEvent(eventId: string): Promise<EventLedgerItem | undefined> {
    const response = (await this.#client.send(
      new GetCommand({
        TableName: this.#tableName,
        Key: { pk: eventKey(eventId), sk: "EVENT" },
        ConsistentRead: true,
      }),
    )) as GetCommandOutput;
    return response.Item as EventLedgerItem | undefined;
  }
}

function eventKey(eventId: string): string {
  return `EVENT#${eventId}`;
}

function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    error.name === "ConditionalCheckFailedException"
  );
}
