import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import {
  GetCommand,
  type GetCommandOutput,
  PutCommand,
  QueryCommand,
  type QueryCommandOutput,
  ScanCommand,
  type ScanCommandOutput,
  TransactWriteCommand,
  UpdateCommand,
  type UpdateCommandOutput,
} from "@aws-sdk/lib-dynamodb";

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
} from "../domain.js";
import type { ProvisioningStore } from "../memory-store.js";

type DocumentClient = Pick<DynamoDBDocumentClient, "send">;

export class DynamoProvisioningStore implements ProvisioningStore {
  readonly #client: DocumentClient;
  readonly #tableName: string;

  constructor(client: DocumentClient, tableName: string) {
    if (!tableName) throw new Error("DynamoDB table name is required");
    this.#client = client;
    this.#tableName = tableName;
  }

  async claimEvent(claim: EventClaim): Promise<EventClaimResult> {
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: {
            ...withoutUndefined(claim),
            pk: eventPartition(claim.eventId),
            sk: "EVENT",
            recordType: "EVENT",
          },
          ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
        }),
      );
      return { status: "claimed", claim: structuredClone(claim) };
    } catch (error) {
      if (!isConditionalCheckFailure(error)) throw error;
    }

    const stored = await this.#get<EventClaim>({
      pk: eventPartition(claim.eventId),
      sk: "EVENT",
    });
    if (!stored) throw new SafeProvisioningError("STORE_CONFLICT", true);
    const existing = copyEventClaim(stored);
    return {
      status: existing.payloadDigest === claim.payloadDigest ? "duplicate" : "conflict",
      claim: existing,
    };
  }

  async listEventClaims(): Promise<readonly EventClaim[]> {
    const claims: EventClaim[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const response = (await this.#client.send(
        new ScanCommand({
          TableName: this.#tableName,
          FilterExpression: "recordType = :recordType",
          ExpressionAttributeValues: { ":recordType": "EVENT" },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      )) as ScanCommandOutput;
      claims.push(
        ...(response.Items ?? []).map((item) =>
          copyEventClaim(hydrate<EventClaim>(item)),
        ),
      );
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey !== undefined);

    return claims.sort((left, right) => left.eventId.localeCompare(right.eventId));
  }

  async getOrder(subscriptionId: string): Promise<OrderRecord | undefined> {
    return this.#get<OrderRecord>(orderKey(subscriptionId));
  }

  async putOrder(
    order: OrderRecord,
    expectedVersion?: number,
  ): Promise<OrderRecord> {
    if (
      (expectedVersion === undefined && order.version !== 0) ||
      (expectedVersion !== undefined && order.version !== expectedVersion)
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }
    const key = orderKey(order.subscriptionId);
    const stored =
      expectedVersion === undefined
        ? structuredClone(order)
        : { ...structuredClone(order), version: expectedVersion + 1 };
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: {
            ...withoutUndefined(stored),
            ...key,
            recordType: "ORDER",
          },
          ConditionExpression:
            expectedVersion === undefined
              ? "attribute_not_exists(pk) AND attribute_not_exists(sk)"
              : "#version = :expectedVersion",
          ...(expectedVersion === undefined
            ? {}
            : {
                ExpressionAttributeNames: { "#version": "version" },
                ExpressionAttributeValues: {
                  ":expectedVersion": expectedVersion,
                },
              }),
        }),
      );
      return stored;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      throw error;
    }
  }

  async getJob(subscriptionId: string): Promise<ProvisioningJob | undefined> {
    return this.#get<ProvisioningJob>(jobKey(subscriptionId));
  }

  async putJob(
    job: ProvisioningJob,
    expectedVersion?: number,
  ): Promise<ProvisioningJob> {
    if (job.jobId !== deterministicJobId(job.subscriptionId)) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }
    if (
      (expectedVersion === undefined && job.version !== 0) ||
      (expectedVersion !== undefined && job.version !== expectedVersion)
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT");
    }

    const key = jobKey(job.subscriptionId);
    const stored =
      expectedVersion === undefined
        ? structuredClone(job)
        : { ...structuredClone(job), version: expectedVersion + 1 };
    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: { ...withoutUndefined(stored), ...key, recordType: "JOB" },
          ConditionExpression:
            expectedVersion === undefined
              ? "attribute_not_exists(pk) AND attribute_not_exists(sk)"
              : "jobId = :jobId AND #version = :expectedVersion",
          ...(expectedVersion === undefined
            ? {}
            : {
                ExpressionAttributeNames: { "#version": "version" },
                ExpressionAttributeValues: {
                  ":jobId": job.jobId,
                  ":expectedVersion": expectedVersion,
                },
              }),
        }),
      );
      return stored;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      throw error;
    }
  }

  async acquireJobExecutionLease(
    subscriptionId: string,
    ownerId: string,
    now: number,
    leaseDurationMs: number,
  ): Promise<JobExecutionLeaseClaimResult> {
    validateLeaseInput(subscriptionId, ownerId, now, leaseDurationMs);
    const key = executionLeaseKey(subscriptionId);
    try {
      const response = (await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: key,
          UpdateExpression:
            "SET recordType = :recordType, subscriptionId = :subscriptionId, ownerId = :ownerId, expiresAt = :expiresAt, fencingToken = if_not_exists(fencingToken, :zero) + :one",
          ConditionExpression: "attribute_not_exists(pk) OR expiresAt <= :now",
          ExpressionAttributeValues: {
            ":recordType": "JOB_EXECUTION_LEASE",
            ":subscriptionId": subscriptionId,
            ":ownerId": ownerId,
            ":expiresAt": now + leaseDurationMs,
            ":now": now,
            ":zero": 0,
            ":one": 1,
          },
          ReturnValues: "ALL_NEW",
        }),
      )) as UpdateCommandOutput;
      const lease = response.Attributes
        ? hydrate<JobExecutionLease>(response.Attributes)
        : undefined;
      if (!validLease(lease, subscriptionId, ownerId)) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      return { status: "acquired", lease };
    } catch (error) {
      if (isConditionalCheckFailure(error)) return { status: "held" };
      throw error;
    }
  }

  async renewJobExecutionLease(
    lease: JobExecutionLease,
    now: number,
    leaseDurationMs: number,
  ): Promise<JobExecutionLease> {
    validateLeaseInput(
      lease.subscriptionId,
      lease.ownerId,
      now,
      leaseDurationMs,
    );
    try {
      const response = (await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: executionLeaseKey(lease.subscriptionId),
          UpdateExpression: "SET expiresAt = :expiresAt",
          ConditionExpression:
            "ownerId = :ownerId AND fencingToken = :fencingToken AND expiresAt > :now",
          ExpressionAttributeValues: {
            ":ownerId": lease.ownerId,
            ":fencingToken": lease.fencingToken,
            ":expiresAt": now + leaseDurationMs,
            ":now": now,
          },
          ReturnValues: "ALL_NEW",
        }),
      )) as UpdateCommandOutput;
      const renewed = response.Attributes
        ? hydrate<JobExecutionLease>(response.Attributes)
        : undefined;
      if (
        !validLease(
          renewed,
          lease.subscriptionId,
          lease.ownerId,
          lease.fencingToken,
        )
      ) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      return renewed;
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      throw error;
    }
  }

  async releaseJobExecutionLease(lease: JobExecutionLease): Promise<void> {
    try {
      await this.#client.send(
        new UpdateCommand({
          TableName: this.#tableName,
          Key: executionLeaseKey(lease.subscriptionId),
          UpdateExpression: "SET expiresAt = :releasedAt",
          ConditionExpression: "ownerId = :ownerId AND fencingToken = :fencingToken",
          ExpressionAttributeValues: {
            ":ownerId": lease.ownerId,
            ":fencingToken": lease.fencingToken,
            ":releasedAt": 0,
          },
        }),
      );
    } catch (error) {
      // A stale owner must not expire its successor's lease.
      if (isConditionalCheckFailure(error)) return;
      throw error;
    }
  }

  async getCredentialHandoffPointer(
    subscriptionId: string,
    handoffId: string,
  ): Promise<CredentialHandoffPointer | undefined> {
    return this.#get<CredentialHandoffPointer>(
      credentialHandoffKey(subscriptionId, handoffId),
    );
  }

  async beginCredentialHandoff(
    pointer: CredentialHandoffPointer,
    lease: JobExecutionLease,
    now: number,
    expectedPublicationGeneration?: number,
  ): Promise<CredentialHandoffPointer> {
    if (
      pointer.state !== "pending" ||
      pointer.subscriptionId !== lease.subscriptionId ||
      pointer.fencingToken !== lease.fencingToken ||
      pointer.publicationGeneration !==
        (expectedPublicationGeneration === undefined
          ? 0
          : expectedPublicationGeneration + 1)
    ) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    await this.#transactPointerPut(
      pointer,
      lease,
      now,
      expectedPublicationGeneration === undefined
        ? "attribute_not_exists(pk) AND attribute_not_exists(sk)"
        : "publicationGeneration = :expectedGeneration AND #state <> :revoked",
      expectedPublicationGeneration === undefined
        ? {}
        : {
            names: { "#state": "state" },
            values: {
              ":expectedGeneration": expectedPublicationGeneration,
              ":revoked": "revoked",
            },
          },
    );
    return structuredClone(pointer);
  }

  async bindCredentialHandoff(
    input: CredentialHandoffMutationInput,
    publication: CredentialSecretPublication,
  ): Promise<CredentialHandoffPointer> {
    const bound = { ...input.pointer, ...publication };
    await this.#transactPointerPut(
      bound,
      input.lease,
      input.now,
      "publicationGeneration = :generation AND fencingToken = :pointerFence AND #state = :pending AND (attribute_not_exists(secretId) OR (secretId = :secretId AND publicationId = :publicationId AND credentialId = :credentialId))",
      {
        names: { "#state": "state" },
        values: {
          ":generation": input.pointer.publicationGeneration,
          ":pointerFence": input.pointer.fencingToken,
          ":pending": "pending",
          ":secretId": publication.secretId,
          ":publicationId": publication.publicationId,
          ":credentialId": publication.credentialId,
        },
      },
    );
    return bound;
  }

  async publishCredentialHandoff(
    input: CredentialHandoffMutationInput,
  ): Promise<CredentialHandoffPointer> {
    if (!pointerHasPublication(input.pointer)) {
      throw new SafeProvisioningError("STORE_CONFLICT", true);
    }
    const published = { ...input.pointer, state: "published" as const };
    await this.#transactPointerPut(
      published,
      input.lease,
      input.now,
      "publicationGeneration = :generation AND fencingToken = :pointerFence AND (#state = :pending OR #state = :published) AND secretId = :secretId AND publicationId = :publicationId AND credentialId = :credentialId",
      {
        names: { "#state": "state" },
        values: {
          ":generation": input.pointer.publicationGeneration,
          ":pointerFence": input.pointer.fencingToken,
          ":pending": "pending",
          ":published": "published",
          ":secretId": input.pointer.secretId,
          ":publicationId": input.pointer.publicationId,
          ":credentialId": input.pointer.credentialId,
        },
      },
    );
    return published;
  }

  async revokeCredentialHandoff(
    input: CredentialHandoffMutationInput,
  ): Promise<CredentialHandoffPointer> {
    const revoked = { ...input.pointer, state: "revoked" as const };
    await this.#transactPointerPut(
      revoked,
      input.lease,
      input.now,
      "publicationGeneration = :generation AND fencingToken = :pointerFence",
      {
        values: {
          ":generation": input.pointer.publicationGeneration,
          ":pointerFence": input.pointer.fencingToken,
        },
      },
    );
    return revoked;
  }

  async listResources(subscriptionId: string): Promise<readonly ResourceRecord[]> {
    const resources: ResourceRecord[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const response = (await this.#client.send(
        new QueryCommand({
          TableName: this.#tableName,
          KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
          ExpressionAttributeValues: {
            ":pk": subscriptionPartition(subscriptionId),
            ":prefix": "RESOURCE#",
          },
          ConsistentRead: true,
          ExclusiveStartKey: exclusiveStartKey,
        }),
      )) as QueryCommandOutput;
      resources.push(
        ...(response.Items ?? []).map((item) => hydrate<ResourceRecord>(item)),
      );
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey !== undefined);

    return resources.sort((left, right) =>
      left.resourceKey.localeCompare(right.resourceKey),
    );
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

    const key = resourceKey(resource.subscriptionId, resource.resourceKey);
    const existing = await this.#get<ResourceRecord>(key);
    if (existing) {
      const sameIdentity =
        existing.subscriptionId === resource.subscriptionId &&
        existing.step === resource.step &&
        existing.kind === resource.kind &&
        existing.opaqueId === resource.opaqueId &&
        existing.retention === resource.retention;
      if (!sameIdentity) throw new SafeProvisioningError("STORE_CONFLICT");
      if (existing.retention === "immutable_evidence") return;
    }

    try {
      await this.#client.send(
        new PutCommand({
          TableName: this.#tableName,
          Item: { ...withoutUndefined(resource), ...key, recordType: "RESOURCE" },
          ConditionExpression:
            "attribute_not_exists(pk) OR (subscriptionId = :subscriptionId AND resourceKey = :resourceKey AND #step = :step AND kind = :kind AND opaqueId = :opaqueId AND retention = :retention)",
          ExpressionAttributeNames: { "#step": "step" },
          ExpressionAttributeValues: {
            ":subscriptionId": resource.subscriptionId,
            ":resourceKey": resource.resourceKey,
            ":step": resource.step,
            ":kind": resource.kind,
            ":opaqueId": resource.opaqueId,
            ":retention": resource.retention,
          },
        }),
      );
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      throw error;
    }
  }

  async #get<Value>(key: { pk: string; sk: string }): Promise<Value | undefined> {
    const response = (await this.#client.send(
      new GetCommand({
        TableName: this.#tableName,
        Key: key,
        ConsistentRead: true,
      }),
    )) as GetCommandOutput;
    return response.Item ? hydrate<Value>(response.Item) : undefined;
  }

  async #transactPointerPut(
    pointer: CredentialHandoffPointer,
    lease: JobExecutionLease,
    now: number,
    pointerCondition: string,
    expression: {
      readonly names?: Record<string, string>;
      readonly values?: Record<string, unknown>;
    },
  ): Promise<void> {
    try {
      await this.#client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              ConditionCheck: {
                TableName: this.#tableName,
                Key: executionLeaseKey(lease.subscriptionId),
                ConditionExpression:
                  "ownerId = :leaseOwner AND fencingToken = :leaseFence AND expiresAt > :now",
                ExpressionAttributeValues: {
                  ":leaseOwner": lease.ownerId,
                  ":leaseFence": lease.fencingToken,
                  ":now": now,
                },
              },
            },
            {
              Put: {
                TableName: this.#tableName,
                Item: {
                  ...withoutUndefined(pointer),
                  ...credentialHandoffKey(pointer.subscriptionId, pointer.handoffId),
                  recordType: "CREDENTIAL_HANDOFF",
                },
                ConditionExpression: pointerCondition,
                ...(expression.names === undefined
                  ? {}
                  : { ExpressionAttributeNames: expression.names }),
                ...(expression.values === undefined
                  ? {}
                  : { ExpressionAttributeValues: expression.values }),
              },
            },
          ],
        }),
      );
    } catch (error) {
      if (isConditionalCheckFailure(error) || awsErrorName(error) === "TransactionCanceledException") {
        throw new SafeProvisioningError("STORE_CONFLICT", true);
      }
      throw error;
    }
  }
}

function eventPartition(eventId: string): string {
  return `EVENT#${eventId}`;
}

function subscriptionPartition(subscriptionId: string): string {
  return `SUBSCRIPTION#${subscriptionId}`;
}

function orderKey(subscriptionId: string): { pk: string; sk: string } {
  return { pk: subscriptionPartition(subscriptionId), sk: `ORDER#${subscriptionId}` };
}

function jobKey(subscriptionId: string): { pk: string; sk: string } {
  return { pk: subscriptionPartition(subscriptionId), sk: `JOB#${subscriptionId}` };
}

function executionLeaseKey(subscriptionId: string): { pk: string; sk: string } {
  return {
    pk: subscriptionPartition(subscriptionId),
    sk: `JOB_EXECUTION_LEASE#${subscriptionId}`,
  };
}

function credentialHandoffKey(
  subscriptionId: string,
  handoffId: string,
): { pk: string; sk: string } {
  return {
    pk: subscriptionPartition(subscriptionId),
    sk: `CREDENTIAL_HANDOFF#${handoffId}`,
  };
}

function resourceKey(
  subscriptionId: string,
  deterministicKey: string,
): { pk: string; sk: string } {
  return {
    pk: subscriptionPartition(subscriptionId),
    sk: `RESOURCE#${deterministicKey}`,
  };
}

function hydrate<Value>(item: Record<string, unknown>): Value {
  const { pk: _pk, sk: _sk, recordType: _recordType, ...value } = item;
  return structuredClone(value) as Value;
}

function pointerHasPublication(
  pointer: CredentialHandoffPointer,
): pointer is CredentialHandoffPointer & Required<CredentialSecretPublication> {
  return (
    pointer.secretId !== undefined &&
    pointer.publicationId !== undefined &&
    pointer.credentialId !== undefined
  );
}

function awsErrorName(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const name = (error as { readonly name?: unknown }).name;
  return typeof name === "string" ? name : undefined;
}

function copyEventClaim(claim: EventClaim): EventClaim {
  return {
    eventId: claim.eventId,
    eventType: claim.eventType,
    createdAt: claim.createdAt,
    payloadDigest: claim.payloadDigest,
    ...(claim.subscriptionId === undefined
      ? {}
      : { subscriptionId: claim.subscriptionId }),
  };
}

function withoutUndefined<Value extends object>(value: Value): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, unknown] => entry[1] !== undefined),
  );
}

function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    error.name === "ConditionalCheckFailedException"
  );
}

function validateLeaseInput(
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

function validLease(
  lease: JobExecutionLease | undefined,
  subscriptionId: string,
  ownerId: string,
  fencingToken?: number,
): lease is JobExecutionLease {
  return (
    lease !== undefined &&
    lease.subscriptionId === subscriptionId &&
    lease.ownerId === ownerId &&
    Number.isSafeInteger(lease.fencingToken) &&
    lease.fencingToken > 0 &&
    (fencingToken === undefined || lease.fencingToken === fencingToken) &&
    Number.isSafeInteger(lease.expiresAt) &&
    lease.expiresAt > 0
  );
}
