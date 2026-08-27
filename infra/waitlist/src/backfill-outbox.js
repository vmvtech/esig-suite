"use strict";

const { isDeepStrictEqual } = require("node:util");
const {
  createNotificationOutbox,
  createOpaqueSubmissionId,
  toDynamoItem,
} = require("./handler.js");

const SUBMISSION_ID_PATTERN = /^wl_[0-9a-f]{24}$/;
const SUBMISSION_KEY_PATTERN = /^WAITLIST#[0-9a-f]{64}$/;
const SUBMISSION_ID_VERSION = "random-v1";

const PRIVATE_PROJECTION = Object.freeze([
  "submission_key",
  "submission_id",
  "submission_id_version",
  "created_at",
  "offer",
  "retention_class",
  "expires_at_epoch",
  "record_type",
]);

function projection(names) {
  const expressionAttributeNames = {};
  const projectionExpression = names.map((name, index) => {
    const alias = `#field${index}`;
    expressionAttributeNames[alias] = name;
    return alias;
  }).join(",");
  return { expressionAttributeNames, projectionExpression };
}

function readString(item, field) {
  const value = item?.[field]?.S;
  if (typeof value !== "string") throw new Error("invalid backfill source record");
  return value;
}

function readOptionalString(item, field) {
  const attribute = item?.[field];
  if (attribute === undefined) return undefined;
  if (typeof attribute?.S !== "string") throw new Error("invalid backfill source record");
  return attribute.S;
}

function readInteger(item, field) {
  const value = Number(item?.[field]?.N);
  if (!Number.isSafeInteger(value)) throw new Error("invalid backfill source record");
  return value;
}

function validateSource(item) {
  const submissionKey = readString(item, "submission_key");
  const recordType = readString(item, "record_type");
  const version = readOptionalString(item, "submission_id_version");
  const submissionId = readOptionalString(item, "submission_id");

  if (
    !SUBMISSION_KEY_PATTERN.test(submissionKey) ||
    !["waitlist_submission", "smoke_test"].includes(recordType)
  ) {
    throw new Error("invalid backfill source record");
  }

  if (version !== undefined && version !== SUBMISSION_ID_VERSION) {
    throw new Error("invalid backfill source record");
  }
  if (version === SUBMISSION_ID_VERSION && !SUBMISSION_ID_PATTERN.test(submissionId || "")) {
    throw new Error("invalid backfill source record");
  }

  readInteger(item, "expires_at_epoch");
  return { recordType, submissionId, submissionKey, version };
}

function withOpaqueSubmissionId(item, submissionId) {
  return {
    ...item,
    submission_id: { S: submissionId },
    submission_id_version: { S: SUBMISSION_ID_VERSION },
  };
}

function toOutbox(item) {
  return createNotificationOutbox({
    submission_id: readString(item, "submission_id"),
    submission_id_version: readString(item, "submission_id_version"),
    created_at: readString(item, "created_at"),
    offer: readString(item, "offer"),
    retention_class: readString(item, "retention_class"),
    expires_at_epoch: readInteger(item, "expires_at_epoch"),
    record_type: readString(item, "record_type"),
    source: "pricing",
    contact_permission_status: "asserted_unverified",
    email_verification_status: "unverified",
  });
}

function isConditionalFailure(error) {
  if (error?.name === "ConditionalCheckFailedException") return true;
  if (error?.name !== "TransactionCanceledException") return false;
  const reasons = error.CancellationReasons;
  return Array.isArray(reasons) &&
    reasons.some((reason) => reason?.Code === "ConditionalCheckFailed") &&
    reasons.every((reason) => ["None", "ConditionalCheckFailed"].includes(reason?.Code));
}

function nextOpaqueId(randomBytesFn, previousId) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const candidate = createOpaqueSubmissionId(randomBytesFn);
    if (candidate !== previousId) return candidate;
  }
  throw new Error("backfill entropy source did not produce a fresh ID");
}

function createBackfill({
  client,
  commands,
  now = () => new Date(),
  randomBytesFn,
  logger = console,
} = {}) {
  let resolvedClient = client;
  let resolvedCommands = commands;

  function resolveSdk() {
    if (resolvedClient && resolvedCommands) return;
    const {
      DynamoDBClient,
      GetItemCommand,
      PutItemCommand,
      ScanCommand,
      TransactWriteItemsCommand,
    } = require("@aws-sdk/client-dynamodb");
    resolvedClient = resolvedClient || new DynamoDBClient({});
    resolvedCommands = resolvedCommands || {
      get: (input) => new GetItemCommand(input),
      put: (input) => new PutItemCommand(input),
      scan: (input) => new ScanCommand(input),
      transact: (input) => new TransactWriteItemsCommand(input),
    };
  }

  async function scanAll(tableName) {
    const items = [];
    const sourceProjection = projection(PRIVATE_PROJECTION);
    let exclusiveStartKey;
    do {
      const response = await resolvedClient.send(resolvedCommands.scan({
        TableName: tableName,
        ConsistentRead: true,
        ProjectionExpression: sourceProjection.projectionExpression,
        ExpressionAttributeNames: sourceProjection.expressionAttributeNames,
        ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {}),
      }));
      items.push(...(Array.isArray(response.Items) ? response.Items : []));
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey && Object.keys(exclusiveStartKey).length > 0);
    return items;
  }

  async function verify(outboxTableName, outbox) {
    const expected = toDynamoItem(outbox);
    const outboxProjection = projection(Object.keys(expected));
    const response = await resolvedClient.send(resolvedCommands.get({
      TableName: outboxTableName,
      Key: { outbox_key: expected.outbox_key },
      ConsistentRead: true,
      ProjectionExpression: outboxProjection.projectionExpression,
      ExpressionAttributeNames: outboxProjection.expressionAttributeNames,
    }));
    if (!isDeepStrictEqual(response.Item, expected)) {
      throw new Error("outbox backfill verification failed");
    }
  }

  async function migrateSource({ sourceItem, privateTableName, outboxTableName, nowEpoch }) {
    const source = validateSource(sourceItem);
    const newSubmissionId = nextOpaqueId(randomBytesFn, source.submissionId);
    const migratedItem = withOpaqueSubmissionId(sourceItem, newSubmissionId);
    const active = readInteger(sourceItem, "expires_at_epoch") > nowEpoch;
    const transactItems = [];
    const expressionAttributeNames = {
      "#submission_id": "submission_id",
      "#submission_id_version": "submission_id_version",
    };
    const expressionAttributeValues = {
      ":new_submission_id": { S: newSubmissionId },
      ":submission_id_version": { S: SUBMISSION_ID_VERSION },
    };
    let conditionExpression = "attribute_not_exists(#submission_id_version)";
    if (source.submissionId === undefined) {
      conditionExpression += " AND attribute_not_exists(#submission_id)";
    } else {
      conditionExpression += " AND #submission_id = :old_submission_id";
      expressionAttributeValues[":old_submission_id"] = { S: source.submissionId };
    }

    transactItems.push({
      Update: {
        TableName: privateTableName,
        Key: { submission_key: { S: source.submissionKey } },
        UpdateExpression:
          "SET #submission_id = :new_submission_id, #submission_id_version = :submission_id_version",
        ConditionExpression: conditionExpression,
        ExpressionAttributeNames: expressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues,
      },
    });

    let outbox;
    if (source.recordType === "waitlist_submission" && active) {
      outbox = toOutbox(migratedItem);
      transactItems.push({
        Put: {
          TableName: outboxTableName,
          Item: toDynamoItem(outbox),
          ConditionExpression: "attribute_not_exists(#outbox_key)",
          ExpressionAttributeNames: { "#outbox_key": "outbox_key" },
        },
      });
    }

    if (SUBMISSION_ID_PATTERN.test(source.submissionId || "")) {
      transactItems.push({
        Delete: {
          TableName: outboxTableName,
          Key: { outbox_key: { S: `OUTBOX#${source.submissionId}` } },
        },
      });
    }

    await resolvedClient.send(resolvedCommands.transact({ TransactItems: transactItems }));
    if (outbox) await verify(outboxTableName, outbox);
  }

  return async function backfill({ privateTableName, outboxTableName }) {
    if (!privateTableName || !outboxTableName) throw new Error("backfill tables required");
    resolveSdk();
    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) {
      throw new Error("backfill clock invalid");
    }
    const nowEpoch = Math.floor(timestamp.getTime() / 1000);

    for (let pass = 1; pass <= 3; pass += 1) {
      const sourceItems = await scanAll(privateTableName);
      let inserted = 0;
      let migrated = 0;
      let retryNeeded = false;

      for (const sourceItem of sourceItems) {
        const source = validateSource(sourceItem);
        if (source.version !== SUBMISSION_ID_VERSION) {
          try {
            await migrateSource({ sourceItem, privateTableName, outboxTableName, nowEpoch });
            migrated += 1;
          } catch (error) {
            if (!isConditionalFailure(error)) throw error;
            retryNeeded = true;
          }
          continue;
        }

        if (
          source.recordType !== "waitlist_submission" ||
          readInteger(sourceItem, "expires_at_epoch") <= nowEpoch
        ) {
          continue;
        }

        const outbox = toOutbox(sourceItem);
        const item = toDynamoItem(outbox);
        try {
          await resolvedClient.send(resolvedCommands.put({
            TableName: outboxTableName,
            Item: item,
            ConditionExpression: "attribute_not_exists(#outbox_key)",
            ExpressionAttributeNames: { "#outbox_key": "outbox_key" },
          }));
          inserted += 1;
        } catch (error) {
          if (!isConditionalFailure(error)) throw error;
        }
        await verify(outboxTableName, outbox);
      }

      if (logger && typeof logger.info === "function") {
        logger.info(JSON.stringify({
          event: "waitlist_outbox_backfill_pass",
          pass,
          eligible: sourceItems.length,
          inserted,
          migrated,
        }));
      }
      if (migrated === 0 && inserted === 0 && !retryNeeded) {
        return { status: "verified", passes: pass, eligible: sourceItems.length };
      }
    }
    throw new Error("outbox backfill did not converge");
  };
}

async function main() {
  try {
    const run = createBackfill({
      logger: {
        info(line) {
          process.stderr.write(`${line}\n`);
        },
      },
    });
    const result = await run({
      privateTableName: process.env.WAITLIST_TABLE_NAME,
      outboxTableName: process.env.WAITLIST_OUTBOX_TABLE_NAME,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("waitlist outbox backfill failed\n");
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  PRIVATE_PROJECTION,
  SUBMISSION_ID_VERSION,
  createBackfill,
  toOutbox,
  validateSource,
};
