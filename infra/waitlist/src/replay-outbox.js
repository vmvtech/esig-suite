"use strict";

const { OUTBOX_IMAGE_FIELDS } = require("./notifier.js");

function projection(names) {
  const namesByAlias = {};
  const expression = names.map((name, index) => {
    const alias = `#field${index}`;
    namesByAlias[alias] = name;
    return alias;
  }).join(",");
  return { expression, namesByAlias };
}

function submissionId(item) {
  const value = item?.submission_id?.S;
  if (typeof value !== "string" || !/^wl_[a-f0-9]{24}$/.test(value)) {
    throw new Error("invalid replay record");
  }
  return value;
}

function replayEvent(item, streamArn) {
  const id = submissionId(item);
  return {
    Records: [{
      eventID: `replay-${id}`,
      eventName: "INSERT",
      eventSource: "aws:dynamodb",
      eventSourceARN: streamArn,
      dynamodb: {
        SequenceNumber: BigInt(`0x${id.slice(3)}`).toString(10),
        NewImage: item,
      },
    }],
  };
}

function createReplay({ dynamoClient, lambdaClient, commands, now = () => new Date(), logger = console } = {}) {
  let resolvedDynamo = dynamoClient;
  let resolvedLambda = lambdaClient;
  let resolvedCommands = commands;

  function resolveSdk() {
    if (resolvedDynamo && resolvedLambda && resolvedCommands) return;
    const { DynamoDBClient, ScanCommand } = require("@aws-sdk/client-dynamodb");
    const { InvokeCommand, LambdaClient } = require("@aws-sdk/client-lambda");
    resolvedDynamo = resolvedDynamo || new DynamoDBClient({});
    resolvedLambda = resolvedLambda || new LambdaClient({});
    resolvedCommands = resolvedCommands || {
      scan: (input) => new ScanCommand(input),
      invoke: (input) => new InvokeCommand(input),
    };
  }

  async function scan(tableName, nowEpoch) {
    const items = [];
    const fields = projection(OUTBOX_IMAGE_FIELDS);
    let exclusiveStartKey;
    do {
      const response = await resolvedDynamo.send(resolvedCommands.scan({
        TableName: tableName,
        ConsistentRead: true,
        ProjectionExpression: fields.expression,
        FilterExpression: "#record_type = :record_type AND #expires_at_epoch > :now",
        ExpressionAttributeNames: {
          ...fields.namesByAlias,
          "#record_type": "record_type",
          "#expires_at_epoch": "expires_at_epoch",
        },
        ExpressionAttributeValues: {
          ":record_type": { S: "waitlist_notification_outbox" },
          ":now": { N: String(nowEpoch) },
        },
        ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {}),
      }));
      items.push(...(Array.isArray(response.Items) ? response.Items : []));
      exclusiveStartKey = response.LastEvaluatedKey;
    } while (exclusiveStartKey && Object.keys(exclusiveStartKey).length > 0);
    return items;
  }

  async function invoke(functionName, streamArn, item) {
    const response = await resolvedLambda.send(resolvedCommands.invoke({
      FunctionName: functionName,
      InvocationType: "RequestResponse",
      Payload: Buffer.from(JSON.stringify(replayEvent(item, streamArn))),
    }));
    let result;
    try {
      result = JSON.parse(Buffer.from(response.Payload || []).toString("utf8"));
    } catch {
      throw new Error("notifier replay failed");
    }
    if (
      response.StatusCode !== 200 ||
      response.FunctionError !== undefined ||
      !result ||
      Object.keys(result).join(",") !== "batchItemFailures" ||
      !Array.isArray(result.batchItemFailures) ||
      result.batchItemFailures.length !== 0
    ) {
      throw new Error("notifier replay failed");
    }
  }

  return async function replay({ outboxTableName, notifierFunctionName, streamArn }) {
    if (!outboxTableName || !notifierFunctionName || !streamArn) throw new Error("replay inputs required");
    resolveSdk();
    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) throw new Error("replay clock invalid");
    const nowEpoch = Math.floor(timestamp.getTime() / 1000);
    const replayed = new Set();

    for (let pass = 1; pass <= 3; pass += 1) {
      const eligible = await scan(outboxTableName, nowEpoch);
      const pending = eligible.filter((item) => !replayed.has(submissionId(item)));
      for (const item of pending) {
        await invoke(notifierFunctionName, streamArn, item);
        replayed.add(submissionId(item));
      }
      if (logger && typeof logger.info === "function") {
        logger.info(JSON.stringify({ event: "waitlist_outbox_replay_pass", pass, eligible: eligible.length, replayed: pending.length }));
      }
      if (pending.length === 0) {
        return { status: "verified", passes: pass, eligible: eligible.length, replayed: replayed.size };
      }
    }
    throw new Error("notifier replay did not converge");
  };
}

async function main() {
  try {
    const run = createReplay({ logger: { info: (line) => process.stderr.write(`${line}\n`) } });
    const result = await run({
      outboxTableName: process.env.WAITLIST_OUTBOX_TABLE_NAME,
      notifierFunctionName: process.env.WAITLIST_NOTIFIER_FUNCTION_NAME,
      streamArn: process.env.WAITLIST_OUTBOX_STREAM_ARN,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("waitlist notifier backlog replay failed\n");
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { createReplay, replayEvent };
