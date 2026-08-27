#!/usr/bin/env node
"use strict";

const { createHash, randomBytes } = require("node:crypto");
const { CANARY_INVOCATION_TYPE } = require("./notifier.js");

const FUNCTION_PATTERN = /^[A-Za-z0-9-_]{1,64}$/;
const STREAM_PATTERN = /^arn:aws:dynamodb:us-east-1:456453427852:table\/[A-Za-z0-9_.-]+\/stream\/.+$/;
const MESSAGE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function createCanaryEvent({ nonce, createdAt, expiresAtEpoch, streamArn }) {
  const sequence = BigInt(`0x${createHash("sha256").update(nonce).digest("hex").slice(0, 24)}`).toString(10);
  return {
    invocationType: CANARY_INVOCATION_TYPE,
    Records: [{
      eventID: "activation-canary",
      eventName: "INSERT",
      eventSource: "aws:dynamodb",
      eventSourceARN: streamArn,
      dynamodb: {
        SequenceNumber: sequence,
        NewImage: {
          canary_nonce: { S: nonce },
          created_at: { S: createdAt },
          expires_at_epoch: { N: String(expiresAtEpoch) },
          record_type: { S: "waitlist_notification_canary" },
        },
      },
    }],
  };
}

function createRunner({ lambdaClient, commandFactory, now = () => new Date(), nonce = () => randomBytes(32).toString("base64url") } = {}) {
  let resolvedClient = lambdaClient;
  let resolvedCommandFactory = commandFactory;
  function resolveSdk() {
    if (resolvedClient && resolvedCommandFactory) return;
    const { InvokeCommand, LambdaClient } = require("@aws-sdk/client-lambda");
    resolvedClient = resolvedClient || new LambdaClient({ region: "us-east-1" });
    resolvedCommandFactory = resolvedCommandFactory || ((input) => new InvokeCommand(input));
  }
  return async function run({ functionName, streamArn }) {
    if (!FUNCTION_PATTERN.test(functionName || "") || !STREAM_PATTERN.test(streamArn || "")) throw new Error("canary inputs invalid");
    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) throw new Error("canary clock invalid");
    const canaryNonce = nonce();
    if (!/^[A-Za-z0-9_-]{43}$/.test(canaryNonce) || Buffer.from(canaryNonce, "base64url").length !== 32) throw new Error("canary nonce invalid");
    const createdAt = timestamp.toISOString();
    const expiresAtEpoch = Math.floor(timestamp.getTime() / 1000) + 86400;
    const expiresAt = new Date(expiresAtEpoch * 1000).toISOString();
    resolveSdk();
    const response = await resolvedClient.send(resolvedCommandFactory({
      FunctionName: functionName,
      InvocationType: "RequestResponse",
      Payload: Buffer.from(JSON.stringify(createCanaryEvent({ nonce: canaryNonce, createdAt, expiresAtEpoch, streamArn }))),
    }));
    let result;
    try { result = JSON.parse(Buffer.from(response.Payload || []).toString("utf8")); } catch { throw new Error("canary invocation failed"); }
    if (
      response.StatusCode !== 200 || response.FunctionError !== undefined ||
      !result || Object.keys(result).sort().join(",") !== "canaryNonce,createdAt,expiresAt,sqsMessageId" ||
      result.canaryNonce !== canaryNonce || result.createdAt !== createdAt || result.expiresAt !== expiresAt ||
      !MESSAGE_ID_PATTERN.test(result.sqsMessageId || "")
    ) throw new Error("canary invocation failed");
    return result;
  };
}

async function main() {
  try {
    const result = await createRunner()({
      functionName: process.env.WAITLIST_NOTIFIER_FUNCTION_NAME,
      streamArn: process.env.WAITLIST_OUTBOX_STREAM_ARN,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("waitlist activation canary failed\n");
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { createCanaryEvent, createRunner };
