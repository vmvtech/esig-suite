"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const { createHandler } = require("../src/notifier.js");
const { createRunner } = require("../src/run-canary.js");

const NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const MESSAGE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const KMS_ARN = "arn:aws:kms:us-east-1:633740007231:key/01234567-89ab-cdef-0123-456789abcdef";
const FUNCTION_NAME = "esig-waitlist-production-waitlist-notifier";
const STREAM_ARN = "arn:aws:dynamodb:us-east-1:456453427852:table/esig-waitlist-outbox/stream/2026-08-06T00:00:00.000";

describe("waitlist activation canary runner", () => {
  it("invokes the deployed-handler shape and emits only nonce, actual SQS id, and timestamps", async () => {
    const queueMessages = [];
    const notifier = createHandler({
      env: {
        PRODUCER_ACCOUNT_ID: "456453427852",
        PRODUCER_REGION: "us-east-1",
        WAITLIST_BROKER_KMS_KEY_ARN: KMS_ARN,
        WAITLIST_BROKER_QUEUE_ARN: "arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard.fifo",
        WAITLIST_BROKER_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/633740007231/esig-mail-enqueue-standard.fifo",
      },
      now: () => new Date("2026-08-06T12:00:01.000Z"),
      sendMessage: async (input) => { queueMessages.push(input); return { MessageId: MESSAGE_ID }; },
    });
    const lambdaClient = {
      async send(command) {
        const result = await notifier(JSON.parse(Buffer.from(command.Payload).toString("utf8")));
        return { StatusCode: 200, Payload: Buffer.from(JSON.stringify(result)) };
      },
    };
    const run = createRunner({
      lambdaClient,
      commandFactory: (input) => input,
      now: () => new Date("2026-08-06T12:00:00.000Z"),
      nonce: () => NONCE,
    });
    const result = await run({ functionName: FUNCTION_NAME, streamArn: STREAM_ARN });
    assert.deepEqual(Object.keys(result).sort(), ["canaryNonce", "createdAt", "expiresAt", "sqsMessageId"]);
    assert.equal(result.canaryNonce, NONCE);
    assert.equal(result.sqsMessageId, MESSAGE_ID);
    assert.equal(queueMessages.length, 1);
    assert.doesNotMatch(JSON.stringify(result), /email|offer|name|company|subject/i);
  });

  it("fails closed when Lambda returns a fabricated or mismatched receipt", async () => {
    const run = createRunner({
      lambdaClient: { send: async () => ({ StatusCode: 200, Payload: Buffer.from(JSON.stringify({ canaryNonce: NONCE, sqsMessageId: "fabricated", createdAt: "2026-08-06T12:00:00.000Z", expiresAt: "2026-08-07T12:00:00.000Z" })) }) },
      commandFactory: (input) => input,
      now: () => new Date("2026-08-06T12:00:00.000Z"),
      nonce: () => NONCE,
    });
    await assert.rejects(run({ functionName: FUNCTION_NAME, streamArn: STREAM_ARN }), /invocation failed/);
  });
});
