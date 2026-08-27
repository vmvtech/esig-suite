"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const { createNotificationOutbox, toDynamoItem } = require("../src/handler.js");
const { createReplay } = require("../src/replay-outbox.js");

const NOW = new Date("2026-08-06T12:00:00.000Z");

function oldOutbox() {
  const created = new Date("2026-07-01T00:00:00.000Z");
  return toDynamoItem(createNotificationOutbox({
    submission_id: "wl_0123456789abcdef01234567",
    submission_id_version: "random-v1",
    offer: "shared_starter",
    source: "pricing",
    created_at: created.toISOString(),
    retention_class: "waitlist_180d",
    contact_permission_status: "asserted_unverified",
    email_verification_status: "unverified",
    expires_at_epoch: Math.floor(created.getTime() / 1000) + 180 * 86400,
    record_type: "waitlist_submission",
  }));
}

function harness({ items = [oldOutbox()], response = { StatusCode: 200, Payload: Buffer.from('{"batchItemFailures":[]}') } } = {}) {
  const scans = [];
  const invokes = [];
  const commands = {
    scan: (input) => ({ kind: "scan", input }),
    invoke: (input) => ({ kind: "invoke", input }),
  };
  const run = createReplay({
    now: () => NOW,
    logger: { info() {} },
    commands,
    dynamoClient: { send: async (command) => { scans.push(command.input); return { Items: items }; } },
    lambdaClient: { send: async (command) => { invokes.push(command.input); return response; } },
  });
  return { invokes, run, scans };
}

describe("waitlist notifier backlog replay", () => {
  it("directly invokes the deployed notifier for backlog older than stream retention and converges idempotently", async () => {
    const { invokes, run, scans } = harness();
    const result = await run({ outboxTableName: "outbox", notifierFunctionName: "notifier", streamArn: "arn:stream" });
    assert.deepEqual(result, { status: "verified", passes: 2, eligible: 1, replayed: 1 });
    assert.equal(invokes.length, 1);
    assert.equal(invokes[0].InvocationType, "RequestResponse");
    const event = JSON.parse(Buffer.from(invokes[0].Payload).toString("utf8"));
    assert.equal(event.Records[0].eventName, "INSERT");
    assert.equal(event.Records[0].dynamodb.NewImage.created_at.S, "2026-07-01T00:00:00.000Z");
    assert.equal(scans[0].ConsistentRead, true);
    assert.match(scans[0].FilterExpression, /expires_at_epoch.*> :now/);
  });

  it("skips rows expired at the current-clock boundary", async () => {
    const { invokes, run, scans } = harness({ items: [] });
    const result = await run({ outboxTableName: "outbox", notifierFunctionName: "notifier", streamArn: "arn:stream" });
    assert.deepEqual(result, { status: "verified", passes: 1, eligible: 0, replayed: 0 });
    assert.equal(invokes.length, 0);
    assert.equal(scans[0].ExpressionAttributeValues[":now"].N, String(Math.floor(NOW.getTime() / 1000)));
  });

  it("fails closed on Lambda errors or any reported item failure", async () => {
    for (const response of [
      { StatusCode: 200, FunctionError: "Unhandled", Payload: Buffer.from("{}") },
      { StatusCode: 200, Payload: Buffer.from('{"batchItemFailures":[{"itemIdentifier":"1"}]}') },
    ]) {
      const { run } = harness({ response });
      await assert.rejects(
        run({ outboxTableName: "outbox", notifierFunctionName: "notifier", streamArn: "arn:stream" }),
        /replay failed/,
      );
    }
  });
});
