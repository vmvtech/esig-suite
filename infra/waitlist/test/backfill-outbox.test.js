"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  PRIVATE_PROJECTION,
  createBackfill,
  toOutbox,
} = require("../src/backfill-outbox.js");
const { toDynamoItem } = require("../src/handler.js");

const NOW = new Date("2026-08-06T12:00:00.000Z");
const LEGACY_ID = "wl_0123456789abcdef01234567";
const RANDOM_ID = `wl_${"44".repeat(12)}`;

function sourceItem({ opaque = false, recordType = "waitlist_submission", expired = false } = {}) {
  const createdAt = expired ? "2025-01-01T11:00:00.000Z" : "2026-08-06T11:00:00.000Z";
  const retentionDays = 180;
  return {
    submission_key: { S: `WAITLIST#${"a".repeat(64)}` },
    submission_id: { S: opaque ? RANDOM_ID : LEGACY_ID },
    ...(opaque ? { submission_id_version: { S: "random-v1" } } : {}),
    created_at: { S: createdAt },
    offer: { S: "shared_starter" },
    retention_class: { S: `waitlist_${retentionDays}d` },
    expires_at_epoch: {
      N: String(Math.floor(new Date(createdAt).getTime() / 1000) + retentionDays * 86400),
    },
    record_type: { S: recordType },
  };
}

function conditionalFailure({ transaction = false } = {}) {
  const error = new Error("conditional");
  if (transaction) {
    error.name = "TransactionCanceledException";
    error.CancellationReasons = [
      { Code: "ConditionalCheckFailed" },
      { Code: "None" },
      { Code: "None" },
    ];
  } else {
    error.name = "ConditionalCheckFailedException";
  }
  return error;
}

function harness({ source = sourceItem(), preexisting = false } = {}) {
  let currentSource = structuredClone(source);
  const initialOutbox = preexisting ? toDynamoItem(toOutbox(currentSource)) : undefined;
  const stored = new Map(initialOutbox ? [[initialOutbox.outbox_key.S, initialOutbox]] : []);
  const calls = [];
  const logs = [];
  const commands = {
    scan: (input) => ({ kind: "scan", input }),
    transact: (input) => ({ kind: "transact", input }),
    put: (input) => ({ kind: "put", input }),
    get: (input) => ({ kind: "get", input }),
  };
  const client = {
    async send(command) {
      calls.push(command);
      if (command.kind === "scan") return { Items: [structuredClone(currentSource)] };
      if (command.kind === "transact") {
        const update = command.input.TransactItems[0].Update;
        if (currentSource.submission_id_version !== undefined) {
          throw conditionalFailure({ transaction: true });
        }
        currentSource.submission_id = structuredClone(
          update.ExpressionAttributeValues[":new_submission_id"],
        );
        currentSource.submission_id_version = structuredClone(
          update.ExpressionAttributeValues[":submission_id_version"],
        );
        for (const operation of command.input.TransactItems.slice(1)) {
          if (operation.Put) {
            const key = operation.Put.Item.outbox_key.S;
            if (stored.has(key)) throw conditionalFailure({ transaction: true });
            stored.set(key, structuredClone(operation.Put.Item));
          }
          if (operation.Delete) stored.delete(operation.Delete.Key.outbox_key.S);
        }
        return {};
      }
      if (command.kind === "put") {
        const key = command.input.Item.outbox_key.S;
        if (stored.has(key)) throw conditionalFailure();
        stored.set(key, structuredClone(command.input.Item));
        return {};
      }
      if (command.kind === "get") {
        return { Item: structuredClone(stored.get(command.input.Key.outbox_key.S)) };
      }
      throw new Error("unexpected command");
    },
  };
  const run = createBackfill({
    client,
    commands,
    now: () => NOW,
    randomBytesFn: () => Buffer.alloc(12, 0x44),
    logger: { info: (line) => logs.push(line) },
  });
  return { calls, getSource: () => currentSource, logs, run, stored };
}

describe("opaque-ID and metadata-only waitlist backfill", () => {
  it("atomically rotates a legacy ID and aligns the metadata-only outbox", async () => {
    const { calls, getSource, logs, run, stored } = harness();
    const result = await run({ privateTableName: "private", outboxTableName: "outbox" });
    assert.deepEqual(result, { status: "verified", passes: 2, eligible: 1 });

    assert.equal(getSource().submission_id.S, RANDOM_ID);
    assert.equal(getSource().submission_id_version.S, "random-v1");
    assert.equal(stored.has(`OUTBOX#${LEGACY_ID}`), false);
    assert.equal(stored.has(`OUTBOX#${RANDOM_ID}`), true);

    const scan = calls.find((call) => call.kind === "scan");
    const transaction = calls.find((call) => call.kind === "transact");
    assert.equal(scan.input.ConsistentRead, true);
    assert.deepEqual(
      [...new Set(Object.values(scan.input.ExpressionAttributeNames))].sort(),
      [...PRIVATE_PROJECTION].sort(),
    );
    assert.equal(transaction.input.TransactItems[0].Update.TableName, "private");
    assert.equal(transaction.input.TransactItems[1].Put.TableName, "outbox");
    assert.equal(transaction.input.TransactItems[2].Delete.TableName, "outbox");
    for (const forbidden of ["email", "name", "company", "use_case"]) {
      assert.equal(Object.values(scan.input.ExpressionAttributeNames).includes(forbidden), false);
      assert.doesNotMatch(logs.join("\n"), new RegExp(forbidden));
    }
    assert.doesNotMatch(logs.join("\n"), /wl_[0-9a-f]{24}|WAITLIST#/);
  });

  it("is idempotent when the random-v1 row and matching outbox already exist", async () => {
    const { calls, run } = harness({ source: sourceItem({ opaque: true }), preexisting: true });
    const result = await run({ privateTableName: "private", outboxTableName: "outbox" });
    assert.deepEqual(result, { status: "verified", passes: 1, eligible: 1 });
    assert.equal(calls.filter((call) => call.kind === "transact").length, 0);
    assert.equal(calls.filter((call) => call.kind === "put").length, 1);
    assert.equal(calls.filter((call) => call.kind === "get").length, 1);
  });

  it("rotates expired and smoke rows without creating a notification", async () => {
    for (const source of [
      sourceItem({ expired: true }),
      sourceItem({ recordType: "smoke_test" }),
    ]) {
      const { calls, getSource, run, stored } = harness({ source });
      const result = await run({ privateTableName: "private", outboxTableName: "outbox" });
      assert.deepEqual(result, { status: "verified", passes: 2, eligible: 1 });
      assert.equal(getSource().submission_id.S, RANDOM_ID);
      assert.equal(getSource().submission_id_version.S, "random-v1");
      assert.equal(stored.size, 0);
      const transaction = calls.find((call) => call.kind === "transact");
      assert.equal(transaction.input.TransactItems.some((entry) => entry.Put), false);
    }
  });

  it("generates an opaque ID when a legacy row has no lookup ID", async () => {
    const source = sourceItem();
    delete source.submission_id;
    const { calls, getSource, run } = harness({ source });

    await run({ privateTableName: "private", outboxTableName: "outbox" });

    assert.equal(getSource().submission_id.S, RANDOM_ID);
    const update = calls.find((call) => call.kind === "transact").input.TransactItems[0].Update;
    assert.match(update.ConditionExpression, /attribute_not_exists\(#submission_id\)/);
  });

  it("rejects malformed, version-forged, or over-retained source metadata", () => {
    const overRetained = sourceItem({ opaque: true });
    overRetained.retention_class = { S: "waitlist_365d" };
    assert.throws(() => toOutbox(overRetained), /production submission/);

    const malformed = sourceItem({ opaque: true });
    malformed.submission_id = { S: "not-a-submission" };
    assert.throws(() => toOutbox(malformed), /production submission/);

    const unversioned = sourceItem();
    assert.throws(() => toOutbox(unversioned), /backfill source record|production submission/);
  });
});
