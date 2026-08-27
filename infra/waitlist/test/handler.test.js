"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  ALLOWED_OFFERS,
  createDynamoStore,
  createHandler,
  createNotificationOutbox,
  createSubmission,
} = require("../src/handler.js");

const ORIGIN = "https://e-sig.org";
const FIXED_NOW = new Date("2026-08-06T12:00:00.000Z");

function request(body, overrides = {}) {
  return {
    requestContext: {
      requestId: "unit-test-request",
      identity: { sourceIp: "192.0.2.10" },
    },
    httpMethod: overrides.method || "POST",
    path: "/waitlist",
    body: JSON.stringify(body),
    isBase64Encoded: false,
    ...overrides,
    headers: {
      "content-type": "application/json",
      origin: ORIGIN,
      ...(overrides.headers || {}),
    },
  };
}

function validBody(overrides = {}) {
  return {
    offer: "shared_starter",
    email: "person@example.org",
    name: "Person",
    company: "Example Org",
    useCase: "Sign customer agreements",
    expectedMonthlyEnvelopes: "100-500",
    consent: true,
    website: "",
    source: "pricing",
    ...overrides,
  };
}

function memoryStore() {
  const items = new Map();
  const outboxItems = new Map();
  return {
    items,
    outboxItems,
    async putSubmission(item) {
      if (items.has(item.submission_key)) return false;
      items.set(item.submission_key, structuredClone(item));
      if (item.record_type === "waitlist_submission") {
        const outbox = createNotificationOutbox(item);
        outboxItems.set(outbox.outbox_key, structuredClone(outbox));
      }
      return true;
    },
  };
}

function productionSubmission() {
  return {
    submission_key: "WAITLIST#0123456789abcdef",
    submission_id: "wl_0123456789abcdef01234567",
    submission_id_version: "random-v1",
    email: "person@example.org",
    name: "Private Person",
    company: "Private Company",
    use_case: "Private use case",
    offer: "shared_starter",
    source: "pricing",
    contact_permission_status: "asserted_unverified",
    email_verification_status: "unverified",
    created_at: FIXED_NOW.toISOString(),
    record_type: "waitlist_submission",
    retention_class: "waitlist_180d",
    expires_at_epoch:
      Math.floor(FIXED_NOW.getTime() / 1000) + 180 * 24 * 60 * 60,
  };
}

function parseBody(result) {
  return result.body ? JSON.parse(result.body) : undefined;
}

describe("waitlist handler", () => {
  it("normalizes, stores, and acknowledges a valid first-party submission", async () => {
    const store = memoryStore();
    const handler = createHandler({ store, now: () => FIXED_NOW });

    const result = await handler(
      request(validBody({ email: "  Person@Example.ORG  ", name: "  Person  " })),
    );

    assert.equal(result.statusCode, 202);
    assert.equal(result.headers["access-control-allow-origin"], ORIGIN);
    assert.equal(result.headers["cache-control"], "no-store");
    assert.deepEqual(parseBody(result), { status: "accepted" });
    assert.doesNotMatch(result.body, /person@example\.org/i);
    assert.equal(store.items.size, 1);

    const [stored] = store.items.values();
    assert.equal(stored.email, "person@example.org");
    assert.equal(stored.name, "Person");
    assert.equal(stored.offer, "shared_starter");
    assert.equal(stored.source, "pricing");
    assert.equal(stored.contact_permission_status, "asserted_unverified");
    assert.equal(stored.email_verification_status, "unverified");
    assert.match(stored.submission_id, /^wl_[0-9a-f]{24}$/);
    assert.equal(stored.submission_id_version, "random-v1");
    assert.equal(stored.consent, undefined);
    assert.equal(stored.created_at, FIXED_NOW.toISOString());
    assert.equal(stored.record_type, "waitlist_submission");
    assert.equal(stored.retention_class, "waitlist_180d");
    assert.equal(
      stored.expires_at_epoch,
      Math.floor(FIXED_NOW.getTime() / 1000) + 180 * 24 * 60 * 60,
    );
    assert.equal(store.outboxItems.size, 1);
    const [outbox] = store.outboxItems.values();
    assert.deepEqual(outbox, {
      outbox_key: `OUTBOX#${stored.submission_id}`,
      record_type: "waitlist_notification_outbox",
      submission_id: stored.submission_id,
      offer: "shared_starter",
      source: "pricing",
      created_at: FIXED_NOW.toISOString(),
      retention_class: "waitlist_180d",
      contact_permission_status: "asserted_unverified",
      email_verification_status: "unverified",
      expires_at_epoch:
        Math.floor(FIXED_NOW.getTime() / 1000) + 180 * 24 * 60 * 60,
    });
    assert.doesNotMatch(JSON.stringify(outbox), /person@example\.org|Example Org|Sign customer/i);
  });

  it("uses independent random lookup IDs while keeping the deduplication key stable", () => {
    const value = {
      email: "person@example.org",
      offer: "shared_starter",
      source: "pricing",
    };
    const first = createSubmission(
      value,
      FIXED_NOW,
      180,
      24,
      () => Buffer.alloc(12, 0x11),
    );
    const second = createSubmission(
      value,
      FIXED_NOW,
      180,
      24,
      () => Buffer.alloc(12, 0x22),
    );

    assert.equal(first.submission_key, second.submission_key);
    assert.notEqual(first.submission_id, second.submission_id);
    assert.equal(first.submission_id, `wl_${"11".repeat(12)}`);
    assert.equal(second.submission_id, `wl_${"22".repeat(12)}`);
    assert.doesNotMatch(first.submission_id, /person|example|shared/i);
  });

  it("fails closed without writing when the entropy source is invalid", async () => {
    const store = memoryStore();
    const logs = [];
    const handler = createHandler({
      store,
      now: () => FIXED_NOW,
      randomBytesFn: () => Buffer.alloc(8),
      logger: { error: (line) => logs.push(line) },
    });

    const result = await handler(request(validBody()));

    assert.equal(result.statusCode, 503);
    assert.deepEqual(parseBody(result), { error: "temporarily_unavailable" });
    assert.equal(store.items.size, 0);
    assert.match(logs.join("\n"), /waitlist_submission_id_failure/);
    assert.doesNotMatch(logs.join("\n"), /person@example\.org/);
  });

  it("fails closed to the published 180-day ceiling when configured above it", async () => {
    const store = memoryStore();
    const handler = createHandler({
      store,
      now: () => FIXED_NOW,
      env: { PRODUCTION_RETENTION_DAYS: "365" },
    });

    const result = await handler(request(validBody()));

    assert.equal(result.statusCode, 202);
    const [stored] = store.items.values();
    assert.equal(stored.retention_class, "waitlist_180d");
    assert.equal(
      stored.expires_at_epoch,
      Math.floor(FIXED_NOW.getTime() / 1000) + 180 * 24 * 60 * 60,
    );
  });

  it("deduplicates retries by normalized email and offer with a stable response", async () => {
    const store = memoryStore();
    const handler = createHandler({ store, now: () => FIXED_NOW });

    const first = await handler(request(validBody({ email: "Person@Example.org" })));
    const retry = await handler(request(validBody({ email: " person@example.ORG " })));

    assert.equal(first.statusCode, 202);
    assert.equal(retry.statusCode, 202);
    assert.deepEqual(parseBody(first), { status: "accepted" });
    assert.deepEqual(parseBody(retry), parseBody(first));
    assert.equal(store.items.size, 1);
  });

  it("accepts every published tier and add-on offer identifier", async () => {
    const store = memoryStore();
    const handler = createHandler({ store, now: () => FIXED_NOW });

    for (const [index, offer] of [...ALLOWED_OFFERS].entries()) {
      const result = await handler(
        request(validBody({ offer, email: `lead-${index}@example.org` })),
      );
      assert.equal(result.statusCode, 202, offer);
    }

    assert.equal(store.items.size, ALLOWED_OFFERS.size);
  });

  it("gives example.com smoke records a bounded TTL without a client test flag", async () => {
    const store = memoryStore();
    const handler = createHandler({
      store,
      now: () => FIXED_NOW,
      env: {
        ALLOWED_ORIGIN: ORIGIN,
        SMOKE_TEST_TTL_HOURS: "24",
      },
    });

    const result = await handler(request(validBody({ email: "browser-smoke@example.com" })));
    assert.equal(result.statusCode, 202);
    const [stored] = store.items.values();
    assert.equal(stored.record_type, "smoke_test");
    assert.equal(
      stored.expires_at_epoch,
      Math.floor(FIXED_NOW.getTime() / 1000) + 24 * 60 * 60,
    );
    assert.equal(store.outboxItems.size, 0);

    const clientFlag = await handler(
      request({ ...validBody({ email: "another@example.com" }), smokeTest: true }),
    );
    assert.equal(clientFlag.statusCode, 400);
    assert.deepEqual(parseBody(clientFlag).fields, ["request"]);
  });

  it("treats a populated honeypot as accepted without storing it", async () => {
    const store = memoryStore();
    const handler = createHandler({ store, now: () => FIXED_NOW });

    const result = await handler(request(validBody({ website: "https://bot.invalid" })));

    assert.equal(result.statusCode, 202);
    assert.deepEqual(parseBody(result), { status: "accepted" });
    assert.equal(store.items.size, 0);
  });

  it("rejects non-site origins, unsupported media, invalid fields, and oversized bodies", async () => {
    const store = memoryStore();
    const handler = createHandler({ store, now: () => FIXED_NOW });

    const wrongOrigin = await handler(
      request(validBody(), { headers: { origin: "https://attacker.invalid" } }),
    );
    assert.equal(wrongOrigin.statusCode, 403);
    assert.equal(wrongOrigin.headers["access-control-allow-origin"], undefined);

    const wrongMedia = await handler(
      request(validBody(), { headers: { "content-type": "text/plain" } }),
    );
    assert.equal(wrongMedia.statusCode, 415);

    const invalid = await handler(
      request(
        validBody({
          offer: "not-an-offer",
          email: "not-an-email",
          consent: false,
          source: "elsewhere",
          name: "x".repeat(101),
        }),
      ),
    );
    assert.equal(invalid.statusCode, 400);
    assert.deepEqual(new Set(parseBody(invalid).fields), new Set([
      "email",
      "offer",
      "source",
      "consent",
      "name",
    ]));

    for (const email of ["foo.bar", "two@@example.org", "person@-example.org"]) {
      const malformedEmail = await handler(request(validBody({ email })));
      assert.equal(malformedEmail.statusCode, 400, email);
      assert.ok(parseBody(malformedEmail).fields.includes("email"), email);
    }

    const oversized = await handler({
      ...request(validBody()),
      body: `{"padding":"${"x".repeat(17 * 1024)}"}`,
    });
    assert.equal(oversized.statusCode, 400);
    assert.equal(store.items.size, 0);
  });

  it("does not expose PII, request bodies, or thrown secrets in logs", async () => {
    const logs = [];
    const secretText = "SECRET-do-not-log";
    const email = "private-person@example.org";
    const logger = {
      error: (entry) => logs.push(entry),
      warn: (entry) => logs.push(entry),
    };
    const handler = createHandler({
      store: {
        async putSubmission() {
          throw new Error(`${secretText}:${email}`);
        },
      },
      now: () => FIXED_NOW,
      logger,
    });

    const result = await handler(request(validBody({ email })));

    assert.equal(result.statusCode, 503);
    const transcript = logs.join("\n") + result.body;
    assert.doesNotMatch(transcript, /private-person/i);
    assert.doesNotMatch(transcript, /SECRET-do-not-log/);
    assert.match(transcript, /waitlist_storage_failure/);
  });
});

describe("DynamoDB adapter", () => {
  it("fails closed before writing malformed or over-retained outbox metadata", () => {
    assert.throws(
      () =>
        createNotificationOutbox({
          ...productionSubmission(),
          retention_class: "waitlist_365d",
        }),
      /outbox requires a production submission/,
    );
    assert.throws(
      () =>
        createNotificationOutbox({
          ...productionSubmission(),
          submission_id: "person@example.org",
        }),
      /outbox requires a production submission/,
    );
  });

  it("atomically writes the private submission and metadata-only outbox", async () => {
    const inputs = [];
    const client = {
      async send(input) {
        inputs.push(input);
      },
    };
    const store = createDynamoStore({
      outboxTableName: "waitlist-outbox-table",
      tableName: "waitlist-table",
      client,
      commandFactory: (input) => input,
    });

    const inserted = await store.putSubmission(productionSubmission());

    assert.equal(inserted, true);
    assert.equal(inputs.length, 1);
    assert.equal(inputs[0].ClientRequestToken, undefined);
    assert.equal(inputs[0].TransactItems.length, 2);

    const privatePut = inputs[0].TransactItems[0].Put;
    assert.equal(privatePut.TableName, "waitlist-table");
    assert.equal(privatePut.ConditionExpression, "attribute_not_exists(#submission_key)");
    assert.deepEqual(privatePut.Item.email, { S: "person@example.org" });

    const outboxPut = inputs[0].TransactItems[1].Put;
    assert.equal(outboxPut.TableName, "waitlist-outbox-table");
    assert.equal(outboxPut.ConditionExpression, "attribute_not_exists(#outbox_key)");
    assert.deepEqual(outboxPut.Item.outbox_key, {
      S: "OUTBOX#wl_0123456789abcdef01234567",
    });
    assert.deepEqual(Object.keys(outboxPut.Item).sort(), [
      "contact_permission_status",
      "created_at",
      "email_verification_status",
      "expires_at_epoch",
      "offer",
      "outbox_key",
      "record_type",
      "retention_class",
      "source",
      "submission_id",
    ]);
    assert.doesNotMatch(
      JSON.stringify(outboxPut),
      /person@example\.org|Private Person|Private Company|Private use case/,
    );
  });

  it("writes smoke tests privately without creating notification outbox records", async () => {
    const inputs = [];
    const store = createDynamoStore({
      tableName: "waitlist-table",
      outboxTableName: "waitlist-outbox-table",
      client: { send: async (input) => inputs.push(input) },
      commandFactory: (input) => input,
    });
    const smoke = {
      ...productionSubmission(),
      record_type: "smoke_test",
      retention_class: "smoke_24h",
    };

    assert.equal(await store.putSubmission(smoke), true);
    assert.equal(inputs[0].TransactItems.length, 1);
    assert.equal(inputs[0].TransactItems[0].Put.TableName, "waitlist-table");
  });

  it("maps only an explicit conditional transaction cancellation to a duplicate", async () => {
    const duplicateStore = createDynamoStore({
      outboxTableName: "waitlist-outbox-table",
      tableName: "waitlist-table",
      client: {
        async send() {
          const error = new Error("conditional");
          error.name = "TransactionCanceledException";
          error.CancellationReasons = [
            { Code: "ConditionalCheckFailed" },
            { Code: "None" },
          ];
          throw error;
        },
      },
      commandFactory: (input) => input,
    });
    assert.equal(await duplicateStore.putSubmission(productionSubmission()), false);

    const lookupIdCollisionStore = createDynamoStore({
      outboxTableName: "waitlist-outbox-table",
      tableName: "waitlist-table",
      client: {
        async send() {
          const error = new Error("lookup ID collision");
          error.name = "TransactionCanceledException";
          error.CancellationReasons = [
            { Code: "None" },
            { Code: "ConditionalCheckFailed" },
          ];
          throw error;
        },
      },
      commandFactory: (input) => input,
    });
    await assert.rejects(
      lookupIdCollisionStore.putSubmission(productionSubmission()),
      /lookup ID collision/,
    );

    const conflictStore = createDynamoStore({
      outboxTableName: "waitlist-outbox-table",
      tableName: "waitlist-table",
      client: {
        async send() {
          const error = new Error("retryable");
          error.name = "TransactionCanceledException";
          error.CancellationReasons = [{ Code: "TransactionConflict" }];
          throw error;
        },
      },
      commandFactory: (input) => input,
    });
    await assert.rejects(conflictStore.putSubmission(productionSubmission()), /retryable/);
  });
});
