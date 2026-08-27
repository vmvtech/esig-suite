"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  ALLOWED_OFFERS,
  APPROVED_BROKER_ACCOUNT_ID,
  APPROVED_BROKER_QUEUE_ARN,
  APPROVED_BROKER_QUEUE_NAME,
  APPROVED_BROKER_QUEUE_URL,
  APPROVED_BROKER_REGION,
  BROKER_EVENT_TYPE,
  BROKER_CANARY_EVENT_TYPE,
  BROKER_PAYLOAD_FIELDS,
  BROKER_ROUTE,
  BROKER_SCHEMA_VERSION,
  ACTIVATION_PROOF_READ_INVOCATION_TYPE,
  CANARY_INVOCATION_TYPE,
  CANARY_PAYLOAD_FIELDS,
  DURABLE_IDEMPOTENCY_KEY_FIELDS,
  MESSAGE_GROUP_ID,
  OUTBOX_IMAGE_FIELDS,
  buildBrokerPayload,
  buildCanaryPayload,
  createHandler,
  createSqsSender,
  validateBrokerConfig,
} = require("../src/notifier.js");

const PRODUCER_ACCOUNT_ID = "456453427852";
const BROKER_KMS_KEY_ARN = "arn:aws:kms:us-east-1:633740007231:key/01234567-89ab-cdef-0123-456789abcdef";
const BROKER_ENV = Object.freeze({
  PRODUCER_ACCOUNT_ID,
  PRODUCER_REGION: "us-east-1",
  WAITLIST_BROKER_KMS_KEY_ARN: BROKER_KMS_KEY_ARN,
  WAITLIST_BROKER_QUEUE_URL: APPROVED_BROKER_QUEUE_URL,
  WAITLIST_BROKER_QUEUE_ARN: APPROVED_BROKER_QUEUE_ARN,
});

function stringAttribute(value) {
  return { S: value };
}

function validRecord({
  sequenceNumber = "100000000000000000001",
  eventName = "INSERT",
  eventSource = "aws:dynamodb",
  image = {},
} = {}) {
  return {
    eventID: "safe-event-id",
    eventName,
    eventSource,
    eventSourceARN:
      "arn:aws:dynamodb:us-east-1:111111111111:table/esig-waitlist-outbox/stream/2026-08-06T00:00:00.000",
    dynamodb: {
      SequenceNumber: sequenceNumber,
      NewImage: {
        outbox_key: stringAttribute("OUTBOX#wl_0123456789abcdef01234567"),
        record_type: stringAttribute("waitlist_notification_outbox"),
        submission_id: stringAttribute("wl_0123456789abcdef01234567"),
        offer: stringAttribute("shared_starter"),
        source: stringAttribute("pricing"),
        created_at: stringAttribute("2026-08-06T12:00:00.000Z"),
        retention_class: stringAttribute("waitlist_180d"),
        contact_permission_status: stringAttribute("asserted_unverified"),
        email_verification_status: stringAttribute("unverified"),
        expires_at_epoch: { N: "1801569600" },
        ...image,
      },
    },
  };
}

const CANARY_NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
function canaryRecord() {
  return {
    eventName: "INSERT",
    eventSource: "aws:dynamodb",
    dynamodb: {
      SequenceNumber: "123456789",
      NewImage: {
        canary_nonce: { S: CANARY_NONCE },
        created_at: { S: "2026-08-06T12:00:00.000Z" },
        expires_at_epoch: { N: String(Math.floor(new Date("2026-08-06T12:00:00.000Z").getTime() / 1000) + 86400) },
        record_type: { S: "waitlist_notification_canary" },
      },
    },
  };
}

function collectingSender() {
  const messages = [];
  return {
    messages,
    sendMessage: async (input) => messages.push(structuredClone(input)),
  };
}

describe("waitlist broker payload", () => {
  it("constructs only the frozen metadata allow-list", () => {
    const payload = buildBrokerPayload(validRecord());

    assert.equal(Object.isFrozen(BROKER_PAYLOAD_FIELDS), true);
    assert.equal(Object.isFrozen(OUTBOX_IMAGE_FIELDS), true);
    assert.equal(Object.isFrozen(DURABLE_IDEMPOTENCY_KEY_FIELDS), true);
    assert.deepEqual(DURABLE_IDEMPOTENCY_KEY_FIELDS, ["route", "submissionId"]);
    assert.equal(Object.isFrozen(payload), true);
    assert.deepEqual(Object.keys(payload), BROKER_PAYLOAD_FIELDS);
    assert.deepEqual(payload, {
      route: BROKER_ROUTE,
      schemaVersion: BROKER_SCHEMA_VERSION,
      eventType: BROKER_EVENT_TYPE,
      submissionId: "wl_0123456789abcdef01234567",
      offer: "shared_starter",
      source: "pricing",
      createdAt: "2026-08-06T12:00:00.000Z",
      retentionClass: "waitlist_180d",
      contactPermissionStatus: "asserted_unverified",
      emailVerificationStatus: "unverified",
    });
  });

  it("rejects outbox records containing any PII or caller-controlled mail fields", () => {
    for (const [field, attribute] of Object.entries({
      email: stringAttribute("private-person@example.org"),
      name: stringAttribute("Private Person"),
      company: stringAttribute("Sensitive Company"),
      use_case: stringAttribute("Sensitive use case"),
      to: stringAttribute("attacker@example.org"),
      subject: stringAttribute("Caller controlled"),
      headers: { M: { authorization: stringAttribute("secret") } },
    })) {
      assert.throws(
        () => buildBrokerPayload(validRecord({ image: { [field]: attribute } })),
        /record invalid/,
        field,
      );
    }
  });

  it("accepts only published offers and retention classes up to 180 days", () => {
    for (const offer of ALLOWED_OFFERS) {
      const payload = buildBrokerPayload(
        validRecord({ image: { offer: stringAttribute(offer) } }),
      );
      assert.equal(payload.offer, offer);
    }

    assert.equal(
      buildBrokerPayload(
        validRecord({
          image: {
            retention_class: stringAttribute("waitlist_30d"),
            expires_at_epoch: { N: "1788609600" },
          },
        }),
      ).retentionClass,
      "waitlist_30d",
    );

    assert.throws(
      () =>
        buildBrokerPayload(
          validRecord({
            image: { retention_class: stringAttribute("waitlist_181d") },
          }),
        ),
      /record invalid/,
    );
    assert.throws(
      () =>
        buildBrokerPayload(
          validRecord({
            image: { retention_class: stringAttribute("waitlist_365d") },
          }),
        ),
      /record invalid/,
    );
  });

  it("accepts only records whose expiry is strictly after the current clock", () => {
    const expiry = new Date(1801569600 * 1000);
    assert.equal(buildBrokerPayload(validRecord(), new Date(expiry.getTime() - 1)).submissionId, "wl_0123456789abcdef01234567");
    assert.equal(buildBrokerPayload(validRecord(), expiry), undefined);
    assert.equal(buildBrokerPayload(validRecord(), new Date(expiry.getTime() + 1)), undefined);
    assert.throws(
      () => buildBrokerPayload(validRecord({ image: { expires_at_epoch: { N: "1801569599" } } }), new Date(expiry.getTime() - 1)),
      /record invalid/,
    );
  });
});

describe("waitlist stream notifier", () => {
  it("serves only the exact activation-proof read invocation through the injected reader", async () => {
    const receipt = {
      status: "proof-verified",
      proofDigest: "a".repeat(64),
      proofGeneration: `${"1".padStart(39, "0")}:00000000001754600000:00000000001754600100:${"b".repeat(64)}`,
      proofOrder: `${"1".padStart(39, "0")}:00000000001754600000:00000000001754600100:${"b".repeat(64)}:01`,
    };
    let reads = 0;
    const handler = createHandler({
      env: BROKER_ENV,
      readActivationProofHead: async () => {
        reads += 1;
        return receipt;
      },
    });

    assert.deepEqual(
      await handler({ invocationType: ACTIVATION_PROOF_READ_INVOCATION_TYPE }),
      receipt,
    );
    assert.equal(reads, 1);
    await assert.rejects(
      handler({
        invocationType: ACTIVATION_PROOF_READ_INVOCATION_TYPE,
        Records: [],
      }),
      { message: "waitlist activation proof read failed" },
    );
  });

  it("does not expose proof-reader errors", async () => {
    const handler = createHandler({
      env: BROKER_ENV,
      readActivationProofHead: async () => {
        throw new Error("secret broker detail");
      },
    });
    await assert.rejects(
      handler({ invocationType: ACTIVATION_PROOF_READ_INVOCATION_TYPE }),
      { message: "waitlist activation proof read failed" },
    );
  });

  it("carries the canary nonce through the exact SQS payload and returns the actual MessageId", async () => {
    const messages = [];
    const messageId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const handler = createHandler({
      env: BROKER_ENV,
      now: () => new Date("2026-08-06T12:00:01.000Z"),
      sendMessage: async (input) => { messages.push(input); return { MessageId: messageId }; },
    });
    const result = await handler({ invocationType: CANARY_INVOCATION_TYPE, Records: [canaryRecord()] });
    assert.equal(result.sqsMessageId, messageId);
    assert.equal(result.canaryNonce, CANARY_NONCE);
    const payload = JSON.parse(messages[0].MessageBody);
    assert.deepEqual(Object.keys(payload), CANARY_PAYLOAD_FIELDS);
    assert.equal(payload.eventType, BROKER_CANARY_EVENT_TYPE);
    assert.equal(payload.canaryNonce, CANARY_NONCE);
    assert.doesNotMatch(JSON.stringify(payload), /email|offer|name|company|free.?text/i);
  });

  it("never accepts a canary through the normal stream handler and rejects expired canaries", async () => {
    const sender = collectingSender();
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV, now: () => new Date("2026-08-07T12:00:00.000Z") });
    assert.deepEqual(await handler({ Records: [canaryRecord()] }), { batchItemFailures: [] });
    assert.equal(sender.messages.length, 0);
    await assert.rejects(
      handler({ invocationType: CANARY_INVOCATION_TYPE, Records: [canaryRecord()] }),
      /canary|record invalid/,
    );
    assert.equal(sender.messages.length, 0);
  });

  it("acknowledges structurally valid expired rows without sending or retaining a batch failure", async () => {
    const sender = collectingSender();
    const expiry = new Date(1801569600 * 1000);
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV, now: () => expiry });
    assert.deepEqual(await handler({ Records: [validRecord()] }), { batchItemFailures: [] });
    assert.equal(sender.messages.length, 0);
  });

  it("sends the fixed FIFO route with submission-id deduplication and no headers", async () => {
    const sender = collectingSender();
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV });

    const result = await handler({ Records: [validRecord()] });

    assert.deepEqual(result, { batchItemFailures: [] });
    assert.equal(sender.messages.length, 1);
    assert.deepEqual(Object.keys(sender.messages[0]), [
      "QueueUrl",
      "MessageBody",
      "MessageGroupId",
      "MessageDeduplicationId",
    ]);
    assert.equal(sender.messages[0].QueueUrl, BROKER_ENV.WAITLIST_BROKER_QUEUE_URL);
    assert.equal(sender.messages[0].MessageGroupId, MESSAGE_GROUP_ID);
    assert.equal(sender.messages[0].MessageGroupId, "esig.waitlist.sales.v1");
    assert.equal(
      sender.messages[0].MessageDeduplicationId,
      "wl_0123456789abcdef01234567",
    );
    assert.deepEqual(
      Object.keys(JSON.parse(sender.messages[0].MessageBody)),
      BROKER_PAYLOAD_FIELDS,
    );
    assert.equal(sender.messages[0].MessageAttributes, undefined);
  });

  it("skips non-inserts, smoke tests, honeypots, and duplicate records", async () => {
    const sender = collectingSender();
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV });
    const duplicate = validRecord({ sequenceNumber: "100000000000000000005" });

    const result = await handler({
      Records: [
        validRecord({ eventName: "MODIFY", sequenceNumber: "100000000000000000002" }),
        validRecord({
          sequenceNumber: "100000000000000000003",
          image: { record_type: stringAttribute("smoke_test") },
        }),
        validRecord({
          sequenceNumber: "100000000000000000004",
          image: {
            record_type: stringAttribute("honeypot"),
            website: stringAttribute("https://bot.invalid"),
          },
        }),
        validRecord(),
        duplicate,
      ],
    });

    assert.deepEqual(result, { batchItemFailures: [] });
    assert.equal(sender.messages.length, 1);
  });

  it("emits a stable route and submission id for broker-owned durable at-least-once idempotency", async () => {
    const sender = collectingSender();
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV });
    const record = validRecord();

    await handler({ Records: [record] });
    await handler({ Records: [record] });

    assert.equal(sender.messages.length, 2);
    assert.equal(
      sender.messages[0].MessageDeduplicationId,
      sender.messages[1].MessageDeduplicationId,
    );
    const firstPayload = JSON.parse(sender.messages[0].MessageBody);
    const secondPayload = JSON.parse(sender.messages[1].MessageBody);
    assert.deepEqual(
      DURABLE_IDEMPOTENCY_KEY_FIELDS.map((field) => firstPayload[field]),
      DURABLE_IDEMPOTENCY_KEY_FIELDS.map((field) => secondPayload[field]),
    );
  });

  it("returns the DynamoDB sequence number for each malformed eligible record", async () => {
    const sender = collectingSender();
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV });

    const result = await handler({
      Records: [
        validRecord({
          sequenceNumber: "100000000000000000010",
          image: { offer: { N: "1" } },
        }),
        validRecord({
          sequenceNumber: "100000000000000000011",
          eventSource: "caller:controlled",
        }),
      ],
    });

    assert.deepEqual(result, {
      batchItemFailures: [
        { itemIdentifier: "100000000000000000010" },
        { itemIdentifier: "100000000000000000011" },
      ],
    });
    assert.equal(sender.messages.length, 0);
  });

  it("continues the batch and reports only a failed send", async () => {
    const sent = [];
    const handler = createHandler({
      env: BROKER_ENV,
      sendMessage: async (input) => {
        if (input.MessageDeduplicationId === "wl_0123456789abcdef01234567") {
          throw new Error("broker secret response");
        }
        sent.push(input);
      },
      logger: { error() {} },
    });

    const result = await handler({
      Records: [
        validRecord({ sequenceNumber: "100000000000000000020" }),
        validRecord({
          sequenceNumber: "100000000000000000021",
          image: {
            submission_id: stringAttribute("wl_89abcdef0123456701234568"),
            outbox_key: stringAttribute("OUTBOX#wl_89abcdef0123456701234568"),
          },
        }),
      ],
    });

    assert.deepEqual(result, {
      batchItemFailures: [{ itemIdentifier: "100000000000000000020" }],
    });
    assert.equal(sent.length, 1);
    assert.equal(sent[0].MessageDeduplicationId, "wl_89abcdef0123456701234568");
  });

  it("fails the whole batch generically when an eligible failure has no sequence number", async () => {
    const handler = createHandler({
      env: BROKER_ENV,
      sendMessage: async () => {
        throw new Error("private-person@example.org:SECRET-do-not-log");
      },
      logger: { error() {} },
    });

    await assert.rejects(
      handler({ Records: [validRecord({ sequenceNumber: null })] }),
      { message: "waitlist notifier batch failed" },
    );
  });

  it("treats missing and non-array record lists as empty batches", async () => {
    const sender = collectingSender();
    const handler = createHandler({ sendMessage: sender.sendMessage, env: BROKER_ENV });

    assert.deepEqual(await handler({}), { batchItemFailures: [] });
    assert.deepEqual(await handler({ Records: {} }), { batchItemFailures: [] });
    assert.equal(sender.messages.length, 0);
  });

  it("does not expose PII, queue details, or broker errors in logs", async () => {
    const logs = [];
    const record = validRecord({
      image: { email: stringAttribute("private-person@example.org") },
    });
    const handler = createHandler({
      env: BROKER_ENV,
      sendMessage: async () => {
        throw new Error("SECRET-do-not-log");
      },
      logger: { error: (entry) => logs.push(entry) },
    });

    const result = await handler({ Records: [record] });
    const transcript = logs.join("\n");

    assert.deepEqual(result, {
      batchItemFailures: [{ itemIdentifier: "100000000000000000001" }],
    });
    assert.match(transcript, /waitlist_notifier_record_failed/);
    assert.doesNotMatch(transcript, /private-person|SECRET-do-not-log/i);
    assert.doesNotMatch(
      transcript,
      /111111111111|633740007231|esig-mail-enqueue-standard/i,
    );
  });
});

describe("waitlist broker configuration", () => {
  it("accepts only the hard-pinned Standard-lane FIFO URL and ARN", () => {
    const config = validateBrokerConfig(BROKER_ENV);

    assert.equal(Object.isFrozen(config), true);
    assert.deepEqual(config, {
      queueUrl: BROKER_ENV.WAITLIST_BROKER_QUEUE_URL,
      queueArn: BROKER_ENV.WAITLIST_BROKER_QUEUE_ARN,
      region: APPROVED_BROKER_REGION,
      producerAccountId: PRODUCER_ACCOUNT_ID,
      brokerAccountId: APPROVED_BROKER_ACCOUNT_ID,
      brokerKmsKeyArn: BROKER_KMS_KEY_ARN,
    });
    assert.equal(APPROVED_BROKER_QUEUE_NAME, "esig-mail-enqueue-standard.fifo");
  });

  it("rejects any alternate pair, including internally consistent cross-account FIFO coordinates", () => {
    const invalidEnvironments = [
      {
        ...BROKER_ENV,
        PRODUCER_ACCOUNT_ID: APPROVED_BROKER_ACCOUNT_ID,
      },
      { ...BROKER_ENV, PRODUCER_REGION: "us-west-2" },
      { ...BROKER_ENV, WAITLIST_BROKER_KMS_KEY_ARN: "" },
      {
        ...BROKER_ENV,
        WAITLIST_BROKER_QUEUE_URL:
          "https://sqs.us-east-1.amazonaws.com/333333333333/alternate.fifo",
        WAITLIST_BROKER_QUEUE_ARN:
          "arn:aws:sqs:us-east-1:333333333333:alternate.fifo",
      },
      {
        ...BROKER_ENV,
        WAITLIST_BROKER_QUEUE_ARN:
          `arn:aws:sqs:us-west-2:${APPROVED_BROKER_ACCOUNT_ID}:${APPROVED_BROKER_QUEUE_NAME}`,
      },
      {
        ...BROKER_ENV,
        WAITLIST_BROKER_QUEUE_ARN:
          `arn:aws:sqs:us-east-1:${APPROVED_BROKER_ACCOUNT_ID}:different.fifo`,
      },
      {
        ...BROKER_ENV,
        WAITLIST_BROKER_QUEUE_URL:
          `https://sqs.us-east-1.amazonaws.com/${APPROVED_BROKER_ACCOUNT_ID}/not-fifo`,
      },
      {
        ...BROKER_ENV,
        WAITLIST_BROKER_QUEUE_URL:
          `${BROKER_ENV.WAITLIST_BROKER_QUEUE_URL}?recipient=attacker`,
      },
      {
        ...BROKER_ENV,
        WAITLIST_BROKER_QUEUE_ARN:
          `arn:aws-cn:sqs:us-east-1:${APPROVED_BROKER_ACCOUNT_ID}:${APPROVED_BROKER_QUEUE_NAME}`,
      },
    ];

    for (const env of invalidEnvironments) {
      assert.throws(
        () => validateBrokerConfig(env),
        { message: "waitlist notifier configuration invalid" },
      );
    }
  });

  it("passes the exact command to the injected SQS adapter", async () => {
    const commands = [];
    const config = validateBrokerConfig(BROKER_ENV);
    const send = createSqsSender({
      config,
      client: { send: async (command) => commands.push(command) },
      commandFactory: (input) => ({ input }),
    });
    const input = {
      QueueUrl: config.queueUrl,
      MessageBody: "{}",
      MessageGroupId: BROKER_ROUTE,
      MessageDeduplicationId: "wl_0123456789abcdef01234567",
    };

    await send(input);

    assert.deepEqual(commands, [{ input }]);
  });
});
