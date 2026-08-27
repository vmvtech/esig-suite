"use strict";

const { createHash } = require("node:crypto");
const {
  ACTIVATION_PROOF_READ_INVOCATION_TYPE,
  createActivationProofHeadReader,
} = require("./activation-proof.js");

const BROKER_ROUTE = "esig.waitlist.sales.v1";
const BROKER_EVENT_TYPE = "waitlist.submitted";
const BROKER_CANARY_EVENT_TYPE = "waitlist.activation_canary";
const BROKER_SCHEMA_VERSION = 1;
const MESSAGE_GROUP_ID = BROKER_ROUTE;
const APPROVED_BROKER_ACCOUNT_ID = "633740007231";
const APPROVED_BROKER_REGION = "us-east-1";
const APPROVED_PRODUCER_ACCOUNT_ID = "456453427852";
const APPROVED_PRODUCER_REGION = "us-east-1";
const APPROVED_BROKER_QUEUE_NAME = "esig-mail-enqueue-standard.fifo";
const APPROVED_BROKER_QUEUE_URL =
  `https://sqs.${APPROVED_BROKER_REGION}.amazonaws.com/` +
  `${APPROVED_BROKER_ACCOUNT_ID}/${APPROVED_BROKER_QUEUE_NAME}`;
const APPROVED_BROKER_QUEUE_ARN =
  `arn:aws:sqs:${APPROVED_BROKER_REGION}:` +
  `${APPROVED_BROKER_ACCOUNT_ID}:${APPROVED_BROKER_QUEUE_NAME}`;

const BROKER_PAYLOAD_FIELDS = Object.freeze([
  "route",
  "schemaVersion",
  "eventType",
  "submissionId",
  "offer",
  "source",
  "createdAt",
  "retentionClass",
  "contactPermissionStatus",
  "emailVerificationStatus",
]);

const ALLOWED_OFFERS = Object.freeze([
  "shared_starter",
  "shared_team",
  "shared_scale",
  "business",
  "dedicated",
  "addon_hipaa_baa",
  "addon_hsm_signer",
  "addon_21cfr_part11",
  "addon_uuaid_ent",
  "addon_worm",
  "addon_eidas_qes",
]);

const OUTBOX_IMAGE_FIELDS = Object.freeze([
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
const CANARY_IMAGE_FIELDS = Object.freeze([
  "canary_nonce",
  "created_at",
  "expires_at_epoch",
  "record_type",
]);
const CANARY_PAYLOAD_FIELDS = Object.freeze([
  "route",
  "schemaVersion",
  "eventType",
  "canaryNonce",
  "createdAt",
  "expiresAtEpoch",
]);
const CANARY_INVOCATION_TYPE = "waitlist_activation_canary";
const CANARY_NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SQS_MESSAGE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// FIFO deduplication is short-lived. The broker must persist this key for at
// least the 24-hour producer retry horizon before it renders any notification.
const DURABLE_IDEMPOTENCY_KEY_FIELDS = Object.freeze(["route", "submissionId"]);

const ALLOWED_OFFER_SET = new Set(ALLOWED_OFFERS);
const SUBMISSION_ID_PATTERN = /^wl_[a-f0-9]{24}$/;
const SEQUENCE_NUMBER_PATTERN = /^[0-9]{1,128}$/;
const ACCOUNT_ID_PATTERN = /^[0-9]{12}$/;
const BROKER_KMS_KEY_ARN_PATTERN = /^arn:aws:kms:us-east-1:633740007231:key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function notifierError() {
  return new Error("waitlist notifier record invalid");
}

function configurationError() {
  return new Error("waitlist notifier configuration invalid");
}

function readStringAttribute(image, name) {
  const attribute = image?.[name];
  if (!attribute || typeof attribute !== "object" || typeof attribute.S !== "string") {
    throw notifierError();
  }
  return attribute.S;
}

function readIntegerAttribute(image, name) {
  const attribute = image?.[name];
  if (!attribute || typeof attribute !== "object" || typeof attribute.N !== "string") {
    throw notifierError();
  }
  const value = Number(attribute.N);
  if (!Number.isSafeInteger(value)) throw notifierError();
  return value;
}

function readSequenceNumber(record) {
  const value = record?.dynamodb?.SequenceNumber;
  return typeof value === "string" && SEQUENCE_NUMBER_PATTERN.test(value)
    ? value
    : undefined;
}

function safeLog(logger, level, eventName, sequenceNumber) {
  const write = logger && typeof logger[level] === "function" ? logger[level] : null;
  if (!write) return;

  const safeSequenceNumber =
    typeof sequenceNumber === "string" && SEQUENCE_NUMBER_PATTERN.test(sequenceNumber)
      ? sequenceNumber
      : "unknown";

  try {
    write.call(
      logger,
      JSON.stringify({ event: eventName, sequenceNumber: safeSequenceNumber }),
    );
  } catch {
    // Logging must never change stream retry behavior.
  }
}

function isEligibleInsert(record) {
  return (
    record?.eventName === "INSERT" &&
    record?.dynamodb?.NewImage?.record_type?.S === "waitlist_notification_outbox"
  );
}

function isCanaryInsert(record) {
  return record?.eventName === "INSERT" &&
    record?.dynamodb?.NewImage?.record_type?.S === "waitlist_notification_canary";
}

function isExactIsoTimestamp(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

function retentionDays(value) {
  if (typeof value !== "string") return undefined;
  const match = /^waitlist_([0-9]{2,3})d$/.exec(value);
  if (!match) return undefined;
  const days = Number(match[1]);
  return Number.isInteger(days) && days >= 30 && days <= 180 ? days : undefined;
}

function buildBrokerPayload(record, now = new Date()) {
  if (record?.eventSource !== "aws:dynamodb" || !isEligibleInsert(record)) {
    throw notifierError();
  }

  const image = record.dynamodb.NewImage;
  const imageFields = Object.keys(image).sort();
  if (
    imageFields.length !== OUTBOX_IMAGE_FIELDS.length ||
    imageFields.some((field, index) => field !== OUTBOX_IMAGE_FIELDS[index])
  ) {
    throw notifierError();
  }

  const outboxKey = readStringAttribute(image, "outbox_key");
  const submissionId = readStringAttribute(image, "submission_id");
  const offer = readStringAttribute(image, "offer");
  const source = readStringAttribute(image, "source");
  const createdAt = readStringAttribute(image, "created_at");
  const retentionClass = readStringAttribute(image, "retention_class");
  const expiresAtEpoch = readIntegerAttribute(image, "expires_at_epoch");
  const contactPermissionStatus = readStringAttribute(
    image,
    "contact_permission_status",
  );
  const emailVerificationStatus = readStringAttribute(
    image,
    "email_verification_status",
  );
  const allowedRetentionDays = retentionDays(retentionClass);
  const createdAtEpoch = Math.floor(new Date(createdAt).getTime() / 1000);
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw notifierError();
  const nowEpoch = Math.floor(now.getTime() / 1000);

  if (
    outboxKey !== `OUTBOX#${submissionId}` ||
    !SUBMISSION_ID_PATTERN.test(submissionId) ||
    !ALLOWED_OFFER_SET.has(offer) ||
    source !== "pricing" ||
    !isExactIsoTimestamp(createdAt) ||
    allowedRetentionDays === undefined ||
    expiresAtEpoch !== createdAtEpoch + allowedRetentionDays * 24 * 60 * 60 ||
    contactPermissionStatus !== "asserted_unverified" ||
    emailVerificationStatus !== "unverified"
  ) {
    throw notifierError();
  }
  if (expiresAtEpoch <= nowEpoch) return undefined;

  const values = {
    route: BROKER_ROUTE,
    schemaVersion: BROKER_SCHEMA_VERSION,
    eventType: BROKER_EVENT_TYPE,
    submissionId,
    offer,
    source,
    createdAt,
    retentionClass,
    contactPermissionStatus,
    emailVerificationStatus,
  };

  const payload = {};
  for (const field of BROKER_PAYLOAD_FIELDS) payload[field] = values[field];
  return Object.freeze(payload);
}

function buildCanaryPayload(record, now = new Date()) {
  if (record?.eventSource !== "aws:dynamodb" || !isCanaryInsert(record)) throw notifierError();
  const image = record.dynamodb.NewImage;
  const fields = Object.keys(image).sort();
  if (fields.length !== CANARY_IMAGE_FIELDS.length || fields.some((field, index) => field !== CANARY_IMAGE_FIELDS[index])) {
    throw notifierError();
  }
  const canaryNonce = readStringAttribute(image, "canary_nonce");
  const createdAt = readStringAttribute(image, "created_at");
  const expiresAtEpoch = readIntegerAttribute(image, "expires_at_epoch");
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw notifierError();
  const createdAtEpoch = Math.floor(new Date(createdAt).getTime() / 1000);
  const nowEpoch = Math.floor(now.getTime() / 1000);
  if (
    !CANARY_NONCE_PATTERN.test(canaryNonce) ||
    Buffer.from(canaryNonce, "base64url").length !== 32 ||
    !isExactIsoTimestamp(createdAt) ||
    createdAtEpoch > nowEpoch ||
    expiresAtEpoch !== createdAtEpoch + 86400 ||
    expiresAtEpoch <= nowEpoch
  ) throw notifierError();
  const values = {
    route: BROKER_ROUTE,
    schemaVersion: BROKER_SCHEMA_VERSION,
    eventType: BROKER_CANARY_EVENT_TYPE,
    canaryNonce,
    createdAt,
    expiresAtEpoch,
  };
  const payload = {};
  for (const field of CANARY_PAYLOAD_FIELDS) payload[field] = values[field];
  return Object.freeze(payload);
}

function validateBrokerConfig(env = process.env) {
  const queueUrlValue = env.WAITLIST_BROKER_QUEUE_URL;
  const queueArnValue = env.WAITLIST_BROKER_QUEUE_ARN;
  const producerAccountId = env.PRODUCER_ACCOUNT_ID;
  const producerRegion = env.PRODUCER_REGION;
  const brokerKmsKeyArn = env.WAITLIST_BROKER_KMS_KEY_ARN;

  if (
    typeof queueUrlValue !== "string" ||
    typeof queueArnValue !== "string" ||
    typeof producerAccountId !== "string" ||
    !ACCOUNT_ID_PATTERN.test(producerAccountId) ||
    producerAccountId !== APPROVED_PRODUCER_ACCOUNT_ID ||
    producerRegion !== APPROVED_PRODUCER_REGION ||
    typeof brokerKmsKeyArn !== "string" ||
    !BROKER_KMS_KEY_ARN_PATTERN.test(brokerKmsKeyArn) ||
    queueUrlValue !== APPROVED_BROKER_QUEUE_URL ||
    queueArnValue !== APPROVED_BROKER_QUEUE_ARN
  ) {
    throw configurationError();
  }

  return Object.freeze({
    queueUrl: queueUrlValue,
    queueArn: queueArnValue,
    region: APPROVED_BROKER_REGION,
    producerAccountId,
    brokerAccountId: APPROVED_BROKER_ACCOUNT_ID,
    brokerKmsKeyArn,
  });
}

function createSqsSender({ config, client, commandFactory } = {}) {
  if (!config || typeof config.queueUrl !== "string" || typeof config.region !== "string") {
    throw configurationError();
  }

  let resolvedClient = client;
  let resolvedCommandFactory = commandFactory;

  function resolveSdk() {
    if (resolvedClient && resolvedCommandFactory) return;
    const { SendMessageCommand, SQSClient } = require("@aws-sdk/client-sqs");
    resolvedClient = resolvedClient || new SQSClient({ region: config.region });
    resolvedCommandFactory =
      resolvedCommandFactory || ((input) => new SendMessageCommand(input));
  }

  return async function sendBrokerMessage(input) {
    resolveSdk();
    return resolvedClient.send(resolvedCommandFactory(input));
  };
}

function createHandler({
  sendMessage,
  readActivationProofHead,
  env = process.env,
  logger = console,
  now = () => new Date(),
} = {}) {
  const config = validateBrokerConfig(env);
  let resolvedSendMessage = sendMessage;
  let resolvedReadActivationProofHead = readActivationProofHead;

  return async function waitlistNotifier(event) {
    if (event?.invocationType === ACTIVATION_PROOF_READ_INVOCATION_TYPE) {
      if (
        !event ||
        typeof event !== "object" ||
        Array.isArray(event) ||
        Object.keys(event).length !== 1
      ) {
        throw new Error("waitlist activation proof read failed");
      }
      resolvedReadActivationProofHead =
        resolvedReadActivationProofHead ||
        createActivationProofHeadReader({
          expectedBrokerKmsKeyArn: config.brokerKmsKeyArn,
          now,
        });
      try {
        return await resolvedReadActivationProofHead();
      } catch {
        throw new Error("waitlist activation proof read failed");
      }
    }

    const records = Array.isArray(event?.Records) ? event.Records : [];
    if (event?.invocationType === CANARY_INVOCATION_TYPE) {
      if (Object.keys(event).sort().join(",") !== "Records,invocationType" || records.length !== 1 || !isCanaryInsert(records[0])) {
        throw new Error("waitlist notifier canary failed");
      }
      const payload = buildCanaryPayload(records[0], now());
      resolvedSendMessage = resolvedSendMessage || createSqsSender({ config });
      const response = await resolvedSendMessage({
        QueueUrl: config.queueUrl,
        MessageBody: JSON.stringify(payload),
        MessageGroupId: MESSAGE_GROUP_ID,
        MessageDeduplicationId: `canary-${createHash("sha256").update(payload.canaryNonce).digest("hex")}`,
      });
      if (!SQS_MESSAGE_ID_PATTERN.test(response?.MessageId || "")) throw new Error("waitlist notifier canary failed");
      return {
        canaryNonce: payload.canaryNonce,
        sqsMessageId: response.MessageId,
        createdAt: payload.createdAt,
        expiresAt: new Date(payload.expiresAtEpoch * 1000).toISOString(),
      };
    }
    const failures = [];
    const failedSequenceNumbers = new Set();
    const deliveredSubmissionIds = new Set();

    for (const record of records) {
      if (!isEligibleInsert(record)) continue;

      const sequenceNumber = readSequenceNumber(record);
      try {
        const payload = buildBrokerPayload(record, now());
        if (!payload) continue;
        if (deliveredSubmissionIds.has(payload.submissionId)) continue;

        resolvedSendMessage =
          resolvedSendMessage || createSqsSender({ config });
        await resolvedSendMessage({
          QueueUrl: config.queueUrl,
          MessageBody: JSON.stringify(payload),
          MessageGroupId: MESSAGE_GROUP_ID,
          MessageDeduplicationId: payload.submissionId,
        });
        deliveredSubmissionIds.add(payload.submissionId);
      } catch {
        safeLog(logger, "error", "waitlist_notifier_record_failed", sequenceNumber);
        if (!sequenceNumber) {
          throw new Error("waitlist notifier batch failed");
        }
        if (!failedSequenceNumbers.has(sequenceNumber)) {
          failedSequenceNumbers.add(sequenceNumber);
          failures.push({ itemIdentifier: sequenceNumber });
        }
      }
    }

    return { batchItemFailures: failures };
  };
}

let productionHandler;

async function handler(event) {
  productionHandler = productionHandler || createHandler();
  return productionHandler(event);
}

module.exports = {
  ALLOWED_OFFERS,
  APPROVED_BROKER_ACCOUNT_ID,
  APPROVED_BROKER_QUEUE_ARN,
  APPROVED_BROKER_QUEUE_NAME,
  APPROVED_BROKER_QUEUE_URL,
  APPROVED_BROKER_REGION,
  APPROVED_PRODUCER_ACCOUNT_ID,
  APPROVED_PRODUCER_REGION,
  BROKER_CANARY_EVENT_TYPE,
  BROKER_EVENT_TYPE,
  BROKER_PAYLOAD_FIELDS,
  BROKER_ROUTE,
  BROKER_SCHEMA_VERSION,
  ACTIVATION_PROOF_READ_INVOCATION_TYPE,
  CANARY_IMAGE_FIELDS,
  CANARY_INVOCATION_TYPE,
  CANARY_PAYLOAD_FIELDS,
  DURABLE_IDEMPOTENCY_KEY_FIELDS,
  MESSAGE_GROUP_ID,
  OUTBOX_IMAGE_FIELDS,
  buildBrokerPayload,
  buildCanaryPayload,
  createHandler,
  createSqsSender,
  handler,
  isEligibleInsert,
  validateBrokerConfig,
};
