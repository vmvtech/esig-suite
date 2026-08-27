"use strict";

const SUBMISSION_ID_PATTERN = /^wl_[0-9a-f]{24}$/;

const PROJECTED_ATTRIBUTE_NAMES = Object.freeze({
  "#company": "company",
  "#contact_permission_status": "contact_permission_status",
  "#created_at": "created_at",
  "#email": "email",
  "#email_verification_status": "email_verification_status",
  "#expected_monthly_envelopes": "expected_monthly_envelopes",
  "#name": "name",
  "#offer": "offer",
  "#privacy_notice_version": "privacy_notice_version",
  "#record_type": "record_type",
  "#submission_id": "submission_id",
  "#submission_id_version": "submission_id_version",
  "#use_case": "use_case",
});

const PROJECTION_EXPRESSION = Object.keys(PROJECTED_ATTRIBUTE_NAMES).join(", ");

function readerError(name, message) {
  const error = new Error(message);
  error.name = name;
  return error;
}

function safeRequestId(context) {
  const candidate = context?.awsRequestId;
  return typeof candidate === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(candidate)
    ? candidate
    : "unknown";
}

function safeLog(logger, level, eventName, requestId) {
  const write = logger && typeof logger[level] === "function" ? logger[level] : null;
  if (write) write.call(logger, JSON.stringify({ event: eventName, requestId }));
}

function validateLookupRequest(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) {
    throw readerError("InvalidRequestError", "invalid_request");
  }

  const keys = Object.keys(event);
  if (
    keys.length !== 1 ||
    keys[0] !== "submissionId" ||
    typeof event.submissionId !== "string" ||
    !SUBMISSION_ID_PATTERN.test(event.submissionId)
  ) {
    throw readerError("InvalidRequestError", "invalid_request");
  }

  return event.submissionId;
}

function readString(item, name, { required = false } = {}) {
  const value = item?.[name]?.S;
  if (value === undefined && !required) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    throw readerError("WaitlistReaderIntegrityError", "submission_record_invalid");
  }
  return value;
}

function projectSubmission(item, expectedSubmissionId) {
  if (
    readString(item, "record_type", { required: true }) !== "waitlist_submission" ||
    readString(item, "submission_id", { required: true }) !== expectedSubmissionId ||
    readString(item, "submission_id_version", { required: true }) !== "random-v1"
  ) {
    throw readerError("WaitlistReaderIntegrityError", "submission_record_invalid");
  }

  const submission = {
    submissionId: expectedSubmissionId,
    email: readString(item, "email", { required: true }),
    offer: readString(item, "offer", { required: true }),
    createdAt: readString(item, "created_at", { required: true }),
    consent: {
      contactPermissionStatus: readString(item, "contact_permission_status", {
        required: true,
      }),
      emailVerificationStatus: readString(item, "email_verification_status", {
        required: true,
      }),
      privacyNoticeVersion: readString(item, "privacy_notice_version", {
        required: true,
      }),
    },
  };

  for (const [storedName, responseName] of [
    ["name", "name"],
    ["company", "company"],
    ["expected_monthly_envelopes", "expectedMonthlyEnvelopes"],
    ["use_case", "useCase"],
  ]) {
    const value = readString(item, storedName);
    if (value !== undefined) submission[responseName] = value;
  }

  return submission;
}

function createDynamoReader({ tableName, indexName, client, commandFactory } = {}) {
  if (!tableName) throw new Error("WAITLIST_TABLE_NAME is required");
  if (!indexName) throw new Error("WAITLIST_SUBMISSION_ID_INDEX_NAME is required");

  let resolvedClient = client;
  let resolvedCommandFactory = commandFactory;

  function resolveSdk() {
    if (resolvedClient && resolvedCommandFactory) return;
    const { DynamoDBClient, QueryCommand } = require("@aws-sdk/client-dynamodb");
    resolvedClient = resolvedClient || new DynamoDBClient({});
    resolvedCommandFactory =
      resolvedCommandFactory || ((input) => new QueryCommand(input));
  }

  return {
    async querySubmissionId(submissionId) {
      resolveSdk();
      const command = resolvedCommandFactory({
        TableName: tableName,
        IndexName: indexName,
        KeyConditionExpression: "#submission_id = :submission_id",
        ExpressionAttributeNames: PROJECTED_ATTRIBUTE_NAMES,
        ExpressionAttributeValues: {
          ":submission_id": { S: submissionId },
        },
        ProjectionExpression: PROJECTION_EXPRESSION,
        ConsistentRead: false,
        Limit: 2,
      });
      const result = await resolvedClient.send(command);
      return Array.isArray(result?.Items) ? result.Items : [];
    },
  };
}

function createReader({ store, env = process.env, logger = console } = {}) {
  let resolvedStore = store;

  return async function readWaitlistSubmission(event, context) {
    const requestId = safeRequestId(context);
    const submissionId = validateLookupRequest(event);

    try {
      resolvedStore =
        resolvedStore ||
        createDynamoReader({
          tableName: env.WAITLIST_TABLE_NAME,
          indexName: env.WAITLIST_SUBMISSION_ID_INDEX_NAME,
        });

      const items = await resolvedStore.querySubmissionId(submissionId);
      if (items.length === 0) return { status: "not_found" };
      if (items.length !== 1) {
        safeLog(logger, "error", "waitlist_reader_non_unique_id", requestId);
        throw readerError("WaitlistReaderIntegrityError", "submission_id_not_unique");
      }

      return {
        status: "found",
        submission: projectSubmission(items[0], submissionId),
      };
    } catch (error) {
      if (error?.name === "WaitlistReaderIntegrityError") {
        if (error.message !== "submission_id_not_unique") {
          safeLog(logger, "error", "waitlist_reader_invalid_record", requestId);
        }
        throw error;
      }

      safeLog(logger, "error", "waitlist_reader_storage_failure", requestId);
      throw readerError("WaitlistReaderUnavailableError", "temporarily_unavailable");
    }
  };
}

let productionReader;

async function handler(event, context) {
  productionReader = productionReader || createReader();
  return productionReader(event, context);
}

module.exports = {
  PROJECTION_EXPRESSION,
  PROJECTED_ATTRIBUTE_NAMES,
  SUBMISSION_ID_PATTERN,
  createDynamoReader,
  createReader,
  handler,
  projectSubmission,
  validateLookupRequest,
};
