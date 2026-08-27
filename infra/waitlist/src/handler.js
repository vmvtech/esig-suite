"use strict";

const { createHash, randomBytes } = require("node:crypto");

const DEFAULT_ALLOWED_ORIGIN = "https://e-sig.org";
const DEFAULT_PRODUCTION_RETENTION_DAYS = 180;
const DEFAULT_SMOKE_TEST_TTL_HOURS = 24;
const MAX_BODY_BYTES = 16 * 1024;

const ALLOWED_OFFERS = new Set([
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

const ALLOWED_BODY_KEYS = new Set([
  "offer",
  "email",
  "name",
  "company",
  "useCase",
  "expectedMonthlyEnvelopes",
  "consent",
  "website",
  "source",
]);

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function createOpaqueSubmissionId(randomBytesFn = randomBytes) {
  const value = randomBytesFn(12);
  if (!Buffer.isBuffer(value) || value.length !== 12) {
    throw new Error("submission ID entropy source failed");
  }
  return `wl_${value.toString("hex")}`;
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [name, value] of Object.entries(headers || {})) {
    normalized[String(name).toLowerCase()] = Array.isArray(value)
      ? value.join(",")
      : String(value);
  }
  return normalized;
}

function safeRequestId(event) {
  const candidate = event?.requestContext?.requestId;
  return typeof candidate === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(candidate)
    ? candidate
    : "unknown";
}

function safeLog(logger, level, eventName, requestId) {
  const write = logger && typeof logger[level] === "function" ? logger[level] : null;
  if (write) {
    write.call(logger, JSON.stringify({ event: eventName, requestId }));
  }
}

function response(statusCode, body, requestOrigin, allowedOrigin) {
  const headers = {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    vary: "Origin",
    "x-content-type-options": "nosniff",
  };

  if (requestOrigin === allowedOrigin) {
    headers["access-control-allow-origin"] = allowedOrigin;
    headers["access-control-allow-methods"] = "POST,OPTIONS";
    headers["access-control-allow-headers"] = "content-type";
  }

  return {
    statusCode,
    headers,
    body: body === undefined ? "" : JSON.stringify(body),
    isBase64Encoded: false,
  };
}

function decodeBody(event) {
  if (typeof event?.body !== "string") {
    return { error: "request" };
  }

  let raw;
  try {
    raw = event.isBase64Encoded
      ? Buffer.from(event.body, "base64").toString("utf8")
      : event.body;
  } catch {
    return { error: "request" };
  }

  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    return { error: "request" };
  }

  try {
    const value = JSON.parse(raw);
    if (value === null || Array.isArray(value) || typeof value !== "object") {
      return { error: "request" };
    }
    return { value };
  } catch {
    return { error: "request" };
  }
}

function normalizeEmail(value, errors) {
  if (typeof value !== "string") {
    errors.push("email");
    return "";
  }

  const normalized = value.trim().normalize("NFKC").toLowerCase();
  const at = normalized.lastIndexOf("@");
  const local = normalized.slice(0, at);
  const domain = normalized.slice(at + 1);
  const domainLabels = domain.split(".");
  const valid =
    at > 0 &&
    at === normalized.indexOf("@") &&
    normalized.length <= 254 &&
    local.length >= 1 &&
    local.length <= 64 &&
    /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local) &&
    domain.length >= 3 &&
    domain.length <= 253 &&
    domainLabels.length >= 2 &&
    domainLabels.every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    ) &&
    !/\s|[\u0000-\u001f\u007f]/u.test(normalized) &&
    !local.startsWith(".") &&
    !local.endsWith(".") &&
    !local.includes("..");

  if (!valid) {
    errors.push("email");
    return "";
  }
  return normalized;
}

function normalizeOptionalText(value, field, maxLength, errors) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  if (typeof value !== "string") {
    errors.push(field);
    return undefined;
  }

  const normalized = value.trim().normalize("NFKC");
  if (
    normalized.length > maxLength ||
    /[\u0000\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(normalized)
  ) {
    errors.push(field);
    return undefined;
  }
  return normalized || undefined;
}

function validateSubmission(body) {
  const errors = [];

  for (const key of Object.keys(body)) {
    if (!ALLOWED_BODY_KEYS.has(key)) {
      errors.push("request");
      break;
    }
  }

  const email = normalizeEmail(body.email, errors);
  const offer = typeof body.offer === "string" ? body.offer : "";
  if (!ALLOWED_OFFERS.has(offer)) errors.push("offer");
  if (body.source !== "pricing") errors.push("source");
  if (body.consent !== true) errors.push("consent");

  if (body.website !== undefined && typeof body.website !== "string") {
    errors.push("website");
  }

  const name = normalizeOptionalText(body.name, "name", 100, errors);
  const company = normalizeOptionalText(body.company, "company", 160, errors);
  const useCase = normalizeOptionalText(body.useCase, "useCase", 2000, errors);
  const expectedMonthlyEnvelopes = normalizeOptionalText(
    body.expectedMonthlyEnvelopes,
    "expectedMonthlyEnvelopes",
    64,
    errors,
  );
  if (errors.length > 0) {
    return { errors: [...new Set(errors)] };
  }

  return {
    value: {
      email,
      offer,
      source: "pricing",
      name,
      company,
      use_case: useCase,
      expected_monthly_envelopes: expectedMonthlyEnvelopes,
    },
  };
}

function isSmokeTestEmail(email) {
  return email.slice(email.lastIndexOf("@") + 1) === "example.com";
}

function createSubmission(
  value,
  now,
  productionRetentionDays,
  smokeTestTtlHours,
  randomBytesFn = randomBytes,
) {
  const digest = sha256(`${value.email}\u0000${value.offer}`);
  const submission = {
    submission_key: `WAITLIST#${digest}`,
    submission_id: createOpaqueSubmissionId(randomBytesFn),
    submission_id_version: "random-v1",
    email: value.email,
    offer: value.offer,
    source: value.source,
    contact_permission_status: "asserted_unverified",
    email_verification_status: "unverified",
    privacy_notice_version: "2026-08-06",
    created_at: now.toISOString(),
  };

  for (const [key, optionalValue] of Object.entries({
    name: value.name,
    company: value.company,
    use_case: value.use_case,
    expected_monthly_envelopes: value.expected_monthly_envelopes,
  })) {
    if (optionalValue !== undefined) submission[key] = optionalValue;
  }

  if (isSmokeTestEmail(value.email)) {
    submission.record_type = "smoke_test";
    submission.retention_class = `smoke_${smokeTestTtlHours}h`;
    submission.expires_at_epoch =
      Math.floor(now.getTime() / 1000) + smokeTestTtlHours * 60 * 60;
  } else {
    submission.record_type = "waitlist_submission";
    submission.retention_class = `waitlist_${productionRetentionDays}d`;
    submission.expires_at_epoch =
      Math.floor(now.getTime() / 1000) + productionRetentionDays * 24 * 60 * 60;
  }

  return submission;
}

function toDynamoItem(submission) {
  const item = {};
  for (const [key, value] of Object.entries(submission)) {
    if (typeof value === "string") item[key] = { S: value };
    else if (typeof value === "number") item[key] = { N: String(value) };
    else if (typeof value === "boolean") item[key] = { BOOL: value };
  }
  return item;
}

function createNotificationOutbox(submission) {
  const retentionMatch = /^waitlist_([0-9]{2,3})d$/.exec(
    submission?.retention_class || "",
  );
  const retentionDays = retentionMatch ? Number(retentionMatch[1]) : undefined;
  const createdAt = new Date(submission?.created_at || "");
  const createdAtIsExact =
    !Number.isNaN(createdAt.getTime()) && createdAt.toISOString() === submission?.created_at;
  const expectedExpiry =
    Number.isInteger(retentionDays) && createdAtIsExact
      ? Math.floor(createdAt.getTime() / 1000) + retentionDays * 24 * 60 * 60
      : undefined;

  if (
    submission?.record_type !== "waitlist_submission" ||
    !/^wl_[a-f0-9]{24}$/.test(submission?.submission_id || "") ||
    submission?.submission_id_version !== "random-v1" ||
    !ALLOWED_OFFERS.has(submission?.offer) ||
    submission?.source !== "pricing" ||
    submission?.contact_permission_status !== "asserted_unverified" ||
    submission?.email_verification_status !== "unverified" ||
    !Number.isInteger(retentionDays) ||
    retentionDays < 30 ||
    retentionDays > 180 ||
    submission?.expires_at_epoch !== expectedExpiry
  ) {
    throw new Error("waitlist outbox requires a production submission");
  }

  return {
    outbox_key: `OUTBOX#${submission.submission_id}`,
    record_type: "waitlist_notification_outbox",
    submission_id: submission.submission_id,
    offer: submission.offer,
    source: submission.source,
    created_at: submission.created_at,
    retention_class: submission.retention_class,
    contact_permission_status: submission.contact_permission_status,
    email_verification_status: submission.email_verification_status,
    expires_at_epoch: submission.expires_at_epoch,
  };
}

function isConditionalTransactionDuplicate(error) {
  if (error?.name !== "TransactionCanceledException") return false;
  const reasons = error.CancellationReasons;
  if (!Array.isArray(reasons) || reasons.length === 0) return false;
  if (reasons[0]?.Code !== "ConditionalCheckFailed") return false;
  return reasons.slice(1).every((reason) => reason?.Code === "None");
}

function createDynamoStore({ tableName, outboxTableName, client, commandFactory } = {}) {
  if (!tableName) throw new Error("WAITLIST_TABLE_NAME is required");
  if (!outboxTableName) throw new Error("WAITLIST_OUTBOX_TABLE_NAME is required");

  let resolvedClient = client;
  let resolvedCommandFactory = commandFactory;

  function resolveSdk() {
    if (resolvedClient && resolvedCommandFactory) return;
    const { DynamoDBClient, TransactWriteItemsCommand } = require("@aws-sdk/client-dynamodb");
    resolvedClient = resolvedClient || new DynamoDBClient({});
    resolvedCommandFactory =
      resolvedCommandFactory || ((input) => new TransactWriteItemsCommand(input));
  }

  return {
    async putSubmission(submission) {
      resolveSdk();
      const transactItems = [
        {
          Put: {
            TableName: tableName,
            Item: toDynamoItem(submission),
            ConditionExpression: "attribute_not_exists(#submission_key)",
            ExpressionAttributeNames: {
              "#submission_key": "submission_key",
            },
          },
        },
      ];

      if (submission.record_type === "waitlist_submission") {
        transactItems.push({
          Put: {
            TableName: outboxTableName,
            Item: toDynamoItem(createNotificationOutbox(submission)),
            ConditionExpression: "attribute_not_exists(#outbox_key)",
            ExpressionAttributeNames: {
              "#outbox_key": "outbox_key",
            },
          },
        });
      }

      const command = resolvedCommandFactory({ TransactItems: transactItems });

      try {
        await resolvedClient.send(command);
        return true;
      } catch (error) {
        if (isConditionalTransactionDuplicate(error)) return false;
        throw error;
      }
    },
  };
}

function readSmokeTestTtlHours(value) {
  const parsed = Number(value ?? DEFAULT_SMOKE_TEST_TTL_HOURS);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 168
    ? parsed
    : DEFAULT_SMOKE_TEST_TTL_HOURS;
}

function readProductionRetentionDays(value) {
  const parsed = Number(value ?? DEFAULT_PRODUCTION_RETENTION_DAYS);
  return Number.isInteger(parsed) && parsed >= 30 && parsed <= 180
    ? parsed
    : DEFAULT_PRODUCTION_RETENTION_DAYS;
}

function createHandler({
  store,
  now = () => new Date(),
  randomBytesFn = randomBytes,
  env = process.env,
  logger = console,
} = {}) {
  const allowedOrigin = env.ALLOWED_ORIGIN || DEFAULT_ALLOWED_ORIGIN;
  const productionRetentionDays = readProductionRetentionDays(env.PRODUCTION_RETENTION_DAYS);
  const smokeTestTtlHours = readSmokeTestTtlHours(env.SMOKE_TEST_TTL_HOURS);
  let resolvedStore = store;

  return async function waitlistHandler(event) {
    const headers = normalizeHeaders(event?.headers);
    const requestOrigin = headers.origin;
    const requestId = safeRequestId(event);
    const method = event?.requestContext?.http?.method || event?.httpMethod;

    if (requestOrigin !== allowedOrigin) {
      safeLog(logger, "warn", "waitlist_origin_rejected", requestId);
      return response(403, { error: "forbidden" }, requestOrigin, allowedOrigin);
    }

    if (method === "OPTIONS") {
      return response(204, undefined, requestOrigin, allowedOrigin);
    }
    if (method !== "POST") {
      return response(405, { error: "method_not_allowed" }, requestOrigin, allowedOrigin);
    }

    const contentType = (headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") {
      return response(415, { error: "unsupported_media_type" }, requestOrigin, allowedOrigin);
    }

    const decoded = decodeBody(event);
    if (decoded.error) {
      return response(
        400,
        { error: "validation_failed", fields: [decoded.error] },
        requestOrigin,
        allowedOrigin,
      );
    }

    if (typeof decoded.value.website === "string" && decoded.value.website.trim() !== "") {
      return response(202, { status: "accepted" }, requestOrigin, allowedOrigin);
    }

    const validation = validateSubmission(decoded.value);
    if (validation.errors) {
      return response(
        400,
        { error: "validation_failed", fields: validation.errors },
        requestOrigin,
        allowedOrigin,
      );
    }

    const timestamp = now();
    if (!(timestamp instanceof Date) || Number.isNaN(timestamp.getTime())) {
      safeLog(logger, "error", "waitlist_clock_failure", requestId);
      return response(
        503,
        { error: "temporarily_unavailable" },
        requestOrigin,
        allowedOrigin,
      );
    }

    let submission;
    try {
      submission = createSubmission(
        validation.value,
        timestamp,
        productionRetentionDays,
        smokeTestTtlHours,
        randomBytesFn,
      );
    } catch {
      safeLog(logger, "error", "waitlist_submission_id_failure", requestId);
      return response(
        503,
        { error: "temporarily_unavailable" },
        requestOrigin,
        allowedOrigin,
      );
    }

    try {
      resolvedStore =
        resolvedStore ||
        createDynamoStore({
          outboxTableName: env.WAITLIST_OUTBOX_TABLE_NAME,
          tableName: env.WAITLIST_TABLE_NAME,
        });
      await resolvedStore.putSubmission(submission);
      return response(
        202,
        { status: "accepted" },
        requestOrigin,
        allowedOrigin,
      );
    } catch {
      safeLog(logger, "error", "waitlist_storage_failure", requestId);
      return response(
        503,
        { error: "temporarily_unavailable" },
        requestOrigin,
        allowedOrigin,
      );
    }
  };
}

let productionHandler;

async function handler(event) {
  productionHandler = productionHandler || createHandler();
  return productionHandler(event);
}

module.exports = {
  ALLOWED_OFFERS,
  createOpaqueSubmissionId,
  createDynamoStore,
  createHandler,
  createNotificationOutbox,
  createSubmission,
  handler,
  isSmokeTestEmail,
  toDynamoItem,
  validateSubmission,
};
