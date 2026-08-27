"use strict";

const { createHash } = require("node:crypto");

const EXPECTED = Object.freeze({
  proofHeadKey: "activation-proof-head:esig.waitlist.sales.v1",
  proofRecordPrefix: "activation-proof-record:esig.waitlist.sales.v1:",
  proofTableName: "esig-mail-broker-idempotency-standard",
  proofAccountId: "633740007231",
  proofRegion: "us-east-1",
  producerRoleArn:
    "arn:aws:iam::456453427852:role/esig-waitlist-production-mail-producer",
  queueArn:
    "arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard.fifo",
  route: "esig.waitlist.sales.v1",
});

const ROOT_KEYS = Object.freeze([
  "canaryNonce",
  "checks",
  "expiresAt",
  "gmailDelivery",
  "inboundSesDelivery",
  "kmsKeyArn",
  "mailbox",
  "mailboxReady",
  "mxDomain",
  "mxVerified",
  "proofAccountId",
  "proofRegion",
  "producerRoleArn",
  "queueArn",
  "route",
  "schemaVersion",
  "sesMessageId",
  "sesReceiptRuleSetActive",
  "sesRecipientCoverage",
  "stalwartDelivery",
  "sqsMessageId",
  "sqsSequenceNumber",
  "verifiedAt",
]);
const CHECK_KEYS = Object.freeze(["agentAccess"]);
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const MAX_PROOF_AGE_MS = 24 * 60 * 60 * 1000;
const MIN_PROOF_REMAINING_MS = 15 * 60 * 1000;
const ESIG_LEAD_ID = "e67f6847-3b64-473a-99e3-9469fe945538";
const ESIG_OPS_ID = "b7d97106-ecfa-4fb9-8117-32f5515f0c9b";
const CANARY_NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BROKER_KMS_KEY_ARN_PATTERN = /^arn:aws:kms:us-east-1:633740007231:key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SQS_MESSAGE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SES_RECEIPT_ID_PATTERN = /^sesr_[a-f0-9]{64}$/;
const STALWART_RECEIPT_ID_PATTERN = /^stalwart_[a-f0-9]{64}$/;
const AGENT_EVIDENCE_ID_PATTERN = /^[A-Za-z0-9._:-]{8,128}$/;
const ACTIVATION_PROOF_READ_INVOCATION_TYPE = "waitlist-activation-proof-read-v1";
const SQS_SEQUENCE_NUMBER_PATTERN = /^[0-9]{39}$/;
const MAX_SQS_SEQUENCE_NUMBER = (1n << 128n) - 1n;
const GENERATION_PATTERN = /^([0-9]{39}):([0-9]{20}):([0-9]{20}):([a-f0-9]{64})$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const HEAD_ATTRIBUTE_KEYS = Object.freeze([
  "idempotency_key",
  "proof_canary_nonce",
  "proof_digest",
  "proof_generation",
  "proof_order",
  "proof_rank",
  "proof_record_key",
  "proof_ses_message_id",
  "proof_status",
  "proof_value",
]);

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...expected].sort().join("\0")
  );
}

function validEvidence(value) {
  return typeof value === "string" && AGENT_EVIDENCE_ID_PATTERN.test(value);
}

function validMessageId(value) {
  return typeof value === "string" && /^[\x21-\x7e]{8,256}$/.test(value);
}

function validSqsSequenceNumber(value) {
  return (
    typeof value === "string" &&
    SQS_SEQUENCE_NUMBER_PATTERN.test(value) &&
    BigInt(value) > 0n &&
    BigInt(value) <= MAX_SQS_SEQUENCE_NUMBER
  );
}

function validCanaryNonce(value) {
  return (
    typeof value === "string" &&
    CANARY_NONCE_PATTERN.test(value) &&
    Buffer.from(value, "base64url").length === 32
  );
}

function validDelivery(value, proof, receiptPattern) {
  return (
    exactKeys(value, ["canaryNonce", "evidenceId", "metadataOnly", "receiptId", "sesMessageId", "sqsMessageId", "status"]) &&
    value.status === "delivered" &&
    value.metadataOnly === true &&
    value.canaryNonce === proof.canaryNonce &&
    value.sqsMessageId === proof.sqsMessageId &&
    value.sesMessageId === proof.sesMessageId &&
    validMessageId(value.receiptId) &&
    receiptPattern.test(value.receiptId) &&
    value.evidenceId === value.receiptId
  );
}

function validateActivationProof(value, now = new Date(), expectedBrokerKmsKeyArn) {
  if (!exactKeys(value, ROOT_KEYS) || !exactKeys(value.checks, CHECK_KEYS)) return false;
  if (
    value.schemaVersion !== 1 ||
    !BROKER_KMS_KEY_ARN_PATTERN.test(expectedBrokerKmsKeyArn || "") ||
    value.kmsKeyArn !== expectedBrokerKmsKeyArn ||
    !validCanaryNonce(value.canaryNonce) ||
    !SQS_MESSAGE_ID_PATTERN.test(value.sqsMessageId || "") ||
    !validSqsSequenceNumber(value.sqsSequenceNumber) ||
    !validMessageId(value.sesMessageId) ||
    value.sqsMessageId === value.sesMessageId ||
    value.route !== EXPECTED.route ||
    value.queueArn !== EXPECTED.queueArn ||
    value.producerRoleArn !== EXPECTED.producerRoleArn ||
    value.proofAccountId !== EXPECTED.proofAccountId ||
    value.proofRegion !== EXPECTED.proofRegion ||
    value.mxDomain !== "e-sig.org" ||
    value.mxVerified !== true ||
    value.sesReceiptRuleSetActive !== true ||
    !Array.isArray(value.sesRecipientCoverage) ||
    value.sesRecipientCoverage.length !== 2 ||
    new Set(value.sesRecipientCoverage).size !== 2 ||
    !value.sesRecipientCoverage.includes("e-sig.org") ||
    !value.sesRecipientCoverage.includes("waitlist@e-sig.org") ||
    value.mailbox !== "waitlist@e-sig.org" ||
    value.mailboxReady !== true ||
    !RFC3339_UTC.test(value.verifiedAt) ||
    !RFC3339_UTC.test(value.expiresAt)
  ) return false;

  const verifiedAt = new Date(value.verifiedAt);
  const expiresAt = new Date(value.expiresAt);
  const nowMs = now.getTime();
  if (
    Number.isNaN(nowMs) ||
    Number.isNaN(verifiedAt.getTime()) ||
    Number.isNaN(expiresAt.getTime()) ||
    verifiedAt.getTime() > nowMs ||
    expiresAt.getTime() <= nowMs ||
    expiresAt.getTime() - nowMs < MIN_PROOF_REMAINING_MS ||
    expiresAt.getTime() <= verifiedAt.getTime() ||
    expiresAt.getTime() - verifiedAt.getTime() > MAX_PROOF_AGE_MS
  ) return false;

  const { agentAccess } = value.checks;
  return (
    exactKeys(agentAccess, ["evidenceId", "esigLeadId", "esigOpsId", "granted"]) &&
    agentAccess.granted === true &&
    agentAccess.esigLeadId === ESIG_LEAD_ID &&
    agentAccess.esigOpsId === ESIG_OPS_ID &&
    validEvidence(agentAccess.evidenceId) &&
    validDelivery(value.inboundSesDelivery, value, SES_RECEIPT_ID_PATTERN) &&
    validDelivery(value.stalwartDelivery, value, STALWART_RECEIPT_ID_PATTERN) &&
    validDelivery(value.gmailDelivery, value, SES_RECEIPT_ID_PATTERN) &&
    new Set([
      value.inboundSesDelivery.receiptId,
      value.stalwartDelivery.receiptId,
      value.gmailDelivery.receiptId,
    ]).size === 3
  );
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("proof JSON is not canonicalizable");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error("proof JSON is not canonicalizable");
}

function readStringAttribute(item, name) {
  const attribute = item?.[name];
  if (!exactKeys(attribute, ["S"]) || typeof attribute.S !== "string") return undefined;
  return attribute.S;
}

function readNumberAttribute(item, name) {
  const attribute = item?.[name];
  if (!exactKeys(attribute, ["N"]) || typeof attribute.N !== "string") return undefined;
  return attribute.N;
}

function validateActivationProofHead(item, now = new Date(), expectedBrokerKmsKeyArn) {
  try {
    if (!exactKeys(item, HEAD_ATTRIBUTE_KEYS)) return false;
    const headKey = readStringAttribute(item, "idempotency_key");
    const canaryNonce = readStringAttribute(item, "proof_canary_nonce");
    const digest = readStringAttribute(item, "proof_digest");
    const generation = readStringAttribute(item, "proof_generation");
    const order = readStringAttribute(item, "proof_order");
    const rank = readNumberAttribute(item, "proof_rank");
    const recordKey = readStringAttribute(item, "proof_record_key");
    const sesMessageId = readStringAttribute(item, "proof_ses_message_id");
    const status = readStringAttribute(item, "proof_status");
    const proofValue = readStringAttribute(item, "proof_value");
    const generationMatch = GENERATION_PATTERN.exec(generation || "");

    if (
      headKey !== EXPECTED.proofHeadKey ||
      !generationMatch ||
      generation.length !== 146 ||
      !["1", "2"].includes(rank) ||
      order !== `${generation}:0${rank}` ||
      order.length !== 149 ||
      recordKey !== `${EXPECTED.proofRecordPrefix}${order}` ||
      !DIGEST_PATTERN.test(digest || "") ||
      !validCanaryNonce(canaryNonce) ||
      !validMessageId(sesMessageId) ||
      !((status === "ACTIVE" && rank === "1") ||
        (status === "BLOCKED_FAILED_CANARY" && rank === "2"))
    ) return false;

    const sequenceNumber = BigInt(generationMatch[1]);
    const acceptedEpoch = BigInt(generationMatch[2]);
    const deliveredEpoch = BigInt(generationMatch[3]);
    if (acceptedEpoch <= 0n || deliveredEpoch <= 0n || acceptedEpoch > deliveredEpoch) {
      return false;
    }
    if (sequenceNumber <= 0n || sequenceNumber > MAX_SQS_SEQUENCE_NUMBER) return false;

    let proof;
    try {
      proof = JSON.parse(proofValue);
    } catch {
      return false;
    }
    if (canonicalJson(proof) !== proofValue) return false;
    if (
      createHash("sha256").update(proofValue, "utf8").digest("hex") !== digest ||
      createHash("sha256")
        .update(`${canaryNonce}\u0000${sesMessageId}`, "utf8")
        .digest("hex") !== generationMatch[4] ||
      proof.canaryNonce !== canaryNonce ||
      proof.sesMessageId !== sesMessageId ||
      proof.sqsSequenceNumber !== generationMatch[1] ||
      BigInt(Math.floor(new Date(proof.verifiedAt).getTime() / 1000)) !== deliveredEpoch ||
      !validateActivationProof(proof, now, expectedBrokerKmsKeyArn)
    ) return false;

    return status === "ACTIVE" && rank === "1";
  } catch {
    return false;
  }
}

function createActivationProofHeadReader({
  client,
  commandFactory,
  now = () => new Date(),
  expectedBrokerKmsKeyArn,
} = {}) {
  let resolvedClient = client;
  let resolvedCommandFactory = commandFactory;

  function resolveSdk() {
    if (resolvedClient && resolvedCommandFactory) return;
    const { DynamoDBClient, GetItemCommand } = require("@aws-sdk/client-dynamodb");
    resolvedClient = resolvedClient || new DynamoDBClient({ region: EXPECTED.proofRegion });
    resolvedCommandFactory =
      resolvedCommandFactory || ((input) => new GetItemCommand(input));
  }

  return async function readActivationProofHead() {
    resolveSdk();
    const result = await resolvedClient.send(resolvedCommandFactory({
      TableName: EXPECTED.proofTableName,
      Key: { idempotency_key: { S: EXPECTED.proofHeadKey } },
      ConsistentRead: true,
    }));
    const timestamp = now();
    if (
      !(timestamp instanceof Date) ||
      Number.isNaN(timestamp.getTime()) ||
      !validateActivationProofHead(result?.Item, timestamp, expectedBrokerKmsKeyArn)
    ) {
      throw new Error("activation_proof_head_invalid");
    }

    return {
      status: "proof-verified",
      proofDigest: result.Item.proof_digest.S,
      proofGeneration: result.Item.proof_generation.S,
      proofOrder: result.Item.proof_order.S,
    };
  };
}

module.exports = {
  ACTIVATION_PROOF_READ_INVOCATION_TYPE,
  EXPECTED,
  HEAD_ATTRIBUTE_KEYS,
  canonicalJson,
  createActivationProofHeadReader,
  validateActivationProof,
  validateActivationProofHead,
};
