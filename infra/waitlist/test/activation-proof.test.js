"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { describe, it } = require("node:test");

const {
  EXPECTED,
  canonicalJson,
  createActivationProofHeadReader,
  validateActivationProof,
  validateActivationProofHead,
} = require("../src/activation-proof.js");
const canonicalFixture = require("./fixtures/activation-proof-v1.json");

const NOW = new Date("2026-08-06T12:00:00.000Z");
const KMS_KEY_ARN = "arn:aws:kms:us-east-1:633740007231:key/01234567-89ab-cdef-0123-456789abcdef";
const CANARY_NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SQS_SEQUENCE_NUMBER = "000000000000000000018849496460467696128";

function validate(value, now = NOW) {
  return validateActivationProof(value, now, KMS_KEY_ARN);
}

function proof(overrides = {}) {
  const value = {
    schemaVersion: 1,
    canaryNonce: CANARY_NONCE,
    sqsMessageId: "12345678-1234-1234-1234-123456789abc",
    sqsSequenceNumber: SQS_SEQUENCE_NUMBER,
    sesMessageId: "ses-message-12345678",
    kmsKeyArn: KMS_KEY_ARN,
    route: EXPECTED.route,
    queueArn: EXPECTED.queueArn,
    producerRoleArn: EXPECTED.producerRoleArn,
    proofAccountId: EXPECTED.proofAccountId,
    proofRegion: EXPECTED.proofRegion,
    mxDomain: "e-sig.org",
    mxVerified: true,
    sesReceiptRuleSetActive: true,
    sesRecipientCoverage: ["e-sig.org", "waitlist@e-sig.org"],
    mailbox: "waitlist@e-sig.org",
    mailboxReady: true,
    inboundSesDelivery: { status: "delivered", metadataOnly: true, receiptId: `sesr_${"a".repeat(64)}`, canaryNonce: CANARY_NONCE, sqsMessageId: "12345678-1234-1234-1234-123456789abc", sesMessageId: "ses-message-12345678", evidenceId: `sesr_${"a".repeat(64)}` },
    stalwartDelivery: { status: "delivered", metadataOnly: true, receiptId: `stalwart_${"b".repeat(64)}`, canaryNonce: CANARY_NONCE, sqsMessageId: "12345678-1234-1234-1234-123456789abc", sesMessageId: "ses-message-12345678", evidenceId: `stalwart_${"b".repeat(64)}` },
    gmailDelivery: { status: "delivered", metadataOnly: true, receiptId: `sesr_${"c".repeat(64)}`, canaryNonce: CANARY_NONCE, sqsMessageId: "12345678-1234-1234-1234-123456789abc", sesMessageId: "ses-message-12345678", evidenceId: `sesr_${"c".repeat(64)}` },
    verifiedAt: "2026-08-06T11:55:00.000Z",
    expiresAt: "2026-08-07T11:55:00.000Z",
    checks: {
      agentAccess: {
        granted: true,
        esigLeadId: "e67f6847-3b64-473a-99e3-9469fe945538",
        esigOpsId: "b7d97106-ecfa-4fb9-8117-32f5515f0c9b",
        evidenceId: "agents:20260806",
      },
    },
  };
  return { ...value, ...overrides };
}

function proofHead(proofValue = proof(), overrides = {}) {
  const canonicalProof = canonicalJson(proofValue);
  const deliveredEpoch = Math.floor(new Date(proofValue.verifiedAt).getTime() / 1000);
  const acceptedEpoch = deliveredEpoch - 60;
  const tieBreaker = createHash("sha256")
    .update(`${proofValue.canaryNonce}\u0000${proofValue.sesMessageId}`, "utf8")
    .digest("hex");
  const generation = `${proofValue.sqsSequenceNumber}:${String(acceptedEpoch).padStart(20, "0")}:${String(deliveredEpoch).padStart(20, "0")}:${tieBreaker}`;
  const order = `${generation}:01`;
  return {
    idempotency_key: { S: EXPECTED.proofHeadKey },
    proof_canary_nonce: { S: proofValue.canaryNonce },
    proof_digest: {
      S: createHash("sha256").update(canonicalProof, "utf8").digest("hex"),
    },
    proof_generation: { S: generation },
    proof_order: { S: order },
    proof_rank: { N: "1" },
    proof_record_key: { S: `${EXPECTED.proofRecordPrefix}${order}` },
    proof_ses_message_id: { S: proofValue.sesMessageId },
    proof_status: { S: "ACTIVE" },
    proof_value: { S: canonicalProof },
    ...overrides,
  };
}

describe("waitlist lane activation proof", () => {
  it("accepts the canonical broker-aligned 23-key proof fixture", () => {
    assert.equal(Object.keys(canonicalFixture).length, 23);
    assert.equal(validate(canonicalFixture), true);
  });
  it("accepts only a fresh proof bound to the exact route, queue, producer, and agents", () => {
    assert.equal(validate(proof()), true);
    assert.equal(validate(proof({ queueArn: "arn:aws:sqs:us-east-1:633740007231:fake.fifo" })), false);
    assert.equal(validate(proof({ producerRoleArn: "arn:aws:iam::456453427852:role/fake" })), false);
    assert.equal(validate(proof({ proofAccountId: "456453427852" })), false);
    assert.equal(validate(proof({ sqsSequenceNumber: "0".repeat(39) })), false);
    assert.equal(validate(proof({ sqsSequenceNumber: "340282366920938463463374607431768211456" })), false);
    assert.equal(validate(proof({ sqsSequenceNumber: "18849496460467696128" })), false);

    const wrongAgent = proof();
    wrongAgent.checks.agentAccess.esigOpsId = "00000000-0000-0000-0000-000000000000";
    assert.equal(validate(wrongAgent), false);
  });

  it("rejects expired, overlong, reversed, future-skewed, and structurally fake proofs", () => {
    assert.equal(validate(proof({ expiresAt: "2026-08-06T12:00:00.000Z" })), false);
    assert.equal(validate(proof({ expiresAt: "2026-08-06T12:14:59.999Z" })), false);
    assert.equal(validate(proof({ expiresAt: "2026-08-07T11:55:00.001Z" })), false);
    assert.equal(validate(proof({ verifiedAt: "2026-08-06T12:04:00.000Z", expiresAt: "2026-08-06T12:03:00.000Z" })), false);
    assert.equal(validate(proof({ verifiedAt: "2026-08-06T12:00:00.001Z" })), false);
    assert.equal(validate({ ...proof(), injected: true }), false);
  });

  it("requires the exact 32-byte canary nonce representation", () => {
    assert.equal(validate(proof({ canaryNonce: `${CANARY_NONCE}A` })), false);
    assert.equal(validate(proof({ canaryNonce: CANARY_NONCE.slice(0, -1) })), false);
    assert.equal(validate(proof({ canaryNonce: "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" })), false);
  });

  it("rejects incomplete coverage, access, or metadata-only delivery evidence", () => {
    for (const mutate of [
      (value) => { value.mxVerified = false; },
      (value) => { value.sesRecipientCoverage = ["e-sig.org"]; },
      (value) => { value.mailboxReady = false; },
      (value) => { value.checks.agentAccess.granted = false; },
      (value) => { value.inboundSesDelivery.status = "failed"; },
      (value) => { value.stalwartDelivery.metadataOnly = false; },
      (value) => { value.gmailDelivery.status = "failed"; },
    ]) {
      const value = proof();
      mutate(value);
      assert.equal(validate(value), false);
    }
  });

  it("rejects missing KMS binding and mismatched canary receipts", () => {
    assert.equal(validateActivationProof(proof(), NOW), false);
    assert.equal(validateActivationProof(proof(), NOW, "arn:aws:kms:us-east-1:633740007231:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), false);
    const mismatched = proof();
    mismatched.gmailDelivery.canaryNonce = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    assert.equal(validate(mismatched), false);
    const mismatchedMessage = proof();
    mismatchedMessage.stalwartDelivery.sesMessageId = "different-ses-message";
    assert.equal(validate(mismatchedMessage), false);
    const duplicateReceipt = proof();
    duplicateReceipt.gmailDelivery.receiptId = duplicateReceipt.stalwartDelivery.receiptId;
    duplicateReceipt.gmailDelivery.evidenceId = duplicateReceipt.stalwartDelivery.receiptId;
    assert.equal(validate(duplicateReceipt), false);
    const forgedEvidence = proof();
    forgedEvidence.inboundSesDelivery.evidenceId = `sesr_${"d".repeat(64)}`;
    assert.equal(validate(forgedEvidence), false);
    assert.equal(validate(proof({ sesMessageId: "ses-message-\u00e9" })), false);
  });

  it("accepts only the exact active, canonical, ledger-linked DynamoDB proof head", () => {
    const head = proofHead();
    assert.equal(validateActivationProofHead(head, NOW, KMS_KEY_ARN), true);

    const mismatchedSequenceProof = proof({
      sqsSequenceNumber: "000000000000000000018849496460467696129",
    });
    const mismatchedSequenceValue = canonicalJson(mismatchedSequenceProof);

    for (const candidate of [
      { ...head, injected: { S: "value" } },
      { ...head, proof_status: { S: "BLOCKED_FAILED_CANARY" } },
      { ...head, proof_rank: { N: "2" } },
      { ...head, proof_digest: { S: "0".repeat(64) } },
      { ...head, proof_canary_nonce: { S: "B".repeat(43) } },
      { ...head, proof_generation: { S: head.proof_generation.S.replace(/^[0-9]{39}/, "0".repeat(39)) } },
      {
        ...head,
        proof_value: { S: mismatchedSequenceValue },
        proof_digest: {
          S: createHash("sha256").update(mismatchedSequenceValue, "utf8").digest("hex"),
        },
      },
    ]) {
      assert.equal(validateActivationProofHead(candidate, NOW, KMS_KEY_ARN), false);
    }
  });

  it("reads exactly one strongly consistent proof head and returns only the immutable receipt", async () => {
    const commands = [];
    const head = proofHead();
    const read = createActivationProofHeadReader({
      expectedBrokerKmsKeyArn: KMS_KEY_ARN,
      now: () => NOW,
      client: {
        send: async (command) => {
          commands.push(command);
          return { Item: head };
        },
      },
      commandFactory: (input) => ({ input }),
    });

    assert.deepEqual(await read(), {
      status: "proof-verified",
      proofDigest: head.proof_digest.S,
      proofGeneration: head.proof_generation.S,
      proofOrder: head.proof_order.S,
    });
    assert.deepEqual(commands, [{
      input: {
        TableName: EXPECTED.proofTableName,
        Key: { idempotency_key: { S: EXPECTED.proofHeadKey } },
        ConsistentRead: true,
      },
    }]);

    const reject = createActivationProofHeadReader({
      expectedBrokerKmsKeyArn: KMS_KEY_ARN,
      now: () => NOW,
      client: { send: async () => ({}) },
      commandFactory: (input) => ({ input }),
    });
    await assert.rejects(reject(), { message: "activation_proof_head_invalid" });
  });
});
