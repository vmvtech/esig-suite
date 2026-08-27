"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  PROJECTED_ATTRIBUTE_NAMES,
  createDynamoReader,
  createReader,
} = require("../src/reader.js");

const SUBMISSION_ID = "wl_0123456789abcdef01234567";

function string(value) {
  return { S: value };
}

function storedSubmission(overrides = {}) {
  return {
    submission_id: string(SUBMISSION_ID),
    submission_id_version: string("random-v1"),
    email: string("person@example.org"),
    name: string("Private Person"),
    company: string("Private Company"),
    use_case: string("Private use case"),
    expected_monthly_envelopes: string("100-500"),
    offer: string("shared_starter"),
    created_at: string("2026-08-06T12:00:00.000Z"),
    contact_permission_status: string("asserted_unverified"),
    email_verification_status: string("unverified"),
    privacy_notice_version: string("2026-08-06"),
    record_type: string("waitlist_submission"),
    ...overrides,
  };
}

describe("private waitlist reader", () => {
  it("returns only the approved operational projection for one exact opaque ID", async () => {
    const seen = [];
    const reader = createReader({
      store: {
        async querySubmissionId(submissionId) {
          seen.push(submissionId);
          return [storedSubmission()];
        },
      },
      logger: { error: () => assert.fail("success must not log") },
    });

    const result = await reader({ submissionId: SUBMISSION_ID });

    assert.deepEqual(seen, [SUBMISSION_ID]);
    assert.deepEqual(result, {
      status: "found",
      submission: {
        submissionId: SUBMISSION_ID,
        email: "person@example.org",
        offer: "shared_starter",
        createdAt: "2026-08-06T12:00:00.000Z",
        consent: {
          contactPermissionStatus: "asserted_unverified",
          emailVerificationStatus: "unverified",
          privacyNoticeVersion: "2026-08-06",
        },
        name: "Private Person",
        company: "Private Company",
        expectedMonthlyEnvelopes: "100-500",
        useCase: "Private use case",
      },
    });
    assert.deepEqual(Object.keys(result).sort(), ["status", "submission"]);
    assert.equal(Object.hasOwn(result.submission, "submissionKey"), false);
    assert.equal(Object.hasOwn(result.submission, "source"), false);
    assert.equal(Object.hasOwn(result.submission, "expiresAt"), false);
  });

  it("returns not_found without widening the query", async () => {
    let calls = 0;
    const reader = createReader({
      store: { async querySubmissionId() { calls += 1; return []; } },
    });

    assert.deepEqual(await reader({ submissionId: SUBMISSION_ID }), { status: "not_found" });
    assert.equal(calls, 1);
  });

  it("fails closed for a duplicate opaque ID", async () => {
    const logs = [];
    const reader = createReader({
      store: { async querySubmissionId() { return [storedSubmission(), storedSubmission()]; } },
      logger: { error: (line) => logs.push(line) },
    });

    await assert.rejects(
      reader({ submissionId: SUBMISSION_ID }, { awsRequestId: "reader-test" }),
      (error) => error.name === "WaitlistReaderIntegrityError" &&
        error.message === "submission_id_not_unique",
    );
    assert.match(logs.join("\n"), /waitlist_reader_non_unique_id/);
    assert.doesNotMatch(logs.join("\n"), /wl_[0-9a-f]{24}|person@example\.org/);
  });

  it("rejects malformed or expanded requests before querying", async () => {
    let calls = 0;
    const reader = createReader({
      store: { async querySubmissionId() { calls += 1; return []; } },
    });
    const invalid = [
      null,
      "submission",
      {},
      { submissionId: "wl_short" },
      { submissionId: "wl_0123456789ABCDEF01234567" },
      { submissionId: SUBMISSION_ID, include: "all" },
    ];

    for (const event of invalid) {
      await assert.rejects(
        reader(event),
        (error) => error.name === "InvalidRequestError" && error.message === "invalid_request",
      );
    }
    assert.equal(calls, 0);
  });

  it("rejects legacy deterministic or malformed records", async () => {
    for (const item of [
      storedSubmission({ submission_id_version: undefined }),
      storedSubmission({ submission_id_version: string("legacy-deterministic-v0") }),
      storedSubmission({ record_type: string("smoke_test") }),
      storedSubmission({ email: undefined }),
    ]) {
      const reader = createReader({
        store: { async querySubmissionId() { return [item]; } },
        logger: { error() {} },
      });
      await assert.rejects(
        reader({ submissionId: SUBMISSION_ID }),
        (error) => error.name === "WaitlistReaderIntegrityError",
      );
    }
  });

  it("queries only the exact GSI key with a bounded projected result", async () => {
    const inputs = [];
    const adapter = createDynamoReader({
      tableName: "private-table",
      indexName: "submission-id-index",
      client: { async send(input) { inputs.push(input); return { Items: [] }; } },
      commandFactory: (input) => input,
    });

    assert.deepEqual(await adapter.querySubmissionId(SUBMISSION_ID), []);
    assert.equal(inputs.length, 1);
    assert.equal(inputs[0].TableName, "private-table");
    assert.equal(inputs[0].IndexName, "submission-id-index");
    assert.equal(inputs[0].KeyConditionExpression, "#submission_id = :submission_id");
    assert.deepEqual(inputs[0].ExpressionAttributeValues, {
      ":submission_id": { S: SUBMISSION_ID },
    });
    assert.equal(inputs[0].Limit, 2);
    assert.equal(inputs[0].ConsistentRead, false);
    assert.deepEqual(inputs[0].ExpressionAttributeNames, PROJECTED_ATTRIBUTE_NAMES);
    assert.equal(Object.hasOwn(inputs[0], "FilterExpression"), false);
    assert.equal(Object.hasOwn(inputs[0], "ExclusiveStartKey"), false);
  });

  it("never logs IDs, PII, or upstream exception text", async () => {
    const logs = [];
    const reader = createReader({
      store: {
        async querySubmissionId() {
          throw new Error(`person@example.org Private Company ${SUBMISSION_ID}`);
        },
      },
      logger: { error: (line) => logs.push(line) },
    });

    await assert.rejects(
      reader({ submissionId: SUBMISSION_ID }, { awsRequestId: "safe-request-id" }),
      (error) => error.name === "WaitlistReaderUnavailableError" &&
        error.message === "temporarily_unavailable",
    );
    const transcript = logs.join("\n");
    assert.match(transcript, /waitlist_reader_storage_failure/);
    assert.doesNotMatch(transcript, /person@example\.org|Private Company|wl_[0-9a-f]{24}/);
  });
});
