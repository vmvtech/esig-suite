"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { tmpdir } = require("node:os");
const { chmod, mkdtemp, readFile, rm, writeFile } = require("node:fs/promises");
const { join } = require("node:path");
const { describe, it } = require("node:test");

const waitlistRoot = join(__dirname, "..");
const templatePath = join(waitlistRoot, "template.yaml");
const bootstrapPath = join(waitlistRoot, "artifact-bootstrap.yaml");
const deployScriptPath = join(waitlistRoot, "scripts", "deploy.sh");
const packagePath = join(waitlistRoot, "package.json");
const lockPath = join(waitlistRoot, "package-lock.json");
const brokerKmsKeyArn = "arn:aws:kms:us-east-1:633740007231:key/01234567-89ab-cdef-0123-456789abcdef";

function spawnResult(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

function validActivationProofReceipt(overrides = {}) {
  const generation = `${"1".padStart(39, "0")}:00000000001754599940:00000000001754600240:${"a".repeat(64)}`;
  return JSON.stringify({
    status: "proof-verified",
    proofDigest: "b".repeat(64),
    proofGeneration: generation,
    proofOrder: `${generation}:01`,
    ...overrides,
  });
}

async function runActivationPreflight({
  proofJson = validActivationProofReceipt(),
  secondProofJson = proofJson,
  backfillExit = 0,
  backfillOutput = '{"status":"verified","passes":2,"eligible":1}',
  replayExit = 0,
  replayOutput = '{"status":"verified","passes":2,"eligible":1,"replayed":1}',
  writerVersion = "metadata-outbox-v1",
  kmsKeyArn = brokerKmsKeyArn,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "esig-waitlist-preflight-test."));
  const awsPath = join(directory, "aws-stub.sh");
  const npmPath = join(directory, "npm-stub.sh");
  const nodePath = join(directory, "node-stub.sh");
  const logPath = join(directory, "aws.log");
  const proofCounterPath = join(directory, "proof-seen");

  const awsStub = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$AWS_STUB_LOG"
arguments="$*"
if [[ "$arguments" == *"ArtifactBucketName"* ]]; then echo artifact-bucket; exit 0; fi
if [[ "$arguments" == *"ParameterKey=='WaitlistNotifierEnabled'"* ]]; then echo false; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistTableName'"* ]]; then echo waitlist-table; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistNotificationOutboxTableName'"* ]]; then echo waitlist-outbox-table; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistOutboxWriterVersion'"* ]]; then echo "$WRITER_VERSION"; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistNotificationOutboxStreamArn'"* ]]; then echo arn:aws:dynamodb:us-east-1:456453427852:table/waitlist-outbox/stream/2026-08-06T00:00:00.000; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistNotifierFunctionName'"* ]]; then echo waitlist-notifier; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistNotifierRoleArn'"* ]]; then echo arn:aws:iam::456453427852:role/esig-waitlist-production-mail-producer; exit 0; fi
if [[ "$arguments" == *"OutputKey=='WaitlistBrokerKmsKeyArn'"* ]]; then echo "$WAITLIST_BROKER_KMS_KEY_ARN"; exit 0; fi
if [[ "$1 $2" == "s3api get-public-access-block" ]]; then printf 'True\\tTrue\\tTrue\\tTrue\\n'; exit 0; fi
if [[ "$1 $2" == "s3api get-bucket-versioning" ]]; then echo Enabled; exit 0; fi
if [[ "$1 $2" == "s3api get-bucket-encryption" ]]; then echo AES256; exit 0; fi
if [[ "$1 $2" == "s3api get-bucket-policy" ]]; then
  echo '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::artifact-bucket","arn:aws:s3:::artifact-bucket/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
  exit 0
fi
if [[ "$1 $2" == "lambda invoke" ]]; then
  response_file="\${!#}"
  if [[ -e "$PROOF_COUNTER_FILE" ]]; then printf '%s\n' "$SECOND_PROOF_JSON" > "$response_file"; else : > "$PROOF_COUNTER_FILE"; printf '%s\n' "$PROOF_JSON" > "$response_file"; fi
  printf '{"StatusCode":200}\n'
  exit 0
fi
if [[ "$1 $2" == "lambda list-event-source-mappings" ]]; then echo Disabled; exit 0; fi
if [[ "$1 $2" == "cloudformation package" ]]; then
  template_file=""
  output_file=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --template-file) template_file="$2"; shift 2 ;;
      --output-template-file) output_file="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  cp "$template_file" "$output_file"
  exit 0
fi
if [[ "$1 $2" == "cloudformation deploy" ]]; then exit 0; fi
echo "unexpected aws stub call" >&2
exit 2
`;

  const nodeStub = `#!/usr/bin/env bash
set -euo pipefail
printf 'node %s\n' "$*" >> "$AWS_STUB_LOG"
if [[ "$1" == */src/backfill-outbox.js ]]; then
  printf '%s\n' "$BACKFILL_OUTPUT"
  exit "$BACKFILL_EXIT"
fi
if [[ "$1" == */src/replay-outbox.js ]]; then
  printf '%s\n' "$REPLAY_OUTPUT"
  exit "$REPLAY_EXIT"
fi
exec "$REAL_NODE_BIN" "$@"
`;

  try {
    await writeFile(awsPath, awsStub, { mode: 0o700 });
    await writeFile(npmPath, "#!/usr/bin/env bash\nexit 0\n", { mode: 0o700 });
    await writeFile(nodePath, nodeStub, { mode: 0o700 });
    await chmod(awsPath, 0o700);
    await chmod(npmPath, 0o700);
    await chmod(nodePath, 0o700);

    const result = await spawnResult("bash", [deployScriptPath], {
      cwd: join(waitlistRoot, "..", ".."),
      env: {
        ...process.env,
        AWS_BIN: awsPath,
        AWS_REGION: "us-east-1",
        AWS_STUB_LOG: logPath,
        BACKFILL_EXIT: String(backfillExit),
        BACKFILL_OUTPUT: backfillOutput,
        REPLAY_EXIT: String(replayExit),
        REPLAY_OUTPUT: replayOutput,
        EXECUTE_CHANGESET: "0",
        NODE_BIN: nodePath,
        NPM_BIN: npmPath,
        PROOF_JSON: proofJson,
        SECOND_PROOF_JSON: secondProofJson,
        REAL_NODE_BIN: process.execPath,
        TMPDIR: directory,
        PROOF_COUNTER_FILE: proofCounterPath,
        WRITER_VERSION: writerVersion,
        WAITLIST_BROKER_QUEUE_ARN:
          "arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard.fifo",
        WAITLIST_BROKER_QUEUE_URL:
          "https://sqs.us-east-1.amazonaws.com/633740007231/esig-mail-enqueue-standard.fifo",
        WAITLIST_NOTIFIER_ENABLED: "true",
        WAITLIST_BROKER_KMS_KEY_ARN: kmsKeyArn,
      },
    });
    const log = await readFile(logPath, "utf8").catch(() => "");
    return { ...result, log };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("waitlist CloudFormation", () => {
  it("retains an encrypted, recoverable table with code-enforced TTL configuration", async () => {
    const template = await readFile(templatePath, "utf8");
    const tableSection = template.slice(
      template.indexOf("  WaitlistTable:"),
      template.indexOf("  WaitlistNotificationOutboxTable:"),
    );
    const outboxTableSection = template.slice(
      template.indexOf("  WaitlistNotificationOutboxTable:"),
      template.indexOf("  WaitlistFunction:"),
    );

    assert.match(
      template,
      /ProductionRetentionDays:\n\s+Type: Number\n\s+Default: 180\n\s+MinValue: 30\n\s+MaxValue: 180/,
    );
    assert.match(template, /SmokeTestTtlHours:\n\s+Type: Number\n\s+Default: 24/);
    assert.match(tableSection, /DeletionPolicy: Retain/);
    assert.match(tableSection, /UpdateReplacePolicy: Retain/);
    assert.match(tableSection, /BillingMode: PAY_PER_REQUEST/);
    assert.match(tableSection, /PointInTimeRecoveryEnabled: true/);
    assert.match(tableSection, /SSEEnabled: true/);
    assert.match(tableSection, /SSEType: KMS/);
    assert.doesNotMatch(tableSection, /StreamViewType:/);
    assert.match(
      tableSection,
      /TimeToLiveSpecification:\n\s+AttributeName: expires_at_epoch\n\s+Enabled: true/,
    );
    assert.match(outboxTableSection, /DeletionPolicy: Retain/);
    assert.match(outboxTableSection, /UpdateReplacePolicy: Retain/);
    assert.match(outboxTableSection, /AttributeName: outbox_key/);
    assert.match(outboxTableSection, /PointInTimeRecoveryEnabled: true/);
    assert.match(outboxTableSection, /SSEEnabled: true/);
    assert.match(outboxTableSection, /SSEType: KMS/);
    assert.match(outboxTableSection, /StreamViewType: NEW_IMAGE/);
    assert.match(outboxTableSection, /Value: notification-metadata/);
  });

  it("uses a SAM-managed regional REST deployment protected by bounded per-IP WAF", async () => {
    const template = await readFile(templatePath, "utf8");

    assert.match(template, /Type: AWS::Serverless::Api/);
    assert.match(template, /EndpointConfiguration:\n\s+Type: REGIONAL/);
    assert.match(template, /StageName: Prod/);
    assert.match(template, /SubmitWaitlist:\n\s+Type: Api/);
    assert.doesNotMatch(template, /Type: AWS::ApiGateway::Deployment/);
    assert.match(template, /Type: AWS::WAFv2::WebACL/);
    assert.match(template, /Type: AWS::WAFv2::WebACLAssociation/);
    assert.match(template, /RateBasedStatement:/);
    assert.match(template, /AggregateKeyType: IP/);
    assert.match(template, /EvaluationWindowSec: 300/);
    assert.equal((template.match(/SampledRequestsEnabled: false/g) || []).length, 2);
    assert.match(template, /DependsOn: WaitlistRestApiProdStage/);
    assert.match(template, /stages\/Prod/);
    assert.match(template, /DataTraceEnabled: false/);
    assert.match(template, /LoggingLevel: "OFF"/);
    assert.doesNotMatch(template, /AWS::Serverless::HttpApi/);
  });

  it("returns CORS only for the production site and exposes the staged endpoint", async () => {
    const template = await readFile(templatePath, "utf8");

    assert.match(
      template,
      /AllowOrigin: "'https:\/\/e-sig\.org'"/,
    );
    assert.match(template, /ALLOWED_ORIGIN: https:\/\/e-sig\.org/);
    assert.doesNotMatch(template, /Access-Control-Allow-Origin:[^\n]*\*/);
    assert.match(template, /Path: \/waitlist/);
    assert.match(
      template,
      /Value: !Sub https:\/\/\$\{WaitlistRestApi\}\.execute-api\.\$\{AWS::Region\}\.\$\{AWS::URLSuffix\}\/Prod\/waitlist/,
    );
  });

  it("grants intake only atomic write access to the private and outbox tables", async () => {
    const template = await readFile(templatePath, "utf8");
    const functionSection = template.slice(
      template.indexOf("  WaitlistFunction:"),
      template.indexOf("  WaitlistFunctionLogGroup:"),
    );

    assert.match(functionSection, /WAITLIST_OUTBOX_TABLE_NAME: !Ref WaitlistNotificationOutboxTable/);
    assert.match(functionSection, /Action: dynamodb:TransactWriteItems/);
    assert.match(
      functionSection,
      /Resource:\n\s+- !GetAtt WaitlistTable\.Arn\n\s+- !GetAtt WaitlistNotificationOutboxTable\.Arn/,
    );
    assert.doesNotMatch(functionSection, /dynamodb:(PutItem|GetItem|UpdateItem|DeleteItem|Scan|Query|BatchWriteItem)/);
    assert.doesNotMatch(functionSection, /Action: ["']?\*["']?/);
    assert.doesNotMatch(functionSection, /Resource: ["']?\*["']?/);
    assert.doesNotMatch(functionSection, /(secretsmanager|ssm):/i);
    assert.doesNotMatch(functionSection, /sqs:/i);
    assert.doesNotMatch(template, /Tracing: Active/);
  });

  it("keeps an exact-ID reader disabled behind one role principal and index-only Query", async () => {
    const template = await readFile(templatePath, "utf8");
    const tableSection = template.slice(
      template.indexOf("  WaitlistTable:"),
      template.indexOf("  WaitlistNotificationOutboxTable:"),
    );
    const executionRoleSection = template.slice(
      template.indexOf("  WaitlistReaderExecutionRole:"),
      template.indexOf("  WaitlistReaderFunction:"),
    );
    const readerSection = template.slice(
      template.indexOf("  WaitlistReaderFunction:"),
      template.indexOf("  WaitlistReaderInvokeRole:"),
    );
    const invokeRoleSection = template.slice(
      template.indexOf("  WaitlistReaderInvokeRole:"),
      template.indexOf("  WaitlistNotifierDeadLetterQueue:"),
    );

    assert.match(
      template,
      /WaitlistReaderEnabled:\n\s+Type: String\n\s+Default: "false"\n\s+AllowedValues: \["true", "false"\]/,
    );
    assert.match(
      template,
      /AllowedPattern: \^\(\?:not-configured\|arn:aws:iam::\[0-9\]\{12\}:role\//,
    );
    assert.doesNotMatch(
      template.slice(
        template.indexOf("  WaitlistReaderPrincipalArn:"),
        template.indexOf("  WaitlistReaderActivationPreflight:"),
      ),
      /:user\/|:root|\*/,
    );
    assert.match(template, /ReaderActivationGuard:/);
    assert.match(template, /opaque-ids-verified/);
    assert.match(tableSection, /AttributeName: submission_id\n\s+AttributeType: S/);
    assert.match(tableSection, /IndexName: submission-id-index/);
    assert.match(tableSection, /ProjectionType: INCLUDE/);
    for (const field of [
      "email",
      "name",
      "company",
      "use_case",
      "expected_monthly_envelopes",
      "offer",
      "created_at",
      "contact_permission_status",
      "email_verification_status",
      "privacy_notice_version",
      "record_type",
      "submission_id_version",
    ]) {
      assert.match(tableSection, new RegExp(`- ${field}`));
    }

    assert.match(executionRoleSection, /Condition: WaitlistReaderIsEnabled/);
    assert.match(executionRoleSection, /Service: lambda\.amazonaws\.com/);
    assert.match(executionRoleSection, /Action: dynamodb:Query/);
    assert.match(
      executionRoleSection,
      /Resource: !Sub \$\{WaitlistTable\.Arn\}\/index\/submission-id-index/,
    );
    assert.doesNotMatch(executionRoleSection, /dynamodb:(Scan|GetItem|BatchGetItem)|Resource: ["']?\*["']?/);
    assert.match(executionRoleSection, /- logs:CreateLogStream/);
    assert.match(executionRoleSection, /- logs:PutLogEvents/);
    assert.doesNotMatch(executionRoleSection, /logs:CreateLogGroup/);
    assert.match(
      executionRoleSection,
      /log-group:\/aws\/lambda\/\$\{AWS::StackName\}-waitlist-reader:\*/,
    );

    assert.match(readerSection, /Condition: WaitlistReaderIsEnabled/);
    assert.match(readerSection, /DependsOn: WaitlistReaderLogGroup/);
    assert.match(readerSection, /Handler: src\/reader\.handler/);
    assert.match(readerSection, /Role: !GetAtt WaitlistReaderExecutionRole\.Arn/);
    assert.match(readerSection, /WAITLIST_SUBMISSION_ID_INDEX_NAME: submission-id-index/);
    assert.doesNotMatch(readerSection, /Events:|FunctionUrl|Cors:|Api:|HttpApi:|Policies:/);
    assert.match(
      template,
      /WaitlistReaderLogGroup:[\s\S]*Condition: WaitlistReaderIsEnabled[\s\S]*LogGroupName: !Sub \/aws\/lambda\/\$\{AWS::StackName\}-waitlist-reader/,
    );

    assert.match(invokeRoleSection, /Condition: WaitlistReaderIsEnabled/);
    assert.match(invokeRoleSection, /AWS: !Ref WaitlistReaderPrincipalArn/);
    assert.match(invokeRoleSection, /Action: lambda:InvokeFunction/);
    assert.match(invokeRoleSection, /Resource: !GetAtt WaitlistReaderFunction\.Arn/);
    assert.doesNotMatch(invokeRoleSection, /Principal: ["']?\*["']?|Resource: ["']?\*["']?/);

    assert.match(template, /WaitlistOpaqueIdWriterVersion:[\s\S]*Value: opaque-id-random-v1/);
    assert.match(template, /WaitlistReaderRequestContract:[\s\S]*submissionId/);
    assert.match(template, /WaitlistReaderResponseFields:[\s\S]*expectedMonthlyEnvelopes/);
    assert.doesNotMatch(template, /WaitlistReaderInvokeCommand:/);
  });

  it("keeps the notifier disabled while pinning the exact cross-account FIFO coordinates", async () => {
    const template = await readFile(templatePath, "utf8");
    const queueUrlParameter = template.slice(
      template.indexOf("  WaitlistBrokerQueueUrl:"),
      template.indexOf("  WaitlistBrokerQueueArn:"),
    );
    const queueArnParameter = template.slice(
      template.indexOf("  WaitlistBrokerQueueArn:"),
      template.indexOf("  WaitlistBrokerKmsKeyArn:"),
    );
    const activationParameter = template.slice(
      template.indexOf("  WaitlistNotifierActivationPreflight:"),
      template.indexOf("\nRules:"),
    );

    assert.match(
      template,
      /WaitlistNotifierEnabled:\n\s+Type: String\n\s+Default: "false"\n\s+AllowedValues: \["true", "false"\]/,
    );
    assert.match(template, /WaitlistNotifierIsEnabled: !Equals \[!Ref WaitlistNotifierEnabled, "true"\]/);
    assert.match(template, /NotifierActivationGuard:/);
    assert.match(
      queueUrlParameter,
      /Default: https:\/\/sqs\.us-east-1\.amazonaws\.com\/633740007231\/esig-mail-enqueue-standard\.fifo/,
    );
    assert.match(
      queueUrlParameter,
      /https:\/\/sqs\.us-east-1\.amazonaws\.com\/633740007231\/esig-mail-enqueue-standard\.fifo/,
    );
    assert.match(
      queueArnParameter,
      /Default: arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard\.fifo/,
    );
    assert.match(
      queueArnParameter,
      /arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard\.fifo/,
    );
    assert.match(activationParameter, /Default: not-approved/);
    assert.match(activationParameter, /AllowedValues: \[not-approved, proof-and-backfill-verified\]/);
    assert.match(template, /Fresh exact lane proof and a converged metadata-only outbox backfill are required/);
    assert.match(
      template,
      /WaitlistNotifierFunction:\n\s+Type: AWS::Serverless::Function\n\s+DependsOn: WaitlistNotifierStreamAccessPolicy/,
    );
    assert.match(template, /Enabled: !If \[WaitlistNotifierIsEnabled, true, false\]/);
    assert.match(template, /WAITLIST_BROKER_QUEUE_ARN: !Ref WaitlistBrokerQueueArn/);
    assert.match(template, /WAITLIST_BROKER_QUEUE_URL: !Ref WaitlistBrokerQueueUrl/);
  });

  it("filters eligible inserts and retries failed notifications through an encrypted alarmed DLQ", async () => {
    const template = await readFile(templatePath, "utf8");
    const notifierSection = template.slice(
      template.indexOf("  WaitlistNotifierFunction:"),
      template.indexOf("  WaitlistNotifierFunctionLogGroup:"),
    );

    assert.match(notifierSection, /Handler: src\/notifier\.handler/);
    assert.match(
      notifierSection,
      /Stream: !GetAtt WaitlistNotificationOutboxTable\.StreamArn/,
    );
    assert.match(notifierSection, /StartingPosition: TRIM_HORIZON/);
    assert.match(notifierSection, /BisectBatchOnFunctionError: true/);
    assert.match(notifierSection, /MaximumRecordAgeInSeconds: 86400/);
    assert.match(notifierSection, /MaximumRetryAttempts: 5/);
    assert.match(notifierSection, /FunctionResponseTypes: \[ReportBatchItemFailures\]/);
    assert.match(
      notifierSection,
      /Pattern: '\{"eventName":\["INSERT"\],"dynamodb":\{"NewImage":\{"record_type":\{"S":\["waitlist_notification_outbox"\]\}\}\}\}'/,
    );
    assert.match(notifierSection, /DestinationConfig:[\s\S]*OnFailure:[\s\S]*Type: SQS/);
    assert.match(
      notifierSection,
      /Destination: !GetAtt WaitlistNotifierDeadLetterQueue\.Arn/,
    );
    assert.match(template, /WaitlistNotifierDeadLetterQueue:[\s\S]*SqsManagedSseEnabled: true/);
    assert.match(template, /WaitlistNotifierDeadLetterQueuePolicy:/);
    assert.match(template, /aws:SecureTransport: "false"/);
    assert.match(template, /WaitlistNotifierDeadLetterAlarm:/);
    assert.match(template, /MetricName: ApproximateNumberOfMessagesVisible/);
  });

  it("limits notifier IAM to exact stream, queue, and proof-head access", async () => {
    const template = await readFile(templatePath, "utf8");
    const notifierRoleSection = template.slice(
      template.indexOf("  WaitlistNotifierRole:"),
      template.indexOf("  WaitlistNotifierStreamAccessPolicy:"),
    );
    const notifierStreamSection = template.slice(
      template.indexOf("  WaitlistNotifierStreamAccessPolicy:"),
      template.indexOf("  WaitlistNotifierBrokerAccessPolicy:"),
    );
    const notifierBrokerSection = template.slice(
      template.indexOf("  WaitlistNotifierBrokerAccessPolicy:"),
      template.indexOf("  WaitlistNotifierFunction:"),
    );
    const notifierSection = template.slice(
      template.indexOf("  WaitlistNotifierFunction:"),
      template.indexOf("  WaitlistNotifierFunctionLogGroup:"),
    );

    assert.match(notifierRoleSection, /Type: AWS::IAM::Role/);
    assert.doesNotMatch(notifierRoleSection, /Condition: WaitlistNotifierIsEnabled/);
    assert.match(
      notifierRoleSection,
      /RoleName: esig-waitlist-production-mail-producer/,
    );
    assert.match(notifierRoleSection, /Service: lambda\.amazonaws\.com/);
    assert.match(notifierRoleSection, /Action: sts:AssumeRole/);
    assert.match(notifierRoleSection, /- logs:CreateLogStream/);
    assert.match(notifierRoleSection, /- logs:PutLogEvents/);
    assert.doesNotMatch(notifierRoleSection, /logs:CreateLogGroup/);
    assert.match(notifierRoleSection, /log-group:\/aws\/lambda\/\$\{AWS::StackName\}-waitlist-notifier:\*/);
    assert.doesNotMatch(notifierRoleSection, /dynamodb:|sqs:/);
    assert.match(notifierStreamSection, /Type: AWS::IAM::Policy/);
    assert.doesNotMatch(notifierStreamSection, /Condition:/);
    assert.match(notifierStreamSection, /Roles: \[!Ref WaitlistNotifierRole\]/);
    for (const action of [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams",
    ]) {
      assert.match(notifierStreamSection, new RegExp(`- ${action}`));
    }
    assert.match(
      notifierStreamSection,
      /Resource: !GetAtt WaitlistNotificationOutboxTable\.StreamArn/,
    );
    assert.doesNotMatch(notifierStreamSection, /WaitlistTable\.StreamArn/);
    assert.match(notifierStreamSection, /Resource: !GetAtt WaitlistNotifierDeadLetterQueue\.Arn/);
    assert.match(notifierBrokerSection, /Condition: WaitlistBrokerAccessIsConfigured/);
    assert.match(notifierBrokerSection, /Action: sqs:SendMessage/);
    assert.match(notifierBrokerSection, /Resource: !Ref WaitlistBrokerQueueArn/);
    assert.match(notifierBrokerSection, /- kms:GenerateDataKey/);
    assert.match(notifierBrokerSection, /- kms:Decrypt/);
    assert.match(notifierBrokerSection, /Resource: !Ref WaitlistBrokerKmsKeyArn/);
    assert.match(notifierBrokerSection, /kms:ViaService: sqs\.us-east-1\.amazonaws\.com/);
    assert.match(notifierBrokerSection, /kms:EncryptionContext:aws:sqs:queue-arn: arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard\.fifo/);
    assert.match(notifierBrokerSection, /Action: dynamodb:GetItem/);
    assert.match(notifierBrokerSection, /Resource: arn:aws:dynamodb:us-east-1:633740007231:table\/esig-mail-broker-idempotency-standard/);
    assert.match(notifierBrokerSection, /dynamodb:LeadingKeys:[\s\S]*activation-proof-head:esig\.waitlist\.sales\.v1/);
    assert.match(notifierBrokerSection, /kms:ViaService: dynamodb\.us-east-1\.amazonaws\.com/);
    assert.match(notifierBrokerSection, /kms:EncryptionContext:aws:dynamodb:tableName: esig-mail-broker-idempotency-standard/);
    assert.doesNotMatch(
      `${notifierStreamSection}${notifierBrokerSection}`,
      /dynamodb:(PutItem|UpdateItem|DeleteItem|Scan|Query|BatchWriteItem|TransactWriteItems)/,
    );
    assert.equal((notifierBrokerSection.match(/Action: dynamodb:GetItem/g) || []).length, 1);
    assert.doesNotMatch(`${notifierStreamSection}${notifierBrokerSection}`, /sqs:(ReceiveMessage|DeleteMessage|GetQueueAttributes|\*)/);
    assert.doesNotMatch(`${notifierStreamSection}${notifierBrokerSection}`, /Action: ["']?\*["']?/);
    assert.doesNotMatch(`${notifierStreamSection}${notifierBrokerSection}`, /Resource: ["']?\*["']?/);
    assert.doesNotMatch(`${notifierStreamSection}${notifierBrokerSection}`, /(secretsmanager|ssm|ses|smtp):/i);
    assert.match(notifierSection, /FunctionName: !Sub \$\{AWS::StackName\}-waitlist-notifier/);
    assert.match(notifierSection, /DependsOn: WaitlistNotifierStreamAccessPolicy/);
    assert.match(notifierSection, /Role: !GetAtt WaitlistNotifierRole\.Arn/);
    assert.doesNotMatch(notifierSection, /Policies:/);
    assert.match(
      template,
      /WaitlistNotifierRoleArn:\n\s+Value: !GetAtt WaitlistNotifierRole\.Arn/,
    );
    assert.match(template, /WaitlistActivationProofReadContract:[\s\S]*waitlist-activation-proof-read-v1/);
  });

  it("alarms on Lambda errors and throttles, API 5xx, and WAF blocks", async () => {
    const template = await readFile(templatePath, "utf8");

    assert.match(template, /WaitlistFunctionErrorsAlarm:/);
    assert.match(template, /MetricName: Errors/);
    assert.match(template, /WaitlistFunctionThrottlesAlarm:/);
    assert.match(template, /MetricName: Throttles/);
    assert.match(template, /WaitlistApiServerErrorsAlarm:/);
    assert.match(template, /MetricName: 5XXError/);
    assert.match(template, /WaitlistWafBlocksAlarm:/);
    assert.match(template, /MetricName: BlockedRequests/);
    assert.match(template, /Value: esig-waitlist-waf/);
    assert.match(template, /Value: esig-waitlist-rate-limit/);
    assert.equal((template.match(/AlarmActions:/g) || []).length, 5);
    assert.equal((template.match(/CATEGORY=Availability/g) || []).length, 4);
    assert.equal((template.match(/CATEGORY=Security/g) || []).length, 1);
  });
});

describe("waitlist deployment artifacts", () => {
  it("bootstraps a retained private, encrypted, versioned artifact bucket", async () => {
    const bootstrap = await readFile(bootstrapPath, "utf8");

    assert.match(bootstrap, /DeletionPolicy: Retain/);
    assert.match(bootstrap, /UpdateReplacePolicy: Retain/);
    assert.match(
      bootstrap,
      /ArtifactBucketPolicy:\n\s+Type: AWS::S3::BucketPolicy\n\s+DeletionPolicy: Retain\n\s+UpdateReplacePolicy: Retain/,
    );
    assert.match(bootstrap, /SSEAlgorithm: AES256/);
    assert.match(bootstrap, /BlockPublicAcls: true/);
    assert.match(bootstrap, /BlockPublicPolicy: true/);
    assert.match(bootstrap, /IgnorePublicAcls: true/);
    assert.match(bootstrap, /RestrictPublicBuckets: true/);
    assert.match(bootstrap, /VersioningConfiguration:\n\s+Status: Enabled/);
    assert.match(bootstrap, /ExpirationInDays: 365/);
    assert.match(bootstrap, /NoncurrentDays: 30/);
    assert.match(bootstrap, /aws:SecureTransport: "false"/);
  });

  it("builds and deploys in one owner-restricted fresh temporary flow", async () => {
    const deployScript = await readFile(deployScriptPath, "utf8");

    assert.match(deployScript, /mktemp -d "\$\{TMPDIR:-\/tmp\}\/esig-waitlist-release\.XXXXXX"/);
    assert.match(deployScript, /chmod 700 "\$release_dir"/);
    assert.match(deployScript, /trap 'rm -rf "\$release_dir"' EXIT/);
    assert.match(deployScript, /cloudformation deploy[\s\S]*artifact-bootstrap\.yaml/);
    assert.match(deployScript, /BOOTSTRAP_ONLY=\$\{BOOTSTRAP_ONLY:-0\}/);
    assert.match(deployScript, /if \[\[ "\$BOOTSTRAP_ONLY" == "1" \]\]/);
    assert.match(deployScript, /application deployment never bootstraps implicitly/);
    assert.match(deployScript, /OutputKey=='ArtifactBucketName'/);
    assert.match(deployScript, /BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets/);
    assert.match(deployScript, /get-bucket-versioning/);
    assert.match(deployScript, /get-bucket-encryption/);
    assert.match(deployScript, /get-bucket-policy/);
    assert.match(deployScript, /aws:SecureTransport/);
    assert.match(deployScript, /npm[^\n]*ci|"\$NPM_BIN" ci/);
    assert.match(deployScript, /cloudformation package/);
    assert.match(deployScript, /PACKAGED_TEMPLATE_SHA256/);
    assert.match(deployScript, /EXECUTE_CHANGESET=\$\{EXECUTE_CHANGESET:-0\}/);
    assert.match(deployScript, /deploy_args\+=\(--no-execute-changeset\)/);
    assert.match(
      deployScript,
      /--capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND/,
    );
    assert.doesNotMatch(deployScript, /--capabilities CAPABILITY_IAM/);
    assert.match(deployScript, /WAITLIST_NOTIFIER_ENABLED=\$\{WAITLIST_NOTIFIER_ENABLED:-\}/);
    assert.match(
      deployScript,
      /APPROVED_BROKER_QUEUE_URL=https:\/\/sqs\.us-east-1\.amazonaws\.com\/633740007231\/esig-mail-enqueue-standard\.fifo/,
    );
    assert.match(
      deployScript,
      /APPROVED_BROKER_QUEUE_ARN=arn:aws:sqs:us-east-1:633740007231:esig-mail-enqueue-standard\.fifo/,
    );
    assert.match(deployScript, /current_notifier_enabled=/);
    assert.match(deployScript, /WaitlistNotificationOutboxTableName/);
    assert.match(deployScript, /WaitlistOutboxWriterVersion/);
    assert.match(deployScript, /metadata-outbox-v1/);
    assert.match(deployScript, /backfill-outbox\.js/);
    assert.match(deployScript, /waitlist-activation-proof-read-v1/);
    assert.match(deployScript, /lambda invoke/);
    assert.doesNotMatch(deployScript, /ssm get-parameter|activation-proof\.js|--with-decryption/);
    assert.match(deployScript, /metadata-only outbox backfill did not verify zero missing records/);
    assert.match(deployScript, /WaitlistNotifierActivationPreflight=\$activation_preflight/);
    assert.equal((deployScript.match(/--parameter-overrides/g) || []).length, 1);
    assert.doesNotMatch(deployScript, /PACKAGED_TEMPLATE=\$\{PACKAGED_TEMPLATE/);
    assert.doesNotMatch(deployScript, /esig-waitlist-packaged-template\.yaml/);
  });

  it("activates only after a converged backfill and fresh exact lane proof", async () => {
    const clear = await runActivationPreflight();

    assert.equal(clear.code, 0, clear.stderr);
    assert.match(clear.log, /node .*\/src\/backfill-outbox\.js/);
    assert.match(clear.log, /node .*\/src\/replay-outbox\.js/);
    assert.match(clear.log, /lambda list-event-source-mappings/);
    assert.match(clear.log, /lambda invoke .*waitlist-activation-proof-read-v1/);
    assert.match(clear.log, /cloudformation package/);
    assert.match(clear.log, /cloudformation deploy/);
    assert.match(clear.log, /WaitlistNotifierActivationPreflight=proof-and-backfill-verified/);
    assert.equal((clear.log.match(/lambda invoke/g) || []).length, 2);
    assert.ok(clear.log.indexOf("lambda invoke") < clear.log.indexOf("replay-outbox.js"));
    assert.ok(clear.log.lastIndexOf("lambda invoke") > clear.log.indexOf("replay-outbox.js"));

    const failedBackfill = await runActivationPreflight({ backfillExit: 1 });
    assert.equal(failedBackfill.code, 1);
    assert.doesNotMatch(failedBackfill.log, /cloudformation deploy/);

    const fakeResult = await runActivationPreflight({ backfillOutput: '{"status":"verified"}' });
    assert.equal(fakeResult.code, 1);
    assert.match(fakeResult.stderr, /did not verify zero missing records/);

    const blocked = JSON.parse(validActivationProofReceipt());
    blocked.status = "BLOCKED_FAILED_CANARY";
    const overflow = JSON.parse(validActivationProofReceipt());
    overflow.proofGeneration = `340282366920938463463374607431768211456:00000000001754599940:00000000001754600240:${"e".repeat(64)}`;
    overflow.proofOrder = `${overflow.proofGeneration}:01`;
    for (const proofJson of ["", "{}", JSON.stringify(blocked), JSON.stringify(overflow)]) {
      const rejectedProof = await runActivationPreflight({ proofJson });
      assert.equal(rejectedProof.code, 1);
      assert.match(rejectedProof.stderr, /exact lane proof is invalid, stale, or incomplete/);
      assert.match(rejectedProof.log, /lambda invoke/);
      assert.doesNotMatch(rejectedProof.log, /backfill-outbox|replay-outbox|cloudformation deploy/);
    }

    const changedGeneration = JSON.parse(validActivationProofReceipt());
    changedGeneration.proofDigest = "c".repeat(64);
    changedGeneration.proofGeneration = `${"2".padStart(39, "0")}:00000000001754600000:00000000001754600300:${"d".repeat(64)}`;
    changedGeneration.proofOrder = `${changedGeneration.proofGeneration}:01`;
    const expiredDuringReplay = await runActivationPreflight({ secondProofJson: JSON.stringify(changedGeneration) });
    assert.equal(expiredDuringReplay.code, 1);
    assert.match(expiredDuringReplay.stderr, /expired or changed during backlog replay/);
    assert.match(expiredDuringReplay.log, /replay-outbox/);
    assert.doesNotMatch(expiredDuringReplay.log, /cloudformation deploy/);

    const oldWriter = await runActivationPreflight({ writerVersion: "None" });
    assert.equal(oldWriter.code, 1);
    assert.match(oldWriter.stderr, /metadata-outbox-v1 handler/);

    const failedReplay = await runActivationPreflight({ replayExit: 1 });
    assert.equal(failedReplay.code, 1);
    assert.doesNotMatch(failedReplay.log, /cloudformation deploy/);

    const missingKms = await runActivationPreflight({ kmsKeyArn: "" });
    assert.equal(missingKms.code, 1);
    assert.match(missingKms.stderr, /exact Standard-account broker CMK ARN/);
  });

  it("pins the DynamoDB and SQS SDKs and records the exact resolved packages", async () => {
    const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
    const packageLock = JSON.parse(await readFile(lockPath, "utf8"));

    assert.equal(packageJson.engines.node, ">=20");
    assert.equal(packageJson.dependencies["@aws-sdk/client-dynamodb"], "3.1103.0");
    assert.equal(packageJson.dependencies["@aws-sdk/client-lambda"], "3.1103.0");
    assert.equal(packageJson.dependencies["@aws-sdk/client-sqs"], "3.1103.0");
    assert.equal(
      packageLock.packages["node_modules/@aws-sdk/client-dynamodb"].version,
      "3.1103.0",
    );
    assert.equal(packageLock.packages["node_modules/@aws-sdk/client-lambda"].version, "3.1103.0");
    assert.equal(
      packageLock.packages["node_modules/@aws-sdk/client-sqs"].version,
      "3.1103.0",
    );
  });
});
