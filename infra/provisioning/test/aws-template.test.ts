import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

const root = new URL("../", import.meta.url);

describe("control-plane CloudFormation", () => {
  it("uses API Gateway v2, retained DynamoDB state, FIFO retry, and bounded Lambdas", async () => {
    const template = await readFile(new URL("template.yaml", root), "utf8");

    expect(template).toContain("AWS::Serverless::HttpApi");
    expect(template).toContain('PayloadFormatVersion: "2.0"');
    expect(template).toContain("BillingMode: PAY_PER_REQUEST");
    expect(template).toContain("PointInTimeRecoveryEnabled: true");
    expect(template).toContain("FifoQueue: true");
    expect(template).toContain("ProvisioningDeadLetterQueue");
    expect(template).toContain("ReservedConcurrentExecutions");
    expect(template).toContain("RetentionInDays: !Ref LogRetentionDays");
    expect(template).toContain("ProvisioningDeadLetterAlarm");
    expect(template).toContain("WebhookServerErrorsAlarm");
    expect(template).toContain("ProvisioningQueueAgeAlarm");
    expect(template).not.toContain("WorkerErrorsAlarm");
    expect(template.match(/CodeUri: lambda\//g)).toHaveLength(2);
    expect(template).toContain("Handler: handlers/webhook.handler");
    expect(template).toContain("Handler: handlers/worker.handler");
    expect(template).toContain("secretsmanager:GetSecretValue");
    expect(template).not.toMatch(/whsec_[A-Za-z0-9]/);
  });

  it("grants the webhook only the AWS operations it performs", async () => {
    const template = await readFile(new URL("template.yaml", root), "utf8");
    const webhookSection = template.slice(
      template.indexOf("  WebhookFunction:"),
      template.indexOf("  WebhookFunctionLogGroup:"),
    );

    expect(webhookSection).toContain("dynamodb:PutItem");
    expect(webhookSection).toContain("dynamodb:GetItem");
    expect(webhookSection).toContain("dynamodb:UpdateItem");
    expect(webhookSection).toContain("sqs:SendMessage");
    expect(webhookSection).toContain("secretsmanager:GetSecretValue");
    expect(webhookSection).not.toContain("Action: \"*\"");
    expect(webhookSection).not.toContain("Resource: \"*\"");
  });

  it("gates all provisioning authority behind the disabled-by-default worker flag", async () => {
    const template = await readFile(new URL("template.yaml", root), "utf8");
    const workerSection = template.slice(
      template.indexOf("  WorkerFunction:"),
      template.indexOf("  WorkerFunctionLogGroup:"),
    );
    const unconditionalWorkerIam = workerSection.slice(
      workerSection.indexOf("      Policies:"),
      workerSection.indexOf("            - !If"),
    );

    expect(template).toContain("OperationalWorkerEnabled:");
    expect(template).toContain('Default: "false"');
    expect(template).toContain(
      'OperationalWorkerIsEnabled: !Equals [!Ref OperationalWorkerEnabled, "true"]',
    );
    expect(unconditionalWorkerIam).toContain("sqs:ReceiveMessage");
    expect(unconditionalWorkerIam).not.toContain("dynamodb:");
    expect(unconditionalWorkerIam).not.toContain("cloudformation:");
    expect(unconditionalWorkerIam).not.toContain("iam:PassRole");
    expect(unconditionalWorkerIam).not.toContain("secretsmanager:");
    expect(workerSection).toContain("dynamodb:GetItem");
    expect(workerSection).toContain("dynamodb:PutItem");
    expect(workerSection).toContain("dynamodb:Query");
    expect(workerSection).toContain("dynamodb:TransactWriteItems");
    expect(workerSection).toContain("stack/esig-dedicated-*/*");
    expect(workerSection).not.toContain("stack/esig-customer-*/*");
    expect(workerSection).not.toContain("dynamodb:Scan");
    expect(workerSection).not.toContain("cloudformation:DescribeStackEvents");
    expect(workerSection).toContain(
      "- secretsmanager:CreateSecret\n                  - secretsmanager:DescribeSecret\n                Resource: !Sub arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:e-sig/cloud/activation/*",
    );
    expect(workerSection).toContain(
      "- secretsmanager:CreateSecret\n                  - secretsmanager:GetSecretValue\n                Resource: !Sub arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:e-sig/cloud/database-password/*",
    );
    expect(workerSection).not.toContain("secretsmanager:PutSecretValue");
    expect(workerSection.match(/secretsmanager:GetSecretValue/g)).toHaveLength(1);
    expect(workerSection).not.toContain("Action: \"*\"");
    expect(workerSection).not.toContain("Resource: \"*\"");
    expect(template).toContain(
      "CustomerStackExecutionRole:\n    Type: AWS::IAM::Role\n    Condition: OperationalWorkerIsEnabled",
    );
  });
});

describe("customer CloudFormation", () => {
  it("retains and encrypts every customer-owned data-plane resource", async () => {
    const template = await readFile(new URL("customer-stack.yaml", root), "utf8");

    expect(template).toContain("EnableKeyRotation: true");
    expect(template).toContain("VersioningConfiguration:\n        Status: Enabled");
    expect(template).toContain("BlockPublicAcls: true");
    expect(template).toContain("KmsMasterKeyId: !GetAtt CustomerKey.Arn");
    expect(template).toContain("SigningDeadLetterQueue");
    expect(template).toContain("Value: !Ref SupabaseProjectRef");
    expect(template).not.toContain("TagKey:");
    expect(template).not.toContain("TagValue:");
    expect(template.match(/DeletionPolicy: Retain/g)?.length).toBeGreaterThanOrEqual(6);
    expect(template.match(/UpdateReplacePolicy: Retain/g)?.length).toBeGreaterThanOrEqual(6);
    expect(template).not.toContain("AutoDeleteObjects");
    expect(template).not.toMatch(/ExpirationInDays|NoncurrentVersionExpiration/);
  });

  it("accepts the dedicated provider parameters and exposes adapter-facing outputs", async () => {
    const template = await readFile(new URL("customer-stack.yaml", root), "utf8");

    for (const name of [
      "TenantId",
      "SubscriptionId",
      "SupabaseProjectRef",
      "SigningEnabled",
      "KmsKeyArn",
      "DocumentBucketName",
      "SigningQueueUrl",
      "SigningDeadLetterQueueUrl",
    ]) {
      expect(template).toContain(`  ${name}:`);
    }
  });
});
