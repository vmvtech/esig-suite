import { createHash } from "node:crypto";

import {
  CreateSecretCommand,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { describe, expect, it, vi } from "vitest";

import { SecretsManagerDatabasePasswordProvider } from "../src/aws/secrets-manager-database-password.js";
import { deterministicTenantId, SafeProvisioningError } from "../src/domain.js";
import type { ProvisioningRequest } from "../src/providers/types.js";

const PREFIX = "e-sig/private-preview/database-passwords";
const EXISTING_PASSWORD = "A".repeat(48);
const LEAK_MARKER = "database-password-DO-NOT-EXPOSE";

const REQUEST: ProvisioningRequest = {
  subscriptionId: "sub_dedicated_01J0TEST",
  customerId: "cus_01J0TEST",
  ownerSubject: "owner@example.com",
  planCode: "scale",
  region: "us-east-1",
};

function expectedIdentity(request = REQUEST) {
  const tenantId = deterministicTenantId(request.subscriptionId, "dedicated");
  const subscriptionDigest = createHash("sha256")
    .update("e-sig:database-password:subscription:v1", "utf8")
    .update("\0", "utf8")
    .update(request.subscriptionId, "utf8")
    .digest("hex");
  return {
    tenantId,
    subscriptionDigest,
    secretName: `${PREFIX}/${tenantId}-${subscriptionDigest.slice(0, 24)}`,
  };
}

function storedSecret(password = EXISTING_PASSWORD, request = REQUEST): string {
  return JSON.stringify({ version: 1, ...expectedIdentity(request), secretName: undefined, password });
}

function awsError(name: string, message: string, httpStatusCode?: number): Error {
  return Object.assign(new Error(message), {
    name,
    $metadata: httpStatusCode === undefined ? {} : { httpStatusCode },
  });
}

describe("SecretsManagerDatabasePasswordProvider", () => {
  it("returns an existing identity-bound secret without creating another", async () => {
    const send = vi.fn().mockResolvedValue({ SecretString: storedSecret() });
    const provider = new SecretsManagerDatabasePasswordProvider(
      { send } as never,
      PREFIX,
    );

    await expect(provider.databasePasswordFor(REQUEST)).resolves.toBe(
      EXISTING_PASSWORD,
    );
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]![0]).toBeInstanceOf(GetSecretValueCommand);
    expect(send.mock.calls[0]![0].input).toEqual({
      SecretId: expectedIdentity().secretName,
    });
    expect(expectedIdentity().secretName).not.toContain(REQUEST.subscriptionId);
    expect(expectedIdentity().secretName).not.toContain(REQUEST.ownerSubject);
  });

  it("creates and returns a 288-bit URL-safe ASCII password", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(
        awsError("ResourceNotFoundException", "absent", 404),
      )
      .mockResolvedValueOnce({ ARN: "arn:created" });
    const provider = new SecretsManagerDatabasePasswordProvider(
      { send } as never,
      PREFIX,
      { kmsKeyId: "alias/e-sig-private-preview" },
    );
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const password = await provider.databasePasswordFor(REQUEST);

    expect(password).toMatch(/^[A-Za-z0-9_-]{48}$/);
    expect(send).toHaveBeenCalledTimes(2);
    const create = send.mock.calls[1]![0];
    expect(create).toBeInstanceOf(CreateSecretCommand);
    expect(create.input).toMatchObject({
      Name: expectedIdentity().secretName,
      KmsKeyId: "alias/e-sig-private-preview",
      Description: "Dedicated e-sig Cloud Supabase database password.",
    });
    expect(create.input.ClientRequestToken).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(JSON.parse(create.input.SecretString as string)).toEqual({
      version: 1,
      tenantId: expectedIdentity().tenantId,
      subscriptionDigest: expectedIdentity().subscriptionDigest,
      password,
    });
    expect(create.input.Tags).toEqual([
      { Key: "e-sig:purpose", Value: "dedicated-database-password" },
      { Key: "e-sig:tenant-id", Value: expectedIdentity().tenantId },
      {
        Key: "e-sig:subscription-digest",
        Value: expectedIdentity().subscriptionDigest,
      },
    ]);
    expect(log).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });

  it("recovers the winner when a concurrent creator wins the name", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(awsError("ResourceNotFoundException", "absent", 404))
      .mockRejectedValueOnce(awsError("ResourceExistsException", "race", 400))
      .mockResolvedValueOnce({ SecretString: storedSecret() });
    const provider = new SecretsManagerDatabasePasswordProvider(
      { send } as never,
      PREFIX,
    );

    await expect(provider.databasePasswordFor(REQUEST)).resolves.toBe(
      EXISTING_PASSWORD,
    );
    expect(send.mock.calls.map(([command]) => command.constructor.name)).toEqual([
      "GetSecretValueCommand",
      "CreateSecretCommand",
      "GetSecretValueCommand",
    ]);
  });

  it("recovers a committed secret after an ambiguous create response", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(awsError("ResourceNotFoundException", "absent", 404))
      .mockRejectedValueOnce(awsError("InternalServiceError", LEAK_MARKER, 500))
      .mockResolvedValueOnce({ SecretString: storedSecret() });
    const provider = new SecretsManagerDatabasePasswordProvider(
      { send } as never,
      PREFIX,
    );

    await expect(provider.databasePasswordFor(REQUEST)).resolves.toBe(
      EXISTING_PASSWORD,
    );
  });

  it("rejects colliding or malformed stored identities without exposing content", async () => {
    const send = vi.fn().mockResolvedValue({
      SecretString: storedSecret(EXISTING_PASSWORD, {
        ...REQUEST,
        subscriptionId: "sub_other",
      }),
    });
    const provider = new SecretsManagerDatabasePasswordProvider(
      { send } as never,
      PREFIX,
    );

    const caught = await captureRejection(() =>
      provider.databasePasswordFor(REQUEST),
    );
    expect(caught).toMatchObject({
      safeCode: "PROVIDER_RESPONSE_INVALID",
      retryable: false,
    });
    assertDoesNotExpose(caught, EXISTING_PASSWORD);
  });

  it("redacts AWS failures and preserves only safe retry metadata", async () => {
    const send = vi
      .fn()
      .mockRejectedValue(
        awsError("AccessDeniedException", LEAK_MARKER, 403),
      );
    const provider = new SecretsManagerDatabasePasswordProvider(
      { send } as never,
      PREFIX,
    );

    const caught = await captureRejection(() =>
      provider.databasePasswordFor(REQUEST),
    );
    expect(caught).toBeInstanceOf(SafeProvisioningError);
    expect(caught).toMatchObject({
      safeCode: "PROVIDER_RESOURCE_FAILED",
      retryable: false,
    });
    expect((caught as Error & { cause?: unknown }).cause).toBeUndefined();
    assertDoesNotExpose(caught, LEAK_MARKER);
  });

  it("rejects unsafe configuration and subscription identities", async () => {
    expect(
      () =>
        new SecretsManagerDatabasePasswordProvider(
          { send: vi.fn() } as never,
          "unsafe prefix",
        ),
    ).toThrow("Secrets Manager database-password prefix is invalid");

    const provider = new SecretsManagerDatabasePasswordProvider(
      { send: vi.fn() } as never,
      PREFIX,
    );
    await expect(
      provider.databasePasswordFor({
        ...REQUEST,
        subscriptionId: `unsafe/${LEAK_MARKER}`,
      }),
    ).rejects.toMatchObject({ safeCode: "PROVIDER_INVALID_REQUEST" });
  });
});

async function captureRejection(operation: () => Promise<unknown>): Promise<unknown> {
  try {
    await operation();
  } catch (error: unknown) {
    return error;
  }
  throw new Error("Expected operation to reject");
}

function assertDoesNotExpose(error: unknown, plaintext: string): void {
  expect(String(error)).not.toContain(plaintext);
  expect(JSON.stringify(error)).not.toContain(plaintext);
  expect(error instanceof Error ? error.stack : undefined).not.toContain(plaintext);
}
