import { createHash, randomBytes, randomUUID } from "node:crypto";

import {
  CreateSecretCommand,
  GetSecretValueCommand,
  type GetSecretValueCommandOutput,
  type SecretsManagerClient,
  type Tag,
} from "@aws-sdk/client-secrets-manager";

import { deterministicTenantId, SafeProvisioningError } from "../domain.js";
import type { ProvisioningRequest } from "../providers/types.js";

type SecretsManagerSender = Pick<SecretsManagerClient, "send">;

export interface SecretsManagerDatabasePasswordOptions {
  /** Optional customer-managed KMS key. The AWS-managed key is used otherwise. */
  readonly kmsKeyId?: string;
}

interface StoredDatabasePassword {
  readonly version: 1;
  readonly tenantId: string;
  readonly subscriptionDigest: string;
  readonly password: string;
}

interface PasswordIdentity {
  readonly tenantId: string;
  readonly subscriptionDigest: string;
  readonly secretName: string;
}

const SECRET_NAME_PATTERN = /^[A-Za-z0-9_+=.@/-]+$/;
const OPAQUE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/;
const PASSWORD_PATTERN = /^[A-Za-z0-9_-]{48}$/;
const MAX_SECRET_NAME_BYTES = 512;

/**
 * Resolves one stable database password per deterministic dedicated tenant.
 * Plaintext exists only in the returned value and the encrypted Secrets
 * Manager request/response; errors retain neither provider messages nor cause.
 */
export class SecretsManagerDatabasePasswordProvider {
  readonly #client: SecretsManagerSender;
  readonly #secretNamePrefix: string;
  readonly #kmsKeyId: string | undefined;

  constructor(
    client: SecretsManagerSender,
    secretNamePrefix: string,
    options: SecretsManagerDatabasePasswordOptions = {},
  ) {
    this.#client = client;
    this.#secretNamePrefix = validateSecretNamePrefix(secretNamePrefix);
    this.#kmsKeyId = validateKmsKeyId(options.kmsKeyId);
  }

  readonly databasePasswordFor = async (
    request: ProvisioningRequest,
  ): Promise<string> => {
    const identity = passwordIdentity(this.#secretNamePrefix, request);

    try {
      const existing = await this.#get(identity);
      if (existing !== undefined) return existing;
    } catch (error: unknown) {
      if (error instanceof SafeProvisioningError) throw error;
      throw safeDatabasePasswordError(error);
    }

    const password = generateDatabasePassword();
    const stored: StoredDatabasePassword = {
      version: 1,
      tenantId: identity.tenantId,
      subscriptionDigest: identity.subscriptionDigest,
      password,
    };

    try {
      await this.#client.send(
        new CreateSecretCommand({
          Name: identity.secretName,
          ClientRequestToken: randomUUID(),
          Description: "Dedicated e-sig Cloud Supabase database password.",
          KmsKeyId: this.#kmsKeyId,
          SecretString: JSON.stringify(stored),
          Tags: passwordTags(identity),
        }),
      );
      return password;
    } catch (createError: unknown) {
      // Covers both a concurrent creator and an ambiguous response after AWS
      // durably committed the create operation.
      try {
        const recovered = await this.#get(identity);
        if (recovered !== undefined) return recovered;
      } catch (recoveryError: unknown) {
        if (recoveryError instanceof SafeProvisioningError) throw recoveryError;
        throw safeDatabasePasswordError(recoveryError);
      }

      throw safeDatabasePasswordError(
        createError,
        awsErrorName(createError) === "ResourceExistsException",
      );
    }
  };

  async #get(identity: PasswordIdentity): Promise<string | undefined> {
    let output: GetSecretValueCommandOutput;
    try {
      output = (await this.#client.send(
        new GetSecretValueCommand({ SecretId: identity.secretName }),
      )) as GetSecretValueCommandOutput;
    } catch (error: unknown) {
      if (awsErrorName(error) === "ResourceNotFoundException") return undefined;
      throw error;
    }

    return parseStoredPassword(output.SecretString, identity);
  }
}

function passwordIdentity(
  prefix: string,
  request: ProvisioningRequest,
): PasswordIdentity {
  if (
    typeof request !== "object" ||
    request === null ||
    !OPAQUE_IDENTIFIER_PATTERN.test(request.subscriptionId)
  ) {
    throw new SafeProvisioningError("PROVIDER_INVALID_REQUEST");
  }

  const tenantId = deterministicTenantId(request.subscriptionId, "dedicated");
  const subscriptionDigest = createHash("sha256")
    .update("e-sig:database-password:subscription:v1", "utf8")
    .update("\0", "utf8")
    .update(request.subscriptionId, "utf8")
    .digest("hex");
  const secretName = `${prefix}/${tenantId}-${subscriptionDigest.slice(0, 24)}`;

  if (Buffer.byteLength(secretName, "utf8") > MAX_SECRET_NAME_BYTES) {
    throw new SafeProvisioningError("PROVIDER_INVALID_REQUEST");
  }
  return { tenantId, subscriptionDigest, secretName };
}

function parseStoredPassword(
  secretString: string | undefined,
  identity: PasswordIdentity,
): string {
  if (typeof secretString !== "string") {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }

  let value: unknown;
  try {
    value = JSON.parse(secretString);
  } catch {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }

  if (
    typeof value !== "object" ||
    value === null ||
    (value as Partial<StoredDatabasePassword>).version !== 1 ||
    (value as Partial<StoredDatabasePassword>).tenantId !== identity.tenantId ||
    (value as Partial<StoredDatabasePassword>).subscriptionDigest !==
      identity.subscriptionDigest ||
    typeof (value as Partial<StoredDatabasePassword>).password !== "string" ||
    !PASSWORD_PATTERN.test((value as StoredDatabasePassword).password)
  ) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }

  return (value as StoredDatabasePassword).password;
}

function generateDatabasePassword(): string {
  // 288 random bits become exactly 48 URL-safe ASCII characters without padding.
  return randomBytes(36).toString("base64url");
}

function passwordTags(identity: PasswordIdentity): Tag[] {
  return [
    { Key: "e-sig:purpose", Value: "dedicated-database-password" },
    { Key: "e-sig:tenant-id", Value: identity.tenantId },
    {
      Key: "e-sig:subscription-digest",
      Value: identity.subscriptionDigest,
    },
  ];
}

function validateSecretNamePrefix(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.startsWith("/") ||
    value.endsWith("/") ||
    value.includes("//") ||
    Buffer.byteLength(value, "utf8") > 255 ||
    !SECRET_NAME_PATTERN.test(value)
  ) {
    throw new Error("Secrets Manager database-password prefix is invalid");
  }
  return value;
}

function validateKmsKeyId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) {
    throw new Error("Secrets Manager database-password KMS key ID is invalid");
  }
  return value;
}

function awsErrorName(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const name = (error as { readonly name?: unknown }).name;
  return typeof name === "string" ? name : undefined;
}

function safeDatabasePasswordError(
  error: unknown,
  forceRetryable = false,
): SafeProvisioningError {
  return new SafeProvisioningError(
    "PROVIDER_RESOURCE_FAILED",
    forceRetryable || isRetryableAwsError(error),
  );
}

function isRetryableAwsError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return true;
  const candidate = error as {
    readonly name?: unknown;
    readonly $metadata?: { readonly httpStatusCode?: unknown };
  };
  const statusCode = candidate.$metadata?.httpStatusCode;
  if (typeof statusCode === "number") {
    if (statusCode === 408 || statusCode === 425 || statusCode === 429) return true;
    if (statusCode >= 500) return true;
    if (statusCode >= 400) return false;
  }

  return ![
    "AccessDeniedException",
    "DecryptionFailure",
    "InvalidParameterException",
    "InvalidRequestException",
  ].includes(typeof candidate.name === "string" ? candidate.name : "");
}
