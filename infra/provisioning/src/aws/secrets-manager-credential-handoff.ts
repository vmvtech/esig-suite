import { createHash } from "node:crypto";

import {
  CreateSecretCommand,
  DescribeSecretCommand,
  type DescribeSecretCommandOutput,
  type SecretsManagerClient,
  type Tag,
} from "@aws-sdk/client-secrets-manager";

import {
  SafeProvisioningError,
  type CredentialHandoffPointer,
  type CredentialSecretPublication,
  type OneTimeCredentialHandoff,
  type OneTimeCredentialHandoffInput,
} from "../domain.js";

type SecretsManagerSender = Pick<SecretsManagerClient, "send">;

export interface SecretsManagerCredentialHandoffOptions {
  readonly kmsKeyId?: string;
}

const SECRET_NAME_PATTERN = /^[A-Za-z0-9_+=.@/-]+$/;
const OPAQUE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const MAX_SECRET_NAME_BYTES = 512;
const MAX_SECRET_VALUE_BYTES = 65_536;

const TAGS = {
  handoff: "e-sig:handoff-id",
  job: "e-sig:job-id",
  subscription: "e-sig:subscription-id",
  activation: "e-sig:activation-generation",
  publication: "e-sig:publication-generation",
  fence: "e-sig:fencing-token",
  credential: "e-sig:credential-id",
  publicationId: "e-sig:publication-id",
} as const;

/** Creates one immutable secret per fenced credential publication. */
export class SecretsManagerOneTimeCredentialHandoff
  implements OneTimeCredentialHandoff
{
  readonly #client: SecretsManagerSender;
  readonly #secretNamePrefix: string;
  readonly #kmsKeyId: string | undefined;

  constructor(
    client: SecretsManagerSender,
    secretNamePrefix: string,
    options: SecretsManagerCredentialHandoffOptions = {},
  ) {
    this.#client = client;
    this.#secretNamePrefix = validateSecretNamePrefix(secretNamePrefix);
    this.#kmsKeyId = validateKmsKeyId(options.kmsKeyId);
  }

  describePublication(
    input: OneTimeCredentialHandoffInput,
  ): CredentialSecretPublication {
    assertValidHandoffInput(input);
    const publicationId = deterministicPublicationVersionId(input);
    const publicationSuffix = publicationId.replaceAll("-", "").slice(0, 24);
    const secretId = `${this.#secretNamePrefix}/${input.handoffId}/a${input.activationGeneration}-p${input.publicationGeneration}-f${input.fencingToken}-${publicationSuffix}`;
    if (Buffer.byteLength(secretId, "utf8") > MAX_SECRET_NAME_BYTES) {
      throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
    }
    return {
      secretId,
      publicationId,
      credentialId: input.credential.id,
    };
  }

  async createImmutable(
    input: OneTimeCredentialHandoffInput,
  ): Promise<CredentialSecretPublication> {
    const publication = this.describePublication(input);
    const tags = publicationTags(input, publication);
    try {
      await this.#client.send(
        new CreateSecretCommand({
          Name: publication.secretId,
          ClientRequestToken: publication.publicationId,
          Description: "Immutable one-time e-sig Cloud credential handoff.",
          KmsKeyId: this.#kmsKeyId,
          SecretString: input.credential.plaintext,
          Tags: [...tags],
        }),
      );
      return publication;
    } catch (error: unknown) {
      if (awsErrorName(error) !== "ResourceExistsException") {
        throw safeHandoffError(error);
      }
    }

    const metadata = await this.#describe(publication.secretId);
    if (
      metadata === undefined ||
      !matchesPublicationMetadata(metadata, publication, tags)
    ) {
      throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
    }
    return publication;
  }

  async verifyPublication(pointer: CredentialHandoffPointer): Promise<boolean> {
    if (!pointerHasPublication(pointer)) return false;
    try {
      const metadata = await this.#describe(pointer.secretId);
      if (metadata === undefined) return false;
      return matchesPublicationMetadata(metadata, pointer, pointerTags(pointer));
    } catch (error: unknown) {
      if (error instanceof SafeProvisioningError) throw error;
      throw safeHandoffError(error);
    }
  }

  async #describe(
    secretId: string,
  ): Promise<DescribeSecretCommandOutput | undefined> {
    try {
      return (await this.#client.send(
        new DescribeSecretCommand({ SecretId: secretId }),
      )) as DescribeSecretCommandOutput;
    } catch (error: unknown) {
      if (awsErrorName(error) === "ResourceNotFoundException") return undefined;
      throw error;
    }
  }
}

function publicationTags(
  input: OneTimeCredentialHandoffInput,
  publication: CredentialSecretPublication,
): readonly Tag[] {
  return [
    { Key: TAGS.handoff, Value: input.handoffId },
    { Key: TAGS.job, Value: input.jobId },
    { Key: TAGS.subscription, Value: input.subscriptionId },
    { Key: TAGS.activation, Value: String(input.activationGeneration) },
    { Key: TAGS.publication, Value: String(input.publicationGeneration) },
    { Key: TAGS.fence, Value: String(input.fencingToken) },
    { Key: TAGS.credential, Value: publication.credentialId },
    { Key: TAGS.publicationId, Value: publication.publicationId },
  ];
}

function pointerTags(pointer: CredentialHandoffPointer): readonly Tag[] {
  if (!pointerHasPublication(pointer)) return [];
  return [
    { Key: TAGS.handoff, Value: pointer.handoffId },
    { Key: TAGS.job, Value: pointer.jobId },
    { Key: TAGS.subscription, Value: pointer.subscriptionId },
    { Key: TAGS.activation, Value: String(pointer.activationGeneration) },
    { Key: TAGS.publication, Value: String(pointer.publicationGeneration) },
    { Key: TAGS.fence, Value: String(pointer.fencingToken) },
    { Key: TAGS.credential, Value: pointer.credentialId },
    { Key: TAGS.publicationId, Value: pointer.publicationId },
  ];
}

function matchesPublicationMetadata(
  metadata: DescribeSecretCommandOutput,
  publication: CredentialSecretPublication,
  expectedTags: readonly Tag[],
): boolean {
  return (
    metadata.DeletedDate === undefined &&
    metadata.Name === publication.secretId &&
    metadata.VersionIdsToStages?.[publication.publicationId]?.includes(
      "AWSCURRENT",
    ) === true &&
    matchesTags(metadata, expectedTags)
  );
}

function matchesTags(
  metadata: DescribeSecretCommandOutput,
  expected: readonly Tag[],
): boolean {
  const actual = new Map(
    (metadata.Tags ?? []).map((tag) => [tag.Key, tag.Value] as const),
  );
  return expected.every((tag) => actual.get(tag.Key) === tag.Value);
}

function pointerHasPublication(
  pointer: CredentialHandoffPointer,
): pointer is CredentialHandoffPointer & Required<CredentialSecretPublication> {
  return (
    pointer.secretId !== undefined &&
    pointer.publicationId !== undefined &&
    pointer.credentialId !== undefined
  );
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
    throw new Error("Secrets Manager credential secret-name prefix is invalid");
  }
  return value;
}

function validateKmsKeyId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) {
    throw new Error("Secrets Manager credential KMS key ID is invalid");
  }
  return value;
}

function assertValidHandoffInput(input: OneTimeCredentialHandoffInput): void {
  assertOpaqueIdentifier(input.handoffId);
  assertOpaqueIdentifier(input.jobId);
  assertOpaqueIdentifier(input.subscriptionId);
  assertOpaqueIdentifier(input.credential.id);
  if (
    !validCounter(input.activationGeneration, true) ||
    !validCounter(input.publicationGeneration, true) ||
    !validCounter(input.fencingToken, false) ||
    typeof input.credential.plaintext !== "string" ||
    input.credential.plaintext.length === 0 ||
    Buffer.byteLength(input.credential.plaintext, "utf8") > MAX_SECRET_VALUE_BYTES
  ) {
    throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
  }
}

function validCounter(value: number, allowZero: boolean): boolean {
  return Number.isSafeInteger(value) && (allowZero ? value >= 0 : value > 0);
}

function assertOpaqueIdentifier(value: string): void {
  if (typeof value !== "string" || !OPAQUE_IDENTIFIER_PATTERN.test(value)) {
    throw new SafeProvisioningError("CREDENTIAL_HANDOFF_REQUIRED");
  }
}

function deterministicPublicationVersionId(
  input: OneTimeCredentialHandoffInput,
): string {
  const bytes = createHash("sha256")
    .update("e-sig:immutable-credential-publication:v2", "utf8")
    .update("\0", "utf8")
    .update(input.subscriptionId, "utf8")
    .update("\0", "utf8")
    .update(input.jobId, "utf8")
    .update("\0", "utf8")
    .update(input.handoffId, "utf8")
    .update("\0", "utf8")
    .update(String(input.activationGeneration), "utf8")
    .update("\0", "utf8")
    .update(String(input.publicationGeneration), "utf8")
    .update("\0", "utf8")
    .update(String(input.fencingToken), "utf8")
    .update("\0", "utf8")
    .update(input.credential.id, "utf8")
    .digest()
    .subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function awsErrorName(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const name = (error as { readonly name?: unknown }).name;
  return typeof name === "string" ? name : undefined;
}

function safeHandoffError(error: unknown): SafeProvisioningError {
  return new SafeProvisioningError(
    "CREDENTIAL_HANDOFF_REQUIRED",
    isRetryableAwsError(error),
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
    "InvalidParameterException",
    "InvalidRequestException",
    "DecryptionFailure",
  ].includes(typeof candidate.name === "string" ? candidate.name : "");
}
