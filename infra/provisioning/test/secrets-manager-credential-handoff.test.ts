import { createHash } from "node:crypto";

import {
  CreateSecretCommand,
  DescribeSecretCommand,
} from "@aws-sdk/client-secrets-manager";
import { describe, expect, it, vi } from "vitest";

import { SecretsManagerOneTimeCredentialHandoff } from "../src/aws/secrets-manager-credential-handoff.js";
import type {
  CredentialHandoffPointer,
  OneTimeCredentialHandoffInput,
} from "../src/domain.js";

const TEST_PLAINTEXT = "esig_private_preview_secret_DO_NOT_EXPOSE";
const PREFIX = "e-sig/private-preview/credential-handoffs";

function handoffInput(
  overrides: Partial<OneTimeCredentialHandoffInput> = {},
): OneTimeCredentialHandoffInput {
  return {
    handoffId: "handoff_01J0TEST",
    jobId: "job_01J0TEST",
    subscriptionId: "sub_01J0TEST",
    activationGeneration: 2,
    publicationGeneration: 3,
    fencingToken: 7,
    credential: {
      id: "credential_01J0TEST",
      plaintext: TEST_PLAINTEXT,
    },
    ...overrides,
  };
}

function pointerFor(
  handoff: SecretsManagerOneTimeCredentialHandoff,
  input = handoffInput(),
): CredentialHandoffPointer {
  return {
    handoffId: input.handoffId,
    jobId: input.jobId,
    subscriptionId: input.subscriptionId,
    activationGeneration: input.activationGeneration,
    publicationGeneration: input.publicationGeneration,
    fencingToken: input.fencingToken,
    state: "published",
    ...handoff.describePublication(input),
  };
}

function metadata(pointer: CredentialHandoffPointer) {
  if (
    pointer.secretId === undefined ||
    pointer.publicationId === undefined ||
    pointer.credentialId === undefined
  ) {
    throw new Error("test pointer must describe a published credential");
  }
  return {
    Name: pointer.secretId,
    VersionIdsToStages: {
      [pointer.publicationId]: ["AWSCURRENT"],
    },
    Tags: [
      { Key: "e-sig:handoff-id", Value: pointer.handoffId },
      { Key: "e-sig:job-id", Value: pointer.jobId },
      { Key: "e-sig:subscription-id", Value: pointer.subscriptionId },
      {
        Key: "e-sig:activation-generation",
        Value: String(pointer.activationGeneration),
      },
      {
        Key: "e-sig:publication-generation",
        Value: String(pointer.publicationGeneration),
      },
      { Key: "e-sig:fencing-token", Value: String(pointer.fencingToken) },
      { Key: "e-sig:credential-id", Value: pointer.credentialId },
      { Key: "e-sig:publication-id", Value: pointer.publicationId },
    ],
  };
}

function awsError(name: string, status = 400): Error {
  return Object.assign(new Error("safe fake failure"), {
    name,
    $metadata: { httpStatusCode: status },
  });
}

describe("SecretsManagerOneTimeCredentialHandoff", () => {
  it("creates one immutable fenced secret with complete identity tags", async () => {
    const send = vi.fn().mockResolvedValue({ ARN: "arn:created" });
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
      { kmsKeyId: "alias/e-sig-private-preview" },
    );
    const input = handoffInput();
    const publication = await handoff.createImmutable(input);

    expect(send).toHaveBeenCalledTimes(1);
    const command = send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(CreateSecretCommand);
    expect(command.input).toMatchObject({
      Name: publication.secretId,
      ClientRequestToken: publication.publicationId,
      SecretString: TEST_PLAINTEXT,
      KmsKeyId: "alias/e-sig-private-preview",
      Tags: metadata({ ...pointerFor(handoff, input), ...publication }).Tags,
    });
    expect(command.input.ClientRequestToken).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(command.input.Tags).not.toContainEqual(
      expect.objectContaining({ Key: "e-sig:credential-digest" }),
    );
    expect(command.input.Name).toContain("-p3-f7-");
    expect(JSON.stringify(publication)).not.toContain(TEST_PLAINTEXT);
  });

  it("keeps publication identity and Describe-visible metadata independent of plaintext", async () => {
    const send = vi.fn().mockResolvedValue({ ARN: "arn:created" });
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
    );
    const firstInput = handoffInput();
    const secondPlaintext = "different-secret-with-the-same-credential-identity";
    const secondInput = handoffInput({
      credential: {
        id: firstInput.credential.id,
        plaintext: secondPlaintext,
      },
    });

    const firstPublication = await handoff.createImmutable(firstInput);
    const secondPublication = await handoff.createImmutable(secondInput);
    expect(secondPublication).toEqual(firstPublication);

    const describeVisible = send.mock.calls.map(([command]) => ({
      Name: command.input.Name,
      ClientRequestToken: command.input.ClientRequestToken,
      Description: command.input.Description,
      KmsKeyId: command.input.KmsKeyId,
      Tags: command.input.Tags,
    }));
    expect(describeVisible[1]).toEqual(describeVisible[0]);

    const exposed = JSON.stringify({
      publication: firstPublication,
      createMetadata: describeVisible[0],
    });
    expect(exposed).not.toContain(TEST_PLAINTEXT);
    expect(exposed).not.toContain(secondPlaintext);
    expect(exposed).not.toContain(
      createHash("sha256").update(TEST_PLAINTEXT, "utf8").digest("hex"),
    );
    expect(exposed).not.toContain(
      createHash("sha256").update(secondPlaintext, "utf8").digest("hex"),
    );
  });

  it("recovers commit-unknown CreateSecret only after exact Describe verification", async () => {
    const send = vi.fn();
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
    );
    const pointer = pointerFor(handoff);
    send
      .mockRejectedValueOnce(awsError("ResourceExistsException"))
      .mockResolvedValueOnce(metadata(pointer));

    await expect(handoff.createImmutable(handoffInput())).resolves.toEqual(
      handoff.describePublication(handoffInput()),
    );
    expect(send.mock.calls[0]![0]).toBeInstanceOf(CreateSecretCommand);
    expect(send.mock.calls[1]![0]).toBeInstanceOf(DescribeSecretCommand);
  });

  it("rejects a colliding immutable secret with mismatched fence identity", async () => {
    const send = vi.fn();
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
    );
    const pointer = pointerFor(handoff);
    const mismatched = metadata({ ...pointer, fencingToken: 6 });
    send
      .mockRejectedValueOnce(awsError("ResourceExistsException"))
      .mockResolvedValueOnce(mismatched);

    await expect(handoff.createImmutable(handoffInput())).rejects.toMatchObject({
      safeCode: "CREDENTIAL_HANDOFF_REQUIRED",
    });
  });

  it("rejects commit-unknown recovery when the deterministic version is absent", async () => {
    const send = vi.fn();
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
    );
    const pointer = pointerFor(handoff);
    send
      .mockRejectedValueOnce(awsError("ResourceExistsException"))
      .mockResolvedValueOnce({
        ...metadata(pointer),
        VersionIdsToStages: { unrelated: ["AWSCURRENT"] },
      });

    await expect(handoff.createImmutable(handoffInput())).rejects.toMatchObject({
      safeCode: "CREDENTIAL_HANDOFF_REQUIRED",
    });
  });

  it("verifies published metadata without reading the secret value", async () => {
    const send = vi.fn();
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
    );
    const pointer = pointerFor(handoff);
    send
      .mockResolvedValueOnce(metadata(pointer))
      .mockRejectedValueOnce(awsError("ResourceNotFoundException", 404));

    await expect(handoff.verifyPublication(pointer)).resolves.toBe(true);
    await expect(handoff.verifyPublication(pointer)).resolves.toBe(false);
    expect(send.mock.calls.every(([command]) => command instanceof DescribeSecretCommand)).toBe(true);
  });

  it("does not verify identity tags without the expected immutable version", async () => {
    const send = vi.fn();
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send } as never,
      PREFIX,
    );
    const pointer = pointerFor(handoff);
    send.mockResolvedValueOnce({
      ...metadata(pointer),
      VersionIdsToStages: { unrelated: ["AWSCURRENT"] },
    });

    await expect(handoff.verifyPublication(pointer)).resolves.toBe(false);
    expect(send.mock.calls[0]![0]).toBeInstanceOf(DescribeSecretCommand);
  });

  it("uses distinct immutable names for a higher fence or publication generation", () => {
    const handoff = new SecretsManagerOneTimeCredentialHandoff(
      { send: vi.fn() } as never,
      PREFIX,
    );
    const original = handoff.describePublication(handoffInput());
    const higherFence = handoff.describePublication(
      handoffInput({ fencingToken: 8 }),
    );
    const nextGeneration = handoff.describePublication(
      handoffInput({ publicationGeneration: 4 }),
    );

    expect(new Set([original.secretId, higherFence.secretId, nextGeneration.secretId])).toHaveLength(3);
    expect(new Set([original.publicationId, higherFence.publicationId, nextGeneration.publicationId])).toHaveLength(3);
  });
});
