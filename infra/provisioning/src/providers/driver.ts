import {
  SafeProvisioningError,
  deterministicTenantId,
  type DeploymentMode,
  type ProvisioningDriver,
  type ProvisioningIdentity,
  type ResourceDisposition,
  type ResourceRecord,
  type StepCompensationInput,
  type StepCompensationResult,
  type StepExecutionInput,
  type StepExecutionResult,
} from "../domain.js";
import { deriveProviderIdentifiers } from "./deterministic.js";
import type {
  ProviderResources,
  ProvisioningProvider,
  ProvisioningRequest,
} from "./types.js";

export const PROVIDER_STATE_RESOURCE_KIND = "provider_state_v1";

const MAX_OPAQUE_ID_LENGTH = 512;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REGION_PATTERN = /^[a-z]{2}(?:-[a-z]+)+-\d$/;

type ProviderStatus = ProviderResources["status"];

interface SharedSnapshot {
  readonly v: 1;
  readonly g: number;
  readonly m: "s";
  readonly c: string;
  readonly s: ProviderStatus;
}

interface DedicatedSnapshot {
  readonly v: 1;
  readonly g: number;
  readonly m: "d";
  readonly p: string;
  readonly k: string;
  readonly s: ProviderStatus;
}

type ProviderSnapshot = SharedSnapshot | DedicatedSnapshot;

interface ReconstructedResources<TResources extends ProviderResources> {
  readonly resources: TResources;
  readonly generation: number;
}

export interface ProviderProvisioningDriverOptions<
  TResources extends ProviderResources,
> {
  readonly provider: ProvisioningProvider<TResources>;
  /** Deployment region supplied by runtime composition; billing events omit it. */
  readonly region: string;
}

/**
 * Adapts the atomic provider boundary to the durable step orchestrator.
 * Provider snapshots contain identifiers only; credential plaintext is returned
 * solely through StepExecutionResult.oneTimeCredential.
 */
export class ProviderProvisioningDriver<
  TResources extends ProviderResources,
> implements ProvisioningDriver
{
  readonly mode: DeploymentMode;
  readonly requiresCredentialHandoff = true;

  readonly #provider: ProvisioningProvider<TResources>;
  readonly #region: string;

  constructor(options: ProviderProvisioningDriverOptions<TResources>) {
    if (!REGION_PATTERN.test(options.region)) {
      throw new SafeProvisioningError("PROVIDER_INVALID_REQUEST");
    }
    this.#provider = options.provider;
    this.#region = options.region;
    this.mode = options.provider.mode;
  }

  async executeStep(input: StepExecutionInput): Promise<StepExecutionResult> {
    this.#validateInputIdentity(input.order, input.job.tenantId);

    if (input.step === "api_credential") {
      return this.#provisionOrReissue(input);
    }
    if (input.step === "mark_ready") {
      return this.#markReady(input);
    }
    return {};
  }

  async compensateStep(
    input: StepCompensationInput,
  ): Promise<StepCompensationResult> {
    this.#validateInputIdentity(input.order, input.job.tenantId);
    const request = this.#request(input.order);
    const prior = this.#reconstruct(input.resources, request);
    const targetStatus =
      input.order.billingState === "past_due" ? "suspended" : "disabled";
    let lifecycleSnapshot: ReturnType<typeof snapshotResource> | undefined;
    const inactiveLifecycleReceipt = input.resources.some(
      (resource) =>
        resource.kind === PROVIDER_STATE_RESOURCE_KIND &&
        resource.retention === "mutable" &&
        resource.status !== "active",
    );

    if (
      prior?.resources.status !== targetStatus &&
      !(inactiveLifecycleReceipt && prior?.resources.status !== "suspended")
    ) {
      if (prior === undefined) {
        const result =
          targetStatus === "suspended"
            ? await this.#provider.suspendUnknown(request)
            : await this.#provider.compensateUnknown(request);
        if (
          result.mode !== this.mode ||
          result.tenantId !== input.job.tenantId ||
          (result.outcome !== "absent" && result.outcome !== targetStatus)
        ) {
          throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
        }
      } else {
        const transitioned =
          targetStatus === "suspended"
            ? await this.#provider.suspend(request, prior.resources)
            : await this.#provider.compensate(request, prior.resources);
        this.#validateProviderResources(transitioned, request, input.job.tenantId);
        if (
          transitioned.status !== targetStatus ||
          !sameProviderIdentity(prior.resources, transitioned)
        ) {
          throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
        }
        lifecycleSnapshot = snapshotResource(
          transitioned,
          nextGeneration(prior, transitioned),
        );
      }
    }

    return {
      ...(lifecycleSnapshot === undefined
        ? {}
        : { resources: [lifecycleSnapshot] }),
      dispositions: input.stepResources
        .filter((resource) => resource.retention === "mutable")
        .map((resource) => ({
          resourceKey: resource.resourceKey,
          status: compensationStatus(input.step),
        })),
    };
  }

  async #provisionOrReissue(
    input: StepExecutionInput,
  ): Promise<StepExecutionResult> {
    const request = this.#request(input.order);
    const prior = this.#reconstruct(input.resources, request);

    if ((input.job.activationGeneration ?? 0) > 0 && prior !== undefined) {
      if (input.credentialHandoffCompleted) {
        // The orchestrator persists the resumed provider snapshot before it
        // publishes the immutable credential. A verified publication on retry
        // therefore makes that snapshot authoritative: invoking resume again
        // would rotate the provider credential away from the published value.
        if (prior.resources.status !== "provisioning") {
          throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
        }
        return {
          resources: [snapshotResource(prior.resources, prior.generation)],
        };
      }
      const result = await this.#provider.resume(request, prior.resources);
      this.#validateProviderResources(result.resources, request, input.job.tenantId);
      if (
        result.resources.status !== "provisioning" ||
        !sameProviderIdentity(
          prior.resources,
          result.resources,
          this.mode === "shared",
        ) ||
        result.oneTimeCredential === undefined
      ) {
        throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
      }
      validateOneTimeCredential(result.oneTimeCredential, result.resources);
      return {
        resources: [
          snapshotResource(
            result.resources,
            nextGeneration(prior, result.resources),
          ),
        ],
        oneTimeCredential: result.oneTimeCredential,
      };
    }

    if (prior !== undefined && !input.credentialHandoffCompleted) {
      const result = await this.#provider.reissueCredential(
        request,
        prior.resources,
      );
      this.#validateProviderResources(
        result.resources,
        request,
        input.job.tenantId,
      );
      if (
        !sameProviderIdentity(
          prior.resources,
          result.resources,
          this.mode === "shared",
        ) ||
        (this.mode === "shared" &&
          prior.resources.mode === "shared" &&
          result.resources.mode === "shared" &&
          prior.resources.credentialId === result.resources.credentialId)
      ) {
        throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
      }
      validateOneTimeCredential(result.oneTimeCredential, result.resources);
      return {
        resources: [
          snapshotResource(
            result.resources,
            nextGeneration(prior, result.resources),
          ),
        ],
        oneTimeCredential: result.oneTimeCredential,
      };
    }

    const result = await this.#provider.provision(request, prior?.resources);
    this.#validateProviderResources(
      result.resources,
      request,
      input.job.tenantId,
    );
    if (
      prior !== undefined &&
      !sameProviderIdentity(prior.resources, result.resources)
    ) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    if (result.resources.status === "disabled") {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    if (result.oneTimeCredential !== undefined) {
      validateOneTimeCredential(result.oneTimeCredential, result.resources);
      if (input.credentialHandoffCompleted) {
        throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
      }
    }

    const generation = nextGeneration(prior, result.resources);
    return {
      resources: [snapshotResource(result.resources, generation)],
      ...(result.oneTimeCredential === undefined
        ? {}
        : { oneTimeCredential: result.oneTimeCredential }),
    };
  }

  async #markReady(input: StepExecutionInput): Promise<StepExecutionResult> {
    const request = this.#request(input.order);
    const prior = this.#reconstruct(input.resources, request);
    if (prior === undefined) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }

    const ready = await this.#provider.markReady(request, prior.resources);
    this.#validateProviderResources(ready, request, input.job.tenantId);
    if (
      ready.status !== "ready" ||
      !sameProviderIdentity(prior.resources, ready)
    ) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    return {
      resources: [snapshotResource(ready, nextGeneration(prior, ready))],
    };
  }

  #request(order: ProvisioningIdentity): ProvisioningRequest {
    return {
      subscriptionId: order.subscriptionId,
      customerId: order.customerId,
      ownerSubject: order.ownerSubject,
      planCode: order.plan,
      region: this.#region,
    };
  }

  #validateInputIdentity(
    order: ProvisioningIdentity,
    jobTenantId: string,
  ): void {
    if (order.mode !== this.mode) {
      throw new SafeProvisioningError("MODE_MISMATCH");
    }
    if (jobTenantId !== deterministicTenantId(order.subscriptionId, this.mode)) {
      throw new SafeProvisioningError("PROVIDER_CONFLICT");
    }
  }

  #validateProviderResources(
    resources: TResources,
    request: ProvisioningRequest,
    jobTenantId: string,
  ): void {
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, this.mode);
    const commonIsValid =
      resources.mode === this.mode &&
      resources.subscriptionId === request.subscriptionId &&
      resources.tenantId === jobTenantId &&
      resources.tenantId === identifiers.tenantId &&
      (resources.status === "provisioning" ||
        resources.status === "ready" ||
        resources.status === "suspended" ||
        resources.status === "disabled");

    if (!commonIsValid) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
    if (resources.mode === "shared") {
      if (
        resources.storageNamespace !== identifiers.storageNamespace ||
        !nonEmpty(resources.credentialId)
      ) {
        throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
      }
      return;
    }
    if (
      resources.projectName !== identifiers.projectName ||
      resources.stackName !== identifiers.stackName ||
      !nonEmpty(resources.projectRef) ||
      !nonEmpty(resources.stackId)
    ) {
      throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
    }
  }

  #reconstruct(
    records: readonly ResourceRecord[],
    request: ProvisioningRequest,
  ): ReconstructedResources<TResources> | undefined {
    const snapshots = records
      .filter((record) => record.kind === PROVIDER_STATE_RESOURCE_KIND)
      .map((record) => decodeSnapshot(record.opaqueId));
    if (snapshots.length === 0) return undefined;

    const generation = Math.max(...snapshots.map((snapshot) => snapshot.g));
    const latest = snapshots.filter((snapshot) => snapshot.g === generation);
    const canonical = JSON.stringify(latest[0]);
    if (
      latest.length === 0 ||
      latest.some((snapshot) => JSON.stringify(snapshot) !== canonical)
    ) {
      throw new SafeProvisioningError("PROVIDER_CONFLICT");
    }

    const snapshot = latest[0]!;
    if (
      (this.mode === "shared" && snapshot.m !== "s") ||
      (this.mode === "dedicated" && snapshot.m !== "d")
    ) {
      throw new SafeProvisioningError("PROVIDER_CONFLICT");
    }

    const identifiers = deriveProviderIdentifiers(request.subscriptionId, this.mode);
    const resources: ProviderResources =
      snapshot.m === "s"
        ? {
            mode: "shared",
            subscriptionId: request.subscriptionId,
            tenantId: identifiers.tenantId,
            storageNamespace: identifiers.storageNamespace,
            credentialId: snapshot.c,
            status: snapshot.s,
          }
        : {
            mode: "dedicated",
            subscriptionId: request.subscriptionId,
            tenantId: identifiers.tenantId,
            projectRef: snapshot.p,
            projectName: identifiers.projectName,
            stackId: snapshot.k,
            stackName: identifiers.stackName,
            status: snapshot.s,
          };
    this.#validateProviderResources(
      resources as TResources,
      request,
      identifiers.tenantId,
    );
    return { resources: resources as TResources, generation };
  }
}

export function createProviderProvisioningDriver<
  TResources extends ProviderResources,
>(
  options: ProviderProvisioningDriverOptions<TResources>,
): ProviderProvisioningDriver<TResources> {
  return new ProviderProvisioningDriver(options);
}

function nextGeneration<TResources extends ProviderResources>(
  prior: ReconstructedResources<TResources> | undefined,
  resources: TResources,
): number {
  if (prior === undefined) return 0;
  return sameProviderResources(prior.resources, resources)
    ? prior.generation
    : prior.generation + 1;
}

function snapshotResource(
  resources: ProviderResources,
  generation: number,
): {
  readonly kind: string;
  readonly opaqueId: string;
  readonly retention: "mutable";
} {
  if (!validGeneration(generation)) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
  const snapshot: ProviderSnapshot =
    resources.mode === "shared"
      ? {
          v: 1,
          g: generation,
          m: "s",
          c: resources.credentialId,
          s: resources.status,
        }
      : {
          v: 1,
          g: generation,
          m: "d",
          p: resources.projectRef,
          k: resources.stackId,
          s: resources.status,
        };
  const opaqueId = Buffer.from(JSON.stringify(snapshot), "utf8").toString(
    "base64url",
  );
  if (opaqueId.length === 0 || opaqueId.length > MAX_OPAQUE_ID_LENGTH) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
  return {
    kind: PROVIDER_STATE_RESOURCE_KIND,
    opaqueId,
    retention: "mutable",
  };
}

function decodeSnapshot(opaqueId: string): ProviderSnapshot {
  if (
    opaqueId.length === 0 ||
    opaqueId.length > MAX_OPAQUE_ID_LENGTH ||
    !BASE64URL_PATTERN.test(opaqueId)
  ) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }

  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(opaqueId, "base64url").toString("utf8"));
  } catch {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
  if (!isRecord(value) || value.v !== 1 || !validGeneration(value.g)) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
  if (
    value.s !== "provisioning" &&
    value.s !== "ready" &&
    value.s !== "suspended" &&
    value.s !== "disabled"
  ) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
  if (value.m === "s" && nonEmpty(value.c)) {
    return value as unknown as SharedSnapshot;
  }
  if (value.m === "d" && nonEmpty(value.p) && nonEmpty(value.k)) {
    return value as unknown as DedicatedSnapshot;
  }
  throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
}

function validateOneTimeCredential(value: {
  readonly id: string;
  readonly plaintext: string;
}, resources: ProviderResources): void {
  if (
    !nonEmpty(value.id) ||
    !nonEmpty(value.plaintext) ||
    (resources.mode === "shared" && value.id !== resources.credentialId)
  ) {
    throw new SafeProvisioningError("PROVIDER_RESPONSE_INVALID");
  }
}

function compensationStatus(
  step: StepCompensationInput["step"],
): ResourceDisposition["status"] {
  if (step === "api_credential") return "revoked";
  if (
    step === "plan_entitlement" ||
    step === "activation_metadata" ||
    step === "mark_ready"
  ) {
    return "disabled";
  }
  return "quarantined";
}

function sameProviderResources(
  left: ProviderResources,
  right: ProviderResources,
): boolean {
  if (!sameProviderIdentity(left, right) || left.status !== right.status) {
    return false;
  }
  return true;
}

function sameProviderIdentity(
  left: ProviderResources,
  right: ProviderResources,
  allowSharedCredentialRotation = false,
): boolean {
  if (
    left.mode !== right.mode ||
    left.subscriptionId !== right.subscriptionId ||
    left.tenantId !== right.tenantId
  ) {
    return false;
  }
  if (left.mode === "shared" && right.mode === "shared") {
    return (
      left.storageNamespace === right.storageNamespace &&
      (allowSharedCredentialRotation || left.credentialId === right.credentialId)
    );
  }
  if (left.mode === "dedicated" && right.mode === "dedicated") {
    return (
      left.projectRef === right.projectRef &&
      left.projectName === right.projectName &&
      left.stackId === right.stackId &&
      left.stackName === right.stackName
    );
  }
  return false;
}

function validGeneration(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
