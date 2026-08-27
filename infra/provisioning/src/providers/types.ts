export type ProvisioningMode = "shared" | "dedicated";
export type ProvisioningPlan = "starter" | "team" | "scale";

export interface ProvisioningRequest {
  readonly subscriptionId: string;
  readonly customerId: string;
  readonly ownerSubject: string;
  readonly planCode: ProvisioningPlan;
  readonly region: string;
}

export interface OneTimeCredential {
  readonly id: string;
  readonly plaintext: string;
}

interface BaseProviderResources {
  readonly mode: ProvisioningMode;
  readonly subscriptionId: string;
  readonly tenantId: string;
  readonly status: "provisioning" | "ready" | "suspended" | "disabled";
}

export interface SharedProviderResources extends BaseProviderResources {
  readonly mode: "shared";
  readonly storageNamespace: string;
  readonly credentialId: string;
}

export interface DedicatedProviderResources extends BaseProviderResources {
  readonly mode: "dedicated";
  readonly projectRef: string;
  readonly projectName: string;
  readonly stackId: string;
  readonly stackName: string;
}

export type ProviderResources =
  | SharedProviderResources
  | DedicatedProviderResources;

export interface ProvisioningResult<
  TResources extends ProviderResources = ProviderResources,
> {
  readonly resources: TResources;
  readonly created: boolean;
  /** Present only on the first successful credential creation. Never persist it. */
  readonly oneTimeCredential?: OneTimeCredential;
}

/**
 * A credential rotation result. The plaintext is intentionally outside the
 * persistable resource record and must be handed off exactly once.
 */
export interface CredentialReissueResult<
  TResources extends ProviderResources = ProviderResources,
> {
  readonly resources: TResources;
  readonly oneTimeCredential: OneTimeCredential;
}

/** Result of converging effects when the original resource record was lost. */
export interface UnknownCompensationResult {
  readonly mode: ProvisioningMode;
  readonly tenantId: string;
  readonly outcome: "absent" | "disabled";
}

export interface UnknownSuspensionResult {
  readonly mode: ProvisioningMode;
  readonly tenantId: string;
  readonly outcome: "absent" | "suspended";
}

/**
 * A deployment-mode boundary. Provisioning and compensation methods converge
 * when repeated with the same identity. Credential reissue intentionally
 * rotates on every successful call so a lost one-time secret can be replaced.
 */
export interface ProvisioningProvider<
  TResources extends ProviderResources = ProviderResources,
> {
  readonly mode: TResources["mode"];

  provision(
    request: ProvisioningRequest,
    prior?: TResources,
  ): Promise<ProvisioningResult<TResources>>;

  reissueCredential(
    request: ProvisioningRequest,
    resources: TResources,
  ): Promise<CredentialReissueResult<TResources>>;

  markReady(
    request: ProvisioningRequest,
    resources: TResources,
  ): Promise<TResources>;

  resume(
    request: ProvisioningRequest,
    resources: TResources,
  ): Promise<ProvisioningResult<TResources>>;

  suspend(
    request: ProvisioningRequest,
    resources: TResources,
  ): Promise<TResources>;

  disable(
    request: ProvisioningRequest,
    resources: TResources,
  ): Promise<TResources>;

  compensate(
    request: ProvisioningRequest,
    resources: TResources,
  ): Promise<TResources>;

  /**
   * Discover and disable deterministic resources after a commit-unknown
   * failure, without creating any missing resource.
   */
  compensateUnknown(
    request: ProvisioningRequest,
  ): Promise<UnknownCompensationResult>;

  suspendUnknown(request: ProvisioningRequest): Promise<UnknownSuspensionResult>;
}

export type FetchTransport = typeof globalThis.fetch;
