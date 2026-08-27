import {
  deriveProviderIdentifiers,
  normalizeOwnerEmail,
  validateProvisioningRequest,
} from "./deterministic.js";
import {
  errorForHttpStatus,
  ProviderError,
  providerError,
  type ProviderOperation,
} from "./errors.js";
import type {
  CredentialReissueResult,
  FetchTransport,
  ProvisioningPlan,
  ProvisioningProvider,
  ProvisioningRequest,
  ProvisioningResult,
  SharedProviderResources,
  UnknownCompensationResult,
  UnknownSuspensionResult,
} from "./types.js";

const DEFAULT_PROVISION_RPC = "provision_esig_tenant";
const DEFAULT_REISSUE_RPC = "reissue_esig_tenant_credential";
const DEFAULT_MARK_READY_RPC = "mark_esig_tenant_ready";
const DEFAULT_DISABLE_RPC = "disable_esig_tenant";
const DEFAULT_RESUME_RPC = "resume_esig_tenant";
const RPC_NAME_PATTERN = /^[a-z][a-z0-9_]*$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLAN_KEYS: Readonly<Record<ProvisioningPlan, string>> = {
  starter: "cloud_starter",
  team: "cloud_team",
  scale: "cloud_scale",
};

export interface SharedProvisioningProviderOptions {
  readonly supabaseUrl: string;
  readonly serviceRoleKey: string;
  readonly fetch?: FetchTransport;
  readonly provisionRpc?: string;
  readonly reissueRpc?: string;
  readonly markReadyRpc?: string;
  readonly disableRpc?: string;
  readonly resumeRpc?: string;
}

interface SharedProvisionResponse {
  readonly tenant_id: string;
  readonly organization_status: "provisioning" | "ready";
  readonly provisioning_state: "provisioning" | "ready";
  readonly storage_namespace: string;
  readonly credential_id: string;
  readonly credential_plaintext: string | null;
  readonly created: boolean;
}

interface SharedReissueResponse {
  readonly credential_id: string;
  readonly credential_plaintext: string;
}

interface SharedResumeResponse {
  readonly tenant_id: string;
  readonly organization_status: "provisioning";
  readonly provisioning_state: "provisioning";
  readonly storage_namespace: string;
  readonly credential_id: string;
  readonly credential_plaintext: string | null;
  readonly resumed: boolean;
}

type RpcBody = Readonly<Record<string, string | null>>;

export class SharedProvisioningProvider
  implements ProvisioningProvider<SharedProviderResources>
{
  readonly mode = "shared" as const;

  readonly #supabaseUrl: string;
  readonly #serviceRoleKey: string;
  readonly #fetch: FetchTransport;
  readonly #provisionRpc: string;
  readonly #reissueRpc: string;
  readonly #markReadyRpc: string;
  readonly #disableRpc: string;
  readonly #resumeRpc: string;

  constructor(options: SharedProvisioningProviderOptions) {
    this.#supabaseUrl = normalizeHttpsOrigin(options.supabaseUrl);
    this.#serviceRoleKey = requireSecret(options.serviceRoleKey);
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#provisionRpc = validateRpcName(
      options.provisionRpc ?? DEFAULT_PROVISION_RPC,
    );
    this.#reissueRpc = validateRpcName(
      options.reissueRpc ?? DEFAULT_REISSUE_RPC,
    );
    this.#markReadyRpc = validateRpcName(
      options.markReadyRpc ?? DEFAULT_MARK_READY_RPC,
    );
    this.#disableRpc = validateRpcName(
      options.disableRpc ?? DEFAULT_DISABLE_RPC,
    );
    this.#resumeRpc = validateRpcName(options.resumeRpc ?? DEFAULT_RESUME_RPC);
  }

  async provision(
    request: ProvisioningRequest,
    prior?: SharedProviderResources,
  ): Promise<ProvisioningResult<SharedProviderResources>> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "shared");
    validatePrior(prior, request, identifiers.tenantId);
    const metadata = deriveSharedTenantMetadata(identifiers.tenantId);

    const response = await this.#rpcJson(
      this.#provisionRpc,
      {
        p_tenant_id: identifiers.tenantId,
        p_subscription_id: request.subscriptionId,
        p_customer_id: request.customerId,
        p_owner_email: normalizeOwnerEmail(request.ownerSubject),
        p_display_name: metadata.displayName,
        p_slug: metadata.slug,
        p_plan_key: PLAN_KEYS[request.planCode],
        p_deployment_mode: "shared",
        p_dedicated_stack_id: null,
      },
      "shared.provision",
    );

    const payload = parseProvisionResponse(response);
    const status = responseStatus(payload);
    if (payload.created !== (payload.credential_plaintext !== null)) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "shared.provision",
      });
    }
    if (
      payload.tenant_id !== identifiers.tenantId ||
      payload.storage_namespace !== identifiers.storageNamespace
    ) {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "shared.provision",
      });
    }
    if (payload.created && (prior !== undefined || status !== "provisioning")) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "shared.provision",
      });
    }
    if (prior && payload.credential_id !== prior.credentialId) {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "shared.provision",
      });
    }

    const resources: SharedProviderResources = {
      mode: "shared",
      subscriptionId: request.subscriptionId,
      tenantId: payload.tenant_id,
      storageNamespace: payload.storage_namespace,
      credentialId: payload.credential_id,
      status,
    };

    if (!payload.created && prior === undefined) {
      const reissued = await this.reissueCredential(request, resources);
      return {
        resources: reissued.resources,
        created: false,
        oneTimeCredential: reissued.oneTimeCredential,
      };
    }

    if (payload.credential_plaintext === null) {
      return { resources, created: payload.created };
    }
    return {
      resources,
      created: payload.created,
      oneTimeCredential: {
        id: payload.credential_id,
        plaintext: payload.credential_plaintext,
      },
    };
  }

  async reissueCredential(
    request: ProvisioningRequest,
    resources: SharedProviderResources,
  ): Promise<CredentialReissueResult<SharedProviderResources>> {
    validateProvisioningRequest(request);
    validatePrior(
      resources,
      request,
      deriveProviderIdentifiers(request.subscriptionId, "shared").tenantId,
    );
    if (resources.status === "disabled" || resources.status === "suspended") {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "shared.credential.reissue",
      });
    }

    const reissued = parseReissueResponse(
      await this.#rpcJson(
        this.#reissueRpc,
        {
          p_tenant_id: resources.tenantId,
          p_subscription_id: request.subscriptionId,
        },
        "shared.credential.reissue",
      ),
    );
    if (reissued.credential_id === resources.credentialId) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "shared.credential.reissue",
      });
    }

    return {
      resources: { ...resources, credentialId: reissued.credential_id },
      oneTimeCredential: {
        id: reissued.credential_id,
        plaintext: reissued.credential_plaintext,
      },
    };
  }

  async markReady(
    request: ProvisioningRequest,
    resources: SharedProviderResources,
  ): Promise<SharedProviderResources> {
    validateProvisioningRequest(request);
    validatePrior(
      resources,
      request,
      deriveProviderIdentifiers(request.subscriptionId, "shared").tenantId,
    );
    if (resources.status === "disabled" || resources.status === "suspended") {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "validate",
      });
    }

    await this.#rpcVoid(
      this.#markReadyRpc,
      { p_tenant_id: resources.tenantId },
      "shared.mark_ready",
    );
    return { ...resources, status: "ready" };
  }

  async disable(
    request: ProvisioningRequest,
    resources: SharedProviderResources,
  ): Promise<SharedProviderResources> {
    validateProvisioningRequest(request);
    validatePrior(
      resources,
      request,
      deriveProviderIdentifiers(request.subscriptionId, "shared").tenantId,
    );

    await this.#rpcVoid(
      this.#disableRpc,
      {
        p_tenant_id: resources.tenantId,
        p_subscription_status: "canceled",
        p_safe_error_code: null,
      },
      "shared.disable",
    );
    return { ...resources, status: "disabled" };
  }

  async suspend(
    request: ProvisioningRequest,
    resources: SharedProviderResources,
  ): Promise<SharedProviderResources> {
    validateProvisioningRequest(request);
    validatePrior(
      resources,
      request,
      deriveProviderIdentifiers(request.subscriptionId, "shared").tenantId,
    );
    if (resources.status === "disabled") {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "shared.disable" });
    }
    await this.#rpcVoid(
      this.#disableRpc,
      {
        p_tenant_id: resources.tenantId,
        p_subscription_status: "past_due",
        p_safe_error_code: null,
      },
      "shared.disable",
    );
    return { ...resources, status: "suspended" };
  }

  async resume(
    request: ProvisioningRequest,
    resources: SharedProviderResources,
  ): Promise<ProvisioningResult<SharedProviderResources>> {
    validateProvisioningRequest(request);
    validatePrior(
      resources,
      request,
      deriveProviderIdentifiers(request.subscriptionId, "shared").tenantId,
    );
    if (resources.status === "disabled") {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "shared.provision" });
    }
    const resumed = parseResumeResponse(
      await this.#rpcJson(
        this.#resumeRpc,
        {
          p_tenant_id: resources.tenantId,
          p_subscription_id: request.subscriptionId,
        },
        "shared.provision",
      ),
    );
    if (
      resumed.tenant_id !== resources.tenantId ||
      resumed.storage_namespace !== resources.storageNamespace ||
      (resumed.resumed && resumed.credential_id === resources.credentialId)
    ) {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "shared.provision" });
    }
    const resumedResources = {
      ...resources,
      credentialId: resumed.credential_id,
      status: "provisioning" as const,
    };
    if (resumed.credential_plaintext === null) {
      const reissued = await this.reissueCredential(request, resumedResources);
      return {
        resources: reissued.resources,
        created: false,
        oneTimeCredential: reissued.oneTimeCredential,
      };
    }
    return {
      resources: resumedResources,
      created: false,
      oneTimeCredential: {
        id: resumed.credential_id,
        plaintext: resumed.credential_plaintext,
      },
    };
  }

  compensate(
    request: ProvisioningRequest,
    resources: SharedProviderResources,
  ): Promise<SharedProviderResources> {
    return this.disable(request, resources);
  }

  async compensateUnknown(
    request: ProvisioningRequest,
  ): Promise<UnknownCompensationResult> {
    validateProvisioningRequest(request);
    const tenantId = deriveProviderIdentifiers(
      request.subscriptionId,
      "shared",
    ).tenantId;

    try {
      await this.#rpcVoid(
        this.#disableRpc,
        {
          p_tenant_id: tenantId,
          p_subscription_status: "canceled",
          p_safe_error_code: null,
        },
        "shared.disable",
      );
    } catch (error) {
      if (error instanceof ProviderError && error.code === "PROVIDER_NOT_FOUND") {
        return { mode: "shared", tenantId, outcome: "absent" };
      }
      throw error;
    }

    return { mode: "shared", tenantId, outcome: "disabled" };
  }

  async suspendUnknown(
    request: ProvisioningRequest,
  ): Promise<UnknownSuspensionResult> {
    validateProvisioningRequest(request);
    const tenantId = deriveProviderIdentifiers(request.subscriptionId, "shared").tenantId;
    try {
      await this.#rpcVoid(
        this.#disableRpc,
        {
          p_tenant_id: tenantId,
          p_subscription_status: "past_due",
          p_safe_error_code: null,
        },
        "shared.disable",
      );
    } catch (error) {
      if (error instanceof ProviderError && error.code === "PROVIDER_NOT_FOUND") {
        return { mode: "shared", tenantId, outcome: "absent" };
      }
      throw error;
    }
    return { mode: "shared", tenantId, outcome: "suspended" };
  }

  async #rpcJson(
    rpcName: string,
    body: RpcBody,
    operation: ProviderOperation,
  ): Promise<unknown> {
    const response = await this.#rpcResponse(rpcName, body, operation);
    try {
      return await response.json();
    } catch {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation,
      });
    }
  }

  async #rpcVoid(
    rpcName: string,
    body: RpcBody,
    operation: ProviderOperation,
  ): Promise<void> {
    await this.#rpcResponse(rpcName, body, operation);
  }

  async #rpcResponse(
    rpcName: string,
    body: RpcBody,
    operation: ProviderOperation,
  ): Promise<Response> {
    let response: Response;
    try {
      response = await this.#fetch(
        `${this.#supabaseUrl}/rest/v1/rpc/${rpcName}`,
        {
          method: "POST",
          headers: {
            apikey: this.#serviceRoleKey,
            Authorization: `Bearer ${this.#serviceRoleKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        },
      );
    } catch {
      throw providerError({
        code: "PROVIDER_TRANSIENT",
        operation,
        retryable: true,
      });
    }

    if (!response.ok) {
      throw errorForHttpStatus(operation, response.status);
    }
    return response;
  }
}

function deriveSharedTenantMetadata(tenantId: string): {
  readonly displayName: string;
  readonly slug: string;
} {
  return {
    displayName: `e-sig Cloud ${tenantId.slice(0, 8)}`,
    slug: `esig-${tenantId.replaceAll("-", "").slice(0, 24)}`,
  };
}

function normalizeHttpsOrigin(value: string): string {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      throw new Error("invalid");
    }
    return url.origin;
  } catch {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
}

function requireSecret(value: string): string {
  if (value.length < 8) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return value;
}

function validateRpcName(value: string): string {
  if (!RPC_NAME_PATTERN.test(value)) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return value;
}

function validatePrior(
  prior: SharedProviderResources | undefined,
  request: ProvisioningRequest,
  tenantId: string,
): void {
  if (
    prior &&
    (prior.mode !== "shared" ||
      prior.subscriptionId !== request.subscriptionId ||
      prior.tenantId !== tenantId ||
      prior.storageNamespace !== `${tenantId}/` ||
      !UUID_PATTERN.test(prior.credentialId))
  ) {
    throw providerError({
      code: "PROVIDER_CONFLICT",
      operation: "validate",
    });
  }
}

function parseProvisionResponse(value: unknown): SharedProvisionResponse {
  const payload = unwrapSingleRow(value);
  if (
    !isRecord(payload) ||
    typeof payload.tenant_id !== "string" ||
    !UUID_PATTERN.test(payload.tenant_id) ||
    (payload.organization_status !== "provisioning" &&
      payload.organization_status !== "ready") ||
    (payload.provisioning_state !== "provisioning" &&
      payload.provisioning_state !== "ready") ||
    typeof payload.storage_namespace !== "string" ||
    payload.storage_namespace.length === 0 ||
    typeof payload.credential_id !== "string" ||
    !UUID_PATTERN.test(payload.credential_id) ||
    (typeof payload.credential_plaintext !== "string" &&
      payload.credential_plaintext !== null) ||
    payload.credential_plaintext === "" ||
    typeof payload.created !== "boolean"
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "shared.provision",
    });
  }
  return payload as unknown as SharedProvisionResponse;
}

function parseReissueResponse(value: unknown): SharedReissueResponse {
  const payload = unwrapSingleRow(value);
  if (
    !isRecord(payload) ||
    typeof payload.credential_id !== "string" ||
    !UUID_PATTERN.test(payload.credential_id) ||
    typeof payload.credential_plaintext !== "string" ||
    payload.credential_plaintext.length === 0
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "shared.credential.reissue",
    });
  }
  return payload as unknown as SharedReissueResponse;
}

function parseResumeResponse(value: unknown): SharedResumeResponse {
  const row = Array.isArray(value) && value.length === 1 ? value[0] : value;
  if (
    !isRecord(row) ||
    typeof row.tenant_id !== "string" ||
    !UUID_PATTERN.test(row.tenant_id) ||
    row.organization_status !== "provisioning" ||
    row.provisioning_state !== "provisioning" ||
    typeof row.storage_namespace !== "string" ||
    typeof row.credential_id !== "string" ||
    !UUID_PATTERN.test(row.credential_id) ||
    (row.credential_plaintext !== null &&
      (typeof row.credential_plaintext !== "string" ||
        row.credential_plaintext.length === 0)) ||
    typeof row.resumed !== "boolean" ||
    row.resumed !== (row.credential_plaintext !== null)
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "shared.provision",
    });
  }
  return row as unknown as SharedResumeResponse;
}

function responseStatus(
  payload: SharedProvisionResponse,
): SharedProviderResources["status"] {
  if (
    payload.organization_status === "ready" &&
    payload.provisioning_state === "ready"
  ) {
    return "ready";
  }
  if (
    payload.organization_status === "provisioning" &&
    payload.provisioning_state === "provisioning"
  ) {
    return "provisioning";
  }
  throw providerError({
    code: "PROVIDER_RESPONSE_INVALID",
    operation: "shared.provision",
  });
}

function unwrapSingleRow(value: unknown): unknown {
  if (Array.isArray(value)) {
    if (value.length !== 1) {
      return undefined;
    }
    return value[0];
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
