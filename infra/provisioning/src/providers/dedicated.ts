import {
  CreateStackCommand,
  DescribeStacksCommand,
  UpdateStackCommand,
  type CloudFormationClient,
  type Stack,
} from "@aws-sdk/client-cloudformation";

import {
  deriveProviderIdentifiers,
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
  DedicatedProviderResources,
  FetchTransport,
  OneTimeCredential,
  ProvisioningProvider,
  ProvisioningRequest,
  ProvisioningResult,
  UnknownCompensationResult,
  UnknownSuspensionResult,
} from "./types.js";

const DEFAULT_MANAGEMENT_BASE_URL = "https://api.supabase.com";
const HEALTH_SERVICES = ["auth", "rest", "storage"] as const;
const ORGANIZATION_SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{1,126}[a-z0-9]$/;

type CloudFormationTransport = Pick<CloudFormationClient, "send">;
type Sleep = (milliseconds: number) => Promise<void>;

export const DEDICATED_REQUIRED_MIGRATIONS = [
  "0001_esig_self_contained.sql",
  "0002_esig_audit_hashchain.sql",
  "0003_esig_pq_keys.sql",
  "0004_esig_cloud_tenants.sql",
] as const;

export type DedicatedRequiredMigration =
  (typeof DEDICATED_REQUIRED_MIGRATIONS)[number];

export interface DedicatedMigrationInput {
  readonly projectRef: string;
  readonly migrations: readonly DedicatedRequiredMigration[];
}

export interface DedicatedMigrationResult {
  /** The adapter must verify these against its durable migration ledger. */
  readonly appliedMigrations: readonly string[];
}

export interface DedicatedTenantInput {
  readonly request: ProvisioningRequest;
  readonly tenantId: string;
  readonly projectRef: string;
  readonly stackId: string;
}

export interface DedicatedTenantIdentity {
  readonly subscriptionId: string;
  readonly tenantId: string;
  readonly projectRef: string;
  readonly stackId: string;
}

export interface DedicatedTenantProvisioningResult {
  readonly tenantId: string;
  readonly status: "provisioning" | "ready";
  readonly created: boolean;
  readonly oneTimeCredential?: OneTimeCredential;
}

export interface DedicatedTenantStateResult {
  readonly tenantId: string;
  readonly status: "ready" | "suspended" | "disabled";
}

export interface DedicatedTenantResumeResult {
  readonly tenantId: string;
  readonly oneTimeCredential: OneTimeCredential;
}

export interface DedicatedCredentialReissueResult {
  readonly tenantId: string;
  readonly oneTimeCredential: OneTimeCredential;
}

/**
 * Project-database boundary for dedicated tenants. Implementations must be
 * idempotent: migrations use a durable checksum ledger and tenant state
 * operations converge on tenantId/subscriptionId. Credential reissue is an
 * intentional rotation on every success. There is deliberately no no-op
 * default.
 */
export interface DedicatedTenantBootstrapper {
  applyMigrations(input: DedicatedMigrationInput): Promise<DedicatedMigrationResult>;
  provisionTenant(
    input: DedicatedTenantInput,
  ): Promise<DedicatedTenantProvisioningResult>;
  reissueCredential(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedCredentialReissueResult>;
  markReady(input: DedicatedTenantIdentity): Promise<DedicatedTenantStateResult>;
  disableTenant(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedTenantStateResult>;
  suspendTenant(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedTenantStateResult>;
  resumeTenant(input: DedicatedTenantIdentity): Promise<DedicatedTenantResumeResult>;
}

export interface DedicatedProvisioningProviderOptions {
  readonly managementToken: string;
  readonly organizationSlug: string;
  readonly databasePasswordFor: (
    request: ProvisioningRequest,
  ) => string | Promise<string>;
  readonly templateUrl: string;
  readonly cloudFormationRoleArn?: string;
  readonly cloudFormation: CloudFormationTransport;
  readonly tenantBootstrapper: DedicatedTenantBootstrapper;
  readonly readinessTimeoutMs: number;
  readonly pollIntervalMs: number;
  readonly fetch?: FetchTransport;
  readonly managementBaseUrl?: string;
  readonly sleep?: Sleep;
  readonly now?: () => number;
}

interface SupabaseProject {
  readonly ref: string;
  readonly name: string;
  readonly status: string;
}

interface ProjectResolution {
  readonly project: SupabaseProject;
  readonly created: boolean;
}

interface StackResolution {
  readonly stack: Stack;
  readonly created: boolean;
}

export class DedicatedProvisioningProvider
  implements ProvisioningProvider<DedicatedProviderResources>
{
  readonly mode = "dedicated" as const;

  readonly #managementToken: string;
  readonly #organizationSlug: string;
  readonly #databasePasswordFor: (
    request: ProvisioningRequest,
  ) => string | Promise<string>;
  readonly #templateUrl: string;
  readonly #cloudFormationRoleArn: string | undefined;
  readonly #cloudFormation: CloudFormationTransport;
  readonly #tenantBootstrapper: DedicatedTenantBootstrapper;
  readonly #readinessTimeoutMs: number;
  readonly #pollIntervalMs: number;
  readonly #fetch: FetchTransport;
  readonly #managementBaseUrl: string;
  readonly #sleep: Sleep;
  readonly #now: () => number;

  constructor(options: DedicatedProvisioningProviderOptions) {
    this.#managementToken = requireSecret(options.managementToken);
    this.#organizationSlug = validateOrganizationSlug(options.organizationSlug);
    this.#databasePasswordFor = options.databasePasswordFor;
    this.#templateUrl = normalizeHttpsUrl(options.templateUrl);
    this.#cloudFormationRoleArn = options.cloudFormationRoleArn
      ? validateCloudFormationRoleArn(options.cloudFormationRoleArn)
      : undefined;
    this.#cloudFormation = options.cloudFormation;
    this.#tenantBootstrapper = validateTenantBootstrapper(
      options.tenantBootstrapper,
    );
    this.#readinessTimeoutMs = positiveInteger(options.readinessTimeoutMs);
    this.#pollIntervalMs = positiveInteger(options.pollIntervalMs);
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#managementBaseUrl = normalizeHttpsUrl(
      options.managementBaseUrl ?? DEFAULT_MANAGEMENT_BASE_URL,
      true,
    );
    this.#sleep = options.sleep ?? defaultSleep;
    this.#now = options.now ?? Date.now;
  }

  async provision(
    request: ProvisioningRequest,
    prior?: DedicatedProviderResources,
  ): Promise<ProvisioningResult<DedicatedProviderResources>> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "dedicated");
    validatePrior(prior, request, identifiers);
    if (prior?.status === "disabled" || prior?.status === "suspended") {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "validate",
      });
    }
    const deadline = this.#deadline();

    const projectResolution = await this.#ensureProject(
      request,
      identifiers.projectName,
      prior?.projectRef,
    );
    await this.#waitForProjectHealth(projectResolution.project.ref, deadline);

    const migrationResult = await this.#tenantBootstrapper.applyMigrations({
      projectRef: projectResolution.project.ref,
      migrations: DEDICATED_REQUIRED_MIGRATIONS,
    });
    validateMigrationResult(migrationResult);

    const stackResolution = await this.#ensureStack(
      request,
      projectResolution.project.ref,
      identifiers,
      deadline,
    );

    if (
      prior &&
      (prior.projectRef !== projectResolution.project.ref ||
        prior.stackId !== stackResolution.stack.StackId)
    ) {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "validate",
      });
    }

    const stackId = stackResolution.stack.StackId;
    if (typeof stackId !== "string" || stackId.length === 0) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "dedicated.stack.describe",
      });
    }

    const tenantResult = await this.#tenantBootstrapper.provisionTenant({
      request,
      tenantId: identifiers.tenantId,
      projectRef: projectResolution.project.ref,
      stackId,
    });
    validateTenantProvisioningResult(tenantResult, identifiers.tenantId, prior);

    const result: ProvisioningResult<DedicatedProviderResources> = {
      created:
        projectResolution.created || stackResolution.created || tenantResult.created,
      resources: {
        mode: "dedicated",
        subscriptionId: request.subscriptionId,
        tenantId: identifiers.tenantId,
        projectRef: projectResolution.project.ref,
        projectName: identifiers.projectName,
        stackId,
        stackName: identifiers.stackName,
        status: tenantResult.status,
      },
    };
    if (tenantResult.oneTimeCredential !== undefined) {
      return { ...result, oneTimeCredential: tenantResult.oneTimeCredential };
    }
    return result;
  }

  async reissueCredential(
    request: ProvisioningRequest,
    resources: DedicatedProviderResources,
  ): Promise<CredentialReissueResult<DedicatedProviderResources>> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(
      request.subscriptionId,
      "dedicated",
    );
    validatePrior(resources, request, identifiers);
    if (resources.status === "disabled" || resources.status === "suspended") {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "dedicated.credential.reissue",
      });
    }

    const result = await this.#tenantBootstrapper.reissueCredential(
      tenantIdentity(request, resources),
    );
    validateCredentialReissueResult(result, resources.tenantId);
    return {
      resources,
      oneTimeCredential: result.oneTimeCredential,
    };
  }

  async disable(
    request: ProvisioningRequest,
    resources: DedicatedProviderResources,
  ): Promise<DedicatedProviderResources> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "dedicated");
    validatePrior(resources, request, identifiers);
    const deadline = this.#deadline();

    const tenantState = await this.#tenantBootstrapper.disableTenant(
      tenantIdentity(request, resources),
    );
    validateTenantStateResult(tenantState, resources.tenantId, "disabled");

    await this.#disableStack(
      request,
      resources.stackName,
      identifiers,
      deadline,
    );
    await this.#pauseProject(resources.projectRef, deadline);

    return { ...resources, status: "disabled" };
  }

  async suspend(
    request: ProvisioningRequest,
    resources: DedicatedProviderResources,
  ): Promise<DedicatedProviderResources> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "dedicated");
    validatePrior(resources, request, identifiers);
    if (resources.status === "disabled") {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "validate" });
    }
    const deadline = this.#deadline();
    const tenantState = await this.#tenantBootstrapper.suspendTenant(
      tenantIdentity(request, resources),
    );
    validateTenantStateResult(tenantState, resources.tenantId, "suspended");
    await this.#disableStack(request, resources.stackName, identifiers, deadline);
    return { ...resources, status: "suspended" };
  }

  async resume(
    request: ProvisioningRequest,
    resources: DedicatedProviderResources,
  ): Promise<ProvisioningResult<DedicatedProviderResources>> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "dedicated");
    validatePrior(resources, request, identifiers);
    if (resources.status === "disabled") {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "validate" });
    }
    const deadline = this.#deadline();
    await this.#waitForProjectHealth(resources.projectRef, deadline);
    await this.#enableStack(request, resources.stackName, identifiers, deadline);
    const resumed = await this.#tenantBootstrapper.resumeTenant(
      tenantIdentity(request, resources),
    );
    if (resumed.tenantId !== resources.tenantId) {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "dedicated.credential.reissue" });
    }
    return {
      resources: { ...resources, status: "provisioning" },
      created: false,
      oneTimeCredential: resumed.oneTimeCredential,
    };
  }

  async markReady(
    request: ProvisioningRequest,
    resources: DedicatedProviderResources,
  ): Promise<DedicatedProviderResources> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "dedicated");
    validatePrior(resources, request, identifiers);
    if (resources.status === "disabled" || resources.status === "suspended") {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "validate",
      });
    }

    const tenantState = await this.#tenantBootstrapper.markReady(
      tenantIdentity(request, resources),
    );
    validateTenantStateResult(tenantState, resources.tenantId, "ready");
    return { ...resources, status: "ready" };
  }

  compensate(
    request: ProvisioningRequest,
    resources: DedicatedProviderResources,
  ): Promise<DedicatedProviderResources> {
    return this.disable(request, resources);
  }

  async compensateUnknown(
    request: ProvisioningRequest,
  ): Promise<UnknownCompensationResult> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(
      request.subscriptionId,
      "dedicated",
    );
    const deadline = this.#deadline();

    const project = await this.#findProjectByName(identifiers.projectName);
    const stack = await this.#describeStack(identifiers.stackName);
    if (!project && !stack) {
      return {
        mode: "dedicated",
        tenantId: identifiers.tenantId,
        outcome: "absent",
      };
    }

    if (stack) {
      validateStackIdentity(stack, request, identifiers.tenantId);
    }

    if (project && stack) {
      const stackId = stack.StackId;
      if (typeof stackId !== "string" || stackId.length === 0) {
        throw providerError({
          code: "PROVIDER_RESPONSE_INVALID",
          operation: "dedicated.stack.describe",
        });
      }
      if (stackParameter(stack, "SupabaseProjectRef") !== project.ref) {
        throw providerError({
          code: "PROVIDER_CONFLICT",
          operation: "dedicated.stack.describe",
        });
      }

      try {
        const tenantState = await this.#tenantBootstrapper.disableTenant({
          subscriptionId: request.subscriptionId,
          tenantId: identifiers.tenantId,
          projectRef: project.ref,
          stackId,
        });
        validateTenantStateResult(
          tenantState,
          identifiers.tenantId,
          "disabled",
        );
      } catch (error) {
        if (!isProviderNotFound(error)) {
          throw error;
        }
      }
    }

    if (stack) {
      try {
        await this.#disableStack(
          request,
          identifiers.stackName,
          identifiers,
          deadline,
        );
      } catch (error) {
        if (!isProviderNotFound(error)) {
          throw error;
        }
      }
    }

    if (project) {
      try {
        await this.#pauseProject(project.ref, deadline);
      } catch (error) {
        if (!isProviderNotFound(error)) {
          throw error;
        }
      }
    }

    return {
      mode: "dedicated",
      tenantId: identifiers.tenantId,
      outcome: "disabled",
    };
  }

  async suspendUnknown(
    request: ProvisioningRequest,
  ): Promise<UnknownSuspensionResult> {
    validateProvisioningRequest(request);
    const identifiers = deriveProviderIdentifiers(request.subscriptionId, "dedicated");
    const deadline = this.#deadline();
    const project = await this.#findProjectByName(identifiers.projectName);
    const stack = await this.#describeStack(identifiers.stackName);
    if (!project && !stack) {
      return { mode: "dedicated", tenantId: identifiers.tenantId, outcome: "absent" };
    }
    if (!project || !stack || typeof stack.StackId !== "string") {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "validate" });
    }
    validateStackIdentity(stack, request, identifiers.tenantId);
    if (stackParameter(stack, "SupabaseProjectRef") !== project.ref) {
      throw providerError({ code: "PROVIDER_CONFLICT", operation: "dedicated.stack.describe" });
    }
    const tenantState = await this.#tenantBootstrapper.suspendTenant({
      subscriptionId: request.subscriptionId,
      tenantId: identifiers.tenantId,
      projectRef: project.ref,
      stackId: stack.StackId,
    });
    validateTenantStateResult(tenantState, identifiers.tenantId, "suspended");
    await this.#disableStack(request, identifiers.stackName, identifiers, deadline);
    return { mode: "dedicated", tenantId: identifiers.tenantId, outcome: "suspended" };
  }

  #deadline(): number {
    return this.#now() + this.#readinessTimeoutMs;
  }

  async #ensureProject(
    request: ProvisioningRequest,
    projectName: string,
    priorProjectRef?: string,
  ): Promise<ProjectResolution> {
    if (priorProjectRef) {
      const priorProject = await this.#describeProject(priorProjectRef);
      if (priorProject && priorProject.name === projectName) {
        return { project: priorProject, created: false };
      }
      if (priorProject) {
        throw providerError({
          code: "PROVIDER_CONFLICT",
          operation: "dedicated.project.describe",
        });
      }
    }

    const existing = await this.#findProjectByName(projectName);
    if (existing) {
      return { project: existing, created: false };
    }

    const databasePassword = await this.#resolveDatabasePassword(request);
    const response = await this.#managementRequest(
      "/v1/projects",
      {
        method: "POST",
        body: JSON.stringify({
          name: projectName,
          organization_slug: this.#organizationSlug,
          db_pass: databasePassword,
          region_selection: {
            type: "smartGroup",
            code: smartRegionFor(request.region),
          },
        }),
      },
      "dedicated.project.create",
      [409],
    );

    if (response.status === 409) {
      const conflictedProject = await this.#findProjectByName(projectName);
      if (!conflictedProject) {
        throw providerError({
          code: "PROVIDER_CONFLICT",
          operation: "dedicated.project.create",
          statusCode: response.status,
        });
      }
      return { project: conflictedProject, created: false };
    }

    const project = await parseProjectResponse(
      response,
      "dedicated.project.create",
    );
    if (project.name !== projectName) {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "dedicated.project.create",
      });
    }
    return { project, created: true };
  }

  async #resolveDatabasePassword(
    request: ProvisioningRequest,
  ): Promise<string> {
    let password: string;
    try {
      password = await this.#databasePasswordFor(request);
    } catch {
      throw providerError({
        code: "PROVIDER_TRANSIENT",
        operation: "dedicated.project.create",
        retryable: true,
      });
    }

    if (typeof password !== "string" || password.length < 16) {
      throw providerError({
        code: "PROVIDER_INVALID_REQUEST",
        operation: "dedicated.project.create",
      });
    }
    return password;
  }

  async #describeProject(projectRef: string): Promise<SupabaseProject | undefined> {
    const response = await this.#managementRequest(
      `/v1/projects/${encodeURIComponent(projectRef)}`,
      { method: "GET" },
      "dedicated.project.describe",
      [404],
    );
    if (response.status === 404) {
      return undefined;
    }
    return parseProjectResponse(response, "dedicated.project.describe");
  }

  async #findProjectByName(
    projectName: string,
  ): Promise<SupabaseProject | undefined> {
    const query = new URLSearchParams({
      search: projectName,
      offset: "0",
      limit: "100",
    });
    const response = await this.#managementRequest(
      `/v1/organizations/${encodeURIComponent(this.#organizationSlug)}/projects?${query.toString()}`,
      { method: "GET" },
      "dedicated.project.list",
    );

    let value: unknown;
    try {
      value = await response.json();
    } catch {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "dedicated.project.list",
      });
    }

    if (!isRecord(value) || !Array.isArray(value.projects)) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "dedicated.project.list",
      });
    }

    const projects = value.projects.map(parseProject);
    if (projects.some((project) => project === undefined)) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "dedicated.project.list",
      });
    }
    const exactMatches = (projects as SupabaseProject[]).filter(
      (project) => project.name === projectName,
    );

    if (exactMatches.length > 1) {
      throw providerError({
        code: "PROVIDER_CONFLICT",
        operation: "dedicated.project.list",
      });
    }

    return exactMatches[0];
  }

  async #waitForProjectHealth(
    projectRef: string,
    deadline: number,
  ): Promise<void> {
    while (true) {
      const query = new URLSearchParams();
      for (const service of HEALTH_SERVICES) {
        query.append("services", service);
      }
      query.set(
        "timeout_ms",
        String(Math.min(this.#pollIntervalMs, 10_000)),
      );

      try {
        const response = await this.#managementRequest(
          `/v1/projects/${encodeURIComponent(projectRef)}/health?${query.toString()}`,
          { method: "GET" },
          "dedicated.project.health",
        );
        const health = await parseJson(
          response,
          "dedicated.project.health",
        );
        if (!Array.isArray(health)) {
          throw providerError({
            code: "PROVIDER_RESPONSE_INVALID",
            operation: "dedicated.project.health",
          });
        }

        const byName = new Map<string, Record<string, unknown>>();
        for (const item of health) {
          if (isRecord(item) && typeof item.name === "string") {
            byName.set(item.name, item);
          }
        }

        if (
          HEALTH_SERVICES.every((service) => {
            const item = byName.get(service);
            return item?.healthy === true && item.status === "ACTIVE_HEALTHY";
          })
        ) {
          return;
        }
      } catch (error) {
        if (!(error instanceof ProviderError) || !error.retryable) {
          throw error;
        }
      }

      await this.#waitOrTimeout(deadline, "dedicated.project.health");
    }
  }

  async #ensureStack(
    request: ProvisioningRequest,
    projectRef: string,
    identifiers: ReturnType<typeof deriveProviderIdentifiers>,
    deadline: number,
  ): Promise<StackResolution> {
    const existing = await this.#describeStack(identifiers.stackName);
    if (existing) {
      validateStackIdentity(existing, request, identifiers.tenantId);
      const stack = await this.#waitForReadyStack(
        identifiers.stackName,
        request,
        identifiers.tenantId,
        deadline,
      );
      return { stack, created: false };
    }

    let created = true;
    try {
      await this.#cloudFormation.send(
        new CreateStackCommand({
          StackName: identifiers.stackName,
          TemplateURL: this.#templateUrl,
          ClientRequestToken: identifiers.stackCreateToken,
          OnFailure: "DO_NOTHING",
          EnableTerminationProtection: true,
          RoleARN: this.#cloudFormationRoleArn,
          Parameters: [
            {
              ParameterKey: "TenantId",
              ParameterValue: identifiers.tenantId,
            },
            {
              ParameterKey: "SubscriptionId",
              ParameterValue: request.subscriptionId,
            },
            {
              ParameterKey: "SupabaseProjectRef",
              ParameterValue: projectRef,
            },
            { ParameterKey: "SigningEnabled", ParameterValue: "true" },
          ],
          Tags: [
            { Key: "e-sig:managed-by", Value: "cloud-provisioning" },
            { Key: "e-sig:subscription-id", Value: request.subscriptionId },
            { Key: "e-sig:tenant-id", Value: identifiers.tenantId },
          ],
        }),
      );
    } catch (error) {
      if (!isCreateConflict(error)) {
        throw awsProviderError("dedicated.stack.create", error);
      }
      created = false;
    }

    const stack = await this.#waitForReadyStack(
      identifiers.stackName,
      request,
      identifiers.tenantId,
      deadline,
    );
    return { stack, created };
  }

  async #describeStack(stackName: string): Promise<Stack | undefined> {
    let output;
    try {
      output = await this.#cloudFormation.send(
        new DescribeStacksCommand({ StackName: stackName }),
      );
    } catch (error) {
      if (awsErrorName(error) === "ValidationError") {
        return undefined;
      }
      throw awsProviderError("dedicated.stack.describe", error);
    }

    if (!output.Stacks || output.Stacks.length !== 1) {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "dedicated.stack.describe",
      });
    }
    return output.Stacks[0];
  }

  async #waitForReadyStack(
    stackName: string,
    request: ProvisioningRequest,
    tenantId: string,
    deadline: number,
  ): Promise<Stack> {
    while (true) {
      try {
        const stack = await this.#describeStack(stackName);
        if (stack) {
          validateStackIdentity(stack, request, tenantId);
          const status = stack.StackStatus;
          if (status === "CREATE_COMPLETE" || status === "UPDATE_COMPLETE") {
            return stack;
          }
          if (isFailedStackStatus(status)) {
            throw providerError({
              code: "PROVIDER_RESOURCE_FAILED",
              operation: "dedicated.stack.describe",
            });
          }
        }
      } catch (error) {
        if (!(error instanceof ProviderError) || !error.retryable) {
          throw error;
        }
      }

      await this.#waitOrTimeout(deadline, "dedicated.stack.describe");
    }
  }

  async #disableStack(
    request: ProvisioningRequest,
    stackName: string,
    identifiers: ReturnType<typeof deriveProviderIdentifiers>,
    deadline: number,
  ): Promise<void> {
    let stack = await this.#describeStack(stackName);
    if (!stack) {
      throw providerError({
        code: "PROVIDER_NOT_FOUND",
        operation: "dedicated.stack.disable",
      });
    }
    validateStackIdentity(stack, request, identifiers.tenantId);

    if (isStackInProgress(stack.StackStatus)) {
      stack = await this.#waitForReadyStack(
        stackName,
        request,
        identifiers.tenantId,
        deadline,
      );
    }

    if (stackParameter(stack, "SigningEnabled") === "false") {
      return;
    }

    try {
      await this.#cloudFormation.send(
        new UpdateStackCommand({
          StackName: stackName,
          UsePreviousTemplate: true,
          RoleARN: this.#cloudFormationRoleArn,
          ClientRequestToken: identifiers.stackDisableToken,
          Parameters: [
            { ParameterKey: "SigningEnabled", ParameterValue: "false" },
          ],
        }),
      );
    } catch (error) {
      if (!isNoUpdatesError(error)) {
        throw awsProviderError("dedicated.stack.disable", error);
      }
      return;
    }

    await this.#waitForDisabledStack(
      stackName,
      request,
      identifiers.tenantId,
      deadline,
    );
  }

  async #enableStack(
    request: ProvisioningRequest,
    stackName: string,
    identifiers: ReturnType<typeof deriveProviderIdentifiers>,
    deadline: number,
  ): Promise<void> {
    let stack = await this.#describeStack(stackName);
    if (!stack) {
      throw providerError({ code: "PROVIDER_NOT_FOUND", operation: "dedicated.stack.create" });
    }
    validateStackIdentity(stack, request, identifiers.tenantId);
    if (isStackInProgress(stack.StackStatus)) {
      stack = await this.#waitForReadyStack(stackName, request, identifiers.tenantId, deadline);
    }
    if (stackParameter(stack, "SigningEnabled") === "true") return;
    try {
      await this.#cloudFormation.send(
        new UpdateStackCommand({
          StackName: stackName,
          UsePreviousTemplate: true,
          RoleARN: this.#cloudFormationRoleArn,
          ClientRequestToken: identifiers.stackCreateToken.replace("create", "enable"),
          Parameters: [{ ParameterKey: "SigningEnabled", ParameterValue: "true" }],
        }),
      );
    } catch (error) {
      if (!isNoUpdatesError(error)) {
        throw awsProviderError("dedicated.stack.create", error);
      }
      return;
    }
    await this.#waitForReadyStack(stackName, request, identifiers.tenantId, deadline);
    const enabled = await this.#describeStack(stackName);
    if (!enabled || stackParameter(enabled, "SigningEnabled") !== "true") {
      throw providerError({
        code: "PROVIDER_RESPONSE_INVALID",
        operation: "dedicated.stack.create",
      });
    }
  }

  async #waitForDisabledStack(
    stackName: string,
    request: ProvisioningRequest,
    tenantId: string,
    deadline: number,
  ): Promise<void> {
    while (true) {
      try {
        const stack = await this.#describeStack(stackName);
        if (stack) {
          validateStackIdentity(stack, request, tenantId);
          if (isFailedStackStatus(stack.StackStatus)) {
            throw providerError({
              code: "PROVIDER_RESOURCE_FAILED",
              operation: "dedicated.stack.disable",
            });
          }
          if (
            !isStackInProgress(stack.StackStatus) &&
            stackParameter(stack, "SigningEnabled") === "false"
          ) {
            return;
          }
        }
      } catch (error) {
        if (!(error instanceof ProviderError) || !error.retryable) {
          throw error;
        }
      }
      await this.#waitOrTimeout(deadline, "dedicated.stack.disable");
    }
  }

  async #pauseProject(projectRef: string, deadline: number): Promise<void> {
    const project = await this.#describeProject(projectRef);
    if (!project) {
      throw providerError({
        code: "PROVIDER_NOT_FOUND",
        operation: "dedicated.project.pause",
      });
    }
    if (project.status === "INACTIVE") {
      return;
    }

    await this.#managementRequest(
      `/v1/projects/${encodeURIComponent(projectRef)}/pause`,
      { method: "POST", body: "{}" },
      "dedicated.project.pause",
      [409],
    );

    while (true) {
      try {
        const current = await this.#describeProject(projectRef);
        if (current?.status === "INACTIVE") {
          return;
        }
      } catch (error) {
        if (!(error instanceof ProviderError) || !error.retryable) {
          throw error;
        }
      }
      await this.#waitOrTimeout(deadline, "dedicated.project.pause");
    }
  }

  async #waitOrTimeout(
    deadline: number,
    operation: ProviderOperation,
  ): Promise<void> {
    const remaining = deadline - this.#now();
    if (remaining <= 0) {
      throw providerError({
        code: "PROVIDER_TIMEOUT",
        operation,
        retryable: true,
      });
    }
    await this.#sleep(Math.min(this.#pollIntervalMs, remaining));
    if (this.#now() >= deadline) {
      throw providerError({
        code: "PROVIDER_TIMEOUT",
        operation,
        retryable: true,
      });
    }
  }

  async #managementRequest(
    path: string,
    init: RequestInit,
    operation: ProviderOperation,
    acceptedStatuses: readonly number[] = [],
  ): Promise<Response> {
    let response: Response;
    try {
      response = await this.#fetch(`${this.#managementBaseUrl}${path}`, {
        ...init,
        headers: {
          Authorization: `Bearer ${this.#managementToken}`,
          "Content-Type": "application/json",
          ...init.headers,
        },
      });
    } catch {
      throw providerError({
        code: "PROVIDER_TRANSIENT",
        operation,
        retryable: true,
      });
    }

    if (!response.ok && !acceptedStatuses.includes(response.status)) {
      throw errorForHttpStatus(operation, response.status);
    }
    return response;
  }
}

function validatePrior(
  prior: DedicatedProviderResources | undefined,
  request: ProvisioningRequest,
  identifiers: ReturnType<typeof deriveProviderIdentifiers>,
): void {
  if (
    prior &&
    (prior.mode !== "dedicated" ||
      prior.subscriptionId !== request.subscriptionId ||
      prior.tenantId !== identifiers.tenantId ||
      prior.projectName !== identifiers.projectName ||
      prior.stackName !== identifiers.stackName)
  ) {
    throw providerError({
      code: "PROVIDER_CONFLICT",
      operation: "validate",
    });
  }
}

function validateTenantBootstrapper(
  value: DedicatedTenantBootstrapper,
): DedicatedTenantBootstrapper {
  if (
    !isRecord(value) ||
    typeof value.applyMigrations !== "function" ||
    typeof value.provisionTenant !== "function" ||
    typeof value.reissueCredential !== "function" ||
    typeof value.markReady !== "function" ||
    typeof value.disableTenant !== "function"
  ) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return value;
}

function validateMigrationResult(result: DedicatedMigrationResult): void {
  if (
    !isRecord(result) ||
    !Array.isArray(result.appliedMigrations) ||
    result.appliedMigrations.length !== DEDICATED_REQUIRED_MIGRATIONS.length ||
    result.appliedMigrations.some((migration) => typeof migration !== "string") ||
    DEDICATED_REQUIRED_MIGRATIONS.some(
      (migration) => !result.appliedMigrations.includes(migration),
    )
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "validate",
    });
  }
}

function validateTenantProvisioningResult(
  result: DedicatedTenantProvisioningResult,
  tenantId: string,
  prior: DedicatedProviderResources | undefined,
): void {
  const expectedStatus = prior?.status === "ready" ? "ready" : "provisioning";
  const credential = isRecord(result) ? result.oneTimeCredential : undefined;
  const credentialIsValid =
    credential === undefined ||
    (isRecord(credential) &&
      typeof credential.id === "string" &&
      credential.id.length > 0 &&
      typeof credential.plaintext === "string" &&
      credential.plaintext.length > 0);
  if (
    !isRecord(result) ||
    result.tenantId !== tenantId ||
    result.status !== expectedStatus ||
    typeof result.created !== "boolean" ||
    (result.created && prior !== undefined) ||
    (result.created && credential === undefined) ||
    !credentialIsValid
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "validate",
    });
  }
}

function validateTenantStateResult(
  result: DedicatedTenantStateResult,
  tenantId: string,
  expectedStatus: DedicatedTenantStateResult["status"],
): void {
  if (
    !isRecord(result) ||
    result.tenantId !== tenantId ||
    result.status !== expectedStatus
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "validate",
    });
  }
}

function validateCredentialReissueResult(
  result: DedicatedCredentialReissueResult,
  tenantId: string,
): void {
  const credential = isRecord(result) ? result.oneTimeCredential : undefined;
  if (
    !isRecord(result) ||
    result.tenantId !== tenantId ||
    !isRecord(credential) ||
    typeof credential.id !== "string" ||
    credential.id.length === 0 ||
    typeof credential.plaintext !== "string" ||
    credential.plaintext.length === 0
  ) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "dedicated.credential.reissue",
    });
  }
}

function tenantIdentity(
  request: ProvisioningRequest,
  resources: DedicatedProviderResources,
): DedicatedTenantIdentity {
  return {
    subscriptionId: request.subscriptionId,
    tenantId: resources.tenantId,
    projectRef: resources.projectRef,
    stackId: resources.stackId,
  };
}

function validateStackIdentity(
  stack: Stack,
  request: ProvisioningRequest,
  tenantId: string,
): void {
  const tags = new Map(stack.Tags?.map((tag) => [tag.Key, tag.Value]));
  if (
    tags.get("e-sig:managed-by") !== "cloud-provisioning" ||
    tags.get("e-sig:subscription-id") !== request.subscriptionId ||
    tags.get("e-sig:tenant-id") !== tenantId
  ) {
    throw providerError({
      code: "PROVIDER_CONFLICT",
      operation: "dedicated.stack.describe",
    });
  }
}

function stackParameter(stack: Stack, key: string): string | undefined {
  return stack.Parameters?.find((parameter) => parameter.ParameterKey === key)
    ?.ParameterValue;
}

function isStackInProgress(status: string | undefined): boolean {
  return status?.endsWith("_IN_PROGRESS") ?? false;
}

function isFailedStackStatus(status: string | undefined): boolean {
  return (
    status?.endsWith("_FAILED") === true ||
    status?.startsWith("ROLLBACK_") === true ||
    status?.startsWith("DELETE_") === true ||
    status?.startsWith("UPDATE_ROLLBACK_") === true ||
    status?.startsWith("IMPORT_ROLLBACK_") === true
  );
}

function awsErrorName(error: unknown): string | undefined {
  return isRecord(error) && typeof error.name === "string"
    ? error.name
    : undefined;
}

function isProviderNotFound(error: unknown): boolean {
  return isRecord(error) && error.code === "PROVIDER_NOT_FOUND";
}

function isCreateConflict(error: unknown): boolean {
  return awsErrorName(error) === "AlreadyExistsException";
}

function isNoUpdatesError(error: unknown): boolean {
  return (
    awsErrorName(error) === "ValidationError" &&
    isRecord(error) &&
    typeof error.message === "string" &&
    error.message.includes("No updates are to be performed")
  );
}

function awsProviderError(
  operation: ProviderOperation,
  error: unknown,
): ProviderError {
  const name = awsErrorName(error);
  if (name === "AccessDenied" || name === "AccessDeniedException") {
    return providerError({ code: "PROVIDER_AUTH_FAILED", operation });
  }
  if (
    name === "Throttling" ||
    name === "ThrottlingException" ||
    name === "ServiceUnavailable" ||
    name === "RequestTimeout" ||
    name === "TimeoutError" ||
    (isRecord(error) && error.$retryable === true)
  ) {
    return providerError({
      code: name?.startsWith("Throttling")
        ? "PROVIDER_RATE_LIMITED"
        : "PROVIDER_TRANSIENT",
      operation,
      retryable: true,
    });
  }
  return providerError({ code: "PROVIDER_RESOURCE_FAILED", operation });
}

async function parseProjectResponse(
  response: Response,
  operation: ProviderOperation,
): Promise<SupabaseProject> {
  const value = await parseJson(response, operation);
  const project = parseProject(value);
  if (!project) {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation,
    });
  }
  return project;
}

function parseProject(value: unknown): SupabaseProject | undefined {
  if (
    !isRecord(value) ||
    typeof value.ref !== "string" ||
    value.ref.length === 0 ||
    typeof value.name !== "string" ||
    typeof value.status !== "string"
  ) {
    return undefined;
  }
  return { ref: value.ref, name: value.name, status: value.status };
}

async function parseJson(
  response: Response,
  operation: ProviderOperation,
): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw providerError({
      code: "PROVIDER_RESPONSE_INVALID",
      operation,
    });
  }
}

function smartRegionFor(region: string): "americas" | "emea" | "apac" {
  if (region.startsWith("us-") || region.startsWith("ca-") || region.startsWith("sa-")) {
    return "americas";
  }
  if (region.startsWith("eu-") || region.startsWith("me-") || region.startsWith("af-")) {
    return "emea";
  }
  if (region.startsWith("ap-")) {
    return "apac";
  }
  throw providerError({
    code: "PROVIDER_INVALID_REQUEST",
    operation: "validate",
  });
}

function validateOrganizationSlug(value: string): string {
  if (!ORGANIZATION_SLUG_PATTERN.test(value)) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return value;
}

function validateCloudFormationRoleArn(value: string): string {
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,512}$/.test(value)) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return value;
}

function normalizeHttpsUrl(value: string, originOnly = false): string {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      (originOnly &&
        (url.pathname !== "/" || Boolean(url.search) || Boolean(url.hash)))
    ) {
      throw new Error("invalid");
    }
    return originOnly ? url.origin : url.toString();
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

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
