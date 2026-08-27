import {
  CreateStackCommand,
  DescribeStacksCommand,
  UpdateStackCommand,
} from "@aws-sdk/client-cloudformation";
import { describe, expect, it, vi } from "vitest";

import {
  DEDICATED_REQUIRED_MIGRATIONS,
  DedicatedProvisioningProvider,
  deriveProviderIdentifiers,
  ProviderError,
  type DedicatedProviderResources,
  type DedicatedProvisioningProviderOptions,
  type DedicatedTenantBootstrapper,
  type ProvisioningRequest,
} from "../src/providers/index.js";

const REQUEST: ProvisioningRequest = {
  subscriptionId: "sub_dedicated_contract_001",
  customerId: "cus_dedicated_contract_001",
  ownerSubject: "owner@example.test",
  planCode: "scale",
  region: "us-east-1",
};

const PROJECT_REF = "abcdefghijklmnopqrst";
const MANAGEMENT_TOKEN = "fake-management-token-for-contract-tests";
const DATABASE_PASSWORD = "fake-unique-database-password-001";
const ROLE_ARN = "arn:aws:iam::123456789012:role/esig-customer-stack";
const CREDENTIAL = {
  id: "credential-dedicated-001",
  plaintext: "one-time-dedicated-credential-001",
} as const;
const REISSUED_CREDENTIAL = {
  id: "credential-dedicated-002",
  plaintext: "one-time-dedicated-credential-002",
} as const;

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function project(status = "ACTIVE_HEALTHY"): Record<string, unknown> {
  return {
    ref: PROJECT_REF,
    name: deriveProviderIdentifiers(REQUEST.subscriptionId, "dedicated").projectName,
    status,
  };
}

function health(ready: boolean): Array<Record<string, unknown>> {
  return ["auth", "rest", "storage"].map((name) => ({
    name,
    healthy: ready,
    status: ready ? "ACTIVE_HEALTHY" : "COMING_UP",
  }));
}

function stack(
  status: string,
  signingEnabled = "true",
): Record<string, unknown> {
  const identifiers = deriveProviderIdentifiers(REQUEST.subscriptionId, "dedicated");
  return {
    StackId: "arn:aws:cloudformation:us-east-1:123456789012:stack/esig/stack-id",
    StackName: identifiers.stackName,
    StackStatus: status,
    Parameters: [
      { ParameterKey: "SigningEnabled", ParameterValue: signingEnabled },
      { ParameterKey: "SupabaseProjectRef", ParameterValue: PROJECT_REF },
    ],
    Tags: [
      { Key: "e-sig:managed-by", Value: "cloud-provisioning" },
      { Key: "e-sig:subscription-id", Value: REQUEST.subscriptionId },
      { Key: "e-sig:tenant-id", Value: identifiers.tenantId },
    ],
  };
}

function missingStack(): Error {
  return Object.assign(new Error("stack does not exist"), {
    name: "ValidationError",
  });
}

function createTenantBootstrapper(
  overrides: Partial<DedicatedTenantBootstrapper> = {},
): DedicatedTenantBootstrapper {
  const tenantId = deriveProviderIdentifiers(
    REQUEST.subscriptionId,
    "dedicated",
  ).tenantId;
  return {
    applyMigrations: vi.fn(async () => ({
      appliedMigrations: [...DEDICATED_REQUIRED_MIGRATIONS],
    })),
    provisionTenant: vi.fn(async () => ({
      tenantId,
      status: "provisioning" as const,
      created: false,
    })),
    reissueCredential: vi.fn(async () => ({
      tenantId,
      oneTimeCredential: REISSUED_CREDENTIAL,
    })),
    markReady: vi.fn(async () => ({
      tenantId,
      status: "ready" as const,
    })),
    disableTenant: vi.fn(async () => ({
      tenantId,
      status: "disabled" as const,
    })),
    suspendTenant: vi.fn(async () => ({
      tenantId,
      status: "suspended" as const,
    })),
    resumeTenant: vi.fn(async () => ({
      tenantId,
      oneTimeCredential: REISSUED_CREDENTIAL,
    })),
    ...overrides,
  };
}

function createProvider(options: {
  fetchMock: ReturnType<typeof vi.fn>;
  sendMock: ReturnType<typeof vi.fn>;
  tenantBootstrapper?: DedicatedTenantBootstrapper;
  timeoutMs?: number;
  intervalMs?: number;
}): DedicatedProvisioningProvider {
  let now = 0;
  return new DedicatedProvisioningProvider({
    managementToken: MANAGEMENT_TOKEN,
    organizationSlug: "contract-org",
    databasePasswordFor: async () => DATABASE_PASSWORD,
    templateUrl: "https://templates.example.test/customer-stack.yaml",
    cloudFormationRoleArn: ROLE_ARN,
    cloudFormation: {
      send: options.sendMock,
    } as unknown as DedicatedProvisioningProviderOptions["cloudFormation"],
    tenantBootstrapper:
      options.tenantBootstrapper ?? createTenantBootstrapper(),
    readinessTimeoutMs: options.timeoutMs ?? 100,
    pollIntervalMs: options.intervalMs ?? 5,
    fetch: options.fetchMock as unknown as typeof fetch,
    now: () => now,
    sleep: async (milliseconds) => {
      now += milliseconds;
    },
  });
}

function readyResources(): DedicatedProviderResources {
  const identifiers = deriveProviderIdentifiers(REQUEST.subscriptionId, "dedicated");
  return {
    mode: "dedicated",
    subscriptionId: REQUEST.subscriptionId,
    tenantId: identifiers.tenantId,
    projectRef: PROJECT_REF,
    projectName: identifiers.projectName,
    stackId: String(stack("CREATE_COMPLETE").StackId),
    stackName: identifiers.stackName,
    status: "ready",
  };
}

describe("DedicatedProvisioningProvider contract", () => {
  it("uses current Supabase endpoints and deterministic CloudFormation identity", async () => {
    const bootstrapCalls: string[] = [];
    const tenantId = deriveProviderIdentifiers(
      REQUEST.subscriptionId,
      "dedicated",
    ).tenantId;
    const tenantBootstrapper = createTenantBootstrapper({
      applyMigrations: vi.fn(async ({ migrations }) => {
        bootstrapCalls.push("migrations");
        return { appliedMigrations: [...migrations] };
      }),
      provisionTenant: vi.fn(async () => {
        bootstrapCalls.push("tenant");
        return {
          tenantId,
          status: "provisioning" as const,
          created: true,
          oneTimeCredential: CREDENTIAL,
        };
      }),
      markReady: vi.fn(async () => {
        bootstrapCalls.push("ready");
        return { tenantId, status: "ready" as const };
      }),
    });
    let healthCalls = 0;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [], pagination: {} });
      }
      if (url.endsWith("/v1/projects") && init?.method === "POST") {
        return jsonResponse(project("INACTIVE"), 201);
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        healthCalls += 1;
        return jsonResponse(health(healthCalls > 1));
      }
      throw new Error("unexpected fake Management API request");
    });

    let describeCalls = 0;
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        describeCalls += 1;
        if (describeCalls === 1) throw missingStack();
        return {
          Stacks: [
            stack(
              describeCalls === 2 ? "CREATE_IN_PROGRESS" : "CREATE_COMPLETE",
            ),
          ],
        };
      }
      if (command instanceof CreateStackCommand) {
        return {};
      }
      throw new Error("unexpected fake CloudFormation command");
    });
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    const result = await provider.provision(REQUEST);

    expect(result.created).toBe(true);
    expect(result.oneTimeCredential).toEqual(CREDENTIAL);
    expect(result.resources).toMatchObject({
      mode: "dedicated",
      projectRef: PROJECT_REF,
      status: "provisioning",
    });
    expect(bootstrapCalls).toEqual(["migrations", "tenant"]);

    const ready = await provider.markReady(REQUEST, result.resources);
    expect(ready.status).toBe("ready");
    expect(bootstrapCalls).toEqual(["migrations", "tenant", "ready"]);
    expect(tenantBootstrapper.applyMigrations).toHaveBeenCalledWith({
      projectRef: PROJECT_REF,
      migrations: DEDICATED_REQUIRED_MIGRATIONS,
    });
    expect(tenantBootstrapper.provisionTenant).toHaveBeenCalledWith({
      request: REQUEST,
      tenantId,
      projectRef: PROJECT_REF,
      stackId: String(stack("CREATE_COMPLETE").StackId),
    });

    const managementCalls = fetchMock.mock.calls as Array<
      [string, RequestInit | undefined]
    >;
    const projectCreate = managementCalls.find(
      ([url, init]) => String(url).endsWith("/v1/projects") && init?.method === "POST",
    );
    expect(projectCreate).toBeDefined();
    expect(JSON.parse(String(projectCreate?.[1]?.body))).toEqual({
      name: deriveProviderIdentifiers(REQUEST.subscriptionId, "dedicated").projectName,
      organization_slug: "contract-org",
      db_pass: DATABASE_PASSWORD,
      region_selection: { type: "smartGroup", code: "americas" },
    });
    const healthUrls = managementCalls
      .map(([url]) => String(url))
      .filter((url) => url.includes("/health?"));
    expect(healthUrls[0]).toContain("services=auth&services=rest&services=storage");

    const createCommand = sendMock.mock.calls
      .map(([command]) => command)
      .find((command) => command instanceof CreateStackCommand);
    expect(createCommand).toBeInstanceOf(CreateStackCommand);
    const identifiers = deriveProviderIdentifiers(REQUEST.subscriptionId, "dedicated");
    expect((createCommand as CreateStackCommand).input).toMatchObject({
      StackName: identifiers.stackName,
      ClientRequestToken: identifiers.stackCreateToken,
      OnFailure: "DO_NOTHING",
      EnableTerminationProtection: true,
      RoleARN: ROLE_ARN,
    });
  });

  it("converges duplicate requests without a second project or stack", async () => {
    let projectExists = false;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({
          projects: projectExists ? [project()] : [],
          pagination: {},
        });
      }
      if (url.endsWith("/v1/projects") && init?.method === "POST") {
        projectExists = true;
        return jsonResponse(project(), 201);
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      if (url.endsWith(`/v1/projects/${PROJECT_REF}`) && init?.method === "GET") {
        return jsonResponse(project());
      }
      throw new Error("unexpected fake Management API request");
    });

    let stackExists = false;
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        if (!stackExists) throw missingStack();
        return { Stacks: [stack("CREATE_COMPLETE")] };
      }
      if (command instanceof CreateStackCommand) {
        stackExists = true;
        return {};
      }
      throw new Error("unexpected fake CloudFormation command");
    });
    const provider = createProvider({ fetchMock, sendMock });

    const first = await provider.provision(REQUEST);
    const duplicate = await provider.provision(REQUEST, first.resources);

    expect(duplicate.created).toBe(false);
    expect(duplicate.resources).toEqual(first.resources);
    expect(
      fetchMock.mock.calls.filter(
        ([url, init]) =>
          String(url).endsWith("/v1/projects") &&
          (init as RequestInit | undefined)?.method === "POST",
      ),
    ).toHaveLength(1);
    expect(
      sendMock.mock.calls.filter(
        ([command]) => command instanceof CreateStackCommand,
      ),
    ).toHaveLength(1);
  });

  it("forwards explicit credential recovery without persisting plaintext", async () => {
    const tenantBootstrapper = createTenantBootstrapper();
    const provider = createProvider({
      fetchMock: vi.fn(),
      sendMock: vi.fn(),
      tenantBootstrapper,
    });
    const resources = readyResources();

    const result = await provider.reissueCredential(REQUEST, resources);

    expect(tenantBootstrapper.reissueCredential).toHaveBeenCalledWith({
      subscriptionId: REQUEST.subscriptionId,
      tenantId: resources.tenantId,
      projectRef: PROJECT_REF,
      stackId: resources.stackId,
    });
    expect(result).toEqual({
      resources,
      oneTimeCredential: REISSUED_CREDENTIAL,
    });
    expect(JSON.stringify(result.resources)).not.toContain(
      REISSUED_CREDENTIAL.plaintext,
    );
  });

  it("resolves a create conflict by exact deterministic project name", async () => {
    let listCalls = 0;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        listCalls += 1;
        return jsonResponse({
          projects: listCalls > 1 ? [project()] : [],
          pagination: {},
        });
      }
      if (url.endsWith("/v1/projects") && init?.method === "POST") {
        return jsonResponse(
          { message: `conflict body contains ${DATABASE_PASSWORD}` },
          409,
        );
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        return { Stacks: [stack("CREATE_COMPLETE")] };
      }
      throw new Error("unexpected fake CloudFormation command");
    });
    const provider = createProvider({ fetchMock, sendMock });

    const result = await provider.provision(REQUEST);

    expect(result.created).toBe(false);
    expect(result.resources.projectRef).toBe(PROJECT_REF);
    expect(listCalls).toBe(2);
  });

  it("returns a retryable safe error and converges on the next attempt", async () => {
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi
      .fn()
      .mockRejectedValueOnce(
        Object.assign(new Error(`do not expose ${DATABASE_PASSWORD}`), {
          name: "ThrottlingException",
        }),
      )
      .mockResolvedValue({ Stacks: [stack("CREATE_COMPLETE")] });
    const provider = createProvider({ fetchMock, sendMock });

    let failure: unknown;
    try {
      await provider.provision(REQUEST);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(ProviderError);
    expect(failure).toMatchObject({
      code: "PROVIDER_RATE_LIMITED",
      retryable: true,
    });
    expect(String(failure)).not.toContain(DATABASE_PASSWORD);

    const retried = await provider.provision(REQUEST);
    expect(retried.resources.status).toBe("provisioning");
  });

  it("fails closed when the required database bootstrap adapter is absent", () => {
    expect(
      () =>
        new DedicatedProvisioningProvider({
          managementToken: MANAGEMENT_TOKEN,
          organizationSlug: "contract-org",
          databasePasswordFor: async () => DATABASE_PASSWORD,
          templateUrl: "https://templates.example.test/customer-stack.yaml",
          cloudFormation: { send: vi.fn() } as unknown as DedicatedProvisioningProviderOptions["cloudFormation"],
          tenantBootstrapper:
            undefined as unknown as DedicatedTenantBootstrapper,
          readinessTimeoutMs: 100,
          pollIntervalMs: 5,
          fetch: vi.fn() as unknown as typeof fetch,
        }),
    ).toThrowError(
      expect.objectContaining({
        code: "PROVIDER_INVALID_REQUEST",
        operation: "validate",
      }),
    );
  });

  it("will not create the customer stack when the migration ledger is incomplete", async () => {
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      throw new Error("unexpected fake Management API request");
    });
    const tenantBootstrapper = createTenantBootstrapper({
      applyMigrations: vi.fn(async () => ({
        appliedMigrations: DEDICATED_REQUIRED_MIGRATIONS.slice(0, 3),
      })),
    });
    const sendMock = vi.fn();
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    await expect(provider.provision(REQUEST)).rejects.toMatchObject({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "validate",
    });
    expect(sendMock).not.toHaveBeenCalled();
    expect(tenantBootstrapper.provisionTenant).not.toHaveBeenCalled();
    expect(tenantBootstrapper.markReady).not.toHaveBeenCalled();
  });

  it("keeps the tenant non-ready when tenant bootstrap or activation fails", async () => {
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        return { Stacks: [stack("CREATE_COMPLETE")] };
      }
      throw new Error("unexpected fake CloudFormation command");
    });
    const bootstrapFailure = new ProviderError({
      code: "PROVIDER_TRANSIENT",
      operation: "validate",
      retryable: true,
    });
    const tenantBootstrapper = createTenantBootstrapper({
      provisionTenant: vi.fn(async () => {
        throw bootstrapFailure;
      }),
    });
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    await expect(provider.provision(REQUEST)).rejects.toBe(bootstrapFailure);
    expect(tenantBootstrapper.markReady).not.toHaveBeenCalled();

    const resources = { ...readyResources(), status: "provisioning" as const };
    const activationFailure = new ProviderError({
      code: "PROVIDER_TRANSIENT",
      operation: "validate",
      retryable: true,
    });
    tenantBootstrapper.markReady = vi.fn(async () => {
      throw activationFailure;
    });

    await expect(provider.markReady(REQUEST, resources)).rejects.toBe(
      activationFailure,
    );
    expect(resources.status).toBe("provisioning");
  });

  it("rejects a tenant bootstrap that claims readiness before markReady", async () => {
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        return { Stacks: [stack("CREATE_COMPLETE")] };
      }
      throw new Error("unexpected fake CloudFormation command");
    });
    const tenantId = deriveProviderIdentifiers(
      REQUEST.subscriptionId,
      "dedicated",
    ).tenantId;
    const tenantBootstrapper = createTenantBootstrapper({
      provisionTenant: vi.fn(async () => ({
        tenantId,
        status: "ready" as const,
        created: false,
      })),
    });
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    await expect(provider.provision(REQUEST)).rejects.toMatchObject({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "validate",
    });
    expect(tenantBootstrapper.markReady).not.toHaveBeenCalled();
  });

  it("does not disable infrastructure before tenant access is revoked", async () => {
    const disableFailure = new ProviderError({
      code: "PROVIDER_TRANSIENT",
      operation: "validate",
      retryable: true,
    });
    const tenantBootstrapper = createTenantBootstrapper({
      disableTenant: vi.fn(async () => {
        throw disableFailure;
      }),
    });
    const fetchMock = vi.fn();
    const sendMock = vi.fn();
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    await expect(provider.disable(REQUEST, readyResources())).rejects.toBe(
      disableFailure,
    );
    expect(sendMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("suspends signing without pausing Supabase and re-enables it on paid recovery", async () => {
    let signingEnabled = true;
    const tenantBootstrapper = createTenantBootstrapper();
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(true));
      }
      throw new Error("unexpected Management API request");
    });
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        return {
          Stacks: [stack("UPDATE_COMPLETE", signingEnabled ? "true" : "false")],
        };
      }
      if (command instanceof UpdateStackCommand) {
        signingEnabled =
          command.input.Parameters?.[0]?.ParameterValue === "true";
        return {};
      }
      throw new Error("unexpected CloudFormation command");
    });
    const provider = createProvider({ fetchMock, sendMock, tenantBootstrapper });

    const suspended = await provider.suspend(REQUEST, readyResources());

    expect(suspended.status).toBe("suspended");
    expect(tenantBootstrapper.suspendTenant).toHaveBeenCalledTimes(1);
    expect(signingEnabled).toBe(false);
    expect(
      fetchMock.mock.calls.some(([url]) => String(url).endsWith("/pause")),
    ).toBe(false);

    const resumed = await provider.resume(REQUEST, suspended);

    expect(resumed.resources.status).toBe("provisioning");
    expect(resumed.oneTimeCredential).toEqual(REISSUED_CREDENTIAL);
    expect(tenantBootstrapper.resumeTenant).toHaveBeenCalledTimes(1);
    expect(signingEnabled).toBe(true);
    const signingUpdates = sendMock.mock.calls
      .map(([command]) => command)
      .filter((command): command is UpdateStackCommand =>
        command instanceof UpdateStackCommand,
      )
      .map((command) => command.input.Parameters?.[0]?.ParameterValue);
    expect(signingUpdates).toEqual(["false", "true"]);
  });

  it("fails with an explicit safe timeout before creating a stack", async () => {
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.includes(`/v1/projects/${PROJECT_REF}/health?`)) {
        return jsonResponse(health(false));
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi.fn();
    const provider = createProvider({
      fetchMock,
      sendMock,
      timeoutMs: 10,
      intervalMs: 5,
    });

    await expect(provider.provision(REQUEST)).rejects.toMatchObject({
      code: "PROVIDER_TIMEOUT",
      operation: "dedicated.project.health",
      retryable: true,
    });
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("converges unknown compensation when no deterministic resources exist", async () => {
    const fetchMock = vi.fn(async (input: unknown) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [], pagination: {} });
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) throw missingStack();
      throw new Error("unexpected fake CloudFormation command");
    });
    const tenantBootstrapper = createTenantBootstrapper();
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    const result = await provider.compensateUnknown(REQUEST);

    expect(result).toEqual({
      mode: "dedicated",
      tenantId: deriveProviderIdentifiers(
        REQUEST.subscriptionId,
        "dedicated",
      ).tenantId,
      outcome: "absent",
    });
    expect(tenantBootstrapper.disableTenant).not.toHaveBeenCalled();
    expect(tenantBootstrapper.applyMigrations).not.toHaveBeenCalled();
    expect(tenantBootstrapper.provisionTenant).not.toHaveBeenCalled();
    expect(
      sendMock.mock.calls.some(
        ([command]) => command instanceof CreateStackCommand,
      ),
    ).toBe(false);
  });

  it("pauses a project-only commit-unknown effect without creating a stack", async () => {
    let projectGets = 0;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.endsWith(`/v1/projects/${PROJECT_REF}`) && init?.method === "GET") {
        projectGets += 1;
        return jsonResponse(
          project(projectGets === 1 ? "ACTIVE_HEALTHY" : "INACTIVE"),
        );
      }
      if (
        url.endsWith(`/v1/projects/${PROJECT_REF}/pause`) &&
        init?.method === "POST"
      ) {
        return jsonResponse({});
      }
      throw new Error("unexpected fake Management API request");
    });
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) throw missingStack();
      throw new Error("unexpected fake CloudFormation command");
    });
    const tenantBootstrapper = createTenantBootstrapper();
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    const result = await provider.compensateUnknown(REQUEST);

    expect(result.outcome).toBe("disabled");
    expect(tenantBootstrapper.disableTenant).not.toHaveBeenCalled();
    expect(tenantBootstrapper.applyMigrations).not.toHaveBeenCalled();
    expect(tenantBootstrapper.provisionTenant).not.toHaveBeenCalled();
    expect(
      sendMock.mock.calls.some(
        ([command]) => command instanceof CreateStackCommand,
      ),
    ).toBe(false);
    expect(
      fetchMock.mock.calls.filter(
        ([url]) => String(url).endsWith(`/v1/projects/${PROJECT_REF}/pause`),
      ),
    ).toHaveLength(1);
  });

  it("revokes, disables, and pauses a project-plus-stack commit-unknown effect", async () => {
    let projectGets = 0;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/v1/organizations/contract-org/projects?")) {
        return jsonResponse({ projects: [project()], pagination: {} });
      }
      if (url.endsWith(`/v1/projects/${PROJECT_REF}`) && init?.method === "GET") {
        projectGets += 1;
        return jsonResponse(
          project(projectGets === 1 ? "ACTIVE_HEALTHY" : "INACTIVE"),
        );
      }
      if (
        url.endsWith(`/v1/projects/${PROJECT_REF}/pause`) &&
        init?.method === "POST"
      ) {
        return jsonResponse({});
      }
      throw new Error("unexpected fake Management API request");
    });
    let describes = 0;
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        describes += 1;
        return {
          Stacks: [stack("UPDATE_COMPLETE", describes < 3 ? "true" : "false")],
        };
      }
      if (command instanceof UpdateStackCommand) return {};
      throw new Error("unexpected fake CloudFormation command");
    });
    const missingTenant = Object.assign(new Error("tenant absent"), {
      code: "PROVIDER_NOT_FOUND" as const,
    });
    const tenantBootstrapper = createTenantBootstrapper({
      disableTenant: vi.fn(async () => {
        throw missingTenant;
      }),
    });
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });

    const result = await provider.compensateUnknown(REQUEST);

    const identifiers = deriveProviderIdentifiers(
      REQUEST.subscriptionId,
      "dedicated",
    );
    expect(result).toEqual({
      mode: "dedicated",
      tenantId: identifiers.tenantId,
      outcome: "disabled",
    });
    expect(tenantBootstrapper.disableTenant).toHaveBeenCalledWith({
      subscriptionId: REQUEST.subscriptionId,
      tenantId: identifiers.tenantId,
      projectRef: PROJECT_REF,
      stackId: String(stack("CREATE_COMPLETE").StackId),
    });
    expect(
      sendMock.mock.calls.filter(
        ([command]) => command instanceof UpdateStackCommand,
      ),
    ).toHaveLength(1);
    expect(
      sendMock.mock.calls.some(
        ([command]) => command instanceof CreateStackCommand,
      ),
    ).toBe(false);
    expect(
      fetchMock.mock.calls.filter(
        ([url]) => String(url).endsWith(`/v1/projects/${PROJECT_REF}/pause`),
      ),
    ).toHaveLength(1);
  });

  it("compensates twice by disabling and pausing, never deleting resources", async () => {
    let projectGets = 0;
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith(`/v1/projects/${PROJECT_REF}`) && init?.method === "GET") {
        projectGets += 1;
        return jsonResponse(project(projectGets === 1 ? "ACTIVE_HEALTHY" : "INACTIVE"));
      }
      if (url.endsWith(`/v1/projects/${PROJECT_REF}/pause`) && init?.method === "POST") {
        return jsonResponse({});
      }
      throw new Error("unexpected fake Management API request");
    });

    let describes = 0;
    const sendMock = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeStacksCommand) {
        describes += 1;
        if (describes === 1) {
          return { Stacks: [stack("UPDATE_COMPLETE", "true")] };
        }
        if (describes === 2) {
          return { Stacks: [stack("UPDATE_IN_PROGRESS", "true")] };
        }
        return { Stacks: [stack("UPDATE_COMPLETE", "false")] };
      }
      if (command instanceof UpdateStackCommand) {
        return {};
      }
      throw new Error("unexpected fake CloudFormation command");
    });
    const tenantBootstrapper = createTenantBootstrapper();
    const provider = createProvider({
      fetchMock,
      sendMock,
      tenantBootstrapper,
    });
    const resources = readyResources();

    const first = await provider.compensate(REQUEST, resources);
    const duplicate = await provider.compensate(REQUEST, first);

    expect(first.status).toBe("disabled");
    expect(duplicate).toEqual(first);
    expect(tenantBootstrapper.disableTenant).toHaveBeenCalledTimes(2);
    expect(tenantBootstrapper.disableTenant).toHaveBeenLastCalledWith({
      subscriptionId: REQUEST.subscriptionId,
      tenantId: resources.tenantId,
      projectRef: PROJECT_REF,
      stackId: resources.stackId,
    });
    const updateCommands = sendMock.mock.calls
      .map(([command]) => command)
      .filter((command) => command instanceof UpdateStackCommand);
    expect(updateCommands).toHaveLength(1);
    expect((updateCommands[0] as UpdateStackCommand).input).toMatchObject({
      RoleARN: ROLE_ARN,
      Parameters: [
        { ParameterKey: "SigningEnabled", ParameterValue: "false" },
      ],
    });
    expect(
      sendMock.mock.calls.some(
        ([command]) => command?.constructor?.name === "DeleteStackCommand",
      ),
    ).toBe(false);
    expect(
      fetchMock.mock.calls.some(
        ([, init]) => (init as RequestInit | undefined)?.method === "DELETE",
      ),
    ).toBe(false);
    expect(
      fetchMock.mock.calls.filter(
        ([url]) => String(url).endsWith(`/v1/projects/${PROJECT_REF}/pause`),
      ),
    ).toHaveLength(1);
  });
});
