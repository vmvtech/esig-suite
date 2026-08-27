import { describe, expect, it, vi } from "vitest";

import { DynamoProvisioningStore } from "../src/aws/dynamo-provisioning-store.js";
import { SecretsManagerDatabasePasswordProvider } from "../src/aws/secrets-manager-database-password.js";
import { SecretsManagerOneTimeCredentialHandoff } from "../src/aws/secrets-manager-credential-handoff.js";
import { DEDICATED_MIGRATION_SOURCES } from "../src/providers/dedicated-migrations.js";
import { DedicatedProvisioningProvider } from "../src/providers/dedicated.js";
import { ProviderProvisioningDriver } from "../src/providers/driver.js";
import { SharedProvisioningProvider } from "../src/providers/shared.js";
import { SupabaseDedicatedTenantBootstrapper } from "../src/providers/supabase-dedicated-bootstrapper.js";
import {
  createProvisioningRuntime,
  type ProvisioningRuntimeConfig,
} from "../src/runtime.js";

function runtimeConfig(): {
  readonly config: ProvisioningRuntimeConfig;
  readonly send: ReturnType<typeof vi.fn>;
  readonly fetch: ReturnType<typeof vi.fn>;
  readonly decodeQueryRows: ReturnType<typeof vi.fn>;
} {
  const send = vi.fn();
  const fetch = vi.fn();
  const decodeQueryRows = vi.fn(() => []);
  return {
    send,
    fetch,
    decodeQueryRows,
    config: {
      clients: {
        dynamo: { send } as never,
        cloudFormation: { send } as never,
        secretsManager: { send } as never,
      },
      tableName: "esig-private-preview-provisioning",
      region: "us-east-1",
      shared: {
        supabaseUrl: "https://shared.example.supabase.co",
        serviceRoleKey: "shared-service-role-test-value",
        fetch: fetch as never,
      },
      dedicated: {
        managementToken: "management-token-test-value",
        organizationSlug: "esig-private-preview",
        templateUrl: "https://artifacts.example.com/customer-stack.yaml",
        readinessTimeoutMs: 60_000,
        pollIntervalMs: 1_000,
        decodeQueryRows,
        fetch: fetch as never,
        managementBaseUrl: "https://api.supabase.com",
        sleep: vi.fn(async () => undefined),
      },
      secrets: {
        databasePasswordPrefix: "e-sig/private-preview/database-passwords",
        credentialHandoffPrefix: "e-sig/private-preview/credential-handoffs",
        databasePasswordKmsKeyId: "alias/e-sig-private-preview",
        credentialHandoffKmsKeyId: "alias/e-sig-private-preview",
      },
      now: () => 1_725_000_000_000,
    },
  };
}

describe("createProvisioningRuntime", () => {
  it("constructs the concrete operational graph without external calls", () => {
    const { config, send, fetch, decodeQueryRows } = runtimeConfig();
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const runtime = createProvisioningRuntime(config);

    expect(runtime.store).toBeInstanceOf(DynamoProvisioningStore);
    expect(runtime.sharedProvider).toBeInstanceOf(SharedProvisioningProvider);
    expect(runtime.dedicatedProvider).toBeInstanceOf(
      DedicatedProvisioningProvider,
    );
    expect(runtime.sharedDriver).toBeInstanceOf(ProviderProvisioningDriver);
    expect(runtime.dedicatedDriver).toBeInstanceOf(ProviderProvisioningDriver);
    expect(runtime.dedicatedTenantBootstrapper).toBeInstanceOf(
      SupabaseDedicatedTenantBootstrapper,
    );
    expect(runtime.databasePasswordProvider).toBeInstanceOf(
      SecretsManagerDatabasePasswordProvider,
    );
    expect(runtime.credentialHandoff).toBeInstanceOf(
      SecretsManagerOneTimeCredentialHandoff,
    );
    expect(Object.isFrozen(runtime)).toBe(true);
    expect(send).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(decodeQueryRows).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });

  it("routes each deployment mode to its concrete provider driver", () => {
    const { config } = runtimeConfig();
    const runtime = createProvisioningRuntime(config);

    expect(runtime.driverFor("shared")).toBe(runtime.sharedDriver);
    expect(runtime.driverFor("dedicated")).toBe(runtime.dedicatedDriver);
    expect(runtime.sharedDriver.mode).toBe("shared");
    expect(runtime.dedicatedDriver.mode).toBe("dedicated");
    expect(() => runtime.driverFor("invalid" as never)).toThrow(
      expect.objectContaining({ safeCode: "MODE_MISMATCH" }),
    );
  });

  it("binds the exact immutable repository migrations into dedicated bootstrap", () => {
    const { config } = runtimeConfig();
    const runtime = createProvisioningRuntime(config);

    expect(runtime.dedicatedMigrationSources).toBe(
      DEDICATED_MIGRATION_SOURCES,
    );
    expect(runtime.dedicatedMigrationSources).toHaveLength(4);
    expect(runtime.dedicatedMigrationSources.map(({ name }) => name)).toEqual([
      "0001_esig_self_contained.sql",
      "0002_esig_audit_hashchain.sql",
      "0003_esig_pq_keys.sql",
      "0004_esig_cloud_tenants.sql",
    ]);
    expect(Object.isFrozen(runtime.dedicatedMigrationSources)).toBe(true);
    expect(runtime.dedicatedMigrationSources.every(({ sql }) => sql.length > 0)).toBe(
      true,
    );
  });

  it("requires the explicit Management API rows decoder", () => {
    const { config } = runtimeConfig();
    const invalid = {
      ...config,
      dedicated: { ...config.dedicated, decodeQueryRows: undefined },
    } as unknown as ProvisioningRuntimeConfig;

    expect(() => createProvisioningRuntime(invalid)).toThrow(
      expect.objectContaining({
        code: "PROVIDER_INVALID_REQUEST",
        operation: "migration.ledger",
      }),
    );
  });

  it("delegates validation to the concrete adapter constructors", () => {
    const { config } = runtimeConfig();
    expect(() =>
      createProvisioningRuntime({
        ...config,
        region: "invalid-region",
      }),
    ).toThrow(expect.objectContaining({ safeCode: "PROVIDER_INVALID_REQUEST" }));
  });
});
