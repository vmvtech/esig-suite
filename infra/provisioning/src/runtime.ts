import type { CloudFormationClient } from "@aws-sdk/client-cloudformation";
import type { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

import { DynamoProvisioningStore } from "./aws/dynamo-provisioning-store.js";
import { SecretsManagerDatabasePasswordProvider } from "./aws/secrets-manager-database-password.js";
import { SecretsManagerOneTimeCredentialHandoff } from "./aws/secrets-manager-credential-handoff.js";
import {
  SafeProvisioningError,
  type DeploymentMode,
  type ProvisioningDriver,
} from "./domain.js";
import type { ProvisioningWorkerDependencies } from "./handlers/worker.js";
import { DEDICATED_MIGRATION_SOURCES } from "./providers/dedicated-migrations.js";
import { DedicatedProvisioningProvider } from "./providers/dedicated.js";
import { ProviderProvisioningDriver } from "./providers/driver.js";
import { SharedProvisioningProvider } from "./providers/shared.js";
import {
  SupabaseDedicatedTenantBootstrapper,
  type SupabaseManagementQueryRowsDecoder,
} from "./providers/supabase-dedicated-bootstrapper.js";
import type {
  DedicatedProviderResources,
  FetchTransport,
  SharedProviderResources,
} from "./providers/types.js";

type DynamoClient = Pick<DynamoDBDocumentClient, "send">;
type CloudFormationTransport = Pick<CloudFormationClient, "send">;
type SecretsManagerTransport = Pick<SecretsManagerClient, "send">;

export interface ProvisioningRuntimeConfig {
  readonly clients: {
    readonly dynamo: DynamoClient;
    readonly cloudFormation: CloudFormationTransport;
    readonly secretsManager: SecretsManagerTransport;
  };
  readonly tableName: string;
  /** Runtime region used to reconstruct provider requests from billing orders. */
  readonly region: string;
  readonly shared: {
    readonly supabaseUrl: string;
    readonly serviceRoleKey: string;
    readonly fetch?: FetchTransport;
  };
  readonly dedicated: {
    readonly managementToken: string;
    readonly organizationSlug: string;
    readonly templateUrl: string;
    readonly cloudFormationRoleArn?: string;
    readonly readinessTimeoutMs: number;
    readonly pollIntervalMs: number;
    readonly decodeQueryRows: SupabaseManagementQueryRowsDecoder;
    readonly fetch?: FetchTransport;
    readonly managementBaseUrl?: string;
    readonly sleep?: (milliseconds: number) => Promise<void>;
  };
  readonly secrets: {
    readonly databasePasswordPrefix: string;
    readonly credentialHandoffPrefix: string;
    readonly databasePasswordKmsKeyId?: string;
    readonly credentialHandoffKmsKeyId?: string;
  };
  readonly now?: () => number;
}

/**
 * Concrete adapters retained alongside worker-compatible dependencies for
 * deployment validation and dependency-level tests. Constructing this object
 * performs no AWS, Supabase, or CloudFormation calls.
 */
export interface ProvisioningRuntime extends ProvisioningWorkerDependencies {
  readonly sharedProvider: SharedProvisioningProvider;
  readonly dedicatedProvider: DedicatedProvisioningProvider;
  readonly sharedDriver: ProviderProvisioningDriver<SharedProviderResources>;
  readonly dedicatedDriver: ProviderProvisioningDriver<DedicatedProviderResources>;
  readonly dedicatedTenantBootstrapper: SupabaseDedicatedTenantBootstrapper;
  readonly databasePasswordProvider: SecretsManagerDatabasePasswordProvider;
  readonly dedicatedMigrationSources: typeof DEDICATED_MIGRATION_SOURCES;
}

/**
 * Builds the operational dependency graph without reading environment state or
 * installing it as the deployed Lambda handler. The caller must explicitly
 * supply every client, secret reference/value, endpoint, and response decoder.
 */
export function createProvisioningRuntime(
  config: ProvisioningRuntimeConfig,
): ProvisioningRuntime {
  const store = new DynamoProvisioningStore(
    config.clients.dynamo,
    config.tableName,
  );
  const databasePasswordProvider = new SecretsManagerDatabasePasswordProvider(
    config.clients.secretsManager,
    config.secrets.databasePasswordPrefix,
    { kmsKeyId: config.secrets.databasePasswordKmsKeyId },
  );
  const credentialHandoff = new SecretsManagerOneTimeCredentialHandoff(
    config.clients.secretsManager,
    config.secrets.credentialHandoffPrefix,
    { kmsKeyId: config.secrets.credentialHandoffKmsKeyId },
  );
  const dedicatedTenantBootstrapper =
    new SupabaseDedicatedTenantBootstrapper({
      managementToken: config.dedicated.managementToken,
      migrations: DEDICATED_MIGRATION_SOURCES,
      decodeQueryRows: config.dedicated.decodeQueryRows,
      fetch: config.dedicated.fetch,
      managementBaseUrl: config.dedicated.managementBaseUrl,
    });
  const sharedProvider = new SharedProvisioningProvider({
    supabaseUrl: config.shared.supabaseUrl,
    serviceRoleKey: config.shared.serviceRoleKey,
    fetch: config.shared.fetch,
  });
  const dedicatedProvider = new DedicatedProvisioningProvider({
    managementToken: config.dedicated.managementToken,
    organizationSlug: config.dedicated.organizationSlug,
    databasePasswordFor: databasePasswordProvider.databasePasswordFor,
    templateUrl: config.dedicated.templateUrl,
    cloudFormationRoleArn: config.dedicated.cloudFormationRoleArn,
    cloudFormation: config.clients.cloudFormation,
    tenantBootstrapper: dedicatedTenantBootstrapper,
    readinessTimeoutMs: config.dedicated.readinessTimeoutMs,
    pollIntervalMs: config.dedicated.pollIntervalMs,
    fetch: config.dedicated.fetch,
    managementBaseUrl: config.dedicated.managementBaseUrl,
    sleep: config.dedicated.sleep,
    now: config.now,
  });
  const sharedDriver = new ProviderProvisioningDriver({
    provider: sharedProvider,
    region: config.region,
  });
  const dedicatedDriver = new ProviderProvisioningDriver({
    provider: dedicatedProvider,
    region: config.region,
  });

  const driverFor = (mode: DeploymentMode): ProvisioningDriver => {
    if (mode === "shared") return sharedDriver;
    if (mode === "dedicated") return dedicatedDriver;
    throw new SafeProvisioningError("MODE_MISMATCH");
  };

  return Object.freeze({
    store,
    driverFor,
    credentialHandoff,
    now: config.now,
    sharedProvider,
    dedicatedProvider,
    sharedDriver,
    dedicatedDriver,
    dedicatedTenantBootstrapper,
    databasePasswordProvider,
    dedicatedMigrationSources: DEDICATED_MIGRATION_SOURCES,
  });
}
