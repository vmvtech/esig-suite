import { createHash } from "node:crypto";

import {
  DEDICATED_REQUIRED_MIGRATIONS,
  type DedicatedCredentialReissueResult,
  type DedicatedMigrationInput,
  type DedicatedMigrationResult,
  type DedicatedRequiredMigration,
  type DedicatedTenantBootstrapper,
  type DedicatedTenantIdentity,
  type DedicatedTenantInput,
  type DedicatedTenantProvisioningResult,
  type DedicatedTenantResumeResult,
  type DedicatedTenantStateResult,
} from "./dedicated.js";
import {
  deriveProviderIdentifiers,
  normalizeOwnerEmail,
  validateProvisioningRequest,
} from "./deterministic.js";
import type { ProviderErrorCode } from "./errors.js";
import type { FetchTransport, ProvisioningPlan } from "./types.js";

const DEFAULT_MANAGEMENT_BASE_URL = "https://api.supabase.com";
const MIGRATION_LEDGER = "public.esig_cloud_schema_migrations";
const MIGRATION_LOCK = "e-sig:dedicated:schema-migrations:v1";
const PROJECT_REF_PATTERN = /^[a-z0-9]{20}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CHECKSUM_PATTERN = /^[0-9a-f]{64}$/;
const PLAN_KEYS: Readonly<Record<ProvisioningPlan, string>> = {
  starter: "cloud_starter",
  team: "cloud_team",
  scale: "cloud_scale",
};

const CREATE_LEDGER_SQL = `
CREATE TABLE IF NOT EXISTS ${MIGRATION_LEDGER} (
  version text PRIMARY KEY CHECK (version ~ '^000[1-4]_esig_[a-z0-9_]+\\.sql$'),
  ordinal smallint NOT NULL UNIQUE CHECK (ordinal BETWEEN 1 AND 4),
  checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
  applied_at timestamptz NOT NULL DEFAULT now()
);`;

const READ_LEDGER_SQL = `
WITH migration_lock AS MATERIALIZED (
  SELECT pg_advisory_xact_lock(hashtext($1::text)) AS acquired
)
SELECT COALESCE(
  jsonb_agg(
    jsonb_build_object(
      'version', migration.version,
      'ordinal', migration.ordinal,
      'checksum', migration.checksum
    ) ORDER BY migration.ordinal
  ) FILTER (WHERE migration.version IS NOT NULL),
  '[]'::jsonb
) AS migrations
FROM migration_lock
LEFT JOIN ${MIGRATION_LEDGER} AS migration ON true;`;

const PROVISION_TENANT_SQL = `
SELECT
  tenant_id::text AS tenant_id,
  organization_status,
  provisioning_state,
  storage_namespace,
  credential_id::text AS credential_id,
  credential_plaintext,
  created
FROM public.provision_esig_tenant(
  $1::uuid,
  $2::text,
  $3::text,
  $4::text,
  $5::text,
  $6::text,
  $7::text,
  $8::text,
  $9::text
);`;

const MARK_READY_SQL = `
WITH target AS MATERIALIZED (
  SELECT organization.id
  FROM public.esig_organizations AS organization
  WHERE organization.id = $1::uuid
    AND organization.stripe_subscription_id = $2::text
    AND organization.dedicated_stack_id = $3::text
), applied AS MATERIALIZED (
  SELECT public.mark_esig_tenant_ready(target.id) AS ignored
  FROM target
)
SELECT
  organization.id::text AS tenant_id,
  organization.status AS organization_status,
  provisioning.state AS provisioning_state
FROM applied
JOIN target ON true
JOIN public.esig_organizations AS organization ON organization.id = target.id
JOIN public.esig_tenant_provisioning AS provisioning
  ON provisioning.tenant_id = organization.id;`;

const REISSUE_CREDENTIAL_SQL = `
WITH target AS MATERIALIZED (
  SELECT organization.id
  FROM public.esig_organizations AS organization
  WHERE organization.id = $1::uuid
    AND organization.stripe_subscription_id = $2::text
    AND organization.dedicated_stack_id = $3::text
), reissued AS MATERIALIZED (
  SELECT
    credential.credential_id,
    credential.credential_plaintext
  FROM target
  CROSS JOIN LATERAL public.reissue_esig_tenant_credential(
    target.id,
    $2::text
  ) AS credential
)
SELECT
  target.id::text AS tenant_id,
  reissued.credential_id::text AS credential_id,
  reissued.credential_plaintext
FROM target
JOIN reissued ON true;`;

const DISABLE_TENANT_SQL = `
WITH target AS MATERIALIZED (
  SELECT organization.id
  FROM public.esig_organizations AS organization
  WHERE organization.id = $1::uuid
    AND organization.stripe_subscription_id = $2::text
    AND organization.dedicated_stack_id = $3::text
), applied AS MATERIALIZED (
  SELECT public.disable_esig_tenant(target.id, $4::text, $5::text) AS ignored
  FROM target
)
SELECT
  organization.id::text AS tenant_id,
  organization.status AS organization_status,
  provisioning.state AS provisioning_state
FROM applied
JOIN target ON true
JOIN public.esig_organizations AS organization ON organization.id = target.id
JOIN public.esig_tenant_provisioning AS provisioning
  ON provisioning.tenant_id = organization.id;`;

const RESUME_TENANT_SQL = `
WITH target AS MATERIALIZED (
  SELECT organization.id
  FROM public.esig_organizations AS organization
  WHERE organization.id = $1::uuid
    AND organization.stripe_subscription_id = $2::text
    AND organization.dedicated_stack_id = $3::text
)
SELECT
  resumed.tenant_id::text AS tenant_id,
  resumed.organization_status,
  resumed.provisioning_state,
  resumed.storage_namespace,
  resumed.credential_id::text AS credential_id,
  resumed.credential_plaintext,
  resumed.resumed
FROM target
CROSS JOIN LATERAL public.resume_esig_tenant(target.id, $2::text) AS resumed;`;

export interface SupabaseDedicatedMigrationSource {
  readonly name: DedicatedRequiredMigration;
  readonly sql: string;
}

/**
 * The Management API documents the database/query request but intentionally
 * leaves its successful response schema open. Keep that unstable translation
 * at this one boundary and make deployment choose it explicitly.
 */
export type SupabaseManagementQueryRowsDecoder = (
  payload: unknown,
) => readonly unknown[];

export interface SupabaseDedicatedTenantBootstrapperOptions {
  readonly managementToken: string;
  readonly migrations: readonly SupabaseDedicatedMigrationSource[];
  readonly decodeQueryRows: SupabaseManagementQueryRowsDecoder;
  readonly fetch?: FetchTransport;
  readonly managementBaseUrl?: string;
}

type BootstrapOperation =
  | "migration.ledger"
  | "migration.apply"
  | "tenant.provision"
  | "tenant.reissue"
  | "tenant.mark_ready"
  | "tenant.resume"
  | "tenant.suspend"
  | "tenant.disable";

const SAFE_MESSAGES: Readonly<Record<ProviderErrorCode, string>> = {
  PROVIDER_INVALID_REQUEST: "Dedicated database bootstrap request is invalid.",
  PROVIDER_AUTH_FAILED: "Dedicated database bootstrap authentication failed.",
  PROVIDER_RATE_LIMITED: "Dedicated database bootstrap rate limit reached.",
  PROVIDER_CONFLICT: "Dedicated database bootstrap integrity conflict.",
  PROVIDER_NOT_FOUND: "Dedicated database project was not found.",
  PROVIDER_TRANSIENT: "Dedicated database bootstrap is temporarily unavailable.",
  PROVIDER_TIMEOUT: "Dedicated database bootstrap timed out.",
  PROVIDER_RESPONSE_INVALID: "Dedicated database bootstrap returned invalid proof.",
  PROVIDER_RESOURCE_FAILED: "Dedicated database bootstrap failed.",
};

export class SupabaseDedicatedBootstrapError extends Error {
  readonly code: ProviderErrorCode;
  readonly operation: BootstrapOperation;
  readonly retryable: boolean;
  readonly statusCode?: number;

  constructor(options: {
    code: ProviderErrorCode;
    operation: BootstrapOperation;
    retryable?: boolean;
    statusCode?: number;
  }) {
    super(SAFE_MESSAGES[options.code]);
    this.name = "SupabaseDedicatedBootstrapError";
    this.code = options.code;
    this.operation = options.operation;
    this.retryable = options.retryable ?? false;
    this.statusCode = options.statusCode;
  }
}

interface ImmutableMigrationSource extends SupabaseDedicatedMigrationSource {
  readonly ordinal: number;
  readonly checksum: string;
}

interface MigrationLedgerRow {
  readonly version: DedicatedRequiredMigration;
  readonly ordinal: number;
  readonly checksum: string;
}

interface ProvisionTenantRow {
  readonly tenant_id: string;
  readonly organization_status: "provisioning" | "ready";
  readonly provisioning_state: "provisioning" | "ready";
  readonly storage_namespace: string;
  readonly credential_id: string;
  readonly credential_plaintext: string | null;
  readonly created: boolean;
}

interface TenantStateRow {
  readonly tenant_id: string;
  readonly organization_status: "ready" | "disabled";
  readonly provisioning_state: "ready" | "disabled";
}

interface CredentialReissueRow {
  readonly tenant_id: string;
  readonly credential_id: string;
  readonly credential_plaintext: string;
}

interface ResumeTenantRow {
  readonly tenant_id: string;
  readonly organization_status: "provisioning";
  readonly provisioning_state: "provisioning";
  readonly storage_namespace: string;
  readonly credential_id: string;
  readonly credential_plaintext: string | null;
  readonly resumed: boolean;
}

export class SupabaseDedicatedTenantBootstrapper
  implements DedicatedTenantBootstrapper
{
  readonly #managementToken: string;
  readonly #migrations: readonly ImmutableMigrationSource[];
  readonly #decodeQueryRows: SupabaseManagementQueryRowsDecoder;
  readonly #fetch: FetchTransport;
  readonly #managementBaseUrl: string;

  constructor(options: SupabaseDedicatedTenantBootstrapperOptions) {
    this.#managementToken = requireSecret(options.managementToken);
    this.#migrations = immutableMigrationSources(options.migrations);
    this.#decodeQueryRows = requireDecoder(options.decodeQueryRows);
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#managementBaseUrl = normalizeHttpsOrigin(
      options.managementBaseUrl ?? DEFAULT_MANAGEMENT_BASE_URL,
    );
  }

  async applyMigrations(
    input: DedicatedMigrationInput,
  ): Promise<DedicatedMigrationResult> {
    const projectRef = validateProjectRef(input.projectRef);
    validateRequestedMigrations(input.migrations);
    await this.#ensureLedger(projectRef);

    let ledger = await this.#readAndValidateLedger(projectRef);
    for (const migration of this.#migrations.slice(ledger.length)) {
      const query = migrationApplicationSql(migration);
      let requestError: unknown;
      try {
        await this.#postSql(
          projectRef,
          query,
          [],
          false,
          "migration.apply",
        );
      } catch (error: unknown) {
        requestError = error;
      }

      try {
        ledger = await this.#readAndValidateLedger(projectRef);
      } catch (proofError: unknown) {
        if (
          proofError instanceof SupabaseDedicatedBootstrapError &&
          (proofError.code === "PROVIDER_CONFLICT" ||
            proofError.code === "PROVIDER_RESPONSE_INVALID")
        ) {
          throw proofError;
        }
        if (requestError !== undefined) throw requestError;
        throw proofError;
      }

      const applied = ledger[migration.ordinal - 1];
      if (
        applied?.version !== migration.name ||
        applied.checksum !== migration.checksum
      ) {
        if (requestError !== undefined) throw requestError;
        throw bootstrapError(
          "PROVIDER_RESPONSE_INVALID",
          "migration.apply",
        );
      }
      // If the request outcome was unknown but the durable ledger proves the
      // exact checksum, the transaction committed and retry is safe to skip.
    }

    if (ledger.length !== this.#migrations.length) {
      throw bootstrapError("PROVIDER_RESPONSE_INVALID", "migration.ledger");
    }
    return { appliedMigrations: ledger.map((row) => row.version) };
  }

  async provisionTenant(
    input: DedicatedTenantInput,
  ): Promise<DedicatedTenantProvisioningResult> {
    validateProvisioningRequest(input.request);
    const projectRef = validateProjectRef(input.projectRef);
    validateTenantIdentity(input.request.subscriptionId, input.tenantId);
    validateStackId(input.stackId);
    const metadata = tenantMetadata(input.tenantId);

    const rows = await this.#queryRows(
      projectRef,
      PROVISION_TENANT_SQL,
      [
        input.tenantId,
        input.request.subscriptionId,
        input.request.customerId,
        normalizeOwnerEmail(input.request.ownerSubject),
        metadata.displayName,
        metadata.slug,
        PLAN_KEYS[input.request.planCode],
        "dedicated",
        input.stackId,
      ],
      "tenant.provision",
    );
    const row = parseProvisionTenantRow(rows);
    if (
      row.tenant_id !== input.tenantId ||
      row.storage_namespace !== `${input.tenantId}/`
    ) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.provision");
    }
    const status = matchingProvisioningStatus(row);
    const result: DedicatedTenantProvisioningResult = {
      tenantId: row.tenant_id,
      status,
      created: row.created,
    };
    if (row.credential_plaintext === null) return result;
    return {
      ...result,
      oneTimeCredential: {
        id: row.credential_id,
        plaintext: row.credential_plaintext,
      },
    };
  }

  async reissueCredential(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedCredentialReissueResult> {
    validateDedicatedIdentity(input);
    const rows = await this.#queryRows(
      input.projectRef,
      REISSUE_CREDENTIAL_SQL,
      [input.tenantId, input.subscriptionId, input.stackId],
      "tenant.reissue",
    );
    const row = parseCredentialReissueRow(rows);
    if (row.tenant_id !== input.tenantId) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.reissue");
    }
    return {
      tenantId: row.tenant_id,
      oneTimeCredential: {
        id: row.credential_id,
        plaintext: row.credential_plaintext,
      },
    };
  }

  async markReady(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedTenantStateResult> {
    validateDedicatedIdentity(input);
    const rows = await this.#queryRows(
      input.projectRef,
      MARK_READY_SQL,
      [input.tenantId, input.subscriptionId, input.stackId],
      "tenant.mark_ready",
    );
    const row = parseTenantStateRow(rows, "ready", "tenant.mark_ready");
    if (row.tenant_id !== input.tenantId) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.mark_ready");
    }
    return { tenantId: row.tenant_id, status: "ready" };
  }

  async disableTenant(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedTenantStateResult> {
    validateDedicatedIdentity(input);
    const rows = await this.#queryRows(
      input.projectRef,
      DISABLE_TENANT_SQL,
      [input.tenantId, input.subscriptionId, input.stackId, "canceled", null],
      "tenant.disable",
    );
    const row = parseTenantStateRow(rows, "disabled", "tenant.disable");
    if (row.tenant_id !== input.tenantId) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.disable");
    }
    return { tenantId: row.tenant_id, status: "disabled" };
  }

  async suspendTenant(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedTenantStateResult> {
    validateDedicatedIdentity(input);
    const rows = await this.#queryRows(
      input.projectRef,
      DISABLE_TENANT_SQL,
      [input.tenantId, input.subscriptionId, input.stackId, "past_due", null],
      "tenant.suspend",
    );
    const row = parseTenantStateRow(rows, "suspended", "tenant.suspend");
    if (row.tenant_id !== input.tenantId) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.suspend");
    }
    return { tenantId: row.tenant_id, status: "suspended" };
  }

  async resumeTenant(
    input: DedicatedTenantIdentity,
  ): Promise<DedicatedTenantResumeResult> {
    validateDedicatedIdentity(input);
    let rows = await this.#queryRows(
      input.projectRef,
      RESUME_TENANT_SQL,
      [input.tenantId, input.subscriptionId, input.stackId],
      "tenant.resume",
    );
    const resumed = parseResumeTenantRow(rows);
    if (
      resumed.tenant_id !== input.tenantId ||
      resumed.storage_namespace !== `${input.tenantId}/`
    ) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.resume");
    }
    if (resumed.credential_plaintext !== null) {
      return {
        tenantId: resumed.tenant_id,
        oneTimeCredential: {
          id: resumed.credential_id,
          plaintext: resumed.credential_plaintext,
        },
      };
    }
    const reissueRows = await this.#queryRows(
      input.projectRef,
      REISSUE_CREDENTIAL_SQL,
      [input.tenantId, input.subscriptionId, input.stackId],
      "tenant.reissue",
    );
    const row = parseCredentialReissueRow(reissueRows);
    if (row.tenant_id !== input.tenantId) {
      throw bootstrapError("PROVIDER_CONFLICT", "tenant.resume");
    }
    return {
      tenantId: row.tenant_id,
      oneTimeCredential: {
        id: row.credential_id,
        plaintext: row.credential_plaintext,
      },
    };
  }

  async #ensureLedger(projectRef: string): Promise<void> {
    let requestError: unknown;
    try {
      await this.#postSql(
        projectRef,
        CREATE_LEDGER_SQL,
        [],
        false,
        "migration.ledger",
      );
      return;
    } catch (error: unknown) {
      requestError = error;
    }

    // CREATE TABLE is idempotent. A read after an unknown transport outcome is
    // authoritative proof that the server committed it.
    try {
      await this.#readAndValidateLedger(projectRef);
    } catch {
      throw requestError;
    }
  }

  async #readAndValidateLedger(
    projectRef: string,
  ): Promise<readonly MigrationLedgerRow[]> {
    const rows = await this.#queryRows(
      projectRef,
      READ_LEDGER_SQL,
      [MIGRATION_LOCK],
      "migration.ledger",
    );
    if (rows.length !== 1 || !isRecord(rows[0])) {
      throw bootstrapError("PROVIDER_RESPONSE_INVALID", "migration.ledger");
    }
    const migrations = rows[0].migrations;
    if (!Array.isArray(migrations)) {
      throw bootstrapError("PROVIDER_RESPONSE_INVALID", "migration.ledger");
    }
    if (migrations.length > this.#migrations.length) {
      throw bootstrapError("PROVIDER_CONFLICT", "migration.ledger");
    }

    const ledger: MigrationLedgerRow[] = [];
    for (let index = 0; index < migrations.length; index += 1) {
      const value = migrations[index];
      const expected = this.#migrations[index];
      if (
        !isRecord(value) ||
        value.version !== expected.name ||
        value.ordinal !== expected.ordinal ||
        typeof value.checksum !== "string" ||
        !CHECKSUM_PATTERN.test(value.checksum)
      ) {
        throw bootstrapError("PROVIDER_CONFLICT", "migration.ledger");
      }
      if (value.checksum !== expected.checksum) {
        throw bootstrapError("PROVIDER_CONFLICT", "migration.ledger");
      }
      ledger.push({
        version: expected.name,
        ordinal: expected.ordinal,
        checksum: value.checksum,
      });
    }
    return ledger;
  }

  async #queryRows(
    projectRef: string,
    query: string,
    parameters: readonly unknown[],
    operation: BootstrapOperation,
  ): Promise<readonly unknown[]> {
    const payload = await this.#postSql(
      projectRef,
      query,
      parameters,
      false,
      operation,
    );
    try {
      const rows = this.#decodeQueryRows(payload);
      if (!Array.isArray(rows)) throw new Error("invalid query rows");
      return rows;
    } catch {
      throw bootstrapError("PROVIDER_RESPONSE_INVALID", operation);
    }
  }

  async #postSql(
    projectRef: string,
    query: string,
    parameters: readonly unknown[],
    readOnly: boolean,
    operation: BootstrapOperation,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(
        `${this.#managementBaseUrl}/v1/projects/${encodeURIComponent(projectRef)}/database/query`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.#managementToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            query,
            parameters,
            read_only: readOnly,
          }),
        },
      );
    } catch {
      throw bootstrapError("PROVIDER_TRANSIENT", operation, true);
    }

    if (!response.ok) throw httpError(response.status, operation);
    let body: string;
    try {
      body = await response.text();
    } catch {
      throw bootstrapError("PROVIDER_RESPONSE_INVALID", operation);
    }
    if (body.length === 0) return undefined;
    try {
      return JSON.parse(body) as unknown;
    } catch {
      throw bootstrapError("PROVIDER_RESPONSE_INVALID", operation);
    }
  }
}

function migrationApplicationSql(migration: ImmutableMigrationSource): string {
  return `
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('${MIGRATION_LOCK}'));
SELECT 1 / CASE WHEN
  NOT EXISTS (
    SELECT 1 FROM ${MIGRATION_LEDGER} WHERE version = '${migration.name}'
  )
  AND (SELECT count(*) FROM ${MIGRATION_LEDGER}) = ${migration.ordinal - 1}
  AND NOT EXISTS (
    SELECT 1 FROM ${MIGRATION_LEDGER} WHERE ordinal >= ${migration.ordinal}
  )
THEN 1 ELSE 0 END;

${migration.sql}

INSERT INTO ${MIGRATION_LEDGER} (version, ordinal, checksum)
VALUES ('${migration.name}', ${migration.ordinal}, '${migration.checksum}');
COMMIT;`;
}

function immutableMigrationSources(
  sources: readonly SupabaseDedicatedMigrationSource[],
): readonly ImmutableMigrationSource[] {
  if (sources.length !== DEDICATED_REQUIRED_MIGRATIONS.length) {
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "migration.ledger");
  }
  const copied = sources.map((source, index) => {
    const expectedName = DEDICATED_REQUIRED_MIGRATIONS[index];
    if (
      source.name !== expectedName ||
      typeof source.sql !== "string" ||
      source.sql.trim().length === 0
    ) {
      throw bootstrapError("PROVIDER_INVALID_REQUEST", "migration.ledger");
    }
    return Object.freeze({
      name: expectedName,
      sql: source.sql,
      ordinal: index + 1,
      checksum: sha256(source.sql),
    });
  });
  return Object.freeze(copied);
}

function validateRequestedMigrations(
  requested: readonly DedicatedRequiredMigration[],
): void {
  if (
    requested.length !== DEDICATED_REQUIRED_MIGRATIONS.length ||
    requested.some(
      (migration, index) => migration !== DEDICATED_REQUIRED_MIGRATIONS[index],
    )
  ) {
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "migration.apply");
  }
}

function parseProvisionTenantRow(rows: readonly unknown[]): ProvisionTenantRow {
  const value = rows.length === 1 ? rows[0] : undefined;
  if (
    !isRecord(value) ||
    typeof value.tenant_id !== "string" ||
    !UUID_PATTERN.test(value.tenant_id) ||
    (value.organization_status !== "provisioning" &&
      value.organization_status !== "ready") ||
    (value.provisioning_state !== "provisioning" &&
      value.provisioning_state !== "ready") ||
    typeof value.storage_namespace !== "string" ||
    typeof value.credential_id !== "string" ||
    !UUID_PATTERN.test(value.credential_id) ||
    (value.credential_plaintext !== null &&
      (typeof value.credential_plaintext !== "string" ||
        value.credential_plaintext.length === 0)) ||
    typeof value.created !== "boolean" ||
    value.created !== (value.credential_plaintext !== null)
  ) {
    throw bootstrapError("PROVIDER_RESPONSE_INVALID", "tenant.provision");
  }
  return value as unknown as ProvisionTenantRow;
}

function matchingProvisioningStatus(
  row: ProvisionTenantRow,
): DedicatedTenantProvisioningResult["status"] {
  if (
    row.organization_status === "provisioning" &&
    row.provisioning_state === "provisioning"
  ) {
    return "provisioning";
  }
  if (
    row.organization_status === "ready" &&
    row.provisioning_state === "ready"
  ) {
    return "ready";
  }
  throw bootstrapError("PROVIDER_RESPONSE_INVALID", "tenant.provision");
}

function parseTenantStateRow(
  rows: readonly unknown[],
  expected: "ready" | "suspended" | "disabled",
  operation: "tenant.mark_ready" | "tenant.suspend" | "tenant.disable",
): TenantStateRow {
  if (rows.length === 0) {
    throw bootstrapError("PROVIDER_NOT_FOUND", operation);
  }
  const value = rows.length === 1 ? rows[0] : undefined;
  if (
    !isRecord(value) ||
    typeof value.tenant_id !== "string" ||
    !UUID_PATTERN.test(value.tenant_id) ||
    value.organization_status !== expected ||
    value.provisioning_state !== expected
  ) {
    throw bootstrapError("PROVIDER_RESPONSE_INVALID", operation);
  }
  return value as unknown as TenantStateRow;
}


function parseResumeTenantRow(rows: readonly unknown[]): ResumeTenantRow {
  const value = rows.length === 1 ? rows[0] : undefined;
  if (
    !isRecord(value) ||
    typeof value.tenant_id !== "string" ||
    !UUID_PATTERN.test(value.tenant_id) ||
    value.organization_status !== "provisioning" ||
    value.provisioning_state !== "provisioning" ||
    typeof value.storage_namespace !== "string" ||
    typeof value.credential_id !== "string" ||
    !UUID_PATTERN.test(value.credential_id) ||
    (value.credential_plaintext !== null &&
      (typeof value.credential_plaintext !== "string" ||
        value.credential_plaintext.length === 0)) ||
    typeof value.resumed !== "boolean" ||
    value.resumed !== (value.credential_plaintext !== null)
  ) {
    throw bootstrapError("PROVIDER_RESPONSE_INVALID", "tenant.resume");
  }
  return value as unknown as ResumeTenantRow;
}

function parseCredentialReissueRow(
  rows: readonly unknown[],
): CredentialReissueRow {
  if (rows.length === 0) {
    throw bootstrapError("PROVIDER_NOT_FOUND", "tenant.reissue");
  }
  const value = rows.length === 1 ? rows[0] : undefined;
  if (
    !isRecord(value) ||
    typeof value.tenant_id !== "string" ||
    !UUID_PATTERN.test(value.tenant_id) ||
    typeof value.credential_id !== "string" ||
    !UUID_PATTERN.test(value.credential_id) ||
    typeof value.credential_plaintext !== "string" ||
    value.credential_plaintext.length === 0
  ) {
    throw bootstrapError("PROVIDER_RESPONSE_INVALID", "tenant.reissue");
  }
  return value as unknown as CredentialReissueRow;
}

function validateDedicatedIdentity(input: DedicatedTenantIdentity): void {
  validateProjectRef(input.projectRef);
  validateTenantIdentity(input.subscriptionId, input.tenantId);
  validateStackId(input.stackId);
}

function validateTenantIdentity(subscriptionId: string, tenantId: string): void {
  if (
    !UUID_PATTERN.test(tenantId) ||
    deriveProviderIdentifiers(subscriptionId, "dedicated").tenantId !== tenantId
  ) {
    throw bootstrapError("PROVIDER_CONFLICT", "tenant.provision");
  }
}

function validateStackId(stackId: string): void {
  if (
    stackId.length === 0 ||
    stackId.length > 2048 ||
    /[\u0000-\u001f\u007f]/.test(stackId)
  ) {
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "tenant.provision");
  }
}

function validateProjectRef(projectRef: string): string {
  if (!PROJECT_REF_PATTERN.test(projectRef)) {
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "tenant.provision");
  }
  return projectRef;
}

function tenantMetadata(tenantId: string): {
  readonly displayName: string;
  readonly slug: string;
} {
  return {
    displayName: `e-sig Cloud ${tenantId.slice(0, 8)}`,
    slug: `esig-${tenantId.replaceAll("-", "").slice(0, 24)}`,
  };
}

function requireSecret(value: string): string {
  if (typeof value !== "string" || value.length < 8) {
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "migration.ledger");
  }
  return value;
}

function requireDecoder(
  value: SupabaseManagementQueryRowsDecoder,
): SupabaseManagementQueryRowsDecoder {
  if (typeof value !== "function") {
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "migration.ledger");
  }
  return value;
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
    throw bootstrapError("PROVIDER_INVALID_REQUEST", "migration.ledger");
  }
}

function httpError(
  statusCode: number,
  operation: BootstrapOperation,
): SupabaseDedicatedBootstrapError {
  if (statusCode === 401 || statusCode === 403) {
    return bootstrapError("PROVIDER_AUTH_FAILED", operation, false, statusCode);
  }
  if (statusCode === 404) {
    return bootstrapError("PROVIDER_NOT_FOUND", operation, false, statusCode);
  }
  if (statusCode === 409) {
    return bootstrapError("PROVIDER_CONFLICT", operation, false, statusCode);
  }
  if (statusCode === 429) {
    return bootstrapError("PROVIDER_RATE_LIMITED", operation, true, statusCode);
  }
  if (statusCode === 408 || statusCode === 425 || statusCode >= 500) {
    return bootstrapError("PROVIDER_TRANSIENT", operation, true, statusCode);
  }
  return bootstrapError("PROVIDER_RESOURCE_FAILED", operation, false, statusCode);
}

function bootstrapError(
  code: ProviderErrorCode,
  operation: BootstrapOperation,
  retryable = false,
  statusCode?: number,
): SupabaseDedicatedBootstrapError {
  return new SupabaseDedicatedBootstrapError({
    code,
    operation,
    retryable,
    statusCode,
  });
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
