import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  DEDICATED_REQUIRED_MIGRATIONS,
  type DedicatedRequiredMigration,
} from "../src/providers/dedicated.js";
import { deriveProviderIdentifiers } from "../src/providers/deterministic.js";
import {
  SupabaseDedicatedBootstrapError,
  SupabaseDedicatedTenantBootstrapper,
  type SupabaseDedicatedMigrationSource,
} from "../src/providers/supabase-dedicated-bootstrapper.js";
import type {
  FetchTransport,
  ProvisioningRequest,
} from "../src/providers/types.js";

const MANAGEMENT_TOKEN = "fake-management-token";
const PROJECT_REF = "abcdefghijklmnopqrst";
const STACK_ID =
  "arn:aws:cloudformation:us-east-1:123456789012:stack/esig-test/stack-uuid";
const CREDENTIAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const REISSUED_CREDENTIAL_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const REQUEST: ProvisioningRequest = {
  subscriptionId: "sub_dedicated_contract_001",
  customerId: "cus_dedicated_contract_001",
  ownerSubject: " Owner+Dedicated@Example.com ",
  planCode: "team",
  region: "us-east-1",
};
const TENANT_ID = deriveProviderIdentifiers(
  REQUEST.subscriptionId,
  "dedicated",
).tenantId;

const MIGRATION_SOURCES: readonly SupabaseDedicatedMigrationSource[] =
  DEDICATED_REQUIRED_MIGRATIONS.map((name, index) => ({
    name,
    sql: `SELECT ${index + 1} AS migration_${index + 1};`,
  }));

interface LedgerRow {
  readonly version: DedicatedRequiredMigration;
  readonly ordinal: number;
  readonly checksum: string;
}

interface SqlCall {
  readonly url: string;
  readonly headers: Headers;
  readonly query: string;
  readonly parameters: readonly unknown[];
  readonly readOnly: boolean;
}

interface HarnessOptions {
  readonly initialLedger?: readonly LedgerRow[];
  readonly commitUnknownOrdinal?: number;
  readonly corruptCommitUnknownProof?: boolean;
  readonly omitProofOrdinal?: number;
  readonly ledgerPayload?: unknown;
  readonly provisionRows?: readonly unknown[];
  readonly reissueRows?: readonly unknown[];
  readonly markReadyRows?: readonly unknown[];
  readonly disableRows?: readonly unknown[];
  readonly statusFor?: (query: string) => number | undefined;
}

function harness(options: HarnessOptions = {}) {
  const ledger: LedgerRow[] = [...(options.initialLedger ?? [])];
  const calls: SqlCall[] = [];
  const committedUnknown = new Set<number>();
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      readonly query: string;
      readonly parameters: readonly unknown[];
      readonly read_only: boolean;
    };
    const call: SqlCall = {
      url: String(input),
      headers: new Headers(init?.headers),
      query: body.query,
      parameters: body.parameters,
      readOnly: body.read_only,
    };
    calls.push(call);

    const status = options.statusFor?.(body.query);
    if (status !== undefined) {
      return jsonResponse({ ignored: true }, status);
    }
    if (body.query.includes("CREATE TABLE IF NOT EXISTS")) {
      return jsonResponse({});
    }
    if (body.query.includes("jsonb_agg")) {
      return jsonResponse(
        options.ledgerPayload ?? [{ migrations: ledger.map((row) => ({ ...row })) }],
      );
    }
    if (body.query.includes("INSERT INTO public.esig_cloud_schema_migrations")) {
      const source = MIGRATION_SOURCES.find((candidate) =>
        body.query.includes(candidate.sql),
      );
      if (source === undefined) throw new Error("unknown migration source");
      const ordinal = MIGRATION_SOURCES.indexOf(source) + 1;
      const row: LedgerRow = {
        version: source.name,
        checksum: checksum(source.sql),
        ordinal,
      };
      if (row.ordinal !== options.omitProofOrdinal) ledger.push(row);
      if (
        row.ordinal === options.commitUnknownOrdinal &&
        !committedUnknown.has(row.ordinal)
      ) {
        committedUnknown.add(row.ordinal);
        if (options.corruptCommitUnknownProof) {
          ledger[ledger.length - 1] = { ...row, checksum: "0".repeat(64) };
        }
        throw new TypeError("simulated connection loss after commit");
      }
      return jsonResponse({});
    }
    if (body.query.includes("FROM public.provision_esig_tenant")) {
      return jsonResponse(
        options.provisionRows ?? [provisionRow({ created: true })],
      );
    }
    if (body.query.includes("reissue_esig_tenant_credential")) {
      return jsonResponse(
        options.reissueRows ?? [
          {
            tenant_id: TENANT_ID,
            credential_id: REISSUED_CREDENTIAL_ID,
            credential_plaintext: "esig_live_reissued_secret",
          },
        ],
      );
    }
    if (body.query.includes("mark_esig_tenant_ready")) {
      return jsonResponse(
        options.markReadyRows ?? [stateRow("ready")],
      );
    }
    if (body.query.includes("disable_esig_tenant")) {
      return jsonResponse(
        options.disableRows ?? [stateRow("disabled")],
      );
    }
    throw new Error("unexpected SQL request");
  });

  const adapter = new SupabaseDedicatedTenantBootstrapper({
    managementToken: MANAGEMENT_TOKEN,
    migrations: MIGRATION_SOURCES,
    decodeQueryRows: (payload) => {
      if (!Array.isArray(payload)) throw new Error("unexpected response shape");
      return payload;
    },
    fetch: fetchMock as FetchTransport,
  });
  return { adapter, calls, fetchMock, ledger };
}

function jsonResponse(value: unknown, status = 201): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function checksum(sql: string): string {
  return createHash("sha256").update(sql, "utf8").digest("hex");
}

function ledgerPrefix(length: number): readonly LedgerRow[] {
  return MIGRATION_SOURCES.slice(0, length).map((source, index) => ({
    version: source.name,
    ordinal: index + 1,
    checksum: checksum(source.sql),
  }));
}

function provisionRow(options: {
  readonly created: boolean;
  readonly status?: "provisioning" | "ready";
}): Record<string, unknown> {
  const status = options.status ?? "provisioning";
  return {
    tenant_id: TENANT_ID,
    organization_status: status,
    provisioning_state: status,
    storage_namespace: `${TENANT_ID}/`,
    credential_id: CREDENTIAL_ID,
    credential_plaintext: options.created ? "esig_live_one_time_secret" : null,
    created: options.created,
  };
}

function stateRow(status: "ready" | "disabled"): Record<string, unknown> {
  return {
    tenant_id: TENANT_ID,
    organization_status: status,
    provisioning_state: status,
  };
}

function migrationInput(
  migrations: readonly DedicatedRequiredMigration[] =
    DEDICATED_REQUIRED_MIGRATIONS,
) {
  return { projectRef: PROJECT_REF, migrations };
}

function tenantInput() {
  return {
    request: REQUEST,
    tenantId: TENANT_ID,
    projectRef: PROJECT_REF,
    stackId: STACK_ID,
  };
}

function identity() {
  return {
    subscriptionId: REQUEST.subscriptionId,
    tenantId: TENANT_ID,
    projectRef: PROJECT_REF,
    stackId: STACK_ID,
  };
}

describe("SupabaseDedicatedTenantBootstrapper migrations", () => {
  it("requires immutable sources for exactly 0001 through 0004 in order", () => {
    expect(
      () =>
        new SupabaseDedicatedTenantBootstrapper({
          managementToken: MANAGEMENT_TOKEN,
          migrations: [...MIGRATION_SOURCES].reverse(),
          decodeQueryRows: () => [],
        }),
    ).toThrowError(
      expect.objectContaining({ code: "PROVIDER_INVALID_REQUEST" }),
    );

    const { adapter } = harness();
    return expect(
      adapter.applyMigrations(
        migrationInput([...DEDICATED_REQUIRED_MIGRATIONS].reverse()),
      ),
    ).rejects.toMatchObject({ code: "PROVIDER_INVALID_REQUEST" });
  });

  it("applies all migrations transactionally in order and records computed SHA-256", async () => {
    const { adapter, calls, ledger } = harness();

    await expect(adapter.applyMigrations(migrationInput())).resolves.toEqual({
      appliedMigrations: DEDICATED_REQUIRED_MIGRATIONS,
    });

    expect(ledger).toEqual(ledgerPrefix(4));
    const applyCalls = calls.filter((call) =>
      call.query.includes("INSERT INTO public.esig_cloud_schema_migrations"),
    );
    expect(applyCalls).toHaveLength(4);
    expect(applyCalls.map((call) => call.parameters)).toEqual([[], [], [], []]);
    expect(applyCalls.map((call) => call.readOnly)).toEqual([
      false,
      false,
      false,
      false,
    ]);
    for (const [index, call] of applyCalls.entries()) {
      expect(call.query).toContain(MIGRATION_SOURCES[index].sql);
      expect(call.query).toContain(ledgerPrefix(4)[index].checksum);
      expect(call.query).toContain(ledgerPrefix(4)[index].version);
      expect(call.query).toContain("BEGIN;");
      expect(call.query).toContain("COMMIT;");
    }
    expect(calls[0].url).toBe(
      `https://api.supabase.com/v1/projects/${PROJECT_REF}/database/query`,
    );
    expect(calls[0].headers.get("Authorization")).toBe(
      `Bearer ${MANAGEMENT_TOKEN}`,
    );
  });

  it("skips an exact already-applied ledger without replaying DDL", async () => {
    const { adapter, calls } = harness({ initialLedger: ledgerPrefix(4) });

    await expect(adapter.applyMigrations(migrationInput())).resolves.toEqual({
      appliedMigrations: DEDICATED_REQUIRED_MIGRATIONS,
    });
    expect(
      calls.filter((call) =>
        call.query.includes("INSERT INTO public.esig_cloud_schema_migrations"),
      ),
    ).toHaveLength(0);
  });

  it("continues only from a checksum-verified prefix", async () => {
    const { adapter, calls } = harness({ initialLedger: ledgerPrefix(2) });

    await adapter.applyMigrations(migrationInput());
    const applyCalls = calls.filter((call) =>
      call.query.includes("INSERT INTO public.esig_cloud_schema_migrations"),
    );
    expect(
      applyCalls.map(
        (call) =>
          MIGRATION_SOURCES.find((source) => call.query.includes(source.sql))
            ?.name,
      ),
    ).toEqual(DEDICATED_REQUIRED_MIGRATIONS.slice(2));
  });

  it("fails closed on checksum mismatch before issuing DDL", async () => {
    const mismatched: LedgerRow = {
      ...ledgerPrefix(1)[0],
      checksum: "0".repeat(64),
    };
    const { adapter, calls } = harness({ initialLedger: [mismatched] });

    await expect(adapter.applyMigrations(migrationInput())).rejects.toMatchObject({
      code: "PROVIDER_CONFLICT",
      retryable: false,
    });
    expect(calls.some((call) => call.query.includes(MIGRATION_SOURCES[0].sql))).toBe(
      false,
    );
  });

  it("fails closed on non-prefix or malformed ledger proof", async () => {
    const { adapter } = harness({
      initialLedger: [ledgerPrefix(2)[1]],
    });
    await expect(adapter.applyMigrations(migrationInput())).rejects.toMatchObject({
      code: "PROVIDER_CONFLICT",
    });

    const invalid = harness({ ledgerPayload: [{ migrations: "not-an-array" }] });
    await expect(
      invalid.adapter.applyMigrations(migrationInput()),
    ).rejects.toMatchObject({ code: "PROVIDER_RESPONSE_INVALID" });
  });

  it("accepts commit-unknown only after the ledger proves the exact checksum", async () => {
    const { adapter, calls, ledger } = harness({ commitUnknownOrdinal: 2 });

    await expect(adapter.applyMigrations(migrationInput())).resolves.toEqual({
      appliedMigrations: DEDICATED_REQUIRED_MIGRATIONS,
    });
    expect(ledger).toEqual(ledgerPrefix(4));
    expect(
      calls.filter(
        (call) =>
          call.query.includes("INSERT INTO public.esig_cloud_schema_migrations") &&
          call.query.includes(MIGRATION_SOURCES[1].sql),
      ),
    ).toHaveLength(1);
  });

  it("prefers checksum-conflict proof over a retryable commit-unknown error", async () => {
    const { adapter } = harness({
      commitUnknownOrdinal: 2,
      corruptCommitUnknownProof: true,
    });

    await expect(adapter.applyMigrations(migrationInput())).rejects.toMatchObject({
      code: "PROVIDER_CONFLICT",
      retryable: false,
    });
  });

  it("rejects a successful HTTP response that lacks durable commit proof", async () => {
    const { adapter } = harness({ omitProofOrdinal: 3 });

    await expect(adapter.applyMigrations(migrationInput())).rejects.toMatchObject({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "migration.apply",
    });
  });
});

describe("SupabaseDedicatedTenantBootstrapper tenant SQL", () => {
  it("provisions through parameterized SQL and returns plaintext only once", async () => {
    const { adapter, calls } = harness();

    await expect(adapter.provisionTenant(tenantInput())).resolves.toEqual({
      tenantId: TENANT_ID,
      status: "provisioning",
      created: true,
      oneTimeCredential: {
        id: CREDENTIAL_ID,
        plaintext: "esig_live_one_time_secret",
      },
    });

    const call = calls.at(-1)!;
    expect(call.query).toContain("public.provision_esig_tenant");
    expect(call.query).not.toContain(REQUEST.subscriptionId);
    expect(call.query).not.toContain("owner+dedicated@example.com");
    expect(call.parameters).toEqual([
      TENANT_ID,
      REQUEST.subscriptionId,
      REQUEST.customerId,
      "owner+dedicated@example.com",
      `e-sig Cloud ${TENANT_ID.slice(0, 8)}`,
      `esig-${TENANT_ID.replaceAll("-", "").slice(0, 24)}`,
      "cloud_team",
      "dedicated",
      STACK_ID,
    ]);
  });

  it("returns no plaintext for an idempotent duplicate", async () => {
    const { adapter } = harness({
      provisionRows: [provisionRow({ created: false })],
    });

    await expect(adapter.provisionTenant(tenantInput())).resolves.toEqual({
      tenantId: TENANT_ID,
      status: "provisioning",
      created: false,
    });
  });

  it("reissues a lost one-time credential through an identity-guarded RPC", async () => {
    const { adapter, calls } = harness();

    await expect(adapter.reissueCredential(identity())).resolves.toEqual({
      tenantId: TENANT_ID,
      oneTimeCredential: {
        id: REISSUED_CREDENTIAL_ID,
        plaintext: "esig_live_reissued_secret",
      },
    });
    const call = calls.at(-1)!;
    expect(call.query).toContain("public.reissue_esig_tenant_credential");
    expect(call.query).not.toContain(REQUEST.subscriptionId);
    expect(call.parameters).toEqual([
      TENANT_ID,
      REQUEST.subscriptionId,
      STACK_ID,
    ]);
  });

  it("marks ready and disables only a parameter-matched tenant identity", async () => {
    const { adapter, calls } = harness();
    await adapter.provisionTenant(tenantInput());
    await expect(adapter.markReady(identity())).resolves.toEqual({
      tenantId: TENANT_ID,
      status: "ready",
    });
    await expect(adapter.disableTenant(identity())).resolves.toEqual({
      tenantId: TENANT_ID,
      status: "disabled",
    });

    const readyCall = calls.find((call) =>
      call.query.includes("mark_esig_tenant_ready"),
    )!;
    const disableCall = calls.find((call) =>
      call.query.includes("disable_esig_tenant"),
    )!;
    expect(readyCall.parameters).toEqual([
      TENANT_ID,
      REQUEST.subscriptionId,
      STACK_ID,
    ]);
    expect(disableCall.parameters).toEqual([
      TENANT_ID,
      REQUEST.subscriptionId,
      STACK_ID,
      "canceled",
      null,
    ]);
    expect(JSON.stringify([readyCall, disableCall])).not.toContain(
      "esig_live_one_time_secret",
    );
  });

  it("reports an already-absent tenant as not found for compensation convergence", async () => {
    const { adapter } = harness({ disableRows: [] });

    await expect(adapter.disableTenant(identity())).rejects.toMatchObject({
      code: "PROVIDER_NOT_FOUND",
      retryable: false,
    });
  });

  it("fails closed on invalid tenant rows and decoder output", async () => {
    const invalidRow = harness({
      provisionRows: [
        {
          ...provisionRow({ created: true }),
          credential_plaintext: null,
        },
      ],
    });
    await expect(
      invalidRow.adapter.provisionTenant(tenantInput()),
    ).rejects.toMatchObject({ code: "PROVIDER_RESPONSE_INVALID" });

    const fetchMock = vi.fn(async () => jsonResponse({ undocumented: true }));
    const invalidShape = new SupabaseDedicatedTenantBootstrapper({
      managementToken: MANAGEMENT_TOKEN,
      migrations: MIGRATION_SOURCES,
      decodeQueryRows: (payload) => {
        if (!Array.isArray(payload)) throw new Error("invalid");
        return payload;
      },
      fetch: fetchMock as FetchTransport,
    });
    await expect(
      invalidShape.provisionTenant(tenantInput()),
    ).rejects.toMatchObject({ code: "PROVIDER_RESPONSE_INVALID" });
  });

  it("maps transient HTTP failures to safe retryable errors without response text", async () => {
    const { adapter } = harness({
      statusFor: (query) =>
        query.includes("provision_esig_tenant") ? 429 : undefined,
    });

    const error = await adapter.provisionTenant(tenantInput()).catch((value) => value);
    expect(error).toBeInstanceOf(SupabaseDedicatedBootstrapError);
    expect(error).toMatchObject({
      code: "PROVIDER_RATE_LIMITED",
      retryable: true,
      statusCode: 429,
    });
    expect(String(error)).not.toContain(MANAGEMENT_TOKEN);
  });

  it("rejects a deterministic identity mismatch before any database call", async () => {
    const { adapter, fetchMock } = harness();
    await expect(
      adapter.markReady({
        ...identity(),
        tenantId: "11111111-1111-4111-8111-111111111111",
      }),
    ).rejects.toMatchObject({ code: "PROVIDER_CONFLICT" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
