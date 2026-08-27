import { describe, expect, it, vi } from "vitest";

import {
  deriveProviderIdentifiers,
  ProviderError,
  SharedProvisioningProvider,
  type ProvisioningRequest,
} from "../src/providers/index.js";

const REQUEST: ProvisioningRequest = {
  subscriptionId: "sub_provider_contract_001",
  customerId: "cus_provider_contract_001",
  ownerSubject: "owner@example.test",
  planCode: "team",
  region: "us-east-1",
};

const SERVICE_ROLE_KEY = "fake-service-role-key-for-contract-tests";
const CREDENTIAL_ID = "10000000-0000-4000-8000-000000000001";
const REISSUED_CREDENTIAL_ID = "20000000-0000-4000-8000-000000000002";
const ONE_TIME_CREDENTIAL = "fake-one-time-credential-visible-once";
const REISSUED_CREDENTIAL = "fake-reissued-credential-visible-once";

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function voidResponse(): Response {
  return new Response(null, { status: 204 });
}

function provisionPayload(
  request: ProvisioningRequest,
  options: {
    created: boolean;
    plaintext: string | null;
    credentialId?: string;
    status?: "provisioning" | "ready";
  },
): Record<string, unknown> {
  const identifiers = deriveProviderIdentifiers(request.subscriptionId, "shared");
  const status = options.status ?? "provisioning";
  return {
    tenant_id: identifiers.tenantId,
    organization_status: status,
    provisioning_state: status,
    storage_namespace: identifiers.storageNamespace,
    credential_id: options.credentialId ?? CREDENTIAL_ID,
    credential_plaintext: options.plaintext,
    created: options.created,
  };
}

function createProvider(fetchMock: ReturnType<typeof vi.fn>): SharedProvisioningProvider {
  return new SharedProvisioningProvider({
    supabaseUrl: "https://shared-contract.supabase.co",
    serviceRoleKey: SERVICE_ROLE_KEY,
    fetch: fetchMock as unknown as typeof fetch,
  });
}

function requestBody(fetchMock: ReturnType<typeof vi.fn>, call: number): unknown {
  const [, init] = fetchMock.mock.calls[call] as unknown as [string, RequestInit];
  return JSON.parse(String(init.body));
}

describe("SharedProvisioningProvider SQL contract", () => {
  it("sends the exact provisioning RPC contract and returns plaintext separately", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        provisionPayload(REQUEST, {
          created: true,
          plaintext: ONE_TIME_CREDENTIAL,
        }),
      ),
    );
    const provider = createProvider(fetchMock);

    const result = await provider.provision(REQUEST);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe(
      "https://shared-contract.supabase.co/rest/v1/rpc/provision_esig_tenant",
    );
    expect(init).toMatchObject({
      method: "POST",
      headers: {
        apikey: SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
      },
    });

    const identifiers = deriveProviderIdentifiers(REQUEST.subscriptionId, "shared");
    expect(requestBody(fetchMock, 0)).toEqual({
      p_tenant_id: identifiers.tenantId,
      p_subscription_id: REQUEST.subscriptionId,
      p_customer_id: REQUEST.customerId,
      p_owner_email: "owner@example.test",
      p_display_name: `e-sig Cloud ${identifiers.tenantId.slice(0, 8)}`,
      p_slug: `esig-${identifiers.tenantId.replaceAll("-", "").slice(0, 24)}`,
      p_plan_key: "cloud_team",
      p_deployment_mode: "shared",
      p_dedicated_stack_id: null,
    });
    expect(result).toEqual({
      created: true,
      resources: {
        mode: "shared",
        subscriptionId: REQUEST.subscriptionId,
        tenantId: identifiers.tenantId,
        storageNamespace: `${identifiers.tenantId}/`,
        credentialId: CREDENTIAL_ID,
        status: "provisioning",
      },
      oneTimeCredential: {
        id: CREDENTIAL_ID,
        plaintext: ONE_TIME_CREDENTIAL,
      },
    });
  });

  it.each([
    ["starter", "cloud_starter"],
    ["team", "cloud_team"],
    ["scale", "cloud_scale"],
  ] as const)("maps plan %s to SQL plan key %s", async (planCode, planKey) => {
    const request: ProvisioningRequest = { ...REQUEST, planCode };
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        provisionPayload(request, {
          created: true,
          plaintext: ONE_TIME_CREDENTIAL,
        }),
      ),
    );

    await createProvider(fetchMock).provision(request);

    expect(requestBody(fetchMock, 0)).toMatchObject({ p_plan_key: planKey });
  });

  it("converges a known duplicate with the same credential id and no plaintext", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, {
            created: true,
            plaintext: ONE_TIME_CREDENTIAL,
          }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, { created: false, plaintext: null }),
        ),
      );
    const provider = createProvider(fetchMock);

    const first = await provider.provision(REQUEST);
    const duplicate = await provider.provision(REQUEST, first.resources);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(duplicate).toEqual({ resources: first.resources, created: false });
    expect(requestBody(fetchMock, 1)).toEqual(requestBody(fetchMock, 0));
  });

  it("rotates a credential explicitly after a retry recovered prior resources", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, {
            created: true,
            plaintext: ONE_TIME_CREDENTIAL,
          }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, { created: false, plaintext: null }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          credential_id: REISSUED_CREDENTIAL_ID,
          credential_plaintext: REISSUED_CREDENTIAL,
        }),
      );
    const provider = createProvider(fetchMock);

    const first = await provider.provision(REQUEST);
    const recovered = await provider.provision(REQUEST, first.resources);
    const reissued = await provider.reissueCredential(
      REQUEST,
      recovered.resources,
    );

    expect(String(fetchMock.mock.calls[2]?.[0])).toBe(
      "https://shared-contract.supabase.co/rest/v1/rpc/reissue_esig_tenant_credential",
    );
    expect(requestBody(fetchMock, 2)).toEqual({
      p_tenant_id: first.resources.tenantId,
      p_subscription_id: REQUEST.subscriptionId,
    });
    expect(reissued).toEqual({
      resources: {
        ...recovered.resources,
        credentialId: REISSUED_CREDENTIAL_ID,
      },
      oneTimeCredential: {
        id: REISSUED_CREDENTIAL_ID,
        plaintext: REISSUED_CREDENTIAL,
      },
    });
    expect(JSON.stringify(reissued.resources)).not.toContain(
      REISSUED_CREDENTIAL,
    );
  });

  it("rejects a credential reissue that did not rotate the credential id", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, {
            created: true,
            plaintext: ONE_TIME_CREDENTIAL,
          }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          credential_id: CREDENTIAL_ID,
          credential_plaintext: REISSUED_CREDENTIAL,
        }),
      );
    const provider = createProvider(fetchMock);
    const first = await provider.provision(REQUEST);

    await expect(
      provider.reissueCredential(REQUEST, first.resources),
    ).rejects.toMatchObject({
      code: "PROVIDER_RESPONSE_INVALID",
      operation: "shared.credential.reissue",
    });
  });

  it("reissues once after a commit-unknown duplicate without prior resources", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, { created: false, plaintext: null }),
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          credential_id: REISSUED_CREDENTIAL_ID,
          credential_plaintext: REISSUED_CREDENTIAL,
        }),
      );
    const provider = createProvider(fetchMock);

    const result = await provider.provision(REQUEST);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe(
      "https://shared-contract.supabase.co/rest/v1/rpc/reissue_esig_tenant_credential",
    );
    const identifiers = deriveProviderIdentifiers(REQUEST.subscriptionId, "shared");
    expect(requestBody(fetchMock, 1)).toEqual({
      p_tenant_id: identifiers.tenantId,
      p_subscription_id: REQUEST.subscriptionId,
    });
    expect(result).toMatchObject({
      created: false,
      resources: {
        credentialId: REISSUED_CREDENTIAL_ID,
        status: "provisioning",
      },
      oneTimeCredential: {
        id: REISSUED_CREDENTIAL_ID,
        plaintext: REISSUED_CREDENTIAL,
      },
    });
  });

  it("does not claim ready until the successful mark-ready void RPC", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, {
            created: true,
            plaintext: ONE_TIME_CREDENTIAL,
          }),
        ),
      )
      .mockResolvedValueOnce(voidResponse());
    const provider = createProvider(fetchMock);

    const provisioned = await provider.provision(REQUEST);
    expect(provisioned.resources.status).toBe("provisioning");
    const ready = await provider.markReady(REQUEST, provisioned.resources);

    expect(ready.status).toBe("ready");
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe(
      "https://shared-contract.supabase.co/rest/v1/rpc/mark_esig_tenant_ready",
    );
    expect(requestBody(fetchMock, 1)).toEqual({
      p_tenant_id: provisioned.resources.tenantId,
    });
  });

  it("disables idempotently through the successful void RPC", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, {
            created: true,
            plaintext: ONE_TIME_CREDENTIAL,
          }),
        ),
      )
      .mockResolvedValue(voidResponse());
    const provider = createProvider(fetchMock);
    const provisioned = await provider.provision(REQUEST);

    const first = await provider.compensate(REQUEST, provisioned.resources);
    const duplicate = await provider.compensate(REQUEST, first);

    expect(first.status).toBe("disabled");
    expect(duplicate).toEqual(first);
    for (const call of [1, 2]) {
      expect(String(fetchMock.mock.calls[call]?.[0])).toBe(
        "https://shared-contract.supabase.co/rest/v1/rpc/disable_esig_tenant",
      );
      expect(requestBody(fetchMock, call)).toEqual({
        p_tenant_id: provisioned.resources.tenantId,
        p_subscription_status: "canceled",
        p_safe_error_code: null,
      });
    }
  });

  it("treats an absent deterministic tenant as converged compensation", async () => {
    const fetchMock = vi.fn(async (_input: unknown, _init?: RequestInit) =>
      jsonResponse({}, 404),
    );
    const provider = createProvider(fetchMock);

    const result = await provider.compensateUnknown(REQUEST);

    const tenantId = deriveProviderIdentifiers(
      REQUEST.subscriptionId,
      "shared",
    ).tenantId;
    expect(result).toEqual({
      mode: "shared",
      tenantId,
      outcome: "absent",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
      "https://shared-contract.supabase.co/rest/v1/rpc/disable_esig_tenant",
    );
    expect(requestBody(fetchMock, 0)).toEqual({
      p_tenant_id: tenantId,
      p_subscription_status: "canceled",
      p_safe_error_code: null,
    });
  });

  it("keeps credential plaintext out of the persistable resource shape", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        provisionPayload(REQUEST, {
          created: true,
          plaintext: ONE_TIME_CREDENTIAL,
        }),
      ),
    );

    const result = await createProvider(fetchMock).provision(REQUEST);
    const persistedShape = JSON.stringify(result.resources);

    expect(persistedShape).not.toContain(ONE_TIME_CREDENTIAL);
    expect(persistedShape).not.toContain("credential_plaintext");
    expect(result.oneTimeCredential?.plaintext).toBe(ONE_TIME_CREDENTIAL);
  });

  it("returns a retryable body-safe error and converges on retry", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(
        new Error(`remote transport included ${ONE_TIME_CREDENTIAL}`),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          provisionPayload(REQUEST, {
            created: true,
            plaintext: ONE_TIME_CREDENTIAL,
          }),
        ),
      );
    const provider = createProvider(fetchMock);

    let failure: unknown;
    try {
      await provider.provision(REQUEST);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(ProviderError);
    expect(failure).toMatchObject({
      code: "PROVIDER_TRANSIENT",
      retryable: true,
      operation: "shared.provision",
    });
    expect(String(failure)).not.toContain(ONE_TIME_CREDENTIAL);

    const retried = await provider.provision(REQUEST);
    expect(retried.resources.status).toBe("provisioning");
  });
});
