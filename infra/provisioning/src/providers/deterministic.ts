import { createHash } from "node:crypto";

import { deterministicTenantId } from "../domain.js";
import { providerError } from "./errors.js";
import type {
  ProvisioningMode,
  ProvisioningRequest,
} from "./types.js";

const OPAQUE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/;
const REGION_PATTERN = /^[a-z]{2}(?:-[a-z]+)+-\d$/;
const NORMALIZED_EMAIL_PATTERN = /^[^\s@]+@[^\s@]+$/;

function hash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function validateOpaqueId(value: string): void {
  if (
    value.length === 0 ||
    value.length > 200 ||
    !OPAQUE_ID_PATTERN.test(value)
  ) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
}

export function validateProvisioningRequest(request: ProvisioningRequest): void {
  validateOpaqueId(request.subscriptionId);
  validateOpaqueId(request.customerId);
  normalizeOwnerEmail(request.ownerSubject);

  if (
    request.planCode !== "starter" &&
    request.planCode !== "team" &&
    request.planCode !== "scale"
  ) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }

  if (!REGION_PATTERN.test(request.region)) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
}

export function normalizeOwnerEmail(ownerSubject: string): string {
  const normalized = ownerSubject.trim().toLowerCase();
  if (
    normalized.length > 254 ||
    !NORMALIZED_EMAIL_PATTERN.test(normalized)
  ) {
    throw providerError({
      code: "PROVIDER_INVALID_REQUEST",
      operation: "validate",
    });
  }
  return normalized;
}

export interface DeterministicProviderIdentifiers {
  readonly tenantId: string;
  readonly storageNamespace: string;
  readonly projectName: string;
  readonly stackName: string;
  readonly stackCreateToken: string;
  readonly stackDisableToken: string;
}

export function deriveProviderIdentifiers(
  subscriptionId: string,
  mode: ProvisioningMode,
): DeterministicProviderIdentifiers {
  const subscriptionDigest = hash(`e-sig:subscription:${subscriptionId}`);
  const tenantId = deterministicTenantId(subscriptionId, mode);

  return {
    tenantId,
    storageNamespace: `${tenantId}/`,
    projectName: `esig-${subscriptionDigest.slice(0, 20)}`,
    stackName: `esig-dedicated-${subscriptionDigest.slice(0, 24)}`,
    stackCreateToken: `esig-create-${subscriptionDigest.slice(0, 40)}`,
    stackDisableToken: `esig-disable-${subscriptionDigest.slice(0, 40)}`,
  };
}
