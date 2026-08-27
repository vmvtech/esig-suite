export const PROVIDER_ERROR_CODES = [
  "PROVIDER_INVALID_REQUEST",
  "PROVIDER_AUTH_FAILED",
  "PROVIDER_RATE_LIMITED",
  "PROVIDER_CONFLICT",
  "PROVIDER_NOT_FOUND",
  "PROVIDER_TRANSIENT",
  "PROVIDER_TIMEOUT",
  "PROVIDER_RESPONSE_INVALID",
  "PROVIDER_RESOURCE_FAILED",
] as const;

export type ProviderErrorCode = (typeof PROVIDER_ERROR_CODES)[number];

export type ProviderOperation =
  | "validate"
  | "shared.provision"
  | "shared.credential.reissue"
  | "shared.mark_ready"
  | "shared.disable"
  | "dedicated.credential.reissue"
  | "dedicated.project.list"
  | "dedicated.project.create"
  | "dedicated.project.describe"
  | "dedicated.project.health"
  | "dedicated.project.pause"
  | "dedicated.stack.describe"
  | "dedicated.stack.create"
  | "dedicated.stack.disable";

const SAFE_MESSAGES: Readonly<Record<ProviderErrorCode, string>> = {
  PROVIDER_INVALID_REQUEST: "Provisioning request is invalid.",
  PROVIDER_AUTH_FAILED: "Provisioning provider authentication failed.",
  PROVIDER_RATE_LIMITED: "Provisioning provider rate limit reached.",
  PROVIDER_CONFLICT: "Provisioning resource identity conflict.",
  PROVIDER_NOT_FOUND: "Provisioning resource was not found.",
  PROVIDER_TRANSIENT: "Provisioning provider is temporarily unavailable.",
  PROVIDER_TIMEOUT: "Provisioning readiness timed out.",
  PROVIDER_RESPONSE_INVALID: "Provisioning provider returned an invalid response.",
  PROVIDER_RESOURCE_FAILED: "Provisioning resource entered a failed state.",
};

export class ProviderError extends Error {
  readonly code: ProviderErrorCode;
  readonly operation: ProviderOperation;
  readonly retryable: boolean;
  readonly statusCode?: number;

  constructor(options: {
    code: ProviderErrorCode;
    operation: ProviderOperation;
    retryable: boolean;
    statusCode?: number;
  }) {
    super(SAFE_MESSAGES[options.code]);
    this.name = "ProviderError";
    this.code = options.code;
    this.operation = options.operation;
    this.retryable = options.retryable;
    this.statusCode = options.statusCode;
  }
}

export function providerError(options: {
  code: ProviderErrorCode;
  operation: ProviderOperation;
  retryable?: boolean;
  statusCode?: number;
}): ProviderError {
  return new ProviderError({
    ...options,
    retryable: options.retryable ?? false,
  });
}

export function errorForHttpStatus(
  operation: ProviderOperation,
  statusCode: number,
): ProviderError {
  if (statusCode === 401 || statusCode === 403) {
    return providerError({
      code: "PROVIDER_AUTH_FAILED",
      operation,
      statusCode,
    });
  }

  if (statusCode === 404) {
    return providerError({
      code: "PROVIDER_NOT_FOUND",
      operation,
      statusCode,
    });
  }

  if (statusCode === 409) {
    return providerError({
      code: "PROVIDER_CONFLICT",
      operation,
      statusCode,
    });
  }

  if (statusCode === 429) {
    return providerError({
      code: "PROVIDER_RATE_LIMITED",
      operation,
      retryable: true,
      statusCode,
    });
  }

  if (statusCode === 408 || statusCode === 425 || statusCode >= 500) {
    return providerError({
      code: "PROVIDER_TRANSIENT",
      operation,
      retryable: true,
      statusCode,
    });
  }

  return providerError({
    code: "PROVIDER_RESOURCE_FAILED",
    operation,
    statusCode,
  });
}
