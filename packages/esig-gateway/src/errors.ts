// errors.ts
//
// One error type for the whole request path, carrying the HTTP status and a
// stable machine code. Everything the gateway rejects is rejected through here
// so there is exactly one place that decides what a client is told.
//
// Fail-closed discipline: the body returned to the caller is a fixed
// `{ error, code }` pair with NO interpolated internals — no stack, no file
// path, no cert subject, no upstream URL. The dsalvus client logs up to 512
// bytes of our response verbatim into its job output (`internal/assurance/
// sign.go:107`), so anything we put in the body lands in another lane's logs.
// Detail goes to our own structured log, keyed by the request id.

export type GatewayErrorCode =
  | "bad_request"
  | "unsupported_media_type"
  | "payload_too_large"
  | "unauthenticated"
  | "forbidden"
  | "unknown_tenant"
  | "unknown_alias"
  | "stale_timestamp"
  | "not_found"
  | "method_not_allowed"
  | "too_many_requests"
  | "sign_failed"
  | "render_failed"
  | "timeout"
  | "not_ready"
  | "internal";

const STATUS: Record<GatewayErrorCode, number> = {
  bad_request: 400,
  unsupported_media_type: 415,
  payload_too_large: 413,
  unauthenticated: 401,
  forbidden: 403,
  // Deliberately 403, not 404: a distinguishable "no such tenant" response lets
  // an authenticated caller enumerate the tenant registry. Unknown and
  // not-yours are the same answer.
  unknown_tenant: 403,
  unknown_alias: 403,
  stale_timestamp: 400,
  not_found: 404,
  method_not_allowed: 405,
  too_many_requests: 429,
  sign_failed: 500,
  render_failed: 500,
  timeout: 504,
  not_ready: 503,
  internal: 500,
};

/** Public message per code. Never derived from input — see the header note. */
const MESSAGE: Record<GatewayErrorCode, string> = {
  bad_request: "malformed request",
  unsupported_media_type: "expected content-type: application/json",
  payload_too_large: "request body too large",
  unauthenticated: "missing or invalid credential",
  forbidden: "caller not permitted for this tenant",
  unknown_tenant: "caller not permitted for this tenant",
  unknown_alias: "caller not permitted for this tenant",
  stale_timestamp: "request timestamp outside accepted skew",
  not_found: "not found",
  method_not_allowed: "method not allowed",
  too_many_requests: "signing capacity exhausted, retry",
  sign_failed: "signing failed",
  render_failed: "signing failed",
  timeout: "signing deadline exceeded",
  not_ready: "gateway not ready",
  internal: "internal error",
};

export class GatewayError extends Error {
  readonly code: GatewayErrorCode;
  readonly status: number;
  /** Operator-facing detail. Logged, never returned to the caller. */
  readonly detail?: string;

  constructor(code: GatewayErrorCode, detail?: string) {
    super(detail ?? MESSAGE[code]);
    this.name = "GatewayError";
    this.code = code;
    this.status = STATUS[code];
    this.detail = detail;
  }

  /** The exact JSON body sent to the caller. */
  toBody(): { error: string; code: GatewayErrorCode } {
    return { error: MESSAGE[this.code], code: this.code };
  }
}

/** Narrow an unknown throw into a GatewayError without leaking its message. */
export function asGatewayError(e: unknown, fallback: GatewayErrorCode = "internal"): GatewayError {
  if (e instanceof GatewayError) return e;
  return new GatewayError(fallback, e instanceof Error ? e.message : String(e));
}
