// server.ts
//
// The HTTP surface: POST /v1/sign, GET /healthz, GET /ready.
//
// node:http / node:https only — no framework. The routing table is three
// entries and a framework would add a dependency-update surface to a process
// that holds signing keys.
//
// Hosting expectation (handoff §5): PRIVATE reachability only, behind an
// internal ALB or inside the service mesh. Nothing here assumes it; the
// gateway simply must not be published to the internet, and
// `ESIG_GATEWAY_MTLS_SOURCE=socket` (in-process TLS termination with
// requestCert) is the configuration that does not have to trust a proxy header.

import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

import type { GatewayConfig } from "./config.js";
import { GatewayError, asGatewayError } from "./errors.js";
import { Authenticator } from "./auth.js";
import type { TsaPool } from "./tsa.js";
import { Signer, parseSignRequest } from "./sign.js";

/**
 * Bounded concurrency: each in-flight sign holds a Chromium process.
 *
 * The wait queue is bounded too. An unbounded queue does not shed load, it
 * defers it: callers sit until their own 30 s client timeout and dsalvus
 * reports a signing failure with no server-side explanation. A 429 is an
 * honest answer the caller can retry.
 */
export class Semaphore {
  private active = 0;
  private queue: Array<() => void> = [];

  constructor(
    private readonly limit: number,
    private readonly maxQueue = limit * 4,
  ) {}

  get inFlight(): number {
    return this.active;
  }

  async acquire(): Promise<() => void> {
    if (this.active >= this.limit) {
      if (this.queue.length >= this.maxQueue) {
        throw new GatewayError("too_many_requests", `queue depth ${this.queue.length} >= ${this.maxQueue}`);
      }
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active--;
      this.queue.shift()?.();
    };
  }
}

export interface ReadyState {
  ready: boolean;
  checks: Record<string, { ok: boolean; detail?: string }>;
}

export interface ServerDeps {
  config: GatewayConfig;
  auth: Authenticator;
  signer: Signer;
  tsa: TsaPool;
  /** Probe the cert store (a cheap read) so /ready reflects real reachability. */
  probeCertStore: () => Promise<void>;
  log?: (record: Record<string, unknown>) => void;
}

function defaultLog(record: Record<string, unknown>): void {
  // One structured line per event. stdout, so the container runtime collects it.
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...record }) + "\n");
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

/** Read the body with a hard byte cap, aborting as soon as the cap is passed. */
function readBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] ?? NaN);
    if (Number.isFinite(declared) && declared > maxBytes) {
      reject(new GatewayError("payload_too_large", `content-length ${declared} > ${maxBytes}`));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) {
        reject(new GatewayError("payload_too_large", `body exceeded ${maxBytes} bytes`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", (e) => reject(asGatewayError(e, "bad_request")));
  });
}

async function withDeadline<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new GatewayError("timeout", `exceeded ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([p, deadline]);
  } finally {
    clearTimeout(timer!);
  }
}

export function createRequestHandler(deps: ServerDeps): http.RequestListener {
  const { config } = deps;
  const log = deps.log ?? defaultLog;
  const semaphore = new Semaphore(config.maxConcurrentSigns);

  return async (req, res) => {
    const requestId = crypto.randomUUID();
    const started = Date.now();
    const url = new URL(req.url ?? "/", "http://gateway.invalid");
    const route = url.pathname;
    res.setHeader("x-request-id", requestId);

    const finish = (status: number, extra: Record<string, unknown> = {}): void => {
      log({ event: "request", request_id: requestId, route, method: req.method, status, ms: Date.now() - started, ...extra });
    };

    try {
      if (route === "/healthz") {
        if (req.method !== "GET" && req.method !== "HEAD") throw new GatewayError("method_not_allowed");
        // Liveness only: the process is up and the event loop is turning.
        // Deliberately does NOT touch the cert store or the TSA — a liveness
        // probe that fails on a dependency outage gets the pod killed instead
        // of drained, which is how a TSA blip becomes a crashloop.
        sendJson(res, 200, { status: "ok", inflight_signs: semaphore.inFlight });
        finish(200);
        return;
      }

      if (route === "/ready") {
        if (req.method !== "GET" && req.method !== "HEAD") throw new GatewayError("method_not_allowed");
        const state = await readiness(deps);
        sendJson(res, state.ready ? 200 : 503, { status: state.ready ? "ready" : "not_ready", checks: state.checks });
        finish(state.ready ? 200 : 503);
        return;
      }

      if (route !== "/v1/sign") throw new GatewayError("not_found");
      if (req.method !== "POST") throw new GatewayError("method_not_allowed");

      const ctype = String(req.headers["content-type"] ?? "");
      if (!ctype.toLowerCase().startsWith("application/json")) {
        throw new GatewayError("unsupported_media_type", `content-type: ${ctype}`);
      }

      // Authenticate BEFORE reading the body: an unauthenticated caller should
      // not be able to make us buffer megabytes.
      const principal = await deps.auth.authenticate(req);

      const raw = await readBody(req, config.maxBodyBytes);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new GatewayError("bad_request", "body is not valid JSON");
      }
      const body = parseSignRequest(parsed);

      const release = await semaphore.acquire();
      // The slot is released when the REAL work settles, not when the deadline
      // fires — a timed-out sign still holds its Chromium process, and
      // releasing early would let the gateway over-subscribe itself.
      const work = deps.signer.sign(body, principal, requestId).finally(release);
      work.catch(() => undefined); // the deadline may have already answered the caller
      const result = await withDeadline(work, config.signDeadlineMs);

      sendJson(res, 200, result);
      finish(200, {
        tenant: body.tenant,
        cert_alias: body.cert_alias,
        caller: principal.id,
        audit_id: result.audit_id,
        timestamped: result.timestamped,
        pdf_bytes: Buffer.byteLength(result.signed_pdf_base64, "base64"),
      });
    } catch (e) {
      const err = asGatewayError(e);
      if (!res.headersSent) sendJson(res, err.status, err.toBody());
      else res.end();
      // `detail` is operator-only; the caller got the fixed message.
      finish(err.status, { code: err.code, detail: err.detail });
    }
  };
}

export async function readiness(deps: ServerDeps): Promise<ReadyState> {
  const checks: ReadyState["checks"] = {};

  checks.tenants = { ok: deps.config.tenants.size > 0, detail: `${deps.config.tenants.size} tenant(s)` };

  try {
    await deps.probeCertStore();
    checks.cert_store = { ok: true };
  } catch (e) {
    checks.cert_store = { ok: false, detail: e instanceof Error ? e.message : String(e) };
  }

  const tsa = await deps.tsa.health();
  checks.tsa = {
    // A TSA that is configured-but-optional must not hold the pod out of
    // service: the signature degrades to CAdES-B and `timestamped:false` tells
    // dsalvus exactly that. Only a REQUIRED TSA gates readiness.
    ok: tsa.healthy || !deps.config.tsa.required,
    detail: tsa.configured ? `${tsa.healthy ? "healthy" : "unhealthy"}${tsa.error ? `: ${tsa.error}` : ""}` : "not configured",
  };

  if (deps.auth.jwks) {
    try {
      await deps.auth.jwks.warm();
      checks.jwks = { ok: deps.auth.jwks.loaded };
    } catch (e) {
      checks.jwks = { ok: false, detail: e instanceof Error ? e.message : String(e) };
    }
  }

  return { ready: Object.values(checks).every((c) => c.ok), checks };
}

export function createServer(deps: ServerDeps): http.Server | https.Server {
  const handler = createRequestHandler(deps);
  const { tls } = deps.config;
  if (!tls) return http.createServer(handler);
  return https.createServer(
    {
      key: readFileSync(tls.keyPath),
      cert: readFileSync(tls.certPath),
      ca: readFileSync(tls.clientCaPath),
      requestCert: true,
      // Reject at the handshake: an unverified peer never reaches the handler.
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    },
    handler,
  );
}
