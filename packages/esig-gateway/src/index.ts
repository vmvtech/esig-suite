// @e-sig/assurance-gateway
//
// A small internal signing service in front of @e-sig/core.
//
//   POST /v1/sign   { tenant, cert_alias, html_base64, purpose, timestamp }
//                -> { signed_pdf_base64, cert_fingerprint, timestamped }
//   GET  /healthz   liveness
//   GET  /ready     readiness (tenant registry, cert store, TSA, JWKS)
//
// The wire contract is frozen by the dsalvus client (`internal/assurance/
// sign.go`); everything else — algorithm, custody, persistence, transport —
// is this package's decision and is documented in README.md.
//
// Programmatic use (tests, embedding, or swapping in a real store):
//
//   const gw = await createGateway(config, { certStore: new SupabaseCertStore(...) });
//   await gw.listen();

import { FsAuditLogStore, FsCertStore } from "@e-sig/core/fs";
import type { AuditLogStore, CertStore, PdfStorageStore, PqKeyStore } from "@e-sig/core";
import { WormPdfStorageStore, type WormObjectLockClient } from "@e-sig/worm";
import type http from "node:http";
import type https from "node:https";

import { Authenticator, JwksCache } from "./auth.js";
import type { GatewayConfig } from "./config.js";
import { Signer } from "./sign.js";
import { FsPqKeyStore, KeyedMutex } from "./stores.js";
import { TsaPool } from "./tsa.js";
import { createServer, readiness, type ServerDeps } from "./server.js";

export { loadConfigFromEnv, parseTenantRegistry, resolveBinding, certKeyFor, assertSlug } from "./config.js";
export type {
  GatewayConfig,
  TenantBinding,
  AuthConfig,
  AuthMode,
  JwtAuthConfig,
  MtlsAuthConfig,
  TsaConfig,
} from "./config.js";
export { GatewayError } from "./errors.js";
export { Authenticator, JwksCache, ReplayCache, verifyJwt, parseXfcc, type Principal } from "./auth.js";
export { Signer, parseSignRequest, type SignRequestBody, type SignResponseBody } from "./sign.js";
export { FsPqKeyStore, KeyedMutex } from "./stores.js";
export { TsaPool, type TsaHealth } from "./tsa.js";
export { createRequestHandler, createServer, readiness, Semaphore, type ReadyState } from "./server.js";
export { WormPdfStorageStore, type WormObjectLockClient } from "@e-sig/worm";

export interface GatewayOverrides {
  certStore?: CertStore;
  pqKeyStore?: PqKeyStore;
  auditStore?: AuditLogStore;
  /** Sign-time WORM archival. Off unless the owner moves custody here (§6). */
  archive?: PdfStorageStore;
  /**
   * S3-compatible client for WORM archival. Required when
   * `config.wormBucket` is set and no `archive` override is provided.
   * The `@aws-sdk/client-s3` S3 client satisfies this interface structurally.
   */
  wormClient?: WormObjectLockClient;
  /** Substitute the HTML→PDF renderer (tests use a fixture; no Chromium in CI). */
  render?: (html: string) => Promise<Buffer>;
  jwks?: JwksCache;
  fetchImpl?: typeof fetch;
  now?: () => Date;
  log?: (record: Record<string, unknown>) => void;
}

export interface Gateway {
  server: http.Server | https.Server;
  deps: ServerDeps;
  listen(): Promise<{ host: string; port: number }>;
  close(): Promise<void>;
  readiness(): ReturnType<typeof readiness>;
}

export async function createGateway(config: GatewayConfig, overrides: GatewayOverrides = {}): Promise<Gateway> {
  const certStore = overrides.certStore ?? new FsCertStore(config.stateDir);
  const pqKeyStore = overrides.pqKeyStore ?? new FsPqKeyStore(config.stateDir);
  const auditStore = overrides.auditStore ?? new FsAuditLogStore(config.stateDir);
  const tsa = new TsaPool(config.tsa, overrides.fetchImpl ?? fetch);

  // Resolve the archive store: auto-create WormPdfStorageStore when the bucket
  // is configured, unless an explicit archive override is provided (tests,
  // embedding with a custom store).
  let archive = overrides.archive;
  if (!archive && config.wormBucket) {
    if (!overrides.wormClient) {
      throw new Error(
        "ESIG_GATEWAY_WORM_BUCKET is set but no wormClient provided. " +
          "Pass an S3 client via createGateway(config, { wormClient }) or set an explicit archive override.",
      );
    }
    archive = new WormPdfStorageStore(overrides.wormClient, { bucket: config.wormBucket });
  }

  const jwks =
    overrides.jwks ??
    (config.auth.jwt
      ? new JwksCache(config.auth.jwt.jwksUri, config.auth.jwt.jwks, 300_000, 30_000, overrides.fetchImpl ?? fetch)
      : undefined);

  const signer = new Signer({
    config,
    certStore,
    pqKeyStore,
    auditStore,
    tsa,
    mutex: new KeyedMutex(),
    archive,
    render: overrides.render,
    now: overrides.now,
  });

  // Readiness probe for the cert store: a real read against a real partition
  // key, so a broken volume mount or an unreachable database surfaces here
  // rather than on the first dossier of the month.
  const firstTenant = [...config.tenants.values()][0];
  const probeKey = `${firstTenant.tenant}/${firstTenant.aliases[0]}`;
  const probeCertStore = async () => {
    await certStore.findActive(probeKey);
  };

  const deps: ServerDeps = {
    config,
    auth: new Authenticator(config.auth, jwks),
    signer,
    tsa,
    probeCertStore,
    log: overrides.log,
  };

  const server = createServer(deps);

  return {
    server,
    deps,
    listen: () =>
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(config.port, config.host, () => {
          const addr = server.address();
          resolve(
            typeof addr === "object" && addr
              ? { host: addr.address, port: addr.port }
              : { host: config.host, port: config.port },
          );
        });
      }),
    close: () =>
      new Promise((resolve, reject) => {
        server.close((e) => (e ? reject(e) : resolve()));
      }),
    readiness: () => readiness(deps),
  };
}
