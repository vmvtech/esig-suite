#!/usr/bin/env node
// bin.ts — container entrypoint.
//
// Loads config from the environment (which fails loudly and immediately if the
// deployment is misconfigured — an unauthenticated or tenant-less gateway never
// reaches `listen`), starts the server, and drains on SIGTERM so an in-flight
// monthly dossier is not truncated by a rollout.

import { createGateway, loadConfigFromEnv } from "./index.js";

function log(record: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...record }) + "\n");
}

async function main(): Promise<void> {
  const config = await loadConfigFromEnv();

  // Resolve the WORM S3 client. The gateway does not hard-depend on
  // @aws-sdk/client-s3 — the deployment must provide it. In ECS the SDK
  // picks up credentials from the task role automatically.
  let wormClient: import("@e-sig/worm").WormObjectLockClient | undefined;
  if (config.wormBucket) {
    try {
      // @ts-expect-error — @aws-sdk/client-s3 is an optional runtime-only dependency
      const { S3 } = await import("@aws-sdk/client-s3");
      wormClient = new S3({}) as import("@e-sig/worm").WormObjectLockClient;
    } catch {
      throw new Error(
        "ESIG_GATEWAY_WORM_BUCKET is set but @aws-sdk/client-s3 could not be loaded. " +
          "Install it in the container image or provide an explicit archive override.",
      );
    }
  }

  const gw = await createGateway(config, { wormClient });
  const addr = await gw.listen();

  log({
    event: "listening",
    host: addr.host,
    port: addr.port,
    tls: !!config.tls,
    auth_mode: config.auth.mode,
    transitional_auth: config.auth.mode === "api-key",
    tenants: [...config.tenants.keys()],
    tsa: { configured: config.tsa.urls.length > 0, required: config.tsa.required },
    max_concurrent_signs: config.maxConcurrentSigns,
    worm_archive: config.wormBucket ? { bucket: config.wormBucket, mode: "COMPLIANCE" } : false,
  });

  if (config.auth.mode === "api-key") {
    log({
      event: "warning",
      message:
        "running with TRANSITIONAL api-key auth — every audit row is tagged transitional_auth:true. " +
        "Migrate to mtls+jwt (vmv-one/HP-001) before the pilot is treated as production.",
    });
  }

  let shuttingDown = false;
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, () => {
      if (shuttingDown) return;
      shuttingDown = true;
      log({ event: "shutdown", signal });
      gw.close()
        .then(() => process.exit(0))
        .catch((e) => {
          log({ event: "shutdown_error", error: String(e) });
          process.exit(1);
        });
      // Backstop: a wedged Chromium must not hold the pod open past the grace period.
      setTimeout(() => process.exit(0), 20_000).unref();
    });
  }
}

main().catch((e) => {
  log({ event: "fatal", error: e instanceof Error ? e.message : String(e) });
  process.exit(1);
});
