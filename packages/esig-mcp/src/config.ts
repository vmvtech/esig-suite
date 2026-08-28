// config.ts
//
// Env-driven configuration for @e-sig/mcp (docs/architecture/esig-mcp.md §5).
// Pure and synchronous — no I/O, no process.exit — so it is fully unit
// testable by passing a plain env record instead of `process.env`.
//
// Fail-closed by design (I2): v0.1 implements ONLY mode H (human signs).
// `ESIG_MCP_MODES` including "A" or "C" refuses to build a Config at all —
// there is no code path in this package that can start a server for a mode
// it does not implement.

import path from "node:path";

import type { IdentityLevel } from "./identity/types.js";

export type EsigMcpMode = "H" | "A" | "C";

export interface SmtpDeliveryConfig {
  host: string;
  port: number;
  user?: string;
  pass?: string;
  /** Implicit TLS from connect (ESIG_MCP_SMTP_SECURE=1, or port 465). */
  secure: boolean;
  /** ESIG_MCP_SMTP_ALLOW_PLAINTEXT=1 — skip STARTTLS entirely. Off by default. */
  allowPlaintext: boolean;
  /** RedTeam RT-2026-08-27-05 G2: ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS=1 — skip server certificate verification (`rejectUnauthorized: false`) against the system CA. Off by default (verification ON); loud startup warning when set (bin.ts). */
  allowUnverifiedTls: boolean;
}

export interface SesDeliveryConfig {
  region: string;
}

export type DeliveryConfig =
  | { kind: "console" }
  | { kind: "file" }
  | { kind: "webhook"; url: string }
  | {
      kind: "email";
      transport: "smtp" | "ses";
      /** ESIG_MCP_EMAIL_FROM — "Name <addr>" or a bare address. */
      from: string;
      replyTo?: string;
      subjectPrefix?: string;
      smtp?: SmtpDeliveryConfig;
      ses?: SesDeliveryConfig;
    };

/** `ESIG_MCP_REMINDERS` (§15 "Reminders"). Empty `durationsMs` (the default) means reminders are off. */
export interface RemindersConfig {
  /** Parsed `ESIG_MCP_REMINDERS` durations, in milliseconds, in the order configured — reminder N fires `durationsMs[N]` after the envelope was created. */
  durationsMs: number[];
  /** `ESIG_MCP_REMINDER_MAX`, default 3 — the hard cap on reminders sent per signer, independent of how many durations are configured. */
  max: number;
}

/** `ESIG_MCP_EVENTS_WEBHOOK_URL` / `ESIG_MCP_EVENTS_WEBHOOK_SECRET` (§16 "Webhook delivery"). Operator config only — never settable from a tool call. */
export interface EventsWebhookConfig {
  url: string;
  secret: string;
}

export interface EventsConfig {
  /** Undefined means lifecycle events are still logged (`metadata.mcp.events[]`, `esig_list_events`) but never POSTed anywhere. */
  webhook?: EventsWebhookConfig;
}

export interface Config {
  /** Parsed, validated `ESIG_MCP_MODES`. v0.1 always resolves to exactly ["H"]. */
  modes: EsigMcpMode[];
  /** Encrypts the tenant's signing cert + PQ key bundle at rest (CertStore / PqKeyStore). */
  passphrase: string;
  /** Root directory for the Fs* stores (certs.json, envelopes.json, audit-log.ndjson, pq-keys.json, blobs/). */
  dataDir: string;
  /**
   * Confines the `path` input on `esig_verify_document` / `esig_ingest_document`
   * (D6): a connected agent is untrusted by default (design doc §2), so a
   * caller-supplied filesystem path may only resolve inside this directory —
   * never an absolute path outside it, a ".." segment, or a symlink that
   * escapes it. Default `<dataDir>/inbox`.
   */
  docsRoot: string;
  /** Tenant/partition key for CertStore, PqKeyStore, and envelopes. */
  tenant: string;
  /** Cert subject CN (ASCII-clean tenant/org display name). */
  subjectName: string;
  httpHost: string;
  httpPort: number;
  /** Base URL signing links are built from: `${baseUrl}/sign/<token>`. */
  baseUrl: string;
  /**
   * I8 / T1 / T8 escape hatch — OFF unless ESIG_MCP_RETURN_LINKS is exactly
   * "1". When on, `esig_create_envelope`-equivalent calls return raw signing
   * links directly to the MCP caller, which defeats the human-in-the-loop
   * token-custody guarantee. Local demos only; every affected audit row also
   * records this flag (see envelopes.ts).
   */
  returnLinks: boolean;
  delivery: DeliveryConfig;
  /** Embed the hybrid Ed25519 + ML-DSA-65 seal at envelope completion. Default true. */
  pq: boolean;
  maxHtmlBytes: number;
  maxPdfBytes: number;
  envelopesPerHour: number;
  /** RedTeam RT-2026-08-27-05 G6: `ESIG_MCP_MAX_SIGNERS`, default 25 — a per-envelope cap on `esig_create_envelope`'s `signers[]`, enforced at create (envelopes.ts), bounding the email/webhook fan-out one envelope can trigger. */
  maxSigners: number;
  /** Signer identity floor (docs/architecture/esig-mcp.md §12 "Policy"). `esig_create_envelope` may only RAISE this per envelope, never lower it. Default "none" (v0.1 behavior — unchanged). */
  identityMinLevel: IdentityLevel;
  /** https-only UUAID registry base URL. Required when `identityMinLevel` is "L2" (validated here); required per-envelope at create time when an envelope itself requests L2 (envelopes.ts). */
  uuaidRegistryUrl?: string;
  /**
   * The PINNED UUAID registry Ed25519 public key (64 lowercase hex) — the
   * trust anchor L2 verifies registry-signed badges against
   * (`keys[].publicKey`, `uuaid-registry-1`, of the registry's
   * `/.well-known/uuaid-registry.json`). Required when `identityMinLevel` is
   * "L2" (validated here) and per-envelope at create time (envelopes.ts);
   * required at verify time before any network call (identity/verify.ts,
   * `L2_NO_REGISTRY_KEY`).
   */
  uuaidRegistrySigningKey?: string;
  /** Seconds. `ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC`, default 900, max 3600. */
  identityChallengeTtlSec: number;
  /** `ESIG_MCP_REMINDERS` / `ESIG_MCP_REMINDER_MAX` (§15 "Reminders"). Empty schedule (the default) means reminders are off; validated here to require `delivery.kind === "email"`. */
  reminders: RemindersConfig;
  /** §16 "Lifecycle events and webhooks". */
  events: EventsConfig;
  /**
   * `ESIG_MCP_ALLOW_INSECURE_WEBHOOK` — the `ESIG_MCP_DELIVERY=webhook` link-delivery channel ONLY (checked at config time, above, and re-checked at startup, bin.ts F4). RedTeam RT-2026-08-27-05 G5: the events webhook has its OWN `allowInsecureEventsWebhook` flag below rather than sharing this one — the two channels have different operators-in-mind (a link-delivery receiver you stood up yourself vs. an events sink that might be a third party), so a decision to relax one must never silently relax the other.
   */
  allowInsecureWebhook: boolean;
  /** RedTeam RT-2026-08-27-05 G5: `ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK` — the events webhook ONLY; re-checked on every send (events/webhook.ts) and at startup (bin.ts F4). Deliberately separate from `allowInsecureWebhook` above — see that field's own comment. */
  allowInsecureEventsWebhook: boolean;
  /** `ESIG_MCP_ALLOW_PRIVATE_WEBHOOK` — shared by both webhook channels (T18); re-checked on every send and at startup (bin.ts F4). */
  allowPrivateWebhook: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/**
 * Minimum ESIG_MCP_PASSPHRASE length this package enforces at config time.
 *
 * D3 FIX: this used to be 16, while core's own at-rest encryption
 * (`encryptKeyPem` / `decryptKeyPem`, used by both `ensureActiveCert` and
 * `wrapPqKeyBundle`) enforces a HIGHER floor — `MIN_PASSPHRASE_LEN = 24`
 * (cert-issuer.ts:24) — so a 16-23 character passphrase passed `loadConfig`
 * here but threw later, at first seal, from inside
 * `ensureActiveCert`/`ensureActivePqKeys`. Mirrored to 24 here (core does not
 * export its constant) so the two floors can never disagree again.
 */
const MIN_PASSPHRASE_LEN = 24;

const ALL_MODES: EsigMcpMode[] = ["H", "A", "C"];

function parsePositiveInt(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) {
    throw new ConfigError(`${name} must be a positive integer, got "${raw}"`);
  }
  return n;
}

/** Load + validate configuration from an env-like record. Pure; throws `ConfigError` on any invalid input. */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const modesRaw = env.ESIG_MCP_MODES?.trim() || "H";
  const modes = modesRaw
    .split(",")
    .map((m) => m.trim().toUpperCase())
    .filter((m) => m.length > 0) as EsigMcpMode[];

  if (modes.length === 0) {
    throw new ConfigError(`ESIG_MCP_MODES="${modesRaw}" resolved to no modes.`);
  }
  for (const m of modes) {
    if (!ALL_MODES.includes(m)) {
      throw new ConfigError(`ESIG_MCP_MODES="${modesRaw}": unknown mode "${m}" (expected H, A, or C).`);
    }
  }
  const disallowed = modes.filter((m) => m !== "H");
  if (disallowed.length > 0) {
    throw new ConfigError(
      `ESIG_MCP_MODES="${modesRaw}": mode(s) ${disallowed.join(", ")} are not implemented in ` +
        `@e-sig/mcp v0.1 — fail-closed by design (invariant I2). Only mode H (human signs) is ` +
        `supported; modes A and C ship in v0.2 after RedTeam review ` +
        `(docs/architecture/esig-mcp.md §3, §7).`,
    );
  }

  const passphrase = env.ESIG_MCP_PASSPHRASE ?? "";
  if (passphrase.length < MIN_PASSPHRASE_LEN) {
    throw new ConfigError(
      `ESIG_MCP_PASSPHRASE is required and must be at least ${MIN_PASSPHRASE_LEN} characters — it ` +
        `encrypts the tenant's signing cert and post-quantum key bundle at rest.`,
    );
  }

  const dataDir = env.ESIG_MCP_DATA_DIR?.trim() || "./.esig-mcp";
  const docsRoot = path.resolve(env.ESIG_MCP_DOCS_ROOT?.trim() || path.join(dataDir, "inbox"));
  const tenant = env.ESIG_MCP_TENANT?.trim() || "default";
  const subjectName = env.ESIG_MCP_SUBJECT_NAME?.trim() || "e-sig MCP";
  const httpHost = env.ESIG_MCP_HTTP_HOST?.trim() || "127.0.0.1";
  const httpPort = parsePositiveInt(env.ESIG_MCP_HTTP_PORT, 7433, "ESIG_MCP_HTTP_PORT");
  const baseUrl = env.ESIG_MCP_BASE_URL?.trim() || `http://${httpHost}:${httpPort}`;
  const returnLinks = env.ESIG_MCP_RETURN_LINKS === "1";

  // G3(a) FIX (RedTeam rt-verdict-ESIGMCP-V01-20260826, MEDIUM / I11): NO
  // DEFAULT. The old default ("console") prints signing links to stderr,
  // which in the canonical stdio MCP deployment is the agent harness's own
  // captured log — the token IS the signing capability (POST /sign needs no
  // browser), so a silent default handed it straight to the untrusted agent
  // this package's whole threat model (T1/T8) exists to exclude. An operator
  // must now say explicitly where signing links go.
  const deliveryKindRaw = env.ESIG_MCP_DELIVERY?.trim();
  if (!deliveryKindRaw) {
    throw new ConfigError(
      "ESIG_MCP_DELIVERY is required (no default) — set it to one of: " +
        '"file" (writes one JSON receipt per envelope under <ESIG_MCP_DATA_DIR>/outbox/, the ' +
        'quickstart channel), "console" (prints links to stderr — opt-in only, since in a stdio ' +
        "MCP deployment stderr is the agent harness's own log surface), or " +
        '"webhook" (POSTs each link to ESIG_MCP_DELIVERY_WEBHOOK_URL). See invariant I11: ' +
        "https://github.com/vmvtech/esig-suite/blob/main/docs/architecture/esig-mcp.md" +
        "#6-security-invariants-each-becomes-a-test.",
    );
  }
  // G5 FIX: ESIG_MCP_DELIVERY=webhook (checked once, right below) and the
  // §16 events webhook (checked on every send, events/webhook.ts) each get
  // their OWN insecure-http opt-out — see Config.allowInsecureWebhook's own
  // comment. allowPrivateWebhook is still a single shared knob (T18, both
  // webhook channels' SSRF policy).
  const allowInsecureWebhook = env.ESIG_MCP_ALLOW_INSECURE_WEBHOOK === "1";
  const allowInsecureEventsWebhook = env.ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK === "1";
  const allowPrivateWebhook = env.ESIG_MCP_ALLOW_PRIVATE_WEBHOOK === "1";

  const deliveryKind = deliveryKindRaw.toLowerCase();
  let delivery: DeliveryConfig;
  if (deliveryKind === "file") {
    delivery = { kind: "file" };
  } else if (deliveryKind === "console") {
    delivery = { kind: "console" };
  } else if (deliveryKind === "webhook") {
    const url = env.ESIG_MCP_DELIVERY_WEBHOOK_URL?.trim();
    if (!url) {
      throw new ConfigError(
        'ESIG_MCP_DELIVERY="webhook" requires ESIG_MCP_DELIVERY_WEBHOOK_URL to be set.',
      );
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      throw new ConfigError(`ESIG_MCP_DELIVERY_WEBHOOK_URL is not a valid URL: "${url}"`);
    }
    // G3(d): a plaintext webhook URL leaks the signing link (the capability
    // itself) to anything on the network path. Require https:// unless the
    // operator explicitly opts out (e.g. a same-host loopback receiver).
    if (parsedUrl.protocol !== "https:" && !allowInsecureWebhook) {
      throw new ConfigError(
        `ESIG_MCP_DELIVERY_WEBHOOK_URL must use https:// (got "${parsedUrl.protocol}//..."); ` +
          "set ESIG_MCP_ALLOW_INSECURE_WEBHOOK=1 to override for a trusted local/loopback receiver.",
      );
    }
    delivery = { kind: "webhook", url };
  } else if (deliveryKind === "email") {
    const transportRaw = env.ESIG_MCP_EMAIL_TRANSPORT?.trim().toLowerCase();
    if (transportRaw !== "smtp" && transportRaw !== "ses") {
      throw new ConfigError(
        'ESIG_MCP_DELIVERY="email" requires ESIG_MCP_EMAIL_TRANSPORT to be exactly "smtp" or "ses".',
      );
    }
    const from = env.ESIG_MCP_EMAIL_FROM?.trim();
    if (!from) {
      throw new ConfigError(
        'ESIG_MCP_DELIVERY="email" requires ESIG_MCP_EMAIL_FROM (e.g. "Acme <noreply@acme.com>" or a bare address).',
      );
    }
    const replyTo = env.ESIG_MCP_EMAIL_REPLY_TO?.trim() || undefined;
    const subjectPrefix = env.ESIG_MCP_EMAIL_SUBJECT_PREFIX?.trim() || undefined;

    if (transportRaw === "smtp") {
      const host = env.ESIG_MCP_SMTP_HOST?.trim();
      if (!host) {
        throw new ConfigError('ESIG_MCP_EMAIL_TRANSPORT="smtp" requires ESIG_MCP_SMTP_HOST.');
      }
      const port = parsePositiveInt(env.ESIG_MCP_SMTP_PORT, 587, "ESIG_MCP_SMTP_PORT");
      const user = env.ESIG_MCP_SMTP_USER?.trim() || undefined;
      // Never trim a password — leading/trailing whitespace can be part of it.
      const pass = env.ESIG_MCP_SMTP_PASS || undefined;
      if ((user && !pass) || (!user && pass)) {
        throw new ConfigError("ESIG_MCP_SMTP_USER and ESIG_MCP_SMTP_PASS must both be set, or both left unset.");
      }
      const secure = env.ESIG_MCP_SMTP_SECURE === "1" || port === 465;
      const allowPlaintext = env.ESIG_MCP_SMTP_ALLOW_PLAINTEXT === "1";
      // G2: server certificate verification is ON by default — this is a
      // loud, explicit opt-out (bin.ts prints a startup WARNING whenever
      // it's set), never a silent one.
      const allowUnverifiedTls = env.ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS === "1";
      delivery = {
        kind: "email",
        transport: "smtp",
        from,
        replyTo,
        subjectPrefix,
        smtp: { host, port, user, pass, secure, allowPlaintext, allowUnverifiedTls },
      };
    } else {
      const region = env.ESIG_MCP_SES_REGION?.trim();
      if (!region) {
        throw new ConfigError('ESIG_MCP_EMAIL_TRANSPORT="ses" requires ESIG_MCP_SES_REGION.');
      }
      delivery = { kind: "email", transport: "ses", from, replyTo, subjectPrefix, ses: { region } };
    }
  } else {
    throw new ConfigError(
      `ESIG_MCP_DELIVERY="${deliveryKindRaw}": expected "file", "console", "webhook", or "email".`,
    );
  }

  const pq = (env.ESIG_MCP_PQ ?? "1") !== "0";

  const maxHtmlBytes = parsePositiveInt(env.ESIG_MCP_MAX_HTML_BYTES, 512 * 1024, "ESIG_MCP_MAX_HTML_BYTES");
  const maxPdfBytes = parsePositiveInt(
    env.ESIG_MCP_MAX_PDF_BYTES,
    25 * 1024 * 1024,
    "ESIG_MCP_MAX_PDF_BYTES",
  );
  const envelopesPerHour = parsePositiveInt(
    env.ESIG_MCP_ENVELOPES_PER_HOUR,
    60,
    "ESIG_MCP_ENVELOPES_PER_HOUR",
  );
  // G6: bounds the email/webhook fan-out one esig_create_envelope call can
  // trigger — enforced at create() (envelopes.ts), not here (parsing has no
  // signers[] to count).
  const maxSigners = parsePositiveInt(env.ESIG_MCP_MAX_SIGNERS, 25, "ESIG_MCP_MAX_SIGNERS");

  // ---- Signer identity (docs/architecture/esig-mcp.md §12 "Policy") ----

  const identityMinLevelRaw = env.ESIG_MCP_IDENTITY_MIN_LEVEL?.trim() || "none";
  const IDENTITY_LEVELS = ["none", "L0", "L1", "L2"] as const;
  if (!(IDENTITY_LEVELS as readonly string[]).includes(identityMinLevelRaw)) {
    throw new ConfigError(
      `ESIG_MCP_IDENTITY_MIN_LEVEL="${identityMinLevelRaw}": expected one of none, L0, L1, L2.`,
    );
  }
  const identityMinLevel = identityMinLevelRaw as IdentityLevel;

  const uuaidRegistryUrlRaw = env.ESIG_MCP_UUAID_REGISTRY_URL?.trim();
  let uuaidRegistryUrl: string | undefined;
  if (uuaidRegistryUrlRaw) {
    let parsedRegistryUrl: URL;
    try {
      parsedRegistryUrl = new URL(uuaidRegistryUrlRaw);
    } catch {
      throw new ConfigError(`ESIG_MCP_UUAID_REGISTRY_URL is not a valid URL: "${uuaidRegistryUrlRaw}"`);
    }
    // T13: the registry is queried over the open network at sign time —
    // require https:// unconditionally (no escape hatch, unlike the webhook
    // delivery channel: this URL is queried by the server itself on every L2
    // verification, not a one-time operator-chosen local receiver).
    if (parsedRegistryUrl.protocol !== "https:") {
      throw new ConfigError(
        `ESIG_MCP_UUAID_REGISTRY_URL must use https:// (got "${parsedRegistryUrl.protocol}//...").`,
      );
    }
    uuaidRegistryUrl = uuaidRegistryUrlRaw.replace(/\/$/, "");
  }
  // Fail closed at config time when the SERVER-WIDE floor is L2: identical
  // per-envelope validation (an envelope may RAISE its own requested level to
  // L2 even when the config floor is lower) lives in envelopes.ts `create()`.
  if (identityMinLevel === "L2" && !uuaidRegistryUrl) {
    throw new ConfigError(
      'ESIG_MCP_IDENTITY_MIN_LEVEL="L2" requires ESIG_MCP_UUAID_REGISTRY_URL (https://...) to be set.',
    );
  }

  // The PINNED registry Ed25519 public key — the trust anchor L2 verifies
  // badges against (identity/badge.ts). Pinned at config time, never fetched
  // per-request: fetching /.well-known/uuaid-registry.json on demand would
  // let whoever controls TLS/DNS silently swap the trust anchor. Unlike the
  // registry URL this is not pinned per envelope (the URL pin, G3, already
  // fixes WHICH registry attests) — a registry key rotation just fails
  // verification (fail closed) until config is updated.
  const uuaidRegistrySigningKeyRaw = env.ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY?.trim();
  let uuaidRegistrySigningKey: string | undefined;
  if (uuaidRegistrySigningKeyRaw) {
    if (!/^[0-9a-fA-F]{64}$/.test(uuaidRegistrySigningKeyRaw)) {
      throw new ConfigError(
        `ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY must be exactly 64 hex characters (the registry's Ed25519 ` +
          `public key, keys[].publicKey of its /.well-known/uuaid-registry.json), got ${uuaidRegistrySigningKeyRaw.length}.`,
      );
    }
    uuaidRegistrySigningKey = uuaidRegistrySigningKeyRaw.toLowerCase();
  }
  if (identityMinLevel === "L2" && !uuaidRegistrySigningKey) {
    throw new ConfigError(
      'ESIG_MCP_IDENTITY_MIN_LEVEL="L2" requires ESIG_MCP_UUAID_REGISTRY_SIGNING_KEY (the pinned registry ' +
        "Ed25519 public key, 64 hex chars) in addition to ESIG_MCP_UUAID_REGISTRY_URL.",
    );
  }

  const identityChallengeTtlSec = parsePositiveInt(
    env.ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC,
    900,
    "ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC",
  );
  if (identityChallengeTtlSec > 3600) {
    throw new ConfigError(
      `ESIG_MCP_IDENTITY_CHALLENGE_TTL_SEC must be <= 3600 (got ${identityChallengeTtlSec}).`,
    );
  }

  // ---- Reminders (docs/architecture/esig-mcp.md §15 "Reminders") ----

  const remindersRaw = env.ESIG_MCP_REMINDERS?.trim();
  const durationsMs = remindersRaw
    ? remindersRaw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
        .map((s) => parseDuration(s))
    : [];
  const reminderMax = parsePositiveInt(env.ESIG_MCP_REMINDER_MAX, 3, "ESIG_MCP_REMINDER_MAX");

  // A reminder resends the ORIGINAL signing link, which only email delivery
  // persists (encrypted at rest — envelopes.ts `create()`); refuse at config
  // time rather than silently doing nothing once a reminder comes due.
  if (durationsMs.length > 0 && deliveryKind !== "email") {
    throw new ConfigError(
      'ESIG_MCP_REMINDERS requires ESIG_MCP_DELIVERY="email" — reminders resend the original signing ' +
        "link by email, so there is no other channel to resend it through.",
    );
  }

  // ---- Lifecycle event webhooks (docs/architecture/esig-mcp.md §16) ----

  const eventsWebhookUrlRaw = env.ESIG_MCP_EVENTS_WEBHOOK_URL?.trim();
  // Never trim a secret — leading/trailing whitespace can be part of it (same rule as ESIG_MCP_SMTP_PASS above).
  const eventsWebhookSecretRaw = env.ESIG_MCP_EVENTS_WEBHOOK_SECRET;
  let eventsWebhook: EventsWebhookConfig | undefined;
  if (eventsWebhookUrlRaw || eventsWebhookSecretRaw) {
    if (!eventsWebhookUrlRaw || !eventsWebhookSecretRaw) {
      throw new ConfigError(
        "ESIG_MCP_EVENTS_WEBHOOK_URL and ESIG_MCP_EVENTS_WEBHOOK_SECRET must both be set, or both left unset.",
      );
    }
    if (eventsWebhookSecretRaw.length < 32) {
      throw new ConfigError("ESIG_MCP_EVENTS_WEBHOOK_SECRET must be at least 32 characters.");
    }
    let parsedEventsWebhookUrl: URL;
    try {
      parsedEventsWebhookUrl = new URL(eventsWebhookUrlRaw);
    } catch {
      throw new ConfigError(`ESIG_MCP_EVENTS_WEBHOOK_URL is not a valid URL: "${eventsWebhookUrlRaw}"`);
    }
    // T18: re-checked on every send too (events/webhook.ts, since a literal
    // IP or a DNS answer can change between config load and send time) —
    // this is defense in depth at startup, refusing an obviously-bad config
    // before the server ever comes up. G5: its OWN flag, not the
    // link-delivery webhook's.
    if (parsedEventsWebhookUrl.protocol !== "https:" && !allowInsecureEventsWebhook) {
      throw new ConfigError(
        `ESIG_MCP_EVENTS_WEBHOOK_URL must use https:// (got "${parsedEventsWebhookUrl.protocol}//..."); ` +
          "set ESIG_MCP_ALLOW_INSECURE_EVENTS_WEBHOOK=1 to override for a trusted local/loopback receiver.",
      );
    }
    eventsWebhook = { url: eventsWebhookUrlRaw, secret: eventsWebhookSecretRaw };
  }

  return {
    modes,
    passphrase,
    dataDir,
    docsRoot,
    tenant,
    subjectName,
    httpHost,
    httpPort,
    baseUrl,
    returnLinks,
    delivery,
    pq,
    maxHtmlBytes,
    maxPdfBytes,
    envelopesPerHour,
    maxSigners,
    identityMinLevel,
    uuaidRegistryUrl,
    uuaidRegistrySigningKey,
    identityChallengeTtlSec,
    reminders: { durationsMs, max: reminderMax },
    events: { webhook: eventsWebhook },
    allowInsecureWebhook,
    allowInsecureEventsWebhook,
    allowPrivateWebhook,
  };
}

/** Parse a single `ESIG_MCP_REMINDERS` entry, e.g. "24h", "72h", "30m", into milliseconds. */
function parseDuration(raw: string): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(raw);
  if (!m) {
    throw new ConfigError(
      `ESIG_MCP_REMINDERS: invalid duration "${raw}" — expected a number followed by ms, s, m, h, or d (e.g. "24h").`,
    );
  }
  const unitMs: Record<string, number> = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return Number(m[1]) * unitMs[m[2]];
}
