// @e-sig/mcp
//
// The library layer (config/stores/documents/delivery/envelopes/verify/
// sanitize) plus the MCP server + approval-page layer built on top of it
// (docs/architecture/esig-mcp.md §5, §7). `bin.ts` is the real stdio +
// HTTP entrypoint (package.json's `esig-mcp` bin).

export {
  loadConfig,
  ConfigError,
  type Config,
  type EsigMcpMode,
  type DeliveryConfig,
  type SmtpDeliveryConfig,
  type SesDeliveryConfig,
  type RemindersConfig,
  type EventsConfig,
  type EventsWebhookConfig,
  type PillarConfig,
  type PillarSubscriber,
} from "./config.js";

export { sanitizeEnvelopeHtml, type SanitizeResult } from "./sanitize.js";

export {
  buildStores,
  buildStoresFromDataDir,
  listEnvelopes,
  FsPqKeyStore,
  ConcurrencySafeEnvelopeStore,
  EnvelopeConflictError,
  type McpStores,
} from "./stores.js";

export { FsDocumentStore, type DocumentStore } from "./documents.js";

export { checkSealReadiness, type SealReadiness } from "./chrome-preflight.js";

export { resolveDocPath, PathEscapesRootError } from "./docs-root.js";

export {
  ConsoleDelivery,
  FileDelivery,
  WebhookDelivery,
  CapturingDelivery,
  type DeliveryChannel,
  type DeliveryLink,
  type Receipt,
} from "./delivery.js";

// §15: email delivery + reminders (v0.4).
export {
  SmtpTransport,
  SesTransport,
  CapturingTransport,
  type EmailTransport,
  type EmailMessage,
  type SendResult,
  type SmtpTransportOptions,
  type SesTransportOptions,
} from "./email/transport.js";
export { renderSigningEmail, stripControlChars, type EmailTemplateInput, type RenderedEmail } from "./email/templates.js";
export { EmailDelivery, type EmailDeliveryOptions } from "./email/delivery.js";
export { computeDue, Scheduler, type ReminderDueEntry, type SchedulerDeps } from "./reminders.js";

// §16: lifecycle events + webhooks (v0.4).
export { MAX_EVENTS, appendEvent, listEvents, type AppendEventInput } from "./events/log.js";
export type { EsigEvent, EsigEventInput, EsigEventSigner, EsigEventType } from "./events/types.js";
export { tick as expiryTick, type ExpiryTickDeps } from "./events/expiry.js";
export {
  assertSafeWebhookTarget,
  sendWebhook,
  signPayload,
  WebhookSsrfError,
  WebhookDeliveryError,
  type WebhookConfig,
  type WebhookTargetPolicy,
  type LookupFn,
  type PinnedRequestFn,
  type SendWebhookOptions,
} from "./events/webhook.js";
export {
  EventQueue,
  DEFAULT_BACKOFF_SEC,
  type EventQueueDeps,
  type EventDeliveryStatus,
} from "./events/queue.js";

// §17 seam 4: event fan-out to registered sinks (e.g. the Pillar bridge's).
export { EventDispatcher, type EventSink, type EventDispatcherDeps } from "./events/sinks.js";

export {
  EnvelopeService,
  EnvelopeError,
  SEAL_RENDER_LAUNCH_ARGS,
  derivePhase,
  getEnvelopeDocument,
  getPillarUnregisteredSignerIds,
  getSignerReminderState,
  type EnvelopeServiceDeps,
  type SignerInput,
  type CreateEnvelopeArgs,
  type CreatedSigner,
  type CreateEnvelopeResultSummary,
  type EnvelopeStatusSummary,
  type EnvelopePhase,
  type EnvelopeSealState,
  type EnvelopeDocumentMeta,
  type SignerReminderState,
} from "./envelopes.js";

export { verifyDocumentBytes, type VerifyOptions, type VerifyDocumentBytesResult } from "./verify.js";

// §12: signer identity via UUAID + IAASO (v0.2).
export {
  IDENTITY_LEVEL_ORDER,
  maxIdentityLevel,
  IdentityError,
  getEnvelopeIdentityPolicy,
  getSignerIdentityState,
  type IdentityLevel,
  type EnvelopeIdentityPolicy,
  type SignerChallengeState,
  type SignerIdentityRecord,
  type SignerIdentityRegistryRecord,
  type SignerIdentityState,
  type EnvelopeIdentityMetadata,
  type IdentityProofInput,
} from "./identity/types.js";
export {
  issueChallenge,
  finalizeChallenge,
  CHALLENGE_TYPE,
  ChallengeError,
  type IdentityChallengePayload,
} from "./identity/challenge.js";
export {
  verifySignerIdentity,
  localIdFromEd25519Key,
  uuaidFromEd25519Key,
  FOUNDATION_AGENT_UUAID_PREFIX,
  FOUNDATION_AGENT_UUAID_RE,
} from "./identity/verify.js";
export { RegistryClient, RegistryError, RegistryNotFoundError, type VerifyCredentialResult } from "./identity/registry.js";
export { BadgeError, verifyRegistryBadge, hexToBytes, type BadgePayload, type BadgePresentationKey } from "./identity/badge.js";
export type { IdentityProofSource, IdentityProofEvent } from "./identity/proof-source.js";

// §17 seams 2-4: the optional Pillar bridge loader — exported so tests can
// inject a fake `PillarLoader` without ever importing `@e-sig/pillar-bridge`
// or `@uuaid/pillar` themselves.
export {
  defaultPillarLoader,
  resolvePillarLoader,
  type PillarLoader,
  type PillarBridgeModule,
  type PillarBridgeIdentity,
  type PillarBridgeDeliveryChannel,
  type PillarBridgeEventSink,
  type PillarBridgeProofSource,
  type PillarBridgeIdentityProofEvent,
} from "./pillar-loader.js";

export { createMcpServer, V0_1_TOOL_NAMES, type McpServerDeps } from "./server.js";

export { createApprovalServer, createApprovalRequestHandler, type HttpDeps } from "./http.js";
