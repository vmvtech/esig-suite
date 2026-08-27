// @e-sig/mcp
//
// The library layer (config/stores/documents/delivery/envelopes/verify/
// sanitize) plus the MCP server + approval-page layer built on top of it
// (docs/architecture/esig-mcp.md §5, §7). `bin.ts` is the real stdio +
// HTTP entrypoint (package.json's `esig-mcp` bin).

export { loadConfig, ConfigError, type Config, type EsigMcpMode, type DeliveryConfig } from "./config.js";

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

export {
  EnvelopeService,
  EnvelopeError,
  SEAL_RENDER_LAUNCH_ARGS,
  derivePhase,
  type EnvelopeServiceDeps,
  type SignerInput,
  type CreateEnvelopeArgs,
  type CreatedSigner,
  type CreateEnvelopeResultSummary,
  type EnvelopeStatusSummary,
  type EnvelopePhase,
  type EnvelopeSealState,
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
export { verifySignerIdentity } from "./identity/verify.js";
export { RegistryClient, RegistryError, resolveListsKey, type VerifyCredentialResult } from "./identity/registry.js";

export { createMcpServer, V0_1_TOOL_NAMES, type McpServerDeps } from "./server.js";

export { createApprovalServer, createApprovalRequestHandler, type HttpDeps } from "./http.js";
