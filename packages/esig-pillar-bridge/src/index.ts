// index.ts — @e-sig/pillar-bridge public surface.
// docs/architecture/esig-mcp.md §17.

export {
  resolvePillar,
  loadPillar,
  pinnedPillarHashes,
  PILLAR_FILES,
  walkImportGraph,
  assertPillarHashes,
  PillarIsolationError,
  PillarHashMismatchError,
  _resetPillarCacheForTests,
} from "./shim.js";
export type { PillarFile, ResolvePillarOptions, ResolvePillarResult } from "./shim.js";

export type {
  PillarModules,
  PillarEnvelope,
  PillarEnvelopeEnc,
  PillarTransportSignature,
  PillarSealBody,
  PillarOpenVerdict,
  PillarEnvelopeModule,
  PillarIdentityRecord,
  PillarKeychainInstance,
  PillarKeychainCtor,
  PillarCarrierAttempt,
  PillarCarrierDeliverResult,
  PillarCarrierInboxResult,
  PillarCarrierClientInstance,
  PillarCarrierClientCtor,
  PillarTierDefault,
  PillarTierGrant,
  PillarTierModule,
} from "./pillar-types.js";

export { PillarIdentity, localIdFromEd25519Key, uuaidFromEd25519Key } from "./identity.js";
export type { PillarIdentityLoadOptions, PillarIdentityGenerateOptions } from "./identity.js";

export { CarrierClient } from "./carrier.js";
export type { CarrierOptions, CarrierDeliverOptions, CarrierFetchInboxOptions } from "./carrier.js";

export { PillarDelivery } from "./delivery.js";
export type { PillarDeliveryOptions, SignRequestPayload } from "./delivery.js";

export { PillarEventSink } from "./events.js";
export type { PillarEventSinkOptions, PillarEventSubscriber, PillarEventReceipt } from "./events.js";

export { PillarProofSource } from "./proofs.js";
export type { PillarProofSourceOptions } from "./proofs.js";

export type {
  DeliveryLink,
  DeliveryEnvelopeMeta,
  Receipt,
  DeliveryChannel,
  EsigEventSigner,
  EsigEvent,
  EventSink,
  DataIntegrityProofLike,
  IdentityProofEvent,
  IdentityProofSource,
  PillarAuditEvent,
  PillarAuditCallback,
} from "./types.js";
