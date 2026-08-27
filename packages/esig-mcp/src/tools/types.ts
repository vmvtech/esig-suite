// tools/types.ts
//
// The dependency bag every tool module receives. One shared shape (rather
// than a bespoke interface per tool) keeps `server.ts`'s wiring a single
// object literal and keeps each tool file's signature self-documenting about
// what it actually touches (most destructure only 1-2 fields off this).

import type { AuditLogStore, CertStore, PqKeyStore } from "@e-sig/core";

import type { Config } from "../config.js";
import type { DocumentStore } from "../documents.js";
import type { EnvelopeService } from "../envelopes.js";

export interface McpServerDeps {
  config: Config;
  envelopes: EnvelopeService;
  documents: DocumentStore;
  certStore: CertStore;
  pqKeyStore: PqKeyStore;
  /**
   * Only used directly by tools that are NOT already audited inside
   * `EnvelopeService` (create/void/sign write their own rows there) —
   * currently just `esig_ingest_document` (design doc §4 "Prepare tools
   * (allowed, audited)").
   */
  auditStore: AuditLogStore;
}
