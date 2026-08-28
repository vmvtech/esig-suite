// events/types.ts
//
// The lifecycle event shape (docs/architecture/esig-mcp.md §16 "Event log"),
// exactly the 12 types listed there. `phase` is typed against `EnvelopePhase`
// (envelopes.ts) as a TYPE-ONLY import — erased entirely at compile time, so
// it creates no runtime circular dependency between this module and
// envelopes.ts (which imports the runtime `appendEvent` helper from
// `./log.js`, a sibling of this file).
//
// Payload discipline (§16 "never links, tokens, proofs, or document bytes"):
// every emission site in envelopes.ts/http.ts/events/expiry.ts is
// responsible for keeping `data` to safe, already-audited fields (counts,
// booleans, ids, non-secret metadata) — this module only defines the shape,
// it does not sanitize it.

import type { EnvelopePhase } from "../envelopes.js";

export type EsigEventType =
  | "envelope.created"
  | "envelope.viewed"
  | "envelope.signed"
  | "envelope.declined"
  | "envelope.completed"
  | "envelope.sealed"
  | "envelope.seal_failed"
  | "envelope.voided"
  | "envelope.expired"
  | "envelope.reminder_sent"
  | "signer.identity_verified"
  | "signer.identity_rejected";

export interface EsigEventSigner {
  signerId: string;
  name: string;
  email: string;
  status: string;
}

export interface EsigEvent {
  id: string;
  type: EsigEventType;
  /** ISO-8601. */
  createdAt: string;
  envelopeId: string;
  phase: EnvelopePhase;
  signer?: EsigEventSigner;
  data: Record<string, unknown>;
}

/** Everything `appendEvent` (log.ts) needs from a caller — `id`/`createdAt` are stamped by `appendEvent` itself. */
export type EsigEventInput = Omit<EsigEvent, "id" | "createdAt">;
