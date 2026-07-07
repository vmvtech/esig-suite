// @e-sig/uuaid — withUuaidActor
//
// AuditLogStore decorator that stamps the acting agent's UUAID into every
// entry's `metadata` Record before delegating to the wrapped store.
// Contract-safe by design: `AuditLogEntry.metadata` is an open
// Record<string, unknown> in @e-sig/core, so no core change (and no
// store-specific knowledge) is needed — Supabase, filesystem, and custom
// stores all persist the stamp as ordinary metadata, and the audit hash
// chain covers it like any other metadata key.

import type { AuditLogStore, AuditLogEntry, AuditLogRow } from "@e-sig/core";

/** Metadata key written by `withUuaidActor`. */
export const UUAID_ACTOR_METADATA_KEY = "uuaidAgent";

/**
 * Wrap an `AuditLogStore` so every inserted entry carries
 * `metadata.uuaidAgent = agentUuaid`. Existing metadata keys are preserved
 * (a caller-supplied `uuaidAgent` is overwritten — the decorator is
 * authoritative), and the caller's entry object is never mutated.
 *
 * A blank `agentUuaid` (e.g. an unset env var) returns the store unchanged:
 * stamping is cleanly disabled, nothing else about the store changes.
 */
export function withUuaidActor(store: AuditLogStore, agentUuaid: string): AuditLogStore {
  if (!agentUuaid) return store;
  return {
    insert(entry: AuditLogEntry): Promise<AuditLogRow> {
      return store.insert({
        ...entry,
        metadata: { ...entry.metadata, [UUAID_ACTOR_METADATA_KEY]: agentUuaid },
      });
    },
  };
}
