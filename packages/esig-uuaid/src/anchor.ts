// @e-sig/uuaid — anchorChainHead
//
// External anchoring for the esig audit hash chain. Saves the tenant's
// chain-head hash as a client-side-encrypted vault item on an agent's UUAID
// identity (vault key `esig/chain-head/<tenantId>`). UUAID records the
// item's content hash in its own hash-chained ledger, whose Merkle roots
// anchor to Polygon mainnet — external tamper-evidence WITHOUT any document
// content leaving your infrastructure: only the chain-head hash is sent,
// and it is encrypted (AES-256-GCM via @uuaid/vault) before upload.

import type { UuaidClient } from "@uuaid/sdk";

/** The slice of `UuaidClient` this module needs (mock-friendly). */
export type ChainHeadAnchorClient = Pick<UuaidClient, "saveMemory">;

export interface AnchorChainHeadOptions {
  /** A configured `UuaidClient` from `@uuaid/sdk` (only `saveMemory` is used). */
  client: ChainHeadAnchorClient;
  /** UUAID of the agent identity that owns the vault (see `UuaidClient.registerAgent`). */
  agentUuaid: string;
  /**
   * Symmetric vault key (`uvk_…`, see `generateVaultKey` in `@uuaid/vault`).
   * Encryption happens client-side — the key never leaves this process.
   */
  vaultKey: string;
  /** Tenant whose audit chain is being anchored; becomes part of the vault slot key. */
  tenantId: string;
  /** The chain head: `row_hash` (hex) of the tenant's latest audit row. */
  chainHeadHash: string;
}

export interface AnchorChainHeadResult {
  /**
   * sha256 of the stored (encrypted) envelope, as recorded in UUAID's
   * Polygon-anchored ledger. Keep it to cross-check the anchor later.
   */
  contentHash: string;
}

/**
 * Anchor a tenant's audit-chain head under vault key
 * `esig/chain-head/<tenantId>`. The stored plaintext is a small versioned
 * record `{ v: 1, tenantId, chainHeadHash, anchoredAt }` (readable back via
 * `UuaidClient.loadMemory` with the same vault key); it is encrypted before
 * upload, so UUAID only ever sees ciphertext.
 *
 * Throws before any network call if a required option is blank — callers
 * gating on env config (UUAID key unset → skip anchoring) never reach the
 * network by accident.
 */
export async function anchorChainHead(opts: AnchorChainHeadOptions): Promise<AnchorChainHeadResult> {
  const { client, agentUuaid, vaultKey, tenantId, chainHeadHash } = opts;
  if (!client) throw new Error("anchorChainHead: client is required");
  for (const [name, value] of Object.entries({ agentUuaid, vaultKey, tenantId, chainHeadHash })) {
    if (!value) throw new Error(`anchorChainHead: ${name} is required`);
  }
  const payload = JSON.stringify({
    v: 1,
    tenantId,
    chainHeadHash,
    anchoredAt: new Date().toISOString(),
  });
  const { content_hash } = await client.saveMemory(
    agentUuaid,
    `esig/chain-head/${tenantId}`,
    payload,
    vaultKey,
  );
  return { contentHash: content_hash };
}
