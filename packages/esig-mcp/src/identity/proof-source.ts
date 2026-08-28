// identity/proof-source.ts
//
// §17 seam 3 "Identity proof over Pillar" — the fan-in surface esig-mcp
// exposes so an optional bridge (e.g. `@e-sig/pillar-bridge`) can relay an
// out-of-band identity proof — produced by the signer's own agent/wallet,
// sealed over Pillar — into the SAME verification path `POST /sign`'s
// `identityProof` already uses (challenge nonce binding, L0/L1/L1p/L2,
// atomic consumption). `IdentityProofSource`/`IdentityProofEvent` below are
// structurally identical to the bridge contract
// (packages/esig-pillar-bridge/src/types.ts, lines 100-116) — defined
// locally so `@e-sig/mcp` carries no import of the bridge package.
//
// `EnvelopeService.acceptPreVerifiedIdentity` (envelopes.ts) is the entry
// point wired to `onProof` below; `POST /sign` (http.ts) then reads the
// resulting stored record back instead of requiring the human to paste
// anything.

import type { DataIntegrityProof } from "@e-sig/uaid-exch";

/** Structurally identical to `@e-sig/pillar-bridge`'s `IdentityProofEvent` (types.ts:100-110). */
export interface IdentityProofEvent {
  envelopeId: string;
  signerId: string;
  uuaid: string;
  proof: DataIntegrityProof;
  credential?: unknown;
  /** The Pillar uuaid that sealed the proof envelope (the signer's own identity) — informational only; verification never trusts this over the proof itself. */
  senderUuaid: string;
  /** The Pillar envelope id the proof arrived in — the caller's own dedupe key; esig-mcp's own replay defense is still the challenge nonce (T11), consumed atomically regardless of this value. */
  pillarEnvelopeId: string;
}

/** A pluggable source of out-of-band identity proofs — structurally identical to `@e-sig/pillar-bridge`'s `IdentityProofSource` (types.ts:113-116). */
export interface IdentityProofSource {
  start(onProof: (event: IdentityProofEvent) => void): void;
  stop(): void;
}
