// proofs.ts
//
// `PillarProofSource` implements the `IdentityProofSource` contract
// (types.ts) by long-polling our own inbox for wire-kind
// `esig:identity-proof` envelopes and handing each accepted one to the
// caller's `onProof`. docs/architecture/esig-mcp.md §17 seam 3.
//
// This module never verifies the `DataIntegrityProof` it relays — that is
// Stage B's job (`@e-sig/uaid-exch`'s `verifyDataIntegrityProof`, once it
// adopts this contract). It only: (1) enforces a pre-decrypt size cap
// (RT-2026-08-28-01 F5/G3 c), (2) checks the ENVELOPE's own transport
// signature (`envelope.open`, sender-key binding — forged-sender rejection
// happens here, before decrypt), (3) enforces a sender allowlist, default
// deny (F5/G3 a) and a per-sender rate cap (F5/G3 b) against the now-VERIFIED
// sender, (4) decrypts, (5) validates the payload's SHAPE including a
// required, unexpired `expiresAt` (so a malformed or stale message can't
// reach the caller as if it were a fresh proof, F5/G3 e), and (6)
// replay-guards by Pillar envelope id, with the seen-set pruned at the
// carrier's own 14-day TTL (F5/G3 d). Everything that isn't kind
// `esig:identity-proof`, or that fails any of the above, is dropped with
// only its kind counted — never logged in detail (PII minimization,
// matching docs/architecture/esig-mcp.md §12 T14).

import { readFileSync, writeFileSync, existsSync, chmodSync, mkdirSync } from "node:fs";
import path from "node:path";

import { loadPillar } from "./shim.js";
import type { PillarIdentity } from "./identity.js";
import { CarrierClient } from "./carrier.js";
import type { DataIntegrityProofLike, IdentityProofEvent, IdentityProofSource } from "./types.js";
import type { PillarEnvelope, PillarModules } from "./pillar-types.js";

const MAX_SEEN_ENVELOPE_IDS = 2000;
const MAX_WAIT_S = 25;
/** Matches the carrier's own envelope TTL (docs/architecture/esig-mcp.md §17) — a seen-id older than this can never be re-delivered, so it is safe to prune. */
const MAX_SEEN_AGE_MS = 14 * 24 * 60 * 60 * 1000;
/** RT-2026-08-28-01 F5/G3 (b): per-sender rate cap default. */
const DEFAULT_MAX_ENVELOPES_PER_SENDER_PER_MINUTE = 30;
const RATE_WINDOW_MS = 60_000;
/** RT-2026-08-28-01 F5/G3 (c): pre-decrypt size cap default — the community (unauthenticated) tier's body floor. */
const DEFAULT_MAX_ENVELOPE_BYTES = 512 * 1024;

interface ProofSourceState {
  since: number;
  /** Accepted-proof envelope id -> unix ms accepted. Pruned by age (14d) and bounded by count (MAX_SEEN_ENVELOPE_IDS). */
  seenEnvelopeIds: Record<string, number>;
}

export interface PillarProofSourceOptions {
  identity: PillarIdentity;
  carriers: string[];
  /** Directory holding the persisted cursor/seen-set, `<home>/esig-proofs.json` (0600). */
  home: string;
  /** Long-poll seconds per fetch; capped at 25. Default 25. */
  waitS?: number;
  timeoutMs?: number;
  /** Observability only — counts by envelope `kind` seen in one poll batch. Never payload content. */
  onKindCounts?: (counts: Record<string, number>) => void;
  /**
   * Sender allowlist (RT-2026-08-28-01 F5/G3 a) — an `esig:identity-proof`
   * envelope is only considered once `envelope.open()` has verified its
   * transport signature AND this returns true for the now-authenticated
   * `envelope.sender`. esig-mcp wires this to its own active-envelope
   * signers/subscribers. DEFAULT DENY: omitting this option refuses every
   * sender (a source with no allowlist accepts nothing, rather than
   * accepting everything).
   */
  isAllowedSender?: (senderUuaid: string) => boolean;
  /** Per-sender rate cap, accepted envelopes/minute (RT-2026-08-28-01 F5/G3 b). Default 30. */
  maxEnvelopesPerSenderPerMinute?: number;
  /**
   * Pre-decrypt size cap in bytes (RT-2026-08-28-01 F5/G3 c) — an envelope
   * whose JSON-serialized size exceeds this is refused BEFORE `open()` is
   * even called. Default 512 KiB (the community/unauthenticated tier's
   * body floor, docs/architecture/esig-mcp.md §17).
   */
  maxEnvelopeBytes?: number;
}

function isDataIntegrityProofLike(v: unknown): v is DataIntegrityProofLike {
  if (!v || typeof v !== "object") return false;
  const p = v as Record<string, unknown>;
  return (
    p.type === "DataIntegrityProof" &&
    typeof p.cryptosuite === "string" &&
    typeof p.created === "string" &&
    typeof p.verificationMethod === "string" &&
    typeof p.proofPurpose === "string" &&
    typeof p.proofValue === "string"
  );
}

interface IdentityProofPayload {
  v: 1;
  envelopeId: string;
  signerId: string;
  uuaid: string;
  proof: DataIntegrityProofLike;
  /** Required (RT-2026-08-28-01 F5/G3 e: "expiresAt on every esig:* verb") — `handleEnvelope` refuses a payload missing this, and refuses one that has already passed. */
  expiresAt: string;
  credential?: unknown;
}

function isIdentityProofPayload(v: unknown): v is IdentityProofPayload {
  if (!v || typeof v !== "object") return false;
  const p = v as Record<string, unknown>;
  return (
    p.v === 1 &&
    typeof p.envelopeId === "string" &&
    typeof p.signerId === "string" &&
    typeof p.uuaid === "string" &&
    typeof p.expiresAt === "string" &&
    isDataIntegrityProofLike(p.proof)
  );
}

export class PillarProofSource implements IdentityProofSource {
  private running = false;
  private state: ProofSourceState;
  private readonly statePath: string;
  /** Per-sender accepted-timestamp ring, for the rate cap. Not persisted — a process restart resets it, which only ever makes the cap MORE permissive, never less safe. */
  private readonly senderRateWindows = new Map<string, number[]>();

  private constructor(
    private readonly pillar: PillarModules,
    private readonly identity: PillarIdentity,
    private readonly carrier: CarrierClient,
    home: string,
    private readonly waitS: number,
    private readonly timeoutMs: number | undefined,
    private readonly onKindCounts: ((counts: Record<string, number>) => void) | undefined,
    private readonly isAllowedSender: (senderUuaid: string) => boolean,
    private readonly maxEnvelopesPerSenderPerMinute: number,
    private readonly maxEnvelopeBytes: number
  ) {
    this.statePath = path.join(home, "esig-proofs.json");
    this.state = this.loadState();
  }

  static async open(opts: PillarProofSourceOptions): Promise<PillarProofSource> {
    const pillar = await loadPillar();
    const carrier = await CarrierClient.open({ identity: opts.identity, carriers: opts.carriers });
    const waitS = Math.min(opts.waitS ?? MAX_WAIT_S, MAX_WAIT_S);
    return new PillarProofSource(
      pillar,
      opts.identity,
      carrier,
      opts.home,
      waitS,
      opts.timeoutMs,
      opts.onKindCounts,
      // Default deny (RT-2026-08-28-01 F5/G3 a): no allowlist supplied means no sender is accepted.
      opts.isAllowedSender ?? (() => false),
      opts.maxEnvelopesPerSenderPerMinute ?? DEFAULT_MAX_ENVELOPES_PER_SENDER_PER_MINUTE,
      opts.maxEnvelopeBytes ?? DEFAULT_MAX_ENVELOPE_BYTES
    );
  }

  start(onProof: (event: IdentityProofEvent) => void): void {
    if (this.running) return;
    this.running = true;
    void this.pollLoop(onProof);
  }

  stop(): void {
    this.running = false;
  }

  private loadState(): ProofSourceState {
    if (!existsSync(this.statePath)) return { since: 0, seenEnvelopeIds: {} };
    try {
      const raw = JSON.parse(readFileSync(this.statePath, "utf-8")) as Partial<{ since: unknown; seenEnvelopeIds: unknown }>;
      const since = typeof raw.since === "number" ? raw.since : 0;
      const seenEnvelopeIds: Record<string, number> = {};
      if (raw.seenEnvelopeIds && typeof raw.seenEnvelopeIds === "object" && !Array.isArray(raw.seenEnvelopeIds)) {
        for (const [id, seenAt] of Object.entries(raw.seenEnvelopeIds as Record<string, unknown>)) {
          if (typeof seenAt === "number") seenEnvelopeIds[id] = seenAt;
        }
      }
      return { since, seenEnvelopeIds };
    } catch {
      return { since: 0, seenEnvelopeIds: {} };
    }
  }

  private saveState(): void {
    mkdirSync(path.dirname(this.statePath), { recursive: true });
    writeFileSync(this.statePath, JSON.stringify(this.state));
    chmodSync(this.statePath, 0o600);
  }

  /** Record `envelopeId` as accepted at `now`, then prune (age + count bound). */
  private markSeen(envelopeId: string, now: number): void {
    this.state.seenEnvelopeIds[envelopeId] = now;
    this.pruneSeen(now);
  }

  /** RT-2026-08-28-01 F5/G3 (d): drop entries older than the carrier's own 14-day TTL, then re-apply the count bound (oldest-first). */
  private pruneSeen(now: number): void {
    const cutoff = now - MAX_SEEN_AGE_MS;
    const entries = Object.entries(this.state.seenEnvelopeIds).filter(([, seenAt]) => seenAt >= cutoff);
    entries.sort((a, b) => a[1] - b[1]);
    const overflow = entries.length - MAX_SEEN_ENVELOPE_IDS;
    const kept = overflow > 0 ? entries.slice(overflow) : entries;
    this.state.seenEnvelopeIds = Object.fromEntries(kept);
  }

  /** RT-2026-08-28-01 F5/G3 (b): true and consumes one slot if `sender` is under its per-minute cap; false (and no slot consumed) otherwise. */
  private consumeRateBudget(sender: string, now: number): boolean {
    const windowStart = now - RATE_WINDOW_MS;
    const recent = (this.senderRateWindows.get(sender) ?? []).filter((t) => t > windowStart);
    if (recent.length >= this.maxEnvelopesPerSenderPerMinute) {
      this.senderRateWindows.set(sender, recent);
      return false;
    }
    recent.push(now);
    this.senderRateWindows.set(sender, recent);
    return true;
  }

  private async pollLoop(onProof: (event: IdentityProofEvent) => void): Promise<void> {
    while (this.running) {
      try {
        await this.fetchAndHandleOnce(onProof);
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
  }

  /**
   * Run exactly one fetch+handle pass: advance the cursor, dispatch accepted
   * proofs to `onProof`, report this batch's kind counts via `onKindCounts`
   * (same as the background poll loop), and persist state. Exposed publicly
   * so tests (and any caller preferring manual pumping over `start()`'s
   * background loop) can drive one deterministic pass.
   */
  async pollOnce(onProof: (event: IdentityProofEvent) => void): Promise<Record<string, number>> {
    return this.fetchAndHandleOnce(onProof);
  }

  private async fetchAndHandleOnce(onProof: (event: IdentityProofEvent) => void): Promise<Record<string, number>> {
    const result = await this.carrier.fetchInbox({ since: this.state.since, waitS: this.waitS, timeoutMs: this.timeoutMs });
    const kindCounts: Record<string, number> = {};
    for (const { seq, envelope } of result.envelopes) {
      this.state.since = Math.max(this.state.since, seq);
      this.handleEnvelope(envelope, onProof, kindCounts);
    }
    if (Object.keys(kindCounts).length > 0) this.onKindCounts?.(kindCounts);
    this.saveState();
    return kindCounts;
  }

  private handleEnvelope(
    envelope: PillarEnvelope,
    onProof: (event: IdentityProofEvent) => void,
    kindCounts: Record<string, number>
  ): void {
    kindCounts[envelope.kind] = (kindCounts[envelope.kind] ?? 0) + 1;
    if (envelope.kind !== "esig:identity-proof") return;
    if (this.state.seenEnvelopeIds[envelope.id] !== undefined) return; // replay guard

    // (c) Pre-decrypt size cap, BEFORE open() — the only wire representation
    // available at this layer is the already-JSON-parsed envelope object, so
    // this measures its JSON-serialized size as the size proxy.
    const serializedBytes = Buffer.byteLength(JSON.stringify(envelope), "utf-8");
    if (serializedBytes > this.maxEnvelopeBytes) return;

    const verdict = this.pillar.envelope.open(envelope);
    if (!verdict.ok) return;

    // envelope.sender is now cryptographically verified (open() bound the
    // transport signature to it) — safe to allowlist/rate-limit on it.
    if (!this.isAllowedSender(envelope.sender)) return; // (a) sender allowlist, default deny
    const now = Date.now();
    if (!this.consumeRateBudget(envelope.sender, now)) return; // (b) per-sender rate cap

    let payload: unknown;
    try {
      payload = this.pillar.envelope.decrypt(this.identity._keychain(), envelope);
    } catch {
      return;
    }
    if (!isIdentityProofPayload(payload)) return; // shape check includes expiresAt presence

    const expiresAtMs = Date.parse(payload.expiresAt);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now) return; // (e) refuse expired

    this.markSeen(envelope.id, now);
    onProof({
      envelopeId: payload.envelopeId,
      signerId: payload.signerId,
      uuaid: payload.uuaid,
      proof: payload.proof,
      credential: payload.credential,
      senderUuaid: envelope.sender,
      pillarEnvelopeId: envelope.id,
    });
  }
}
