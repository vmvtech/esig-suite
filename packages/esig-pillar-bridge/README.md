# @e-sig/pillar-bridge

Optional [Pillar](https://www.npmjs.com/package/@uuaid/pillar) bridge for
`@e-sig/mcp` — deliver signing links, lifecycle events, and identity proofs
as signed, end-to-end encrypted envelopes over an agent's own inbox, instead
of (or alongside) email/webhooks. Design:
[`docs/architecture/esig-mcp.md` §17](../../docs/architecture/esig-mcp.md).

## What / why

Pillar (IAASO-3050's reference implementation) gives every agent a private,
authenticated inbox with no inbound HTTP required: identities are
self-authenticating UUAIDs (`uuaid:foundation:agent:<localId>` where
`localId = hex(sha256(rawEd25519PubKey))[0..16]`, 8-4-4-4-12), and every
message is end-to-end encrypted + signed before it ever reaches a relay
("carrier"). That is everything the *agent* side of e-signature delivery
was missing — a place to hand a signing link to an agent that has no
listener of its own, with no plaintext ever crossing the wire.

This package is deliberately a separate, **opt-in** dependency of
`@e-sig/mcp`, not a hard one: installing `@uuaid/pillar` pulls its own
dependency graph (libp2p, native `better-sqlite3`) at `npm install` time.
`@e-sig/mcp` never imports this package; an operator who wants Pillar
delivery installs `@e-sig/pillar-bridge` themselves and wires it in as a
`DeliveryChannel`/`EventSink`/`IdentityProofSource` implementation.

## The shim, the hash assert, and process isolation

Pillar's own `"."` entry point (`src/index.mjs`) re-exports `Mailbox`,
`Pillar`, and `createTransport` — importing it statically loads the entire
libp2p + better-sqlite3 graph into the process (763 modules, ~107 MiB RSS),
even though this bridge only ever touches five small, dependency-light
entry files (envelope sealing/opening, the keychain, JCS canonicalization,
the carrier HTTP client, and tier grants) plus one transitive import of
theirs (`net/envelope.mjs` imports `crypto/e2e.mjs`) — 21 modules, 0
libp2p, 0 better-sqlite3, ~0.03s cold start, ~52 MiB RSS, measured.

`src/shim.ts` gets there by resolving Pillar's real on-disk location with
`createRequire(import.meta.url).resolve("@uuaid/pillar")` (which follows
the package's own `"."` export and returns the absolute path to
`src/index.mjs`), taking the `dirname` of that path (Pillar's `src/`
directory), and importing the files it needs from there — either via a bare
subpath specifier (`import("@uuaid/pillar/envelope")`, resolved through
Node's own package resolution + the package's `exports` map) when the
resolved package declares one for every module this bridge needs, or via a
constructed `file://` URL straight from that resolved directory when it
doesn't. **`0.2.0-alpha.12` does declare all of them** (`./envelope
./keychain ./jcs ./tier ./carrier-client`, plus `./e2e`) — the bridge
prefers the subpath route there; **`0.2.0-alpha.11`'s `exports` is still
just `{"."}`**, so the bridge falls back to the `file://` bypass for it.
Node's package `exports` encapsulation only gates resolution of a *bare
specifier* through the package name — it does not apply to an absolute
`file://` URL the caller constructs itself — so the fallback route never
touches `index.mjs`, `mailbox.mjs`, or `transport.mjs`, and therefore never
touches libp2p or better-sqlite3 at *import* time either way (installing
the package via npm still pulls both — that's an install-time cost this
package does not solve, tracked upstream). Either route only runs AFTER the
hash assert below, over the exact bytes at the resolved location — so both
are pinned before use.

This is documented scaffolding, not a recommended pattern for other
packages — its removal is gated on Pillar's own source becoming available
again at the vendor for a proper `exports`-based fix, not merely on
`exports` growing subpaths.

Two things this module verifies before it will hand back a working Pillar
surface:

1. **Static import-graph walk.** Every specifier the five entry files
   (transitively, within Pillar's own `src/` tree) import from is checked —
   by resolved path *and* raw text — against `libp2p`, `better-sqlite3`,
   `mailbox`, `transport`, and `index.mjs`. Any match refuses to load
   (`PillarIsolationError`).
2. **Startup hash assert over the FULL walked closure.** sha256 of *every*
   file the walk actually visited — not just the five entry files, but
   also `crypto/e2e.mjs` (transitively imported by `net/envelope.mjs`) —
   must match a pinned table (`pinnedPillarHashes`, exported) for the two
   `@uuaid/pillar` versions this bridge has been measured against —
   `0.2.0-alpha.11` and `0.2.0-alpha.12`. A version drift, a tampered file,
   or an unrecognized new transitive import (no pin at all) throws
   `PillarHashMismatchError` unless `ESIG_PILLAR_ALLOW_UNPINNED=1` is set,
   in which case it prints a loud warning to stderr, fires an `onAudit`
   callback (`{action:"pillar.unpinned_allowed", version, files}` — pass
   `onAudit` to `loadPillar()`) if one was given, and proceeds anyway — a
   deliberate, visible, AND audited escape hatch, never a silent downgrade.

## Config

| Env var | Used by |
|---|---|
| `ESIG_PILLAR_PASSPHRASE` / `PILLAR_PASSPHRASE` | `PillarIdentity.load`/`.generate` keychain passphrase, when not passed explicitly. Must be at least 24 characters — `load`/`generate` refuse a shorter (or empty) one, naming `ESIG_PILLAR_PASSPHRASE` in the error. |
| `ESIG_PILLAR_ALLOW_UNPINNED=1` | Bypass a failed hash assert (loud stderr warning + `onAudit` event, see above). |

`PillarIdentity.generate({ home })` writes `<home>/keychain.json` (0600, via
Pillar's own `Keychain.save`) and never writes the passphrase itself
anywhere; `.load()` refuses to read a `keychain.json` whose file mode is
readable/writable by group or other. Both accept an `onAudit` callback,
firing `{action:"pillar.identity_loaded"|"pillar.identity_generated", uuaid,
fingerprint}` on success (never the passphrase or key material).
`PillarProofSource` persists its long-poll cursor and replay-guard set to
`<home>/esig-proofs.json` (0600), pruned at the carrier's own 14-day TTL.

## The contract interfaces

`src/types.ts` defines the small, LOCAL structural interfaces this package
implements — the contract `@e-sig/mcp` adopts in Stage B
(`docs/architecture/esig-mcp.md` §17 seams 2-4). They are intentionally
*not* imported from `@e-sig/mcp` (whose `dist` is mid-edit under a
concurrent build lock) and not byte-identical to today's
`packages/esig-mcp/src/delivery.ts` shapes:

```ts
interface DeliveryLink {
  signerId: string; name: string; email: string; url: string;
  pillar?: { uuaid: string; publicKey: string };
}
interface DeliveryEnvelopeMeta { id: string; title: string; expiresAt?: string; message?: string; }
// channel is a literal "pillar" here — mcp's own Receipt.channel is `string`
// (packages/esig-mcp/src/delivery.ts), so this is directly assignable to it.
// PillarDelivery also REFUSES to seal a sign-request when meta.expiresAt is
// missing (RT-2026-08-28-01 G3: expiresAt on every esig:* verb).
interface Receipt { signerId: string; channel: "pillar"; ok: boolean; detail?: string; messageId?: string; }
interface DeliveryChannel { deliver(meta: DeliveryEnvelopeMeta, links: DeliveryLink[]): Promise<Receipt[]>; }

// type/phase stay `string` on THIS side of the seam deliberately — Stage B
// (`@e-sig/mcp`) narrows them to its own real string-literal unions
// (EsigEventType/EnvelopePhase) when it adopts this contract.
interface EsigEvent { id: string; type: string; createdAt: string; envelopeId: string; phase: string; signer?: {...}; data: Record<string, unknown>; }
interface EventSink { publish(event: EsigEvent): Promise<void>; }

interface IdentityProofSource {
  start(onProof: (event: {
    envelopeId: string; signerId: string; uuaid: string;
    proof: DataIntegrityProofLike; credential?: unknown;
    senderUuaid: string; pillarEnvelopeId: string;
  }) => void): void;
  stop(): void;
}
```

## The four `esig:*` wire kinds

`kind` is a routing hint only — unvalidated at Pillar's `seal()`/`open()`
and at carrier ingest, and it is cleartext (every carrier/relay learns "who
asked whom to do what, at what time"). Every security decision in this
package rests on the sealed payload's own signature and the sender-uuaid
binding `envelope.open()` enforces, never on `kind`.

| Wire `kind` | Sender → recipient | Sealed payload |
|---|---|---|
| `esig:sign-request` | `PillarDelivery` | `{v:1, envelopeId, title, url, expiresAt, note?, sender, createdAt}` — `expiresAt` REQUIRED, `PillarDelivery` refuses (`Receipt.ok:false`) to seal one without it |
| `esig:event` | `PillarEventSink` | `{v:1, event: EsigEvent}` |
| `esig:identity-proof` | (recipient's own agent, back to the sender) | `{v:1, envelopeId, signerId, uuaid, expiresAt, proof: DataIntegrityProof, credential?}` — `PillarProofSource` accepts *only* this shape under this kind, `expiresAt` REQUIRED and checked against the current time |
| `esig:sealed` | *(reserved, seam 5 — not implemented by this package)* | — |

## Security notes

- **Keychain custody.** Same discipline as the PDF-signing passphrase — an
  `ESIG_PILLAR_PASSPHRASE`/`PILLAR_PASSPHRASE` env var, never written to
  disk, never logged, and required to be at least 24 characters (`load`/
  `.generate` refuse a shorter or empty one). `keychain.json` and
  `esig-proofs.json` are written 0600; `.load()` additionally refuses to
  read a `keychain.json` whose file mode is readable/writable by group or
  other, rather than silently trusting a loosened permission. `.load()`/
  `.generate()` both accept an `onAudit` callback firing
  `{action:"pillar.identity_loaded"|"pillar.identity_generated", uuaid,
  fingerprint}` (never the passphrase or key material).
- **Recipient-key provenance.** A `DeliveryLink.pillar`/event subscriber
  whose `publicKey` does not derive `uuaid`'s local id — AND whose `uuaid`
  is not exactly `uuaid:foundation:agent:<id>` (Pillar's own binding covers
  only `split(":")[3]`, so the namespace/objectType are pinned here too) —
  is refused (`Receipt.ok:false`), never silently sent. A *substituted*
  uuaid+key pair that both pass this check is a pinning question for the
  creating operator, out of scope for this package.
- **Tier / body budget.** Community (default, unauthenticated) tier caps a
  sealed envelope's JCS payload at `(512 KiB − 811)/2 − 16` bytes; the
  absolute ceiling any tier can reach is 2 MiB
  (`pillar.tier.ABSOLUTE_MAX_BODY`). This package does not raise its own
  tier — pass a `tierGrant` to `CarrierClient.deliver`/`PillarDelivery`'s
  constructor path if the operator holds one.
- **`PillarProofSource` listener hardening (RT-2026-08-28-01 G3).** Before
  an `esig:identity-proof` envelope's payload is ever decrypted or surfaced
  to `onProof`: (1) a pre-decrypt size cap (its JSON-serialized size,
  configurable, default 512 KiB — the community tier floor) is checked
  BEFORE `envelope.open()` is even called; (2) after `open()` verifies the
  transport signature, the now-authenticated `envelope.sender` must pass an
  injectable `isAllowedSender` allowlist — **default deny**: omitting it
  refuses every sender; (3) a per-sender rate cap (injectable, default
  30/minute) applies to the same verified sender; (4) the decrypted
  payload's own `expiresAt` is required and checked against the current
  time. Everything that fails any of these is dropped the same way an
  unrecognized `kind` is — counted, never logged in detail.
- **Replay guard.** `PillarProofSource` persists a bounded (2000-entry,
  14-day-pruned) set of accepted `esig:identity-proof` Pillar envelope ids
  (id → accepted-at timestamp) under `<home>/esig-proofs.json` and drops a
  repeat before it ever reaches `onProof` — carrier re-delivery (`202
  {duplicate:true}`) is expected, at-least-once behavior, not an attack by
  itself. Entries older than the carrier's own 14-day envelope TTL are
  pruned on each accepted proof — they can never be legitimately
  re-delivered, so keeping them around only wastes space.
- **Envelope age.** Pillar's carrier enforces a 24h absolute age window on
  ingest (`MAX_ENVELOPE_AGE_MS`) in both directions — a stale
  `esig:sign-request` is rejected by the carrier before this package ever
  sees it; mint at send time, never hold a pre-signed request. This package
  also requires `expiresAt` on every `esig:*` payload it sends or accepts
  (see the wire-kinds table above) — a shorter, application-level bound
  inside that 24h carrier window.
- **`examples/pillar-agent` reply gating.** The reference recipient
  (`index.mjs`) only considers an envelope whose `recipient` is its own
  uuaid (defense-in-depth on top of whatever the carrier's inbox endpoint
  already filters by), and only replies to a `esig:sign-request` whose
  DECRYPTED payload's own `sender` field matches the envelope's
  transport-verified `sender` — `open()` proves who sealed the envelope,
  not that the plaintext isn't lying about who it claims to be from.
- **Never verifies a proof itself.** `PillarProofSource` relays
  `DataIntegrityProof`/`credential` untouched — verification is Stage B's
  job (`@e-sig/uaid-exch`'s `verifyDataIntegrityProof`/`verifyExchange`),
  keeping this package's trust surface to "did the right key seal this
  envelope to me", nothing more.

## Isolation, measured

`test/shim.test.ts` spawns two child `node` processes — a bare baseline and
one that imports the built shim and calls `loadPillar()` — and diffs
`process.report.getReport().sharedObjects` between them. A DIFFERENCE
against a baseline, not a bare `/sqlite/i` match, is required: on macOS,
every plain node process already links `/usr/lib/libsqlite3.dylib` and a
private `PoirotSQLite` framework as OS-level noise, unrelated to
`better-sqlite3`'s native addon (measured live: a `node -e` one-liner with
zero of this package's code loaded prints those same two paths). The test
asserts no *newly*-loaded object matches `better-sqlite3` or `libp2p`, and
separately asserts the baseline itself DOES carry the macOS sqlite noise (so
the check is provably discriminating, not vacuously passing on an
unmeasured filter). This runs alongside the static import-graph walk's own
result (must find no `libp2p`/`better-sqlite3`/`mailbox`/`transport`/
`index.mjs` reference) — see the build ticket report for the exact counts.
