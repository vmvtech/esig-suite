// @e-sig/uuaid
//
// Opt-in UUAID (https://uuaid.org) adapter for @e-sig/core: agent-identity
// stamping for the audit log (withUuaidActor) and external anchoring of the
// audit hash-chain head (anchorChainHead). Built entirely on the open
// @e-sig/core interfaces — core stays self-hosted and SaaS-free, and nothing
// here runs unless you wire it in.

export { withUuaidActor, UUAID_ACTOR_METADATA_KEY } from "./uuaid-actor.js";
export {
  anchorChainHead,
  type ChainHeadAnchorClient,
  type AnchorChainHeadOptions,
  type AnchorChainHeadResult,
} from "./anchor.js";
