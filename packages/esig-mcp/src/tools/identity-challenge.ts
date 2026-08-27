// tools/identity-challenge.ts — esig_identity_challenge
// (docs/architecture/esig-mcp.md §12 "Challenge"). State-changing
// (issues a per-signer sole-control nonce — idempotent within TTL: the same
// live nonce is returned until it is consumed or expires) and audited via
// `EnvelopeService.issueIdentityChallenge`, which also applies the SAME
// hourly rate limiter esig_create_envelope draws from, under the label
// "challenge". A sender-side agent uses this to relay a challenge to the
// signer's own wallet/agent (the IAASO agent-to-agent exchange path) — the
// alternative to the signer's own link fetching GET /sign/<token>/challenge.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerIdentityChallengeTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_identity_challenge",
    {
      title: "Issue a signer identity challenge",
      description:
        "Issue (or re-issue) the sole-control challenge a signer's wallet/agent must sign to satisfy " +
        "this envelope's identity requirement (docs/architecture/esig-mcp.md §12). The challenge is " +
        "NOT secret — it is bound to this envelope, signer, and content digest (envelopeId, signerId, " +
        "htmlSha256, nonce, issuedAt, expiresAt), and single-use once a valid proof consumes its " +
        "nonce. Re-issuing is idempotent within the challenge TTL: while the prior nonce is live " +
        "and unconsumed the SAME challenge is returned; a fresh nonce is minted only once it has " +
        "been consumed or has expired. Sign the challenge " +
        "with an eddsa-jcs-2022 DataIntegrityProof and present it as `identityProof` on POST /sign. " +
        "Only meaningful for envelopes created with an `identity.minLevel` above \"none\" (or a signer " +
        "with a `identity.signers[].uuaid` pin) — see esig_create_envelope.",
      inputSchema: {
        envelopeId: z.string().min(1).describe("The envelopeId returned by esig_create_envelope."),
        signerId: z.string().min(1).describe("One of the signerIds returned by esig_create_envelope."),
      },
    },
    async ({ envelopeId, signerId }) => {
      try {
        const challenge = await deps.envelopes.issueIdentityChallenge(envelopeId, signerId);
        return toolResult(
          `identity challenge issued for signer ${signerId} on envelope ${envelopeId}, expires ${challenge.expiresAt}`,
          challenge,
        );
      } catch (e) {
        return toolError(messageOf(e));
      }
    },
  );
}
