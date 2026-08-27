// tools/whoami.ts — esig_whoami (design doc §4). Read-only identity/caps
// report. Calling this mints the tenant's signing cert / PQ key bundle on
// first use (same `ensureActiveCert`/`ensureActivePqKeys` idempotent
// get-or-create the seal step uses, envelopes.ts's `seal()`) so a fresh
// install can report real fingerprints before ever creating an envelope —
// but ONLY public material ever leaves this function. I1: no key bytes.

import { ensureActiveCert, ensureActivePqKeys } from "@e-sig/core";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { toolResult } from "./helpers.js";

export function registerWhoamiTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_whoami",
    {
      title: "Show this server's signing identity",
      description:
        "Report this MCP server's configured tenant identity, which signing modes are enabled " +
        "(v0.1 ships mode H — human signs — only; ESIG_MCP_MODES including A or C refuses to " +
        "start at all, invariant I2), its operating caps (size/rate limits, whether post-quantum " +
        "sealing and ESIG_MCP_RETURN_LINKS are on), and the PUBLIC fingerprints of its signing " +
        "certificate and post-quantum key bundle. Never returns private key bytes, PEM, or key " +
        "bundle ciphertext — only identifiers an agent or human can use to recognize this " +
        "server's signed output (e.g. as `expectedMldsa65Fpr` to esig_verify_document).",
      inputSchema: {},
    },
    async () => {
      const { config } = deps;

      const cert = await ensureActiveCert({
        store: deps.certStore,
        tenantId: config.tenant,
        subjectName: config.subjectName,
        passphrase: config.passphrase,
      });

      let postQuantum:
        | { keyId: string; mldsa65Fpr: string; ed25519Public: string; mldsa65Public: string }
        | undefined;
      if (config.pq) {
        const pq = await ensureActivePqKeys({
          store: deps.pqKeyStore,
          tenantId: config.tenant,
          passphrase: config.passphrase,
        });
        // Only `.public` — never `.keys` (the in-memory signing keys).
        postQuantum = {
          keyId: pq.public.keyId,
          mldsa65Fpr: pq.public.mldsa65Fpr,
          ed25519Public: pq.public.ed25519,
          mldsa65Public: pq.public.mldsa65,
        };
      }

      const info = {
        tenant: config.tenant,
        subjectName: config.subjectName,
        baseUrl: config.baseUrl,
        enabledModes: config.modes,
        caps: {
          maxHtmlBytes: config.maxHtmlBytes,
          maxPdfBytes: config.maxPdfBytes,
          envelopesPerHour: config.envelopesPerHour,
          pq: config.pq,
          returnLinks: config.returnLinks,
        },
        cert: {
          // Only public identifiers of the StoredCert row — never
          // `keyPemEncrypted`, never the decrypted `keyPem`/`certPem` this
          // function received alongside `cert` from `ensureActiveCert`.
          id: cert.cert.id,
          certFingerprint: cert.cert.certFingerprint,
          notBefore: cert.cert.notBefore.toISOString(),
          notAfter: cert.cert.notAfter.toISOString(),
        },
        postQuantum,
      };

      const summary =
        `tenant "${config.tenant}", modes [${config.modes.join(",")}], ` +
        `cert fingerprint ${cert.cert.certFingerprint}` +
        (postQuantum ? `, pq keyId ${postQuantum.keyId}` : ", post-quantum sealing disabled");

      return toolResult(summary, info);
    },
  );
}
