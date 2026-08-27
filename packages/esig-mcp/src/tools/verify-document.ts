// tools/verify-document.ts — esig_verify_document (design doc §4, "deliberately
// the widest-open tool: any agent verifying any e-sig document is the viral
// loop"). Read-only; no policy gate; no audit row (not state-changing, I6
// scopes the audit requirement to state-changing tools only).

import { promises as fs } from "node:fs";

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { verifyDocumentBytes } from "../verify.js";
import { resolveDocPath } from "../docs-root.js";
import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerVerifyDocumentTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_verify_document",
    {
      title: "Verify an e-signed PDF",
      description:
        "Verify a PDF's classical PAdES/PKCS#7 signature and, if present, its hybrid Ed25519 + " +
        "ML-DSA-65 post-quantum seal. Pass EXACTLY ONE of `path` (a filesystem path confined to " +
        "this server's ESIG_MCP_DOCS_ROOT), `base64` (raw PDF bytes, base64-encoded), or `docId` (the sha256 " +
        "content hash returned by a prior esig_ingest_document call). Optionally pin " +
        "`expectedUuaid` and/or `expectedMldsa65Fpr` to require the post-quantum seal names a " +
        "specific signer identity, and set `requirePq: true` to reject documents that carry no " +
        "post-quantum seal at all — without it, a document with only a valid classical signature " +
        "still reports ok:true, which is correct for legacy documents but means requirePq is the " +
        "only way to refuse a silent downgrade to classical-only. Any agent may call this on any " +
        "e-sig document; verification never requires possession of a signing token.",
      inputSchema: {
        path: z
          .string()
          .optional()
          .describe(
            "Filesystem path to a PDF file. Resolved ONLY inside this server's confined documents " +
              "root (ESIG_MCP_DOCS_ROOT, default \"<ESIG_MCP_DATA_DIR>/inbox\") — an absolute path " +
              "outside that root, a \"..\" segment, or a symlink escaping it is refused.",
          ),
        base64: z.string().optional().describe("Raw PDF bytes, base64-encoded."),
        docId: z
          .string()
          .optional()
          .describe("A docId returned by esig_ingest_document (sha256 hex of the PDF bytes)."),
        expectedUuaid: z
          .string()
          .optional()
          .describe("Require the post-quantum seal's uuaid to equal this value; otherwise it is only reported."),
        expectedMldsa65Fpr: z
          .string()
          .optional()
          .describe("Require the post-quantum seal's ML-DSA-65 fingerprint to equal this value."),
        requirePq: z
          .boolean()
          .optional()
          .describe("Reject documents with no valid post-quantum seal. Default false (classical-only documents pass)."),
      },
    },
    async ({ path, base64, docId, expectedUuaid, expectedMldsa65Fpr, requirePq }) => {
      const provided = [path, base64, docId].filter((v) => v !== undefined);
      if (provided.length !== 1) {
        return toolError(
          `exactly one of \`path\`, \`base64\`, or \`docId\` must be provided (got ${provided.length}).`,
        );
      }

      let bytes: Buffer;
      try {
        if (path !== undefined) bytes = await fs.readFile(await resolveDocPath(deps.config.docsRoot, path));
        else if (base64 !== undefined) bytes = Buffer.from(base64, "base64");
        else bytes = await deps.documents.get(docId!);
      } catch (e) {
        return toolError(`could not read document: ${messageOf(e)}`);
      }

      let result;
      try {
        result = verifyDocumentBytes(bytes, { expectedUuaid, expectedMldsa65Fpr, requirePq });
      } catch (e) {
        // verifyDocument raises on structurally-invalid PDF bytes rather than
        // returning ok:false — surface that as a tool error, not a crash.
        return toolError(`could not verify document: ${messageOf(e)}`);
      }

      return toolResult(result.summary, result);
    },
  );
}
