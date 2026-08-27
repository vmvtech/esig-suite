// tools/ingest-document.ts — esig_ingest_document (design doc §4, "Prepare
// tools (allowed, audited)"). State-changing (writes to the content-addressed
// workdir) — writes its audit row before returning (I6). `documents.ts`
// itself has no audit dependency (kept storage-only, mirroring
// `FsDocumentStore`'s narrow scope), so the audit call lives here.

import { promises as fs } from "node:fs";

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { resolveDocPath } from "../docs-root.js";
import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerIngestDocumentTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_ingest_document",
    {
      title: "Ingest a PDF document",
      description:
        "Store PDF bytes in this server's content-addressed workdir and return a `docId` (the " +
        "sha256 hex digest of the bytes) usable as `esig_verify_document`'s `docId` input. Pass " +
        "EXACTLY ONE of `path` (a filesystem path confined to this server's ESIG_MCP_DOCS_ROOT) or " +
        "`base64` (raw PDF bytes, base64-encoded). Ingesting the same bytes twice returns the same docId " +
        "without storing a second copy.",
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
      },
    },
    async ({ path, base64 }) => {
      const provided = [path, base64].filter((v) => v !== undefined);
      if (provided.length !== 1) {
        return toolError(`exactly one of \`path\` or \`base64\` must be provided (got ${provided.length}).`);
      }

      let bytes: Buffer;
      try {
        bytes =
          path !== undefined
            ? await fs.readFile(await resolveDocPath(deps.config.docsRoot, path))
            : Buffer.from(base64!, "base64");
      } catch (e) {
        return toolError(`could not read document: ${messageOf(e)}`);
      }

      let result: { docId: string; size: number };
      try {
        result = await deps.documents.ingest(bytes);
      } catch (e) {
        return toolError(messageOf(e));
      }

      // I6: audit row before this call returns success.
      await deps.auditStore.insert({
        tenantId: deps.config.tenant,
        action: "document.ingested",
        targetTable: "document",
        targetId: result.docId,
        metadata: { size: result.size },
      });

      return toolResult(`ingested ${result.size} byte(s) as docId ${result.docId}`, result);
    },
  );
}
