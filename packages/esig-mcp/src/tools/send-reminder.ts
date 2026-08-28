// tools/send-reminder.ts — esig_send_reminder (docs/architecture/esig-mcp.md
// §15 "Reminders", manual path). State-changing; `EnvelopeService.sendReminder()`
// already writes its own audit rows (`envelope.reminder_sent`, one per
// signer reminded) and applies the same hourly rate limiter
// esig_create_envelope/esig_reseal draw from, under the label "reminder" —
// this tool is a thin, validating pass-through, same shape as
// tools/reseal-envelope.ts.

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import type { McpServerDeps } from "./types.js";
import { messageOf, toolError, toolResult } from "./helpers.js";

export function registerSendReminderTool(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "esig_send_reminder",
    {
      title: "Resend a signing reminder",
      description:
        "Resend the original signing link (as a reminder email) to a pending signer, or to every " +
        "still-pending signer on the envelope when signerId is omitted. Only works when reminders are " +
        "configured (ESIG_MCP_REMINDERS non-empty, which also requires ESIG_MCP_DELIVERY=email) — that " +
        "is what causes the original signing link to be stored (encrypted at rest) at envelope " +
        "creation; with no stored link there is nothing to resend. A signer who has already signed or " +
        "declined is reported per-signer as not sent, not thrown as an error.",
      inputSchema: {
        envelopeId: z.string().min(1).describe("The envelopeId returned by esig_create_envelope."),
        signerId: z
          .string()
          .min(1)
          .optional()
          .describe("One of the signerIds returned by esig_create_envelope. Omit to remind every pending signer."),
      },
    },
    async ({ envelopeId, signerId }) => {
      try {
        const result = await deps.envelopes.sendReminder(envelopeId, signerId);
        const okCount = result.sent.filter((s) => s.ok).length;
        return toolResult(
          `envelope ${envelopeId}: sent ${okCount}/${result.sent.length} reminder(s)` +
            (result.sent.some((s) => !s.ok)
              ? `; failures: ${result.sent
                  .filter((s) => !s.ok)
                  .map((s) => `${s.signerId} (${s.error ?? "unknown error"})`)
                  .join(", ")}`
              : ""),
          result,
        );
      } catch (e) {
        return toolError(messageOf(e));
      }
    },
  );
}
