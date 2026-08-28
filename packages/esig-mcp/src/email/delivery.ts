// email/delivery.ts
//
// `EmailDelivery` — the `ESIG_MCP_DELIVERY=email` channel
// (docs/architecture/esig-mcp.md §15). One email per signer link, rendered
// via templates.ts and sent via the configured `EmailTransport` (smtp/ses).
// Receipts never carry a URL (I8 unchanged) — only `messageId` on success or
// `detail` on failure, exactly like every other `DeliveryChannel`
// implementation's failure shape (delivery.ts).

import type { DeliveryChannel, DeliveryLink, Receipt } from "../delivery.js";
import type { EmailTransport } from "./transport.js";
import { renderSigningEmail } from "./templates.js";

export interface EmailDeliveryOptions {
  transport: EmailTransport;
  /** ESIG_MCP_EMAIL_FROM — "Name <addr>" or a bare address. */
  from: string;
  /** ESIG_MCP_EMAIL_REPLY_TO, if configured. */
  replyTo?: string;
  /** ESIG_MCP_EMAIL_SUBJECT_PREFIX, if configured. */
  subjectPrefix?: string;
}

export class EmailDelivery implements DeliveryChannel {
  constructor(private readonly opts: EmailDeliveryOptions) {}

  async deliver(
    envelope: { id: string; title: string; message?: string; expiresAt?: string },
    links: DeliveryLink[],
  ): Promise<Receipt[]> {
    const receipts: Receipt[] = [];
    for (const link of links) {
      const rendered = renderSigningEmail({
        title: envelope.title,
        from: this.opts.from,
        note: envelope.message,
        url: link.url,
        expiresAt: envelope.expiresAt,
        prefix: this.opts.subjectPrefix,
      });
      try {
        const result = await this.opts.transport.send({
          from: this.opts.from,
          to: link.email,
          replyTo: this.opts.replyTo,
          subject: rendered.subject,
          text: rendered.text,
          html: rendered.html,
        });
        receipts.push({ signerId: link.signerId, channel: "email", ok: true, messageId: result.messageId });
      } catch (e) {
        receipts.push({
          signerId: link.signerId,
          channel: "email",
          ok: false,
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }
    return receipts;
  }
}
