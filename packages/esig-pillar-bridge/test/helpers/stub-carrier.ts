// test/helpers/stub-carrier.ts
//
// A local node:http carrier stub for tests — implements just enough of
// `POST /v1/envelopes` and `GET /v1/inbox/<uuaid>` to exercise
// `CarrierClient`/`PillarDelivery`/`PillarEventSink`/`PillarProofSource`
// against real HTTP, without a network dependency.
//
// The inbox auth check below is transcribed directly from the real
// `CarrierServer._verifyInboxAuth` (net/carrier-server.mjs in the
// @uuaid/pillar tarball, 0.2.0-alpha.12) so this stub verifies the signed
// `x-pillar-{pubkey,ts,sig}` headers EXACTLY the way the real carrier
// would — same message string (`GET /v1/inbox/<uuaid>?since=<n>\n<ts>`),
// same self-authenticating uuaid-from-pubkey check, same
// `Keychain.verifyDetached` call (reused from the real, loaded module —
// not reimplemented).

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";

import type { PillarEnvelope, PillarModules } from "../../src/pillar-types.js";

interface StoredEnvelope {
  seq: number;
  envelope: PillarEnvelope;
}

export class StubCarrier {
  private server: Server | null = null;
  private store: StoredEnvelope[] = [];
  private nextSeq = 1;

  constructor(private readonly pillar: PillarModules) {}

  get envelopeCount(): number {
    return this.store.length;
  }

  async listen(): Promise<string> {
    this.server = createServer((req, res) => {
      this.handle(req, res).catch(() => {
        if (!res.writableEnded) json(res, 500, { error: "internal-error" });
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", () => resolve()));
    const addr = this.server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    return `http://127.0.0.1:${port}`;
  }

  async close(): Promise<void> {
    await new Promise<void>((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (req.method === "POST" && url.pathname === "/v1/envelopes") {
      const raw = await readBody(req);
      let envelope: PillarEnvelope;
      try {
        envelope = JSON.parse(raw);
      } catch {
        return json(res, 400, { accepted: false, reason: "bad-json" });
      }
      const verdict = this.pillar.envelope.open(envelope);
      if (!verdict.ok) return json(res, 400, { accepted: false, reason: verdict.reason });
      if (typeof envelope.recipient !== "string" || !envelope.recipient.startsWith("uuaid:")) {
        return json(res, 400, { accepted: false, reason: "bad-recipient" });
      }
      const existing = this.store.find((s) => s.envelope.id === envelope.id);
      // Mirrors carrier-server.mjs exactly: sha256(JSON.stringify(envelope)),
      // not the raw wire bytes (they coincide here since the sender already
      // sent JSON.stringify(envelope) as the body, but this is the real formula).
      if (existing) {
        return json(res, 202, { accepted: true, duplicate: true, seq: existing.seq, sha: sha256Hex(JSON.stringify(existing.envelope)) });
      }
      const seq = this.nextSeq++;
      this.store.push({ seq, envelope });
      return json(res, 202, { accepted: true, seq, sha: sha256Hex(JSON.stringify(envelope)) });
    }

    const inboxMatch = /^\/v1\/inbox\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && inboxMatch) {
      const uuaid = decodeURIComponent(inboxMatch[1]);
      const since = Number(url.searchParams.get("since") ?? 0);
      const wait = Math.min(Number(url.searchParams.get("wait") ?? 0), 30);
      const sincePath = `GET /v1/inbox/${uuaid}?since=${since}`;
      const auth = this.verifyInboxAuth(req.headers, uuaid, sincePath);
      if (!auth.ok) return json(res, 401, { error: auth.reason });

      const fetchRows = () => this.store.filter((s) => s.envelope.recipient === uuaid && s.seq > since);
      let rows = fetchRows();
      const deadline = Date.now() + wait * 1000;
      while (rows.length === 0 && Date.now() < deadline) {
        await sleep(30);
        rows = fetchRows();
      }
      return json(res, 200, { envelopes: rows.map((r) => ({ seq: r.seq, envelope: r.envelope })), now: Date.now() });
    }

    json(res, 404, { error: "not-found" });
  }

  /** Transcribed from CarrierServer._verifyInboxAuth (net/carrier-server.mjs). */
  private verifyInboxAuth(
    headers: IncomingMessage["headers"],
    uuaid: string,
    sincePath: string
  ): { ok: true } | { ok: false; reason: string } {
    const pubkey = headers["x-pillar-pubkey"];
    const ts = headers["x-pillar-ts"];
    const sig = headers["x-pillar-sig"];
    if (typeof pubkey !== "string" || typeof ts !== "string" || typeof sig !== "string") {
      return { ok: false, reason: "missing-auth-headers" };
    }
    if (!/^[0-9a-f]{64}$/i.test(pubkey)) return { ok: false, reason: "bad-pubkey" };
    if (!/^[0-9a-f]{128}$/i.test(sig)) return { ok: false, reason: "bad-sig-encoding" };
    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > 5 * 60 * 1000) {
      return { ok: false, reason: "clock-skew" };
    }
    const localId = this.pillar.Keychain._localIdFromKey(Buffer.from(pubkey, "hex"));
    const derived = `uuaid:foundation:agent:${localId}`;
    if (derived !== uuaid) return { ok: false, reason: "uuaid-pubkey-mismatch" };
    const message = Buffer.from(`${sincePath}\n${ts}`, "utf-8");
    let verified = false;
    try {
      verified = this.pillar.Keychain.verifyDetached(pubkey, message, Buffer.from(sig, "hex"));
    } catch {
      return { ok: false, reason: "verify-threw" };
    }
    if (!verified) return { ok: false, reason: "bad-signature" };
    return { ok: true };
  }
}

function json(res: ServerResponse, code: number, obj: unknown): void {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json" });
  res.end(body);
}

function sha256Hex(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
