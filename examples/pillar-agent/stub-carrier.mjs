// stub-carrier.mjs — a minimal in-process Pillar carrier server, so the
// README walkthrough (and demo.mjs) run fully offline with no network
// dependency on https://pillar.uuaid.org.
//
// Implements just `POST /v1/envelopes` and `GET /v1/inbox/<uuaid>`, mirroring
// the real CarrierServer's verification (net/carrier-server.mjs in the
// @uuaid/pillar package): every posted envelope is checked with the real
// `envelope.open()` before being stored, and every inbox request's signed
// `x-pillar-{pubkey,ts,sig}` headers are verified exactly the way the real
// carrier does (same message string, same self-authenticating uuaid-from-key
// check) — via the SAME `@e-sig/pillar-bridge` shim this example already
// depends on, so there is no separate crypto implementation to trust.

import { createHash } from "node:crypto";
import { createServer } from "node:http";

import { loadPillar } from "@e-sig/pillar-bridge";

/** @returns {Promise<{ url: string, close: () => Promise<void>, envelopeCount: () => number }>} */
export async function startStubCarrier() {
  const pillar = await loadPillar();
  /** @type {Array<{ seq: number, envelope: any }>} */
  const store = [];
  let nextSeq = 1;

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.writableEnded) sendJson(res, 500, { error: "internal-error" });
    });
  });

  async function handle(req, res) {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (req.method === "POST" && url.pathname === "/v1/envelopes") {
      const raw = await readBody(req);
      let envelope;
      try {
        envelope = JSON.parse(raw);
      } catch {
        return sendJson(res, 400, { accepted: false, reason: "bad-json" });
      }
      const verdict = pillar.envelope.open(envelope);
      if (!verdict.ok) return sendJson(res, 400, { accepted: false, reason: verdict.reason });
      if (typeof envelope.recipient !== "string" || !envelope.recipient.startsWith("uuaid:")) {
        return sendJson(res, 400, { accepted: false, reason: "bad-recipient" });
      }
      const existing = store.find((s) => s.envelope.id === envelope.id);
      if (existing) {
        return sendJson(res, 202, { accepted: true, duplicate: true, seq: existing.seq, sha: sha256Hex(JSON.stringify(existing.envelope)) });
      }
      const seq = nextSeq++;
      store.push({ seq, envelope });
      return sendJson(res, 202, { accepted: true, seq, sha: sha256Hex(JSON.stringify(envelope)) });
    }

    const inboxMatch = /^\/v1\/inbox\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && inboxMatch) {
      const uuaid = decodeURIComponent(inboxMatch[1]);
      const since = Number(url.searchParams.get("since") ?? 0);
      const wait = Math.min(Number(url.searchParams.get("wait") ?? 0), 30);
      const sincePath = `GET /v1/inbox/${uuaid}?since=${since}`;
      const auth = verifyInboxAuth(pillar, req.headers, uuaid, sincePath);
      if (!auth.ok) return sendJson(res, 401, { error: auth.reason });

      const fetchRows = () => store.filter((s) => s.envelope.recipient === uuaid && s.seq > since);
      let rows = fetchRows();
      const deadline = Date.now() + wait * 1000;
      while (rows.length === 0 && Date.now() < deadline) {
        await sleep(30);
        rows = fetchRows();
      }
      return sendJson(res, 200, { envelopes: rows.map((r) => ({ seq: r.seq, envelope: r.envelope })), now: Date.now() });
    }

    sendJson(res, 404, { error: "not-found" });
  }

  await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  const url = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;

  return {
    url,
    envelopeCount: () => store.length,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/** Transcribed from CarrierServer._verifyInboxAuth (net/carrier-server.mjs). */
function verifyInboxAuth(pillar, headers, uuaid, sincePath) {
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
  const localId = pillar.Keychain._localIdFromKey(Buffer.from(pubkey, "hex"));
  const derived = `uuaid:foundation:agent:${localId}`;
  if (derived !== uuaid) return { ok: false, reason: "uuaid-pubkey-mismatch" };
  const message = Buffer.from(`${sincePath}\n${ts}`, "utf-8");
  let verified = false;
  try {
    verified = pillar.Keychain.verifyDetached(pubkey, message, Buffer.from(sig, "hex"));
  } catch {
    return { ok: false, reason: "verify-threw" };
  }
  if (!verified) return { ok: false, reason: "bad-signature" };
  return { ok: true };
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json" });
  res.end(body);
}

function sha256Hex(s) {
  return createHash("sha256").update(s).digest("hex");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
