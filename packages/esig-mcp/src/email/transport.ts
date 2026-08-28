// email/transport.ts
//
// The `EmailTransport` seam (docs/architecture/esig-mcp.md §15) plus its two
// built-ins: `SmtpTransport` (dependency-free, node:net/node:tls) and
// `SesTransport` (SESv2 `SendEmail`, `@aws-sdk/client-sesv2` loaded
// dynamically as an OPTIONAL peer dependency — same pattern as the gateway's
// S3 client). `CapturingTransport` is the test double.
//
// T21: credentials (SMTP user/pass) are never logged, never included in a
// tool result or audit row, and are redacted out of every error message this
// module throws — see `redact()` / `SmtpTransport.fail()` below and the
// dedicated key-egress test in test/email.test.ts.

import net from "node:net";
import os from "node:os";
import tls from "node:tls";
import crypto from "node:crypto";

export interface EmailMessage {
  /** "Name <addr>" or a bare address — the operator-configured ESIG_MCP_EMAIL_FROM. */
  from: string;
  /** "Name <addr>" or a bare address — a single recipient (EmailDelivery sends one message per signer). */
  to: string;
  replyTo?: string;
  subject: string;
  text: string;
  html: string;
}

export interface SendResult {
  /** The `Message-ID` header this transport generated (SMTP) or the provider's own id (SES). */
  messageId?: string;
}

export interface EmailTransport {
  send(msg: EmailMessage): Promise<SendResult>;
}

// ---------- shared helpers ----------

/** Strip CR/LF/NUL and other control chars — defense in depth against SMTP header/command injection, independent of whatever the caller (templates.ts) already stripped. */
function stripControlChars(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\x00-\x1f\x7f]/g, "");
}

/** "Name <addr>" | "addr" -> "addr" (the bare address SMTP envelope commands need). */
function extractAddress(value: string): string {
  const cleaned = stripControlChars(value).trim();
  const m = /<([^<>]+)>\s*$/.exec(cleaned);
  return (m ? m[1] : cleaned).trim();
}

/** Replace every occurrence of `secret` in `message` — used so no thrown error can ever carry the SMTP password (T21). */
function redact(message: string, secret?: string): string {
  if (!secret) return message;
  return message.split(secret).join("[redacted]");
}

/**
 * F3 (RedTeam RT-2026-08-27-05): redact every string in `secrets`, in turn,
 * from `message`. T21 originally redacted only the raw password; a server
 * that ECHOES the AUTH command line back in a reply (some do, on a 535 or
 * other error) leaks base64(password) instead — the raw-password redaction
 * alone misses that. Defense in depth: also strip the AUTH PLAIN credential
 * (`base64("\0user\0pass")`), the raw base64(password) an AUTH LOGIN
 * exchange sends on its own line, and base64(user) for the same reason.
 */
function redactAll(message: string, secrets: Array<string | undefined>): string {
  let out = message;
  for (const secret of secrets) out = redact(out, secret);
  return out;
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function normalizeCrlf(s: string): string {
  return s.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
}

/** RFC 5321 §4.5.2 transparency: any line starting with "." gets an extra "." prepended. Operates on an already CRLF-normalized string. */
function dotStuff(s: string): string {
  return s
    .split("\r\n")
    .map((line) => (line.startsWith(".") ? "." + line : line))
    .join("\r\n");
}

function buildMimeMessage(msg: EmailMessage): { raw: string; messageId: string } {
  const boundary = `----=_esig-mcp-${crypto.randomBytes(12).toString("hex")}`;
  const messageId = `<${crypto.randomBytes(16).toString("hex")}@esig-mcp.local>`;
  const headerLines = [
    `From: ${stripControlChars(msg.from)}`,
    `To: ${stripControlChars(msg.to)}`,
    ...(msg.replyTo ? [`Reply-To: ${stripControlChars(msg.replyTo)}`] : []),
    `Subject: ${stripControlChars(msg.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: ${messageId}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ];
  const bodyLines = [
    `--${boundary}`,
    `Content-Type: text/plain; charset="utf-8"`,
    `Content-Transfer-Encoding: 8bit`,
    "",
    msg.text,
    "",
    `--${boundary}`,
    `Content-Type: text/html; charset="utf-8"`,
    `Content-Transfer-Encoding: 8bit`,
    "",
    msg.html,
    "",
    `--${boundary}--`,
  ];
  return { raw: headerLines.join("\r\n") + "\r\n\r\n" + bodyLines.join("\r\n"), messageId };
}

// ---------- SMTP reply parsing ----------

interface SmtpReply {
  code: number;
  raw: string;
}

/** Parse as many complete lines off the front of `buffer` as needed to form one (possibly multi-line) SMTP reply. Returns `undefined` if the buffer does not yet hold a complete reply. */
function parseReply(buffer: string): { reply: SmtpReply; rest: string } | undefined {
  const lines: string[] = [];
  let rest = buffer;
  for (;;) {
    const nlIdx = rest.indexOf("\n");
    if (nlIdx === -1) return undefined;
    let line = rest.slice(0, nlIdx);
    if (line.endsWith("\r")) line = line.slice(0, -1);
    rest = rest.slice(nlIdx + 1);
    lines.push(line);
    const m = /^(\d{3})([ -]|$)/.exec(line);
    if (!m || m[2] !== "-") break; // malformed, or the terminal line of a multi-line reply
  }
  const codeMatch = /^(\d{3})/.exec(lines[lines.length - 1] ?? "");
  const code = codeMatch ? Number(codeMatch[1]) : NaN;
  return { reply: { code, raw: lines.join("\n") }, rest };
}

/** Buffers a socket's incoming bytes and hands out complete SMTP replies, one `readReply()` call at a time, in order. Rebindable across the STARTTLS socket-upgrade (a new underlying socket, same pending-reply queue). */
class SmtpClient {
  private buffer = "";
  private pending: Array<{ resolve: (r: SmtpReply) => void; reject: (e: Error) => void }> = [];
  private socket!: net.Socket | tls.TLSSocket;

  constructor(socket: net.Socket | tls.TLSSocket) {
    this.bind(socket);
  }

  bind(socket: net.Socket | tls.TLSSocket): void {
    // On the STARTTLS upgrade path this is called a second time with a new
    // (TLS-wrapped) socket — the OLD socket's listeners must come off first,
    // or the raw encrypted bytes it keeps emitting on 'data' (Node broadcasts
    // to every listener) get appended to `this.buffer` as if they were plain
    // SMTP text, corrupting reply parsing.
    if (this.socket && this.socket !== socket) {
      this.socket.removeAllListeners("data");
      this.socket.removeAllListeners("error");
      this.socket.removeAllListeners("close");
    }
    this.socket = socket;
    socket.on("data", (chunk: Buffer | string) => {
      this.buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      this.flush();
    });
    socket.on("error", (e: Error) => this.rejectAll(e));
    socket.on("close", () => this.rejectAll(new Error("SMTP connection closed unexpectedly")));
  }

  private flush(): void {
    while (this.pending.length > 0) {
      const parsed = parseReply(this.buffer);
      if (!parsed) return;
      this.buffer = parsed.rest;
      this.pending.shift()!.resolve(parsed.reply);
    }
  }

  private rejectAll(e: Error): void {
    while (this.pending.length > 0) this.pending.shift()!.reject(e);
  }

  readReply(): Promise<SmtpReply> {
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.flush();
    });
  }

  writeLine(line: string): void {
    this.socket.write(line + "\r\n");
  }

  write(raw: string): void {
    this.socket.write(raw);
  }
}

export interface SmtpTransportOptions {
  host: string;
  port: number;
  user?: string;
  pass?: string;
  /** Implicit TLS from the first byte (conventionally port 465 / ESIG_MCP_SMTP_SECURE=1). */
  secure?: boolean;
  /** Skip STARTTLS entirely and proceed over a plaintext connection. Off by default — config.ts refuses this unless the operator explicitly opts in (ESIG_MCP_SMTP_ALLOW_PLAINTEXT=1). */
  allowPlaintext?: boolean;
  /** Socket idle timeout, ms. Default 30_000. */
  timeoutMs?: number;
  /**
   * Injectable TLS connection options for the implicit-TLS connect AND the
   * STARTTLS upgrade. In tests, a self-signed cert's CA plus
   * `rejectUnauthorized:false` (from core's `generateSelfSignedCert`). In
   * production, `bin.ts` sets `{ rejectUnauthorized: false }` here — and
   * only here — when the operator has explicitly set
   * `ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS=1` (G2, a loud opt-out: a startup
   * WARNING is printed whenever it's on). Left unset otherwise, so Node's own
   * default (`rejectUnauthorized: true`) applies — server certificate
   * verification against the system CA is ON by default.
   */
  tlsOptions?: tls.ConnectionOptions;
}

/** node:net/node:tls SMTP client — EHLO, STARTTLS (or implicit TLS), AUTH PLAIN/LOGIN, MAIL FROM/RCPT TO/DATA, QUIT. No third-party dependency. */
export class SmtpTransport implements EmailTransport {
  constructor(private readonly opts: SmtpTransportOptions) {}

  async send(msg: EmailMessage): Promise<SendResult> {
    const timeoutMs = this.opts.timeoutMs ?? 30_000;
    const secure = this.opts.secure ?? this.opts.port === 465;
    let socket: net.Socket | tls.TLSSocket | undefined;

    try {
      socket = secure ? await this.connectTls(timeoutMs) : await this.connectPlain(timeoutMs);
      const armTimeout = (s: net.Socket | tls.TLSSocket): void => {
        s.setTimeout(timeoutMs, () => s.destroy(new Error(`SMTP socket idle timeout after ${timeoutMs}ms`)));
      };
      armTimeout(socket);

      const client = new SmtpClient(socket);
      await this.expect(client, [220], "greeting");
      await this.ehlo(client);

      if (!secure) {
        if (!this.opts.allowPlaintext) {
          client.writeLine("STARTTLS");
          await this.expect(client, [220], "STARTTLS");
          socket = await this.upgradeToTls(socket as net.Socket, timeoutMs);
          armTimeout(socket);
          client.bind(socket);
          await this.ehlo(client);
        }
      }

      if (this.opts.user && this.opts.pass) {
        await this.authenticate(client);
      }

      const fromAddr = extractAddress(msg.from);
      const toAddr = extractAddress(msg.to);

      client.writeLine(`MAIL FROM:<${fromAddr}>`);
      await this.expect(client, [250], "MAIL FROM");
      client.writeLine(`RCPT TO:<${toAddr}>`);
      await this.expect(client, [250, 251], "RCPT TO");
      client.writeLine("DATA");
      await this.expect(client, [354], "DATA");

      const { raw, messageId } = buildMimeMessage(msg);
      client.write(dotStuff(normalizeCrlf(raw)) + "\r\n.\r\n");
      const dataReply = await client.readReply();
      if (dataReply.code !== 250) this.fail(`SMTP DATA failed: ${dataReply.raw}`);

      client.writeLine("QUIT");
      await client.readReply().catch(() => undefined);

      return { messageId };
    } catch (e) {
      throw new Error(redactAll(errorText(e), this.secretsToRedact()));
    } finally {
      socket?.destroy();
    }
  }

  private fail(message: string): never {
    throw new Error(redactAll(message, this.secretsToRedact()));
  }

  /**
   * F3: every string a server-echoed reply could leak the password through —
   * the raw password, its AUTH PLAIN credential encoding
   * (`base64("\0user\0pass")`), the bare `base64(password)` an AUTH LOGIN
   * exchange sends on its own line, and (defense in depth) `base64(user)`.
   * Computed fresh from `this.opts` on every call — never cached.
   */
  private secretsToRedact(): Array<string | undefined> {
    const { user, pass } = this.opts;
    if (!pass) return [];
    const secrets: Array<string | undefined> = [pass, Buffer.from(pass, "utf8").toString("base64")];
    if (user) {
      secrets.push(Buffer.from(`\0${user}\0${pass}`, "utf8").toString("base64"));
      secrets.push(Buffer.from(user, "utf8").toString("base64"));
    }
    return secrets;
  }

  private async expect(client: SmtpClient, codes: number[], step: string): Promise<SmtpReply> {
    const reply = await client.readReply();
    if (!codes.includes(reply.code)) this.fail(`SMTP ${step} failed: ${reply.raw}`);
    return reply;
  }

  private async ehlo(client: SmtpClient): Promise<SmtpReply> {
    const hostname = os.hostname() || "localhost";
    client.writeLine(`EHLO ${hostname}`);
    const reply = await client.readReply();
    if (reply.code === 250) return reply;
    // Some (rare) servers only implement the original HELO — fall back once.
    client.writeLine(`HELO ${hostname}`);
    const heloReply = await client.readReply();
    if (heloReply.code !== 250) this.fail(`SMTP EHLO/HELO failed: ${heloReply.raw}`);
    return heloReply;
  }

  /**
   * AUTH PLAIN first, falling back to AUTH LOGIN when the server rejects
   * PLAIN outright (5xx).
   *
   * F3 (RedTeam RT-2026-08-27-05): every failure message below reports only
   * the reply CODE, never the server's raw reply text (`reply.raw`) — a
   * malicious or misconfigured server can echo the AUTH command line itself
   * back in its reply (some do, particularly on a generic 535), which would
   * otherwise leak base64(password) straight into a thrown error (and from
   * there, an audit row or tool result). `secretsToRedact()` above still
   * strips the same encodings from every OTHER error string in this class as
   * defense in depth, but the fix here is to never embed the untrusted reply
   * text after AUTH at all, rather than relying on redaction alone to catch
   * every encoding a server might choose to echo it in.
   */
  private async authenticate(client: SmtpClient): Promise<void> {
    const user = this.opts.user!;
    const pass = this.opts.pass!;

    const plainCred = Buffer.from(`\0${user}\0${pass}`, "utf8").toString("base64");
    client.writeLine(`AUTH PLAIN ${plainCred}`);
    const plainReply = await client.readReply();
    if (plainReply.code === 235) return;
    if (plainReply.code < 500) {
      // A non-5xx rejection (e.g. 535 bad credentials — some servers use it
      // for both "wrong password" and "mechanism not offered") is a real
      // auth failure, not a "try a different mechanism" signal.
      this.fail(`SMTP AUTH PLAIN failed (server replied ${plainReply.code})`);
    }

    client.writeLine("AUTH LOGIN");
    const loginReply = await client.readReply();
    if (loginReply.code !== 334) this.fail(`SMTP AUTH LOGIN failed (server replied ${loginReply.code})`);
    client.writeLine(Buffer.from(user, "utf8").toString("base64"));
    const userReply = await client.readReply();
    if (userReply.code !== 334) this.fail(`SMTP AUTH LOGIN (username) failed (server replied ${userReply.code})`);
    client.writeLine(Buffer.from(pass, "utf8").toString("base64"));
    const passReply = await client.readReply();
    if (passReply.code !== 235) this.fail(`SMTP AUTH LOGIN failed (server replied ${passReply.code})`);
  }

  private connectPlain(timeoutMs: number): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host: this.opts.host, port: this.opts.port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`SMTP connection to ${this.opts.host}:${this.opts.port} timed out`));
      }, timeoutMs);
      socket.once("connect", () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
    });
  }

  private connectTls(timeoutMs: number): Promise<tls.TLSSocket> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: this.opts.host,
        port: this.opts.port,
        // R5 (verifier finding): SNI (`servername`) is a HOSTNAME concept —
        // sending it as an IP literal is meaningless (there is no name to
        // indicate) and trips Node's own deprecation warning (DEP0123). Only
        // set it when the configured host is actually a name.
        ...(net.isIP(this.opts.host) === 0 ? { servername: this.opts.host } : {}),
        ...this.opts.tlsOptions,
      });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`SMTP TLS connection to ${this.opts.host}:${this.opts.port} timed out`));
      }, timeoutMs);
      socket.once("secureConnect", () => {
        clearTimeout(timer);
        resolve(socket);
      });
      socket.once("error", (e) => {
        clearTimeout(timer);
        reject(this.wrapTlsError(e));
      });
    });
  }

  private upgradeToTls(socket: net.Socket, timeoutMs: number): Promise<tls.TLSSocket> {
    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        socket,
        // R5: see connectTls's identical comment above.
        ...(net.isIP(this.opts.host) === 0 ? { servername: this.opts.host } : {}),
        ...this.opts.tlsOptions,
      });
      const timer = setTimeout(() => {
        tlsSocket.destroy();
        reject(new Error("SMTP STARTTLS upgrade timed out"));
      }, timeoutMs);
      tlsSocket.once("secureConnect", () => {
        clearTimeout(timer);
        resolve(tlsSocket);
      });
      tlsSocket.once("error", (e) => {
        clearTimeout(timer);
        reject(this.wrapTlsError(e));
      });
    });
  }

  /**
   * R2 (verifier finding): a bare Node TLS error (e.g. "self signed
   * certificate", "unable to verify the first certificate") gives an
   * operator no indication this is specifically a CERTIFICATE problem, let
   * alone how to fix it or deliberately opt out. Any error whose `code`
   * matches a certificate-verification failure is rewritten into a clear,
   * actionable message naming the host:port, the code, and the opt-out env
   * var; every other TLS/connection error (a timed-out connect, ECONNREFUSED,
   * etc.) passes through unchanged.
   */
  private wrapTlsError(e: unknown): Error {
    const code = (e as NodeJS.ErrnoException | undefined)?.code ?? "";
    // PURPOSE (Node's `INVALID_PURPOSE`) is included alongside the ticket's
    // named codes: this package's own test suite's self-signed certs are
    // generated by `generateSelfSignedCert` (esig-core) for DOCUMENT signing
    // — no `serverAuth` extended key usage — so Node's TLS purpose check
    // (X509_PURPOSE_SSL_SERVER) correctly rejects them with `INVALID_PURPOSE`
    // rather than a `SELF_SIGNED_CERT_IN_CHAIN`/`DEPTH_ZERO_...` code. That is
    // just as much a "the server certificate is wrong for this use" problem
    // as the other codes — verified live (Node 22, this repo's cert
    // generator): the self-signed-cert-no-opt-out test throws
    // `code: "INVALID_PURPOSE"`, not one of the other named codes.
    if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO|ERR_TLS|PURPOSE/.test(code)) {
      return new Error(
        `SMTP TLS certificate verification failed for ${this.opts.host}:${this.opts.port} (${code}) — fix the ` +
          "server certificate or set ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS=1 to opt out (unsafe)",
      );
    }
    return e instanceof Error ? e : new Error(String(e));
  }
}

// ---------- SES ----------

export interface SesTransportOptions {
  region: string;
  /**
   * Injected client for tests — bypasses the dynamic import of
   * `@aws-sdk/client-sesv2` entirely (that package is an OPTIONAL peer
   * dependency this repo never installs; see the HARD RAILS note in
   * package.json). Shape mirrors the real `SESv2Client`: a single `send()`
   * method taking a command-like object and returning `{MessageId?}`.
   */
  client?: { send(command: unknown): Promise<{ MessageId?: string }> };
}

/**
 * Stand-in for the real SDK's `SendEmailCommand` — used ONLY on the injected
 * (test) path, so the fake client can assert on `.input` without this
 * package ever importing the real, uninstalled `@aws-sdk/client-sesv2`.
 */
class SendEmailCommandStandIn {
  constructor(public readonly input: unknown) {}
}

function sesInput(msg: EmailMessage): Record<string, unknown> {
  return {
    FromEmailAddress: msg.from,
    Destination: { ToAddresses: [msg.to] },
    ...(msg.replyTo ? { ReplyToAddresses: [msg.replyTo] } : {}),
    Content: {
      Simple: {
        Subject: { Data: msg.subject, Charset: "UTF-8" },
        Body: {
          Text: { Data: msg.text, Charset: "UTF-8" },
          Html: { Data: msg.html, Charset: "UTF-8" },
        },
      },
    },
  };
}

/** SESv2 `SendEmail` via `@aws-sdk/client-sesv2`, loaded with a dynamic `import()` — an OPTIONAL peer dependency this package never installs (package.json `peerDependenciesMeta`). Absent module -> one clear startup error naming the install command. */
export class SesTransport implements EmailTransport {
  private resolved?: Promise<{
    client: { send(command: unknown): Promise<{ MessageId?: string }> };
    SendEmailCommand: new (input: unknown) => unknown;
  }>;

  constructor(private readonly opts: SesTransportOptions) {}

  private resolve(): Promise<{
    client: { send(command: unknown): Promise<{ MessageId?: string }> };
    SendEmailCommand: new (input: unknown) => unknown;
  }> {
    if (this.opts.client) {
      return Promise.resolve({ client: this.opts.client, SendEmailCommand: SendEmailCommandStandIn });
    }
    if (!this.resolved) {
      this.resolved = (async () => {
        let mod: {
          SESv2Client: new (cfg: { region: string }) => { send(command: unknown): Promise<{ MessageId?: string }> };
          SendEmailCommand: new (input: unknown) => unknown;
        };
        try {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          mod = (await import("@aws-sdk/client-sesv2")) as typeof mod;
        } catch {
          throw new Error(
            'ESIG_MCP_EMAIL_TRANSPORT="ses" requires the optional peer dependency "@aws-sdk/client-sesv2", ' +
              'which is not installed — run: npm install @aws-sdk/client-sesv2',
          );
        }
        const client = new mod.SESv2Client({ region: this.opts.region });
        return { client, SendEmailCommand: mod.SendEmailCommand };
      })();
    }
    return this.resolved;
  }

  async send(msg: EmailMessage): Promise<SendResult> {
    const { client, SendEmailCommand } = await this.resolve();
    const command = new SendEmailCommand(sesInput(msg));
    const result = await client.send(command);
    return { messageId: result?.MessageId };
  }
}

/** Test double: records every call in-memory instead of sending anywhere. */
export class CapturingTransport implements EmailTransport {
  readonly sent: EmailMessage[] = [];

  async send(msg: EmailMessage): Promise<SendResult> {
    this.sent.push(msg);
    return { messageId: `capture-${this.sent.length}` };
  }
}
