// email.test.ts — §15 "Email delivery" (docs/architecture/esig-mcp.md).
// Exercises SmtpTransport against a real in-test SMTP server (node:net,
// plain + STARTTLS via node:tls), SesTransport against an injected fake
// client (never the real, uninstalled @aws-sdk/client-sesv2), EmailDelivery,
// and the full MCP tool surface (esig_create_envelope's `message`, I8).

import net from "node:net";
import tls from "node:tls";

import { describe, it, expect, afterEach, vi } from "vitest";
import { generateSelfSignedCert } from "@e-sig/core";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  SmtpTransport,
  SesTransport,
  CapturingTransport,
  EmailDelivery,
  renderSigningEmail,
  EnvelopeService,
  buildStores,
  createMcpServer,
  FsDocumentStore,
  type McpServerDeps,
} from "../dist/index.js";
import { makeConfig } from "./helpers.js";

// ---------- a minimal in-test SMTP server (plain + STARTTLS) ----------

interface CapturedMessage {
  mailFrom: string;
  rcptTo: string;
  /** DATA content, dot-UNstuffed, CRLF-joined. */
  data: string;
  /** DATA content exactly as received on the wire, one entry per line, BEFORE dot-unstuffing. */
  rawDataLines: string[];
}

interface CapturedAuth {
  mechanism: "PLAIN" | "LOGIN";
  user: string;
  pass: string;
}

class TestSmtpServer {
  readonly server: net.Server | tls.Server;
  readonly messages: CapturedMessage[] = [];
  readonly authAttempts: CapturedAuth[] = [];
  /** G2: every command line the server received (command mode only, never DATA payload lines) — in order, across the STARTTLS upgrade too, so a test can assert AUTH only ever arrives after the upgrade completes. */
  readonly commandLog: string[] = [];
  private port = 0;

  constructor(
    private readonly opts: {
      starttls?: boolean;
      tlsCredentials?: { key: string; cert: string };
      /** G2: listen with implicit TLS from the first byte (port 465-style) instead of plaintext + STARTTLS — the greeting is sent immediately on the encrypted channel. Requires `tlsCredentials`. */
      implicitTls?: boolean;
      /** Defaults to always-accept. */
      authValidator?: (user: string, pass: string) => boolean;
    } = {},
  ) {
    this.server = opts.implicitTls
      ? tls.createServer({ key: opts.tlsCredentials!.key, cert: opts.tlsCredentials!.cert }, (socket) => this.handleConnection(socket))
      : net.createServer((socket) => this.handleConnection(socket));
  }

  start(): Promise<number> {
    return new Promise((resolve) => {
      this.server.listen(0, "127.0.0.1", () => {
        const addr = this.server.address();
        this.port = typeof addr === "object" && addr ? addr.port : 0;
        resolve(this.port);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()));
  }

  private handleConnection(socket: net.Socket | tls.TLSSocket, isFreshConnection = true): void {
    let buffer = "";
    let mode: "command" | "data" = "command";
    let dataLines: string[] = [];
    let mailFrom = "";
    let rcptTo = "";
    let authState: "none" | "login-user" | "login-pass" = "none";
    let pendingUser = "";

    const write = (line: string): void => {
      socket.write(line + "\r\n");
    };
    // RFC 3207: after STARTTLS the session resets, but the server does NOT
    // send a fresh greeting — the client goes straight to EHLO on the
    // now-encrypted channel. Only a genuinely new (plaintext) connection
    // gets the "220 ready" greeting.
    if (isFreshConnection) write("220 test-smtp ready");

    const onData = (chunk: Buffer | string): void => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        let line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);

        if (mode === "data") {
          if (line === ".") {
            mode = "command";
            const unstuffed = dataLines.map((l) => (l.startsWith(".") ? l.slice(1) : l));
            this.messages.push({ mailFrom, rcptTo, data: unstuffed.join("\r\n"), rawDataLines: [...dataLines] });
            write("250 OK: queued");
            dataLines = [];
            continue;
          }
          dataLines.push(line);
          continue;
        }

        this.commandLog.push(line);

        if (authState === "login-user") {
          pendingUser = Buffer.from(line, "base64").toString("utf8");
          write("334 " + Buffer.from("Password:").toString("base64"));
          authState = "login-pass";
          continue;
        }
        if (authState === "login-pass") {
          const pass = Buffer.from(line, "base64").toString("utf8");
          this.authAttempts.push({ mechanism: "LOGIN", user: pendingUser, pass });
          write(this.opts.authValidator?.(pendingUser, pass) ?? true ? "235 Authentication successful" : "535 Authentication failed");
          authState = "none";
          continue;
        }

        const upper = line.toUpperCase();
        if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
          write("250-test-smtp greets you");
          if (this.opts.starttls && !(socket instanceof tls.TLSSocket)) write("250-STARTTLS");
          write("250 AUTH PLAIN LOGIN");
        } else if (upper === "STARTTLS" && this.opts.starttls) {
          write("220 ready to start TLS");
          socket.removeListener("data", onData);
          const secure = new tls.TLSSocket(socket as net.Socket, {
            isServer: true,
            key: this.opts.tlsCredentials!.key,
            cert: this.opts.tlsCredentials!.cert,
          });
          this.handleConnection(secure, false);
          return;
        } else if (upper.startsWith("AUTH PLAIN")) {
          const b64 = line.split(" ")[2] ?? "";
          const decoded = Buffer.from(b64, "base64").toString("utf8");
          const parts = decoded.split("\0");
          const user = parts[1] ?? "";
          const pass = parts[2] ?? "";
          this.authAttempts.push({ mechanism: "PLAIN", user, pass });
          write(this.opts.authValidator?.(user, pass) ?? true ? "235 Authentication successful" : "535 Authentication failed");
        } else if (upper === "AUTH LOGIN") {
          write("334 " + Buffer.from("Username:").toString("base64"));
          authState = "login-user";
        } else if (upper.startsWith("MAIL FROM:")) {
          mailFrom = line;
          write("250 OK");
        } else if (upper.startsWith("RCPT TO:")) {
          rcptTo = line;
          write("250 OK");
        } else if (upper === "DATA") {
          write("354 Start mail input; end with <CRLF>.<CRLF>");
          mode = "data";
        } else if (upper === "QUIT") {
          write("221 Bye");
          socket.end();
        } else {
          write("500 unrecognized command");
        }
      }
    };

    socket.on("data", onData);
    socket.on("error", () => {
      /* connection reset by a failed-auth client closing early — expected in the wrong-password test */
    });
  }
}

const runningServers: TestSmtpServer[] = [];
afterEach(async () => {
  await Promise.all(runningServers.splice(0).map((s) => s.stop()));
});

async function startServer(opts?: ConstructorParameters<typeof TestSmtpServer>[0]): Promise<{ server: TestSmtpServer; port: number }> {
  const server = new TestSmtpServer(opts);
  const port = await server.start();
  runningServers.push(server);
  return { server, port };
}

// ---------- templates.ts ----------

describe("renderSigningEmail — templates.ts", () => {
  it("escapes HTML and strips control chars; subject has no prefix when none configured", () => {
    const rendered = renderSigningEmail({
      title: "<b>NDA</b> & Co",
      from: "Ops <ops@example.com>",
      note: "Please <sign> soon",
      url: "https://example.com/sign/abc",
    });
    expect(rendered.subject).toBe("Please sign: <b>NDA</b> & Co");
    expect(rendered.html).toContain("&lt;b&gt;NDA&lt;/b&gt; &amp; Co");
    expect(rendered.html).toContain("Please &lt;sign&gt; soon");
    expect(rendered.html).not.toContain("<b>NDA</b>");
    expect(rendered.text).toContain("NDA");
    expect(rendered.html).toContain("https://example.com/sign/abc");
  });

  it("applies the configured prefix", () => {
    const rendered = renderSigningEmail({ title: "NDA", from: "a@b.com", url: "https://x/sign/1", prefix: "Acme" });
    expect(rendered.subject).toBe("[Acme] Please sign: NDA");
  });

  it("strips CR/LF from title/note before they ever reach subject/text/html", () => {
    const rendered = renderSigningEmail({
      title: "NDA\r\nBcc: attacker@evil.com",
      from: "a@b.com",
      note: "line one\r\nBcc: attacker2@evil.com",
      url: "https://x/sign/1",
    });
    expect(rendered.subject).not.toMatch(/[\r\n]/);
    expect(rendered.text).not.toMatch(/^Bcc:/m);
    expect(rendered.html).not.toMatch(/^Bcc:/m);
  });
});

// ---------- SmtpTransport ----------

describe("SmtpTransport — plaintext (ESIG_MCP_SMTP_ALLOW_PLAINTEXT)", () => {
  it(
    "full DATA capture: subject/title/link/note present, document body ABSENT, CRLF in title stripped, dot-stuffing correct",
    async () => {
      const { server, port } = await startServer();
      const transport = new SmtpTransport({ host: "127.0.0.1", port, allowPlaintext: true, timeoutMs: 5_000 });

      const config = await makeConfig({
        delivery: { kind: "email", transport: "smtp", from: "Ops <ops@example.com>" },
      });
      const stores = buildStores(config);
      const delivery = new EmailDelivery({ transport, from: "Ops <ops@example.com>" });
      const service = new EnvelopeService({ config, ...stores, delivery });

      const result = await service.create({
        title: "NDA\r\nBcc: attacker@evil.com",
        html: "<p>SECRET_DOCUMENT_BODY_MARKER — confidential contract terms.</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        message: ".Please review before Friday.",
      });
      expect(result.delivery[0].ok).toBe(true);

      expect(server.messages).toHaveLength(1);
      const msg = server.messages[0];

      // Subject/title/note present.
      expect(msg.data).toMatch(/Subject: .*Please sign: NDABcc: attacker@evil\.com/);
      expect(msg.data).toContain(".Please review before Friday.");

      // No header-injection line — the embedded CRLF in `title` never
      // produced a standalone "Bcc:" header.
      expect(msg.data.split("\r\n")).not.toContain("Bcc: attacker@evil.com");

      // Document body ABSENT — only the title/note/link ever reach the email.
      expect(msg.data).not.toContain("SECRET_DOCUMENT_BODY_MARKER");

      // Dot-stuffing: the RAW wire line was doubled ("..Please...");
      // the reconstructed (unstuffed) body line is back to a single dot.
      expect(msg.rawDataLines).toContain("..Please review before Friday.");
      expect(msg.data.split("\r\n")).toContain(".Please review before Friday.");

      // MAIL FROM / RCPT TO used the bare address, not "Name <addr>".
      expect(msg.mailFrom).toBe("MAIL FROM:<ops@example.com>");
      expect(msg.rcptTo).toBe("RCPT TO:<alice@example.com>");
    },
    10_000,
  );

  it("AUTH PLAIN sends the correct base64(\\0user\\0pass) credential", async () => {
    const { server, port } = await startServer();
    const transport = new SmtpTransport({
      host: "127.0.0.1",
      port,
      allowPlaintext: true,
      user: "smtp-user",
      pass: "smtp-pass",
      timeoutMs: 5_000,
    });

    await transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });

    expect(server.authAttempts).toHaveLength(1);
    expect(server.authAttempts[0].mechanism).toBe("PLAIN");
    expect(server.authAttempts[0].user).toBe("smtp-user");
    expect(server.authAttempts[0].pass).toBe("smtp-pass");
  });

  it("a wrong password fails the send, and the error text never contains the password (falls back to AUTH LOGIN, which also fails)", async () => {
    const { server, port } = await startServer({ authValidator: (_u, p) => p === "correct-password" });
    void server;
    const transport = new SmtpTransport({
      host: "127.0.0.1",
      port,
      allowPlaintext: true,
      user: "smtp-user",
      pass: "wrong-password",
      timeoutMs: 5_000,
    });

    await expect(
      transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" }),
    ).rejects.toThrow(/AUTH/);

    try {
      await transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });
      throw new Error("expected send() to reject");
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      expect(message).not.toContain("wrong-password");
    }
  });
});

describe("SmtpTransport — STARTTLS", () => {
  it("upgrades to TLS with an injected self-signed cert and delivers the message", async () => {
    const cert = generateSelfSignedCert({ subjectName: "esig-mcp test SMTP" });
    const { server, port } = await startServer({
      starttls: true,
      tlsCredentials: { key: cert.keyPem, cert: cert.certPem },
    });

    const transport = new SmtpTransport({
      host: "127.0.0.1",
      port,
      timeoutMs: 5_000,
      // TESTS ONLY (per transport.ts's own doc comment): self-signed cert,
      // so verification against the system trust store would fail.
      tlsOptions: { rejectUnauthorized: false },
    });

    const result = await transport.send({
      from: "Ops <ops@example.com>",
      to: "alice@example.com",
      subject: "Please sign: NDA",
      text: "Sign here: https://example.com/sign/tok",
      html: "<p>Sign here</p>",
    });
    expect(result.messageId).toBeTruthy();

    expect(server.messages).toHaveLength(1);
    expect(server.messages[0].data).toContain("https://example.com/sign/tok");
    expect(server.messages[0].mailFrom).toBe("MAIL FROM:<ops@example.com>");
  });

  // G2 (RedTeam RT-2026-08-27-05, pre-publish gate): server cert verification
  // is ON by default — a self-signed cert MUST be refused unless the
  // operator explicitly opts out.
  it("refuses a self-signed cert WITHOUT the rejectUnauthorized:false opt-out — a clear error, not a silent downgrade", async () => {
    const cert = generateSelfSignedCert({ subjectName: "esig-mcp test SMTP" });
    const { port } = await startServer({ starttls: true, tlsCredentials: { key: cert.keyPem, cert: cert.certPem } });

    // No `tlsOptions` at all — Node's own default (`rejectUnauthorized: true`)
    // applies, and this self-signed cert is not in any trust store.
    const transport = new SmtpTransport({ host: "127.0.0.1", port, timeoutMs: 5_000 });

    // R2 (verifier finding): the thrown error must name the HOST and the
    // opt-out FLAG so an operator can actually act on it, not just a bare
    // Node TLS error message.
    await expect(
      transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" }),
    ).rejects.toThrow(/127\.0\.0\.1.*ESIG_MCP_SMTP_ALLOW_UNVERIFIED_TLS/s);
  });

  // R5 (verifier finding): SNI (`servername`) only makes sense for a
  // hostname — sending it as an IP literal is what triggers Node's DEP0123
  // ("ignoring 'servername' option ... is an IP address") deprecation
  // warning. Spy on the real `tls.connect` (still calls through to the real
  // implementation — this is a real STARTTLS handshake against the in-test
  // server, not a stub) and assert `servername` was never set for an
  // IP-literal host, on both the STARTTLS-upgrade and implicit-TLS paths.
  it("connecting to an IP-literal host never sets `servername` on the TLS options (no DEP0123)", async () => {
    const cert = generateSelfSignedCert({ subjectName: "esig-mcp test SMTP" });
    const connectSpy = vi.spyOn(tls, "connect");

    const { port: starttlsPort } = await startServer({ starttls: true, tlsCredentials: { key: cert.keyPem, cert: cert.certPem } });
    const starttlsTransport = new SmtpTransport({
      host: "127.0.0.1",
      port: starttlsPort,
      timeoutMs: 5_000,
      tlsOptions: { rejectUnauthorized: false }, // self-signed — TESTS ONLY
    });
    await starttlsTransport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });

    const implicitServer = new TestSmtpServer({ implicitTls: true, tlsCredentials: { key: cert.keyPem, cert: cert.certPem } });
    const implicitPort = await implicitServer.start();
    runningServers.push(implicitServer);
    const implicitTransport = new SmtpTransport({
      host: "127.0.0.1",
      port: implicitPort,
      secure: true,
      timeoutMs: 5_000,
      tlsOptions: { rejectUnauthorized: false }, // self-signed — TESTS ONLY
    });
    await implicitTransport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });

    expect(connectSpy.mock.calls.length).toBeGreaterThanOrEqual(2); // upgradeToTls + connectTls, both against 127.0.0.1
    for (const [opts] of connectSpy.mock.calls) {
      expect((opts as tls.ConnectionOptions).servername).toBeUndefined();
    }
    connectSpy.mockRestore();
  });

  it("hard-fails when the server does not advertise/support STARTTLS and ESIG_MCP_SMTP_ALLOW_PLAINTEXT is not set", async () => {
    // Default startServer() (no `starttls: true`): EHLO never advertises
    // STARTTLS, and the server rejects the bare command with a 500 — exactly
    // "STARTTLS not offered/refused."
    const { port } = await startServer();
    const transport = new SmtpTransport({ host: "127.0.0.1", port, timeoutMs: 5_000 }); // allowPlaintext NOT set

    await expect(
      transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" }),
    ).rejects.toThrow(/STARTTLS/);
  });

  it("AUTH is never sent before the STARTTLS upgrade completes — the server's own command order proves it", async () => {
    const cert = generateSelfSignedCert({ subjectName: "esig-mcp test SMTP" });
    const { server, port } = await startServer({ starttls: true, tlsCredentials: { key: cert.keyPem, cert: cert.certPem } });

    const transport = new SmtpTransport({
      host: "127.0.0.1",
      port,
      user: "smtp-user",
      pass: "smtp-pass",
      timeoutMs: 5_000,
      tlsOptions: { rejectUnauthorized: false }, // self-signed — TESTS ONLY
    });
    await transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });

    const starttlsIdx = server.commandLog.findIndex((l) => l.toUpperCase() === "STARTTLS");
    const secondEhloIdx = server.commandLog.findIndex((l, i) => i > starttlsIdx && l.toUpperCase().startsWith("EHLO"));
    const firstAuthIdx = server.commandLog.findIndex((l) => l.toUpperCase().startsWith("AUTH"));
    expect(starttlsIdx).toBeGreaterThanOrEqual(0);
    expect(secondEhloIdx).toBeGreaterThan(starttlsIdx); // EHLO is re-sent on the encrypted channel
    expect(firstAuthIdx).toBeGreaterThan(secondEhloIdx); // AUTH only after the post-upgrade EHLO
  });

  it("implicit TLS (port-465-style / ESIG_MCP_SMTP_SECURE=1): connects encrypted from the first byte and delivers", async () => {
    const cert = generateSelfSignedCert({ subjectName: "esig-mcp test SMTP" });
    const server = new TestSmtpServer({ implicitTls: true, tlsCredentials: { key: cert.keyPem, cert: cert.certPem } });
    const port = await server.start();
    runningServers.push(server);

    const transport = new SmtpTransport({
      host: "127.0.0.1",
      port,
      secure: true, // implicit TLS — mirrors ESIG_MCP_SMTP_SECURE=1 / port 465
      timeoutMs: 5_000,
      tlsOptions: { rejectUnauthorized: false }, // self-signed — TESTS ONLY
    });

    const result = await transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });
    expect(result.messageId).toBeTruthy();
    expect(server.messages).toHaveLength(1);
  });
});

// ---------- F3: server-echoed AUTH replies never leak credentials ----------

describe("SmtpTransport — F3 (RedTeam RT-2026-08-27-05): a server echoing the AUTH line never leaks the password", () => {
  it("a server that echoes the base64(password) line back into its 535 reply never surfaces it (raw or base64) in the thrown error", async () => {
    // A minimal hand-rolled SMTP-like server: greets, accepts EHLO, rejects
    // AUTH PLAIN outright (so the client falls back to AUTH LOGIN, matching
    // the ticket's own scenario), then ECHOES whatever base64 line the
    // client sends as the AUTH LOGIN password straight back into its 535
    // failure reply — simulating a server (malicious, or merely broken)
    // that reflects the AUTH command text.
    const echoServer = net.createServer((socket) => {
      let buffer = "";
      let awaitingPassword = false;
      const write = (line: string): void => socket.write(line + "\r\n");
      write("220 echo-smtp ready");
      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        let idx: number;
        while ((idx = buffer.indexOf("\n")) !== -1) {
          let line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 1);
          if (line.endsWith("\r")) line = line.slice(0, -1);
          const upper = line.toUpperCase();
          if (awaitingPassword) {
            // Echo the exact line (base64(password)) into the failure reply.
            write(`535 authentication failed for ${line}`);
            awaitingPassword = false;
          } else if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
            write("250 echo-smtp greets you");
          } else if (upper.startsWith("AUTH PLAIN")) {
            write("535 AUTH PLAIN not supported");
          } else if (upper === "AUTH LOGIN") {
            write("334 " + Buffer.from("Username:").toString("base64"));
          } else if (!awaitingPassword) {
            // The username line (base64) — reply asking for the password.
            write("334 " + Buffer.from("Password:").toString("base64"));
            awaitingPassword = true;
          }
        }
      });
    });
    await new Promise<void>((resolve) => echoServer.listen(0, "127.0.0.1", () => resolve()));
    const address = echoServer.address();
    const port = typeof address === "object" && address ? address.port : 0;

    const PASSWORD = "super-secret-smtp-password";
    const transport = new SmtpTransport({ host: "127.0.0.1", port, allowPlaintext: true, user: "smtp-user", pass: PASSWORD, timeoutMs: 5_000 });

    let thrownMessage = "";
    try {
      await transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" });
      throw new Error("expected send() to reject");
    } catch (e) {
      thrownMessage = e instanceof Error ? e.message : String(e);
    } finally {
      await new Promise<void>((resolve) => echoServer.close(() => resolve()));
    }

    const passwordBase64 = Buffer.from(PASSWORD, "utf8").toString("base64");
    const plainCredBase64 = Buffer.from(`\0smtp-user\0${PASSWORD}`, "utf8").toString("base64");
    expect(thrownMessage).not.toContain(PASSWORD);
    expect(thrownMessage).not.toContain(passwordBase64);
    expect(thrownMessage).not.toContain(plainCredBase64);
    // F3's actual fix: the server's raw reply text is never embedded after
    // AUTH at all (only the numeric code is), so the echoed line can't reach
    // the message through ANY encoding — this is the strongest assertion.
    expect(thrownMessage).not.toContain("authentication failed for");
    expect(thrownMessage).toMatch(/AUTH LOGIN failed \(server replied 535\)/);
  });
});

// ---------- SesTransport ----------

describe("SesTransport", () => {
  it("with an injected fake client, sends the correctly-shaped SendEmailCommand input", async () => {
    const calls: Array<{ input: unknown }> = [];
    const fakeClient = {
      send: async (command: unknown) => {
        calls.push(command as { input: unknown });
        return { MessageId: "ses-message-id-123" };
      },
    };
    const transport = new SesTransport({ region: "us-east-1", client: fakeClient });

    const result = await transport.send({
      from: "Ops <ops@example.com>",
      to: "alice@example.com",
      replyTo: "reply@example.com",
      subject: "Please sign: NDA",
      text: "text body",
      html: "<p>html body</p>",
    });

    expect(result.messageId).toBe("ses-message-id-123");
    expect(calls).toHaveLength(1);
    const input = calls[0].input as Record<string, unknown>;
    expect(input.FromEmailAddress).toBe("Ops <ops@example.com>");
    expect(input.Destination).toEqual({ ToAddresses: ["alice@example.com"] });
    expect(input.ReplyToAddresses).toEqual(["reply@example.com"]);
    const content = input.Content as { Simple: { Subject: { Data: string }; Body: { Text: { Data: string }; Html: { Data: string } } } };
    expect(content.Simple.Subject.Data).toBe("Please sign: NDA");
    expect(content.Simple.Body.Text.Data).toBe("text body");
    expect(content.Simple.Body.Html.Data).toBe("<p>html body</p>");
  });

  it("without an injected client, the (uninstalled) real SDK import fails with a clear install-command error", async () => {
    const transport = new SesTransport({ region: "us-east-1" });
    await expect(
      transport.send({ from: "a@b.com", to: "c@d.com", subject: "s", text: "t", html: "<p>t</p>" }),
    ).rejects.toThrow(/npm install @aws-sdk\/client-sesv2/);
  });
});

// ---------- EmailDelivery ----------

describe("EmailDelivery", () => {
  it("sends one email per signer link; receipts have no URL", async () => {
    const transport = new CapturingTransport();
    const delivery = new EmailDelivery({ transport, from: "Ops <ops@example.com>", subjectPrefix: "Acme" });

    const receipts = await delivery.deliver(
      { id: "env-1", title: "NDA", message: "please sign" },
      [
        { signerId: "s1", name: "Alice", email: "alice@example.com", url: "https://x/sign/tok1" },
        { signerId: "s2", name: "Bob", email: "bob@example.com", url: "https://x/sign/tok2" },
      ],
    );

    expect(transport.sent).toHaveLength(2);
    expect(transport.sent[0].to).toBe("alice@example.com");
    expect(transport.sent[0].subject).toBe("[Acme] Please sign: NDA");
    expect(transport.sent[0].html).toContain("https://x/sign/tok1");

    expect(receipts).toHaveLength(2);
    for (const r of receipts) {
      expect(r.channel).toBe("email");
      expect(r.ok).toBe(true);
      expect(r.messageId).toBeTruthy();
      expect(JSON.stringify(r)).not.toContain("/sign/");
    }
  });

  it("reports a per-signer failure receipt (ok:false, detail set) when the transport throws — never throws out of deliver()", async () => {
    const failingTransport = { send: async () => { throw new Error("smtp exploded"); } };
    const delivery = new EmailDelivery({ transport: failingTransport, from: "a@b.com" });

    const receipts = await delivery.deliver({ id: "env-1", title: "NDA" }, [
      { signerId: "s1", name: "Alice", email: "alice@example.com", url: "https://x/sign/tok1" },
    ]);
    expect(receipts).toEqual([{ signerId: "s1", channel: "email", ok: false, detail: "smtp exploded" }]);
  });
});

// ---------- full flow via a real MCP client ----------

async function buildEmailHarness(transport: CapturingTransport) {
  const config = await makeConfig({
    returnLinks: false,
    delivery: { kind: "email", transport: "smtp", from: "Ops <ops@example.com>" },
  });
  const stores = buildStores(config);
  const documents = new FsDocumentStore(config.dataDir, config.maxPdfBytes);
  const delivery = new EmailDelivery({ transport, from: "Ops <ops@example.com>" });
  const envelopes = new EnvelopeService({ config, ...stores, documents, delivery });
  const deps: McpServerDeps = {
    config,
    envelopes,
    documents,
    certStore: stores.certStore,
    pqKeyStore: stores.pqKeyStore,
    auditStore: stores.auditStore,
  };
  return { config, envelopes, deps, mcpServer: createMcpServer(deps) };
}

async function connectedClient(mcpServer: ReturnType<typeof createMcpServer>): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([client.connect(clientTransport), mcpServer.connect(serverTransport)]);
  return client;
}

describe("esig_create_envelope over EmailDelivery — full MCP flow (I8)", () => {
  it("delivers by email; the tool result never contains a URL, and the message field is surfaced/escaped", async () => {
    const transport = new CapturingTransport();
    const { mcpServer } = await buildEmailHarness(transport);
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "Consulting Agreement",
        html: "<p>terms</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        message: "Please sign by Friday, <thanks>!",
      },
    });
    expect(result.isError).not.toBe(true);
    expect(JSON.stringify(result)).not.toMatch(/\/sign\//);
    expect((result.structuredContent as Record<string, unknown>).message).toBe("Please sign by Friday, <thanks>!");

    expect(transport.sent).toHaveLength(1);
    expect(transport.sent[0].to).toBe("alice@example.com");
    expect(transport.sent[0].subject).toContain("Consulting Agreement");
    expect(transport.sent[0].html).toContain("Please sign by Friday, &lt;thanks&gt;!");
    expect(transport.sent[0].html).not.toContain("<p>terms</p>");

    await client.close();
  });

  it("message longer than 500 chars is refused with a clear tool error", async () => {
    const transport = new CapturingTransport();
    const { mcpServer } = await buildEmailHarness(transport);
    const client = await connectedClient(mcpServer);

    const result = await client.callTool({
      name: "esig_create_envelope",
      arguments: {
        title: "NDA",
        html: "<p>hi</p>",
        signers: [{ name: "Alice", email: "alice@example.com" }],
        message: "x".repeat(501),
      },
    });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result)).toMatch(/500 character/);
    expect(transport.sent).toHaveLength(0);

    await client.close();
  });
});
