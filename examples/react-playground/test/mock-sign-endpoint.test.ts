import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type ViteDevServer } from "vite";

const configFile = fileURLToPath(new URL("../vite.config.ts", import.meta.url));
let server: ViteDevServer;
let origin: string;

beforeAll(async () => {
  server = await createServer({
    configFile,
    logLevel: "silent",
    server: { host: "127.0.0.1", port: 0, strictPort: true },
  });
  await server.listen();
  const address = server.httpServer?.address() as AddressInfo | null;
  if (!address) throw new Error("Vite test server did not expose an address");
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await server.close();
});

describe("mock sign endpoint", () => {
  it("returns the fixed success body expected by SelfSignFlow", async () => {
    const response = await fetch(`${origin}/api/esign/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        document_id: "demo-agreement-0001",
        signature_image_data_url: "data:image/png;base64,example",
        consent_given: true,
        consent_text_shown: "I agree",
      }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      ok: true,
      signed_pdf_url: "/mock/signed/demo-agreement.pdf",
      download_url: "/mock/signed/demo-agreement.pdf?download=1",
      audit_log_id: "demo-audit-0001",
    });
  });

  it("rejects methods SelfSignFlow does not use", async () => {
    const response = await fetch(`${origin}/api/esign/sign`);

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("POST");
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: "method_not_allowed",
    });
  });
});
