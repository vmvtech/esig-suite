import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const MOCK_SIGN_RESULT = {
  ok: true,
  signed_pdf_url: "/mock/signed/demo-agreement.pdf",
  download_url: "/mock/signed/demo-agreement.pdf?download=1",
  audit_log_id: "demo-audit-0001",
} as const;

function mockSignEndpoint(): Plugin {
  return {
    name: "esig-mock-sign-endpoint",
    configureServer(server) {
      server.middlewares.use("/api/esign/sign", (request, response) => {
        response.setHeader("content-type", "application/json; charset=utf-8");

        if (request.method !== "POST") {
          response.statusCode = 405;
          response.setHeader("allow", "POST");
          response.end(JSON.stringify({ ok: false, code: "method_not_allowed" }));
          return;
        }

        response.statusCode = 200;
        response.end(JSON.stringify(MOCK_SIGN_RESULT));
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), mockSignEndpoint()],
});
