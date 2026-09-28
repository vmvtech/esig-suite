import { fileURLToPath } from "node:url";

import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const eslint = new ESLint({ cwd: fileURLToPath(new URL("..", import.meta.url)) });

async function lintText(code, filePath) {
  const [result] = await eslint.lintText(code, { filePath });
  return result;
}

describe("ESLint flat configuration", () => {
  it("recognizes the Node 20 globals used by scripts", async () => {
    const result = await lintText(
      'console.log(process.version, Buffer.from("ok"), new URL("/", "https://example.com"), fetch, setTimeout);\n',
      "scripts/lint-control.mjs",
    );

    expect(result.errorCount).toBe(0);
  });

  it("rejects unknown script globals", async () => {
    const result = await lintText("missingGlobal();\n", "scripts/lint-mutant.mjs");

    expect(result.messages).toContainEqual(
      expect.objectContaining({ ruleId: "no-undef", severity: 2 }),
    );
  });

  it("reports unused TypeScript variables as warnings", async () => {
    const result = await lintText(
      "const unusedValue: number = 1;\n",
      "packages/esig-core/src/lint-control.ts",
    );

    expect(result.errorCount).toBe(0);
    expect(result.messages).toContainEqual(
      expect.objectContaining({
        ruleId: "@typescript-eslint/no-unused-vars",
        severity: 1,
      }),
    );
  });

  it("ignores generated, vendored, verification, and dependency files", async () => {
    const ignored = await Promise.all([
      "packages/esig-core/dist/index.js",
      "packages/esig-core/src/vendor/placeholder-plain/index.ts",
      "site/verify/verify.js",
      "node_modules/eslint/lib/api.js",
    ].map((file) => eslint.calculateConfigForFile(file)));

    expect(ignored).toEqual([undefined, undefined, undefined, undefined]);
  });
});
