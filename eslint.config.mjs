import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

const typescriptFiles = ["packages/*/src/**/*.ts", "packages/*/src/**/*.tsx"];
const javascriptFiles = ["scripts/**/*.mjs", "demos/**/*.mjs"];

export default defineConfig([
  globalIgnores([
    "**/dist/**",
    "**/vendor/**",
    "site/verify/verify.js",
    "**/node_modules/**",
  ]),
  {
    ...js.configs.recommended,
    name: "esig/recommended",
    files: [...typescriptFiles, ...javascriptFiles],
    rules: {
      ...js.configs.recommended.rules,
      "no-unused-vars": "warn",
    },
  },
  {
    name: "esig/node-globals",
    files: javascriptFiles,
    languageOptions: {
      globals: {
        Buffer: "readonly",
        URL: "readonly",
        console: "readonly",
        fetch: "readonly",
        process: "readonly",
        setTimeout: "readonly",
      },
    },
  },
  ...tseslint.configs.recommended.map((config) => ({
    ...config,
    files: typescriptFiles,
  })),
  {
    name: "esig/typescript-overrides",
    files: typescriptFiles,
    rules: {
      "@typescript-eslint/no-unused-vars": "warn",
    },
  },
  {
    ...reactHooks.configs.flat.recommended,
    name: "esig/react-hooks",
    files: ["packages/*/src/**/*.tsx"],
  },
]);
