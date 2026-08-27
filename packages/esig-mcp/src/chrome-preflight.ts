// chrome-preflight.ts
//
// D2 FIX: Chrome/Chromium is a hard dependency of the seal step (the
// HTML→PDF render inside `EnvelopeService`'s `seal()`, via core's
// `renderHtmlToPdf`) but was otherwise invisible until the signer's last
// click threw (D1 now catches that throw instead of stranding the envelope —
// this module is the separate startup-time warning). `bin.ts` calls
// `checkSealReadiness` once at startup and prints a loud warning when it
// comes back `sealReady: false`; the server still starts either way (T1/H
// mode envelopes can always be created and signed — only sealing needs
// Chrome).
//
// core's own resolver (render-pdf.ts's `resolveExecutablePath`, built from
// `CHROME_ENV_VARS` + `CHROME_CANDIDATES` + `isExecutable`,
// packages/esig-core/src/render-pdf.ts:35-95) is NOT exported from
// `@e-sig/core`'s public barrel — `packages/esig-core/src/index.ts:20` only
// exports `renderHtmlToPdf` and its options type, nothing else from
// render-pdf.ts. (Independently confirmed by this package's own
// test/optional-chrome.test.ts header comment: "core does not export a way
// to check Chrome availability up front ... module-private".) So this
// mirrors the SAME resolution rules — same env var names, same order, same
// per-platform candidate paths, same executable-bit check
// (render-pdf.ts:35-58 for the tables, render-pdf.ts:60-69 for
// `isExecutable`, render-pdf.ts:71-95 for the resolution order this
// function follows) — WITHOUT ever calling `puppeteer.launch`: this is a
// filesystem existence/executable-bit probe only, never a Chrome process
// (fleet Playwright/headless-Chromium ban does not apply — nothing here
// drives a browser).

import { promises as fsp, constants as fsConstants } from "node:fs";

/** Mirrors render-pdf.ts:35 `CHROME_ENV_VARS`, same names, same resolution order. */
const CHROME_ENV_VARS = ["ESIG_CHROME_PATH", "PUPPETEER_EXECUTABLE_PATH", "CHROME_PATH"] as const;

/** Mirrors render-pdf.ts:37-58 `CHROME_CANDIDATES` verbatim. */
const CHROME_CANDIDATES: Partial<Record<NodeJS.Platform, string[]>> = {
  darwin: [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
  ],
  linux: [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/usr/bin/microsoft-edge",
    "/usr/bin/brave-browser",
  ],
  win32: [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  ],
};

/** Mirrors render-pdf.ts:60-69 `isExecutable` — existence + executable bit, never a launch. */
async function isExecutable(p: string, platform: NodeJS.Platform): Promise<boolean> {
  try {
    // X_OK is meaningless on Windows; existence is the useful check there —
    // same rationale as render-pdf.ts:63-64.
    await fsp.access(p, platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export interface SealReadiness {
  sealReady: boolean;
  sealReadyReason: string;
}

/**
 * Startup-only preflight — NEVER launches Chrome. Returns whether SOME
 * Chrome/Chromium executable is reachable via the same rules core's
 * `renderHtmlToPdf` uses to resolve one at seal time, so an operator learns
 * "sealing won't work" at startup instead of at the signer's last click
 * (D1's `seal_failed` phase / `esig_reseal` handle the case where it slips
 * through anyway — e.g. Chrome installed at preflight time but broken at
 * seal time).
 *
 * `env`/`platform` are injectable purely for testing; production
 * (`bin.ts`) calls this with no arguments (`process.env`/`process.platform`).
 */
export async function checkSealReadiness(
  env: Record<string, string | undefined> = process.env,
  platform: NodeJS.Platform = process.platform,
): Promise<SealReadiness> {
  for (const envVar of CHROME_ENV_VARS) {
    const p = env[envVar];
    if (!p) continue;
    if (await isExecutable(p, platform)) {
      return { sealReady: true, sealReadyReason: `found via ${envVar}=${p}` };
    }
    // An explicitly set env var pointing nowhere usable is worth naming
    // specifically — mirrors render-pdf.ts:77-79's own "fail loud rather
    // than silently fall through" choice, though this function never
    // throws (it's a report, not a launch).
    return {
      sealReady: false,
      sealReadyReason: `${envVar}="${p}" is not an executable file — set it to a real Chrome/Chromium binary`,
    };
  }

  if (env.AWS_LAMBDA_FUNCTION_NAME || env.VERCEL_ENV) {
    // Mirrors render-pdf.ts:81-84: on Lambda/Vercel, core resolves
    // `@sparticuz/chromium`'s bundled executable at render time instead of
    // scanning `CHROME_CANDIDATES`. That import is deferred to render time
    // there too (dynamic `import()`), so this preflight reports readiness
    // from the environment signal alone rather than importing an optional
    // peer dependency this package does not itself depend on.
    return {
      sealReady: true,
      sealReadyReason:
        "Lambda/Vercel environment detected — @sparticuz/chromium resolves its bundled Chromium at render time",
    };
  }

  const candidates = CHROME_CANDIDATES[platform] ?? [];
  for (const p of candidates) {
    if (await isExecutable(p, platform)) {
      return { sealReady: true, sealReadyReason: `found system Chrome/Chromium at ${p}` };
    }
  }

  return {
    sealReady: false,
    sealReadyReason:
      "no Chrome/Chromium executable found on this system; set ESIG_CHROME_PATH (or " +
      "PUPPETEER_EXECUTABLE_PATH / CHROME_PATH) to a Chrome/Chromium binary",
  };
}
