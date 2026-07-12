// src/lib/integrations/esig/core/render-pdf.ts
//
// Portable HTML → PDF renderer. puppeteer-core under the hood; auto-detects
// Lambda environment to use @sparticuz/chromium, falls back to system Chrome
// for local dev.

import puppeteer, { type Browser, type PaperFormat } from "puppeteer-core";

export interface RenderHtmlToPdfOptions {
  html: string;
  format?: PaperFormat;
  margin?: { top?: string; bottom?: string; left?: string; right?: string };
  printBackground?: boolean;
  /**
   * Override the chromium executable path. If omitted, resolution order is:
   *   1. ESIG_CHROME_PATH / PUPPETEER_EXECUTABLE_PATH / CHROME_PATH env vars
   *   2. on Vercel / AWS Lambda: load @sparticuz/chromium
   *   3. platform scan: common Chrome/Chromium/Edge/Brave install locations
   * Set this (or an env var) when porting to an environment outside that matrix.
   */
  executablePath?: string;
  /** Override puppeteer launch args. Default: --no-sandbox --disable-setuid-sandbox. */
  launchArgs?: string[];
  /**
   * Enable JavaScript execution in the rendered document. Default FALSE:
   * document templates are static HTML, and executing untrusted/interpolated
   * HTML with JS enabled is an SSRF / data-exfiltration surface. Set true only
   * if your templates genuinely need in-page scripting.
   */
  javascriptEnabled?: boolean;
  /** Max ms to wait for content + subresources to load. Default 30000. */
  timeoutMs?: number;
}

const CHROME_ENV_VARS = ["ESIG_CHROME_PATH", "PUPPETEER_EXECUTABLE_PATH", "CHROME_PATH"] as const;

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

async function isExecutable(p: string): Promise<boolean> {
  try {
    const fs = await import("node:fs");
    // X_OK is meaningless on Windows; existence is the useful check there.
    await fs.promises.access(p, process.platform === "win32" ? fs.constants.F_OK : fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function resolveExecutablePath(opts: RenderHtmlToPdfOptions): Promise<string> {
  if (opts.executablePath) return opts.executablePath;
  for (const envVar of CHROME_ENV_VARS) {
    const p = process.env[envVar];
    if (!p) continue;
    if (await isExecutable(p)) return p;
    // An explicitly set env var pointing nowhere is a config error — fail loud
    // rather than silently falling through to a different browser.
    throw new Error(`renderHtmlToPdf: ${envVar}="${p}" is not an executable file.`);
  }
  if (process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.VERCEL_ENV) {
    const chromium = (await import("@sparticuz/chromium")).default;
    return await chromium.executablePath();
  }
  const candidates = CHROME_CANDIDATES[process.platform] ?? [];
  for (const p of candidates) {
    if (await isExecutable(p)) return p;
  }
  throw new Error(
    "renderHtmlToPdf: no Chrome/Chromium executable found. Tried:\n" +
      candidates.map((p) => `  - ${p}`).join("\n") +
      "\nInstall Chrome/Chromium, or point to a browser with options.executablePath " +
      "or the ESIG_CHROME_PATH / PUPPETEER_EXECUTABLE_PATH / CHROME_PATH env var."
  );
}

async function resolveLaunchArgs(opts: RenderHtmlToPdfOptions): Promise<string[]> {
  if (opts.launchArgs) return opts.launchArgs;
  if (process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.VERCEL_ENV) {
    const chromium = (await import("@sparticuz/chromium")).default;
    return chromium.args;
  }
  return ["--no-sandbox", "--disable-setuid-sandbox"];
}

export async function renderHtmlToPdf(opts: RenderHtmlToPdfOptions): Promise<Buffer> {
  const executablePath = await resolveExecutablePath(opts);
  const args = await resolveLaunchArgs(opts);
  const jsEnabled = opts.javascriptEnabled ?? false;
  const timeout = opts.timeoutMs ?? 30_000;
  let browser: Browser | undefined;
  try {
    browser = await puppeteer.launch({ args, executablePath, headless: true });
    const page = await browser.newPage();
    if (!jsEnabled) await page.setJavaScriptEnabled(false);
    // "load" (not domcontentloaded) so embedded images and logos finish loading
    // before the snapshot — otherwise page.pdf() can capture a blank signature
    // image. The load event waits for all referenced subresources.
    await page.setContent(opts.html, { waitUntil: "load", timeout });
    if (jsEnabled) {
      // Belt-and-suspenders: wait for web fonts to settle (only meaningful when
      // scripting is enabled; reached via globalThis to avoid a DOM-lib dep).
      await page
        .evaluate(() => {
          const d = (globalThis as { document?: { fonts?: { ready?: Promise<unknown> } } }).document;
          return d?.fonts?.ready;
        })
        .catch(() => undefined);
    }
    const pdfBuf = await page.pdf({
      format: opts.format ?? "Letter",
      margin: opts.margin ?? {
        top: "0.5in",
        bottom: "0.5in",
        left: "0.5in",
        right: "0.5in",
      },
      printBackground: opts.printBackground ?? true,
    });
    return Buffer.from(pdfBuf);
  } finally {
    if (browser) {
      await browser.close().catch(() => undefined);
    }
  }
}
