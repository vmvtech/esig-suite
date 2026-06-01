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
   * Override the chromium executable path. If omitted:
   *   - on Vercel / AWS Lambda: load @sparticuz/chromium
   *   - on macOS: /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
   *   - on Linux: try common google-chrome / chromium paths
   * Set this when porting to an environment outside that matrix.
   */
  executablePath?: string;
  /** Override puppeteer launch args. Default: --no-sandbox --disable-setuid-sandbox. */
  launchArgs?: string[];
}

async function resolveExecutablePath(opts: RenderHtmlToPdfOptions): Promise<string> {
  if (opts.executablePath) return opts.executablePath;
  if (process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.VERCEL_ENV) {
    const chromium = (await import("@sparticuz/chromium")).default;
    return await chromium.executablePath();
  }
  if (process.platform === "darwin") {
    return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  }
  for (const p of [
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
  ]) {
    try {
      const fs = await import("node:fs");
      await fs.promises.access(p, fs.constants.X_OK);
      return p;
    } catch {
      // try next
    }
  }
  throw new Error(
    "renderHtmlToPdf: no Chrome/Chromium executable found. Install Chrome or pass options.executablePath."
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
  let browser: Browser | undefined;
  try {
    browser = await puppeteer.launch({ args, executablePath, headless: true });
    const page = await browser.newPage();
    await page.setContent(opts.html, { waitUntil: "domcontentloaded" });
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
