// @e-sig/react — SelfSignedReceipt
//
// Receipt shown after a document is signed via the self-contained pipeline.
// Surfaces the signed-PDF download, the signature image, and cryptographic +
// attribution metadata (cert fingerprint, signer IP). Storage paths are run
// through `downloadHref` (an RLS-gated proxy) since private buckets aren't
// directly browser-fetchable. No framework / design-system dependency.

import type { ReactNode } from "react";

export interface SelfSignedReceiptProps {
  signedPdfUrl: string | null;
  signatureImageUrl: string | null;
  signatory: string | null;
  signedDate: string | null;
  certFingerprint?: string | null;
  signerIp?: string | null;
  /** Map a storage path → a fetchable URL. Default "/api/esign/download/<encoded>". */
  downloadHref?: (storagePath: string) => string;
  title?: string;
  sealLine?: string;
  /** Optional "back" affordance rendered at the bottom. */
  backHref?: string;
  backLabel?: string;
  /** Or supply your own footer node (overrides backHref). */
  footer?: ReactNode;
}

const defaultDownloadHref = (p: string) =>
  `/api/esign/download/${encodeURIComponent(p)}`;

export function SelfSignedReceipt({
  signedPdfUrl,
  signatureImageUrl,
  signatory,
  signedDate,
  certFingerprint,
  signerIp,
  downloadHref = defaultDownloadHref,
  title = "Document signed",
  sealLine = "Cryptographically sealed in-platform — no third-party service.",
  backHref,
  backLabel = "Back",
  footer,
}: SelfSignedReceiptProps) {
  const formattedDate =
    signedDate != null
      ? new Date(signedDate).toLocaleString(undefined, {
          dateStyle: "medium",
          timeStyle: "short",
        })
      : null;

  return (
    <div
      data-testid="self-signed-receipt"
      className="rounded-lg border border-input bg-background p-6"
    >
      <div className="mb-4 flex items-start gap-3">
        <div className="rounded-md bg-emerald-500/10 p-2 text-emerald-600 dark:text-emerald-400">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <path d="m9 11 3 3L22 4" />
          </svg>
        </div>
        <div>
          <h2 className="text-xl font-semibold text-foreground">{title}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{sealLine}</p>
        </div>
      </div>

      <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-muted-foreground">Signatory</dt>
          <dd className="mt-0.5 break-words font-medium text-foreground">{signatory ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Signed at</dt>
          <dd className="mt-0.5 font-medium text-foreground">{formattedDate ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Signed PDF</dt>
          <dd className="mt-0.5">
            {signedPdfUrl ? (
              <a
                href={downloadHref(signedPdfUrl)}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline-offset-4 hover:underline"
                data-testid="self-signed-download-link"
              >
                Download
              </a>
            ) : (
              <span className="text-muted-foreground">Pending</span>
            )}
          </dd>
        </div>
      </dl>

      {signatureImageUrl ? (
        <div className="mt-5 rounded-md border border-input bg-background p-3">
          <p className="mb-2 text-xs text-muted-foreground">Signature</p>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={downloadHref(signatureImageUrl)}
            alt="Captured signature"
            className="max-h-24 max-w-full"
            data-testid="self-signed-signature-image"
          />
        </div>
      ) : null}

      {certFingerprint || signerIp ? (
        <details className="mt-5 rounded-md border border-input bg-muted/30 p-3 text-xs">
          <summary className="cursor-pointer text-muted-foreground">
            Cryptographic + attribution metadata
          </summary>
          <dl className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
            {certFingerprint ? (
              <div>
                <dt className="text-muted-foreground">Signing cert fingerprint (SHA-256)</dt>
                <dd className="mt-0.5 break-all font-mono text-[10px]">{certFingerprint}</dd>
              </div>
            ) : null}
            {signerIp ? (
              <div>
                <dt className="text-muted-foreground">Signer IP</dt>
                <dd className="mt-0.5 font-mono text-[11px]">{signerIp}</dd>
              </div>
            ) : null}
          </dl>
        </details>
      ) : null}

      {footer ?? (backHref ? (
        <div className="mt-5">
          <a
            href={backHref}
            className="inline-flex items-center gap-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
          >
            {backLabel}
          </a>
        </div>
      ) : null)}
    </div>
  );
}
