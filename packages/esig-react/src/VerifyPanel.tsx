// @e-sig/react — VerifyPanel
//
// Read-only verification report for a signed PDF: overall verdict, the
// structural + cryptographic check rows, signer identity, RFC-3161 timestamp
// details, and failure reasons. Feed it the JSON produced by @e-sig/core's
// verifyPdfSignature() (typically proxied through a verify API route).
// Purely presentational — no state, no fetching, no interactivity — so it
// needs no "use client" and renders fine from server components.
// `VerifyPanelResult` is a local structural mirror of core's `VerifyResult`,
// keeping @e-sig/react at zero dependency on @e-sig/core.

/**
 * Structural mirror of @e-sig/core's `VerifyResult`. Core's return value is
 * assignable to this type without importing core.
 */
export interface VerifyPanelResult {
  ok: boolean;
  byteRange?: [number, number, number, number];
  pkcs7ActualSize?: number;
  pkcs7BudgetSize?: number;
  signerCommonName?: string;
  signerOrganization?: string;
  /** SHA-256 over the ByteRange-covered bytes matches the signed messageDigest. */
  digestValid?: boolean;
  /** RSA signature over the signed attributes verifies against the embedded cert. */
  signatureValid?: boolean;
  /** True if an RFC 3161 TimeStampToken (CAdES-T) is embedded. */
  timestamped: boolean;
  /** ISO genTime of the timestamp, if parseable. */
  timestampTime?: string;
  /** Common name of the TSA signer cert, if parseable. */
  tsaCommonName?: string;
  failures: string[];
}

export interface VerifyPanelProps {
  /** The verification verdict (core `VerifyResult` shape). */
  result: VerifyPanelResult;
  /** Name of the verified file, shown under the verdict. */
  fileName?: string;
}

/** Fixed scope caveat — rendered verbatim so the panel never overstates what was checked. */
const CAVEAT =
  "Validates the signature against the certificate embedded in the document (first signature only). Trust in that certificate is your deployment's concern — no chain or revocation checks.";

function CheckRow({ label, state }: { label: string; state: boolean | undefined }) {
  const text = state === true ? "Valid" : state === false ? "Invalid" : "Not evaluated";
  const tone =
    state === true
      ? "text-emerald-600 dark:text-emerald-400"
      : state === false
        ? "text-red-600 dark:text-red-400"
        : "text-muted-foreground";
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-input px-3 py-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={`font-medium ${tone}`}>{text}</span>
    </div>
  );
}

export function VerifyPanel({ result, fileName }: VerifyPanelProps) {
  // The crypto checks only run after ByteRange / DER / PKCS#7 parsing succeeds,
  // so "structure valid" is: overall ok, or either crypto check was evaluated.
  const structureOk: boolean =
    result.ok || result.digestValid !== undefined || result.signatureValid !== undefined;

  const ts = result.timestampTime ? new Date(result.timestampTime) : null;
  const formattedTimestamp =
    ts && !Number.isNaN(ts.getTime())
      ? ts.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
      : (result.timestampTime ?? null);

  return (
    <div
      data-testid="verify-panel"
      className="rounded-lg border border-input bg-background p-6"
    >
      <div className="mb-4 flex items-start gap-3">
        <div
          className={
            result.ok
              ? "rounded-md bg-emerald-500/10 p-2 text-emerald-600 dark:text-emerald-400"
              : "rounded-md bg-red-500/10 p-2 text-red-600 dark:text-red-400"
          }
        >
          {result.ok ? (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <path d="m9 11 3 3L22 4" />
            </svg>
          ) : (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="10" />
              <path d="m15 9-6 6" />
              <path d="m9 9 6 6" />
            </svg>
          )}
        </div>
        <div>
          <h2 className="text-xl font-semibold text-foreground">
            {result.ok ? "Signature valid" : "Verification failed"}
          </h2>
          {fileName ? (
            <p className="mt-1 break-words text-sm text-muted-foreground">{fileName}</p>
          ) : null}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-3">
        <CheckRow label="Structure" state={structureOk} />
        <CheckRow label="Document digest" state={result.digestValid} />
        <CheckRow label="Signature" state={result.signatureValid} />
      </div>

      <dl className="mt-4 grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-muted-foreground">Signer (CN)</dt>
          <dd className="mt-0.5 break-words font-medium text-foreground">
            {result.signerCommonName ?? "—"}
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Organization</dt>
          <dd className="mt-0.5 break-words font-medium text-foreground">
            {result.signerOrganization ?? "—"}
          </dd>
        </div>
        {result.timestamped ? (
          <>
            <div>
              <dt className="text-muted-foreground">Timestamped (RFC 3161)</dt>
              <dd className="mt-0.5 font-medium text-foreground">
                {formattedTimestamp ?? "Yes"}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Timestamp authority</dt>
              <dd className="mt-0.5 break-words font-medium text-foreground">
                {result.tsaCommonName ?? "—"}
              </dd>
            </div>
          </>
        ) : null}
      </dl>

      {!result.ok && result.failures.length > 0 ? (
        <div className="mt-4 rounded-md border border-red-500/30 bg-red-500/5 p-3 text-sm">
          <p className="mb-1 font-medium text-red-600 dark:text-red-400">Failures</p>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground" data-testid="verify-failures">
            {result.failures.map((failure, i) => (
              <li key={i}>{failure}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <p className="mt-5 border-t border-input pt-3 text-xs text-muted-foreground">{CAVEAT}</p>
    </div>
  );
}
