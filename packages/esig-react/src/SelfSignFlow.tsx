"use client";

// @vmvtech/esig-react — SelfSignFlow
//
// Self-contained signing flow: optional document `preview` + SignaturePadCanvas
// + consent checkbox + Sign button. POSTs { document_id, signature_image_data_url }
// to `signEndpoint` and calls `onSigned(result)` on success. No framework
// coupling (no next/navigation) and no design-system dependency — Tailwind
// classes are used but degrade gracefully.

import { useCallback, useRef, useState, type ReactNode } from "react";
import {
  SignaturePadCanvas,
  type SignaturePadCanvasHandle,
} from "./SignaturePadCanvas.js";

export interface SignResult {
  signed_pdf_url?: string;
  download_url?: string;
  audit_log_id?: string;
  [k: string]: unknown;
}

export interface SelfSignFlowProps {
  /** Document being signed; sent as `document_id` in the POST body. */
  documentId: string;
  signer: { name: string; email: string };
  /** Rendered above the signing card (your document/agreement preview). */
  preview?: ReactNode;
  /** Sign endpoint. Default "/api/esign/sign". POSTs { document_id, signature_image_data_url }. */
  signEndpoint?: string;
  /** Extra fields merged into the POST body. */
  extraBody?: Record<string, unknown>;
  consentText?: string;
  title?: string;
  description?: string;
  signLabel?: string;
  pendingLabel?: string;
  /** Called with the parsed success body when signing succeeds. */
  onSigned?: (result: SignResult) => void;
}

export function SelfSignFlow({
  documentId,
  signer,
  preview,
  signEndpoint = "/api/esign/sign",
  extraBody,
  consentText = "I agree to electronically sign this document. I understand my electronic signature has the same legal effect as a handwritten one under ESIGN / UETA.",
  title = "Sign electronically",
  description = "Your signature is captured here, embedded in the PDF, and cryptographically sealed in-platform — no third-party service touches the document.",
  signLabel = "Sign & submit",
  pendingLabel = "Sealing PDF…",
  onSigned,
}: SelfSignFlowProps) {
  const padRef = useRef<SignaturePadCanvasHandle>(null);
  const [pending, setPending] = useState(false);
  const [agreed, setAgreed] = useState(false);
  const [sigEmpty, setSigEmpty] = useState(true);
  const [error, setError] = useState<{ code?: string; reason?: string } | null>(null);

  const handleSignClick = useCallback(async () => {
    setError(null);

    if (!signer.name || !signer.email) {
      setError({ code: "invalid_signatory", reason: "Signatory name + email are required" });
      return;
    }
    const dataUrl = padRef.current?.getImageDataURL();
    if (!dataUrl) {
      setError({ code: "no_signature", reason: "Please sign in the box above before submitting" });
      return;
    }
    if (!agreed) {
      setError({ code: "no_consent", reason: "Please confirm electronic signature consent" });
      return;
    }

    setPending(true);
    try {
      const res = await fetch(signEndpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          document_id: documentId,
          signature_image_data_url: dataUrl,
          ...(extraBody ?? {}),
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || !body.ok) {
        setError({
          code: body.code ?? `http_${res.status}`,
          reason: body.reason ?? body.error ?? `Sign API returned ${res.status}`,
        });
        return;
      }
      onSigned?.(body as SignResult);
    } catch (e) {
      setError({ code: "network_error", reason: e instanceof Error ? e.message : String(e) });
    } finally {
      setPending(false);
    }
  }, [documentId, signer.name, signer.email, agreed, signEndpoint, extraBody, onSigned]);

  return (
    <div className="space-y-6">
      {preview}

      <div className="rounded-lg border border-input bg-background p-6">
        <div className="mb-4">
          <h2 className="text-xl font-semibold text-foreground">{title}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        </div>

        <dl className="mb-4 grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">Signatory</dt>
            <dd className="mt-0.5 font-medium text-foreground">{signer.name}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Email</dt>
            <dd className="mt-0.5 font-medium text-foreground">{signer.email}</dd>
          </div>
        </dl>

        <SignaturePadCanvas ref={padRef} onChange={(isEmpty) => setSigEmpty(isEmpty)} />

        <label className="mt-4 flex cursor-pointer items-start gap-2 rounded-md border border-input bg-muted/30 p-3 text-sm">
          <input
            type="checkbox"
            checked={agreed}
            onChange={(e) => setAgreed(e.target.checked)}
            className="mt-1 h-4 w-4 rounded border-input"
            data-testid="esig-consent-checkbox"
          />
          <span className="text-foreground">{consentText}</span>
        </label>

        {error ? (
          <div className="mt-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
            <div className="font-medium text-foreground">Could not sign document</div>
            <p className="mt-0.5 text-muted-foreground">
              {error.reason ?? error.code ?? "Unknown error"}
            </p>
          </div>
        ) : null}

        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={handleSignClick}
            disabled={pending || sigEmpty || !agreed}
            data-testid="esig-sign-button"
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {pending ? pendingLabel : signLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
