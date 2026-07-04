"use client";

// examples/nextjs-supabase — client wrapper around VerifyPanel.
//
// File input → POST multipart/form-data to /api/esign/verify → render the
// verification report. The file never persists server-side.

import { useState, type ChangeEvent } from "react";
import { VerifyPanel, type VerifyPanelResult } from "@e-sig/react";

export function VerifyClient() {
  const [result, setResult] = useState<VerifyPanelResult | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setFileName(file.name);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/esign/verify", { method: "POST", body: form });
      const json = await res.json();
      if (!res.ok) {
        setError(
          typeof json?.message === "string"
            ? json.message
            : `verification request failed (HTTP ${res.status})`,
        );
        return;
      }
      setResult(json as VerifyPanelResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : "verification request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Verify a signed document</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Upload a PDF signed by this platform to check its cryptographic
          signature. The file is inspected in memory and discarded — nothing is
          stored.
        </p>
      </div>

      <label className="block cursor-pointer rounded-lg border border-dashed border-input p-6 text-sm text-muted-foreground hover:bg-muted/30">
        <input
          type="file"
          accept="application/pdf,.pdf"
          onChange={onFileChange}
          disabled={busy}
          className="block w-full text-sm"
          data-testid="verify-file-input"
        />
      </label>

      {busy ? <p className="text-sm text-muted-foreground">Verifying…</p> : null}
      {error ? (
        <p className="text-sm text-red-600 dark:text-red-400" data-testid="verify-error">
          {error}
        </p>
      ) : null}
      {result ? <VerifyPanel result={result} fileName={fileName ?? undefined} /> : null}
    </div>
  );
}
