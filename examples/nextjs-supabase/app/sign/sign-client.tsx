"use client";

// examples/nextjs-supabase — client wrapper around SelfSignFlow / SelfSignedReceipt.

import { useRouter } from "next/navigation";
import { SelfSignFlow, SelfSignedReceipt } from "@e-sig/react";

type Doc = {
  id: string;
  signer_name: string;
  signer_email: string;
  body_html: string;
  status: string | null;
  signed_pdf_url: string | null;
  signature_image_url: string | null;
  signed_at: string | null;
  signatory: string | null;
};

export function SignClient({ doc }: { doc: Doc }) {
  const router = useRouter();

  if (doc.status === "signed") {
    return (
      <SelfSignedReceipt
        title="Document signed"
        signedPdfUrl={doc.signed_pdf_url}
        signatureImageUrl={doc.signature_image_url}
        signatory={doc.signatory ?? `${doc.signer_name} <${doc.signer_email}>`}
        signedDate={doc.signed_at}
        downloadHref={(p) => `/api/esign/download/${encodeURIComponent(p)}`}
        backHref="/"
        backLabel="Done"
      />
    );
  }

  return (
    <SelfSignFlow
      documentId={doc.id}
      signer={{ name: doc.signer_name, email: doc.signer_email }}
      preview={<div className="prose" dangerouslySetInnerHTML={{ __html: doc.body_html }} />}
      signEndpoint="/api/esign/sign"
      onSigned={() => router.refresh()}
    />
  );
}
