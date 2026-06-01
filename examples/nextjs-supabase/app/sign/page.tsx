// examples/nextjs-supabase — /sign?document=<id>
//
// Server component: load the document, then render the client SelfSignFlow.
// On a successful sign it re-renders to show the receipt. This is the minimal
// wiring of @vmvtech/esig-react against the /api/esign/sign route.

import { createClient } from "@/lib/supabase/server";
import { SignClient } from "./sign-client";

export default async function SignPage({
  searchParams,
}: {
  searchParams: Promise<{ document?: string }>;
}) {
  const { document } = await searchParams;
  if (!document) return <div className="p-8">Missing ?document=&lt;id&gt;</div>;

  const supabase = await createClient();
  const { data: doc } = await supabase
    .from("documents")
    .select("id, signer_name, signer_email, body_html, status, signed_pdf_url, signature_image_url, signed_at, signatory")
    .eq("id", document)
    .single();

  if (!doc) return <div className="p-8">Document not found</div>;

  return (
    <main className="mx-auto max-w-3xl p-8">
      <SignClient doc={doc} />
    </main>
  );
}
