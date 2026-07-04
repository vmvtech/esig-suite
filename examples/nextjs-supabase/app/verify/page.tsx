// examples/nextjs-supabase — /verify
//
// Public "check a signed document" page: pick a PDF → POST /api/esign/verify
// → render <VerifyPanel/>. Server-component shell around the client uploader,
// mirroring the /sign page wiring. No auth — verification is a public-good
// surface (see the verify route's header comment).

import { VerifyClient } from "./verify-client";

export default function VerifyPage() {
  return (
    <main className="mx-auto max-w-3xl p-8">
      <VerifyClient />
    </main>
  );
}
