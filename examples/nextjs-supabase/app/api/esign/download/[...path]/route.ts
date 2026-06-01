// examples/nextjs-supabase — GET /api/esign/download/<storage-path>
//
// RLS-gated proxy for the private `signed-documents` bucket. Uses the caller's
// SESSION client (not service-role) so Storage RLS enforces tenant access — a
// member can only download their own tenant's signed PDFs/signatures.

import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const { path } = await params;
  const storagePath = path.map(decodeURIComponent).join("/");

  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthenticated" }, { status: 401 });

  // Session client → Storage RLS scopes the read to the caller's tenant.
  const { data, error } = await supabase.storage.from("signed-documents").download(storagePath);
  if (error || !data) return NextResponse.json({ error: "Not found" }, { status: 404 });

  const bytes = new Uint8Array(await data.arrayBuffer());
  const isPng = storagePath.endsWith(".png");
  return new NextResponse(bytes, {
    headers: {
      "content-type": isPng ? "image/png" : "application/pdf",
      "content-disposition": "inline",
      "cache-control": "private, no-store",
    },
  });
}
