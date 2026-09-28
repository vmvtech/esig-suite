import { createServerClient } from "@supabase/ssr";
import { cookies, headers } from "next/headers";

function publicSupabaseConfig() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !anonKey) {
    throw new Error(
      "NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY must be set",
    );
  }

  return { url, anonKey };
}

export async function createClient() {
  const { url, anonKey } = publicSupabaseConfig();
  const cookieStore = await cookies();
  const authorization = (await headers()).get("authorization");

  return createServerClient(url, anonKey, {
    global: authorization
      ? { headers: { Authorization: authorization } }
      : undefined,
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Server Components cannot write cookies. Middleware or a Route
          // Handler should refresh the session before rendering when needed.
        }
      },
    },
  });
}
