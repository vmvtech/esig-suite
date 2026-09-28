import Link from "next/link";

export default function HomePage() {
  return (
    <main>
      <h1>E-Sig Supabase Example</h1>
      <p>Sign a document or verify an existing signed PDF.</p>
      <nav aria-label="E-signature examples">
        <ul>
          <li>
            <Link href="/sign">Sign a document</Link>
          </li>
          <li>
            <Link href="/verify">Verify a signed document</Link>
          </li>
        </ul>
      </nav>
    </main>
  );
}
