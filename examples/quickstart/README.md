# @e-sig/core quickstart

Issue a certificate → sign a PDF → verify it → detect tampering. No database,
no browser, no services — one file, one dependency.

```bash
npm install
npm start
```

Expected output ends with `quickstart passed ✓` and a `signed.pdf` appears next
to `index.mjs` (open it in Adobe Reader to inspect the signature panel).

Inside this repo the example runs against the local workspace build
(`npm run quickstart` from the repo root). Copied out standalone, `npm install`
pulls [`@e-sig/core`](https://www.npmjs.com/package/@e-sig/core) from npm.

Next steps: [`examples/nextjs-supabase`](../nextjs-supabase) for the full
multi-tenant flow (Supabase stores, React signature pad, audit log), or the
[docs](https://docs.e-sig.org) for the API reference.
