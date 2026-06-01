# @vmvtech/esig-react

Framework-agnostic React UI for the self-contained PDF e-sign flow. No Next.js /
Supabase / design-system coupling — pass a `signEndpoint` + callbacks.

```bash
npm i @vmvtech/esig-react react react-dom
```

```tsx
import { SelfSignFlow, SelfSignedReceipt, SignaturePadCanvas } from "@vmvtech/esig-react";

<SelfSignFlow
  documentId={doc.id}
  signer={{ name, email }}
  preview={<YourDocumentPreview html={doc.body} />}
  signEndpoint="/api/esign/sign"   // POSTs { document_id, signature_image_data_url }
  onSigned={(result) => router.refresh()}
/>;

// once signed:
<SelfSignedReceipt
  signedPdfUrl={doc.signed_pdf_url}
  signatureImageUrl={doc.signature_image_url}
  signatory={doc.signatory}
  signedDate={doc.signed_at}
  downloadHref={(p) => `/api/esign/download/${encodeURIComponent(p)}`}
  backHref="/"
/>;
```

## Components

- **`SignaturePadCanvas`** — wraps `signature_pad`; imperative handle
  (`getImageDataURL` → PNG data URL, `clear`, `isEmpty`). Fully prop-styled.
- **`SelfSignFlow`** — optional `preview` + canvas + consent checkbox + Sign
  button; POSTs to `signEndpoint`, calls `onSigned(result)`. Labels/consent text
  are props.
- **`SelfSignedReceipt`** — download link + signature image + cert-fingerprint /
  IP metadata; `downloadHref` maps a storage path → a fetchable URL.

Uses Tailwind utility classes (incl. shadcn-style theme tokens like
`bg-primary`, `text-muted-foreground`); they degrade gracefully without Tailwind
and are overridable via `className`. Peer deps: `react`, `react-dom`. Dep:
`signature_pad`. License: MIT.
