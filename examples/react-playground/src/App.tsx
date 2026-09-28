import { useState } from "react";
import {
  SelfSignFlow,
  SignaturePadCanvas,
  type SignResult,
} from "@e-sig/react";

const signer = {
  name: "Alex Morgan",
  email: "alex.morgan@example.com",
};

export function App() {
  const [signed, setSigned] = useState<SignResult | null>(null);

  return (
    <main>
      <header className="hero">
        <p className="eyebrow">@e-sig/react playground</p>
        <h1>Draw, consent, and sign in one self-contained flow.</h1>
        <p className="lede">
          This local harness exercises the public React components against a fixed Vite mock
          endpoint. No document data leaves the development server.
        </p>
      </header>

      <section className="demo-grid" aria-label="React component playground">
        <article className="demo-card standalone-pad">
          <p className="eyebrow">SignaturePadCanvas</p>
          <h2>Standalone signature input</h2>
          <p>Use a mouse, finger, or stylus. Clear the canvas and try another mark.</p>
          <SignaturePadCanvas width={640} height={180} />
        </article>

        <article className="demo-card flow-demo">
          <p className="eyebrow">SelfSignFlow</p>
          <SelfSignFlow
            documentId="demo-agreement-0001"
            signer={signer}
            signEndpoint="/api/esign/sign"
            title="Sign the demonstration agreement"
            description="Your drawing and consent are posted to the playground's local mock endpoint."
            preview={
              <section className="document-preview" aria-label="Agreement preview">
                <span>Demonstration agreement</span>
                <strong>Mutual acknowledgment</strong>
                <p>
                  Alex Morgan acknowledges this local example is for testing the signing user
                  interface only. It does not create a binding agreement.
                </p>
              </section>
            }
            onSigned={setSigned}
          />

          {signed ? (
            <output className="success" data-testid="playground-sign-result">
              <strong>Mock signature accepted</strong>
              <span>Audit record: {String(signed.audit_log_id)}</span>
            </output>
          ) : null}
        </article>
      </section>
    </main>
  );
}
