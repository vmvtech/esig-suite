import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SelfSignedReceipt } from "../src/SelfSignedReceipt.js";

afterEach(cleanup);

describe("SelfSignedReceipt", () => {
  it("renders the signatory, signed timestamp, and mapped download link", () => {
    const signedDate = "2026-09-28T16:15:00-07:00";
    const formattedDate = new Date(signedDate).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
    const downloadHref = vi.fn((path: string) => `/download/${encodeURIComponent(path)}`);
    render(
      <SelfSignedReceipt
        signedPdfUrl="signed/doc 123.pdf"
        signatureImageUrl={null}
        signatory="Ada Example"
        signedDate={signedDate}
        downloadHref={downloadHref}
      />,
    );

    expect(screen.getByText("Ada Example")).toBeTruthy();
    expect(screen.getByText(formattedDate)).toBeTruthy();
    expect((screen.getByTestId("self-signed-download-link") as HTMLAnchorElement).getAttribute("href"))
      .toBe("/download/signed%2Fdoc%20123.pdf");
  });

  it("renders the signature image and cryptographic metadata from props", () => {
    render(
      <SelfSignedReceipt
        signedPdfUrl={null}
        signatureImageUrl="signatures/ada.png"
        signatory="Ada Example"
        signedDate={null}
        certFingerprint="AA:BB:CC"
        signerIp="192.0.2.10"
        downloadHref={(path) => `/private/${path}`}
      />,
    );

    expect((screen.getByTestId("self-signed-signature-image") as HTMLImageElement).src)
      .toContain("/private/signatures/ada.png");
    expect(screen.getByText("AA:BB:CC")).toBeTruthy();
    expect(screen.getByText("192.0.2.10")).toBeTruthy();
  });

  it("renders pending and a custom footer when no signed PDF is available", () => {
    render(
      <SelfSignedReceipt
        signedPdfUrl={null}
        signatureImageUrl={null}
        signatory={null}
        signedDate={null}
        footer={<button type="button">Continue</button>}
      />,
    );

    expect(screen.getByText("Pending")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Continue" })).toBeTruthy();
    expect(screen.queryByTestId("self-signed-download-link")).toBeNull();
  });
});
