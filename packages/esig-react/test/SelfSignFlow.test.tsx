import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/SignaturePadCanvas.js", async () => {
  const React = await import("react");

  const SignaturePadCanvas = React.forwardRef<
    {
      getImageDataURL: () => string;
      clear: () => void;
      isEmpty: () => boolean;
    },
    { onChange?: (isEmpty: boolean) => void }
  >(function MockSignaturePadCanvas({ onChange }, ref) {
    React.useImperativeHandle(ref, () => ({
      getImageDataURL: () => "data:image/png;base64,c2lnbmF0dXJl",
      clear: () => undefined,
      isEmpty: () => false,
    }));

    return (
      <button type="button" data-testid="mock-draw-signature" onClick={() => onChange?.(false)}>
        Draw signature
      </button>
    );
  });

  return { SignaturePadCanvas };
});

import { SelfSignFlow } from "../src/SelfSignFlow.js";

const signer = { name: "Ada Example", email: "ada@example.com" };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeReady(): void {
  fireEvent.click(screen.getByTestId("mock-draw-signature"));
  fireEvent.click(screen.getByTestId("esig-consent-checkbox"));
}

describe("SelfSignFlow", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("keeps signing disabled until consent and a signature both exist", () => {
    render(<SelfSignFlow documentId="doc-123" signer={signer} />);
    const signButton = screen.getByTestId("esig-sign-button") as HTMLButtonElement;

    expect(signButton.disabled).toBe(true);
    fireEvent.click(screen.getByTestId("esig-consent-checkbox"));
    expect(signButton.disabled).toBe(true);
    fireEvent.click(screen.getByTestId("mock-draw-signature"));
    expect(signButton.disabled).toBe(false);
  });

  it("posts the documented body and passes the parsed result to onSigned", async () => {
    const result = { ok: true, signed_pdf_url: "signed/doc-123.pdf" };
    const onSigned = vi.fn();
    vi.mocked(fetch).mockResolvedValue(jsonResponse(result));
    render(
      <SelfSignFlow
        documentId="doc-123"
        signer={signer}
        signEndpoint="/custom/sign"
        consentText="I consent to sign electronically."
        extraBody={{ workflow_id: "workflow-456" }}
        onSigned={onSigned}
      />,
    );

    makeReady();
    fireEvent.click(screen.getByTestId("esig-sign-button"));

    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
    expect(fetch).toHaveBeenCalledWith("/custom/sign", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        document_id: "doc-123",
        signature_image_data_url: "data:image/png;base64,c2lnbmF0dXJl",
        consent_given: true,
        consent_text_shown: "I consent to sign electronically.",
        workflow_id: "workflow-456",
      }),
    });
    await waitFor(() => expect(onSigned).toHaveBeenCalledWith(result));
  });

  it("renders the API reason when the sign endpoint returns non-2xx", async () => {
    const onSigned = vi.fn();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ code: "signature_rejected", reason: "Signature rejected" }, 422),
    );
    render(<SelfSignFlow documentId="doc-123" signer={signer} onSigned={onSigned} />);

    makeReady();
    fireEvent.click(screen.getByTestId("esig-sign-button"));

    expect(await screen.findByText("Signature rejected")).toBeTruthy();
    expect(onSigned).not.toHaveBeenCalled();
  });

  it("renders a network error and restores the sign button", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("Network unavailable"));
    render(<SelfSignFlow documentId="doc-123" signer={signer} />);

    makeReady();
    fireEvent.click(screen.getByTestId("esig-sign-button"));

    expect(await screen.findByText("Network unavailable")).toBeTruthy();
    expect((screen.getByTestId("esig-sign-button") as HTMLButtonElement).disabled).toBe(false);
  });
});
