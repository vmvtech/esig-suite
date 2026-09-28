import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { VerifyPanel, type VerifyPanelResult } from "../src/VerifyPanel.js";

afterEach(cleanup);

const validResult: VerifyPanelResult = {
  ok: true,
  digestValid: true,
  signatureValid: true,
  signerCommonName: "Ada Example",
  signerOrganization: "Example Org",
  timestamped: true,
  timestampTime: "2026-09-28T16:15:00-07:00",
  tsaCommonName: "Example Timestamp Authority",
  failures: [],
};

describe("VerifyPanel", () => {
  it("renders a valid verification result and timestamp details", () => {
    render(<VerifyPanel result={validResult} fileName="signed-example.pdf" />);

    expect(screen.getByText("Signature valid")).toBeTruthy();
    expect(screen.getByText("signed-example.pdf")).toBeTruthy();
    expect(screen.getAllByText("Valid")).toHaveLength(3);
    expect(screen.getByText("Example Timestamp Authority")).toBeTruthy();
  });

  it("renders invalid cryptographic checks and every failure reason", () => {
    render(
      <VerifyPanel
        result={{
          ok: false,
          digestValid: false,
          signatureValid: false,
          timestamped: false,
          failures: ["Document digest mismatch", "RSA signature invalid"],
        }}
      />,
    );

    expect(screen.getByText("Verification failed")).toBeTruthy();
    expect(screen.getAllByText("Invalid")).toHaveLength(2);
    expect(screen.getByText("Document digest mismatch")).toBeTruthy();
    expect(screen.getByText("RSA signature invalid")).toBeTruthy();
  });

  it("renders a structural parse error with unevaluated crypto checks", () => {
    render(
      <VerifyPanel
        result={{
          ok: false,
          timestamped: false,
          failures: ["Invalid PDF ByteRange"],
        }}
        fileName="malformed.pdf"
      />,
    );

    expect(screen.getByText("malformed.pdf")).toBeTruthy();
    expect(screen.getByText("Invalid")).toBeTruthy();
    expect(screen.getAllByText("Not evaluated")).toHaveLength(2);
    expect(screen.getByText("Invalid PDF ByteRange")).toBeTruthy();
  });
});
