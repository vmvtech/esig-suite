import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createRef } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SignaturePadCanvas,
  type SignaturePadCanvasHandle,
} from "../src/SignaturePadCanvas.js";

const PNG_DATA_URL = "data:image/png;base64,c2lnbmF0dXJl";

function pointerEvent(type: string, buttons: number, x: number): MouseEvent {
  const event = new MouseEvent(type, {
    bubbles: true,
    buttons,
    cancelable: true,
    clientX: x,
    clientY: 24,
  });
  Object.defineProperties(event, {
    pointerId: { value: 1 },
    pressure: { value: 0.5 },
  });
  return event;
}

function drawStroke(canvas: HTMLCanvasElement): void {
  fireEvent(canvas, pointerEvent("pointerdown", 1, 12));
  fireEvent(window, pointerEvent("pointermove", 1, 32));
  fireEvent(window, pointerEvent("pointerup", 0, 48));
}

describe("SignaturePadCanvas", () => {
  beforeEach(() => {
    vi.stubGlobal("PointerEvent", MouseEvent);
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({
      arc: vi.fn(),
      beginPath: vi.fn(),
      bezierCurveTo: vi.fn(),
      clearRect: vi.fn(),
      closePath: vi.fn(),
      fill: vi.fn(),
      fillRect: vi.fn(),
      fillStyle: "",
      globalCompositeOperation: "source-over",
      moveTo: vi.fn(),
      scale: vi.fn(),
    } as unknown as CanvasRenderingContext2D);
    vi.spyOn(HTMLCanvasElement.prototype, "toDataURL").mockReturnValue(PNG_DATA_URL);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("renders an empty signature canvas", () => {
    render(<SignaturePadCanvas />);

    expect(screen.getByTestId("signature-pad-canvas").tagName).toBe("CANVAS");
    expect((screen.getByTestId("signature-pad-clear") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Sign above with mouse, finger, or stylus")).toBeTruthy();
  });

  it("reports a completed pointer stroke through onChange", async () => {
    const onChange = vi.fn();
    render(<SignaturePadCanvas onChange={onChange} />);

    drawStroke(screen.getByTestId("signature-pad-canvas") as HTMLCanvasElement);

    await waitFor(() => expect(onChange).toHaveBeenCalledWith(false));
    expect(screen.getByText("Looks good — ready to sign")).toBeTruthy();
    expect((screen.getByTestId("signature-pad-clear") as HTMLButtonElement).disabled).toBe(false);
  });

  it("exports a PNG data URL after a pointer stroke", async () => {
    const ref = createRef<SignaturePadCanvasHandle>();
    render(<SignaturePadCanvas ref={ref} />);

    drawStroke(screen.getByTestId("signature-pad-canvas") as HTMLCanvasElement);
    await waitFor(() => expect(ref.current?.isEmpty()).toBe(false));

    expect(ref.current?.getImageDataURL()).toBe(PNG_DATA_URL);
    expect(HTMLCanvasElement.prototype.toDataURL).toHaveBeenCalledWith("image/png", undefined);
  });

  it("clears a completed signature and reports the reset", async () => {
    const onChange = vi.fn();
    const ref = createRef<SignaturePadCanvasHandle>();
    render(<SignaturePadCanvas ref={ref} onChange={onChange} />);

    drawStroke(screen.getByTestId("signature-pad-canvas") as HTMLCanvasElement);
    await waitFor(() => expect(ref.current?.isEmpty()).toBe(false));
    fireEvent.click(screen.getByTestId("signature-pad-clear"));

    expect(ref.current?.isEmpty()).toBe(true);
    expect(ref.current?.getImageDataURL()).toBeNull();
    expect(onChange).toHaveBeenLastCalledWith(true);
  });
});
