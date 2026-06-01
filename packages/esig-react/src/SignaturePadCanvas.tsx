"use client";

// @vmvtech/esig-react — SignaturePadCanvas
//
// Wraps szimek/signature_pad in a React component with an imperative handle
// (getImageDataURL + clear + isEmpty). Mouse + touch + pen input. Retina-aware.
// No design-system dependency — Tailwind utility classes are used but degrade
// gracefully; pass `className` to restyle. Output: a PNG data URL.

import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import SignaturePad from "signature_pad";

/** Minimal classname joiner (no clsx dependency). */
function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export interface SignaturePadCanvasHandle {
  /** Returns the signature as a data URL (image/png) or null if empty. */
  getImageDataURL: () => string | null;
  /** Clears the canvas. */
  clear: () => void;
  /** True when the user has drawn anything. */
  isEmpty: () => boolean;
}

export interface SignaturePadCanvasProps {
  width?: number;
  height?: number;
  penColor?: string;
  backgroundColor?: string;
  className?: string;
  /** Hint text shown before/after drawing. */
  hintEmpty?: string;
  hintFilled?: string;
  clearLabel?: string;
  onChange?: (isEmpty: boolean) => void;
}

export const SignaturePadCanvas = forwardRef<
  SignaturePadCanvasHandle,
  SignaturePadCanvasProps
>(function SignaturePadCanvas(
  {
    width = 640,
    height = 180,
    penColor = "#0a0a0a",
    backgroundColor = "rgba(255, 255, 255, 0)",
    className,
    hintEmpty = "Sign above with mouse, finger, or stylus",
    hintFilled = "Looks good — ready to sign",
    clearLabel = "Clear",
    onChange,
  },
  ref,
) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const padRef = useRef<SignaturePad | null>(null);
  const [empty, setEmpty] = useState(true);

  // Keep the latest onChange in a ref so the canvas-init effect below does NOT
  // depend on it. Parents commonly pass an inline `onChange={(e) => ...}` that is
  // a new function every render; if that were an effect dependency, the first
  // endStroke → setState → parent re-render → new onChange → effect re-run →
  // `canvas.width = …` (which CLEARS the canvas) would wipe the first signature.
  // (That's the "first stroke disappears, second one sticks" bug.)
  const onChangeRef = useRef(onChange);
  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);

  // Mount-once init. signature_pad needs the canvas internal resolution to match
  // its CSS size × devicePixelRatio for crisp rendering on retina/mobile. Setting
  // canvas.width/height clears the bitmap, so this must run exactly once per
  // canvas (penColor/backgroundColor are config props and effectively stable).
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ratio = Math.max(window.devicePixelRatio || 1, 1);
    canvas.width = canvas.offsetWidth * ratio;
    canvas.height = canvas.offsetHeight * ratio;
    const ctx = canvas.getContext("2d");
    if (ctx) ctx.scale(ratio, ratio);

    const pad = new SignaturePad(canvas, {
      penColor,
      backgroundColor,
      minWidth: 0.8,
      maxWidth: 2.2,
      throttle: 16,
    });
    padRef.current = pad;

    const handleStrokeEnd = () => {
      const isEmpty = pad.isEmpty();
      setEmpty(isEmpty);
      onChangeRef.current?.(isEmpty);
    };
    pad.addEventListener("endStroke", handleStrokeEnd);

    return () => {
      pad.removeEventListener("endStroke", handleStrokeEnd);
      pad.off();
      padRef.current = null;
    };
    // onChange intentionally excluded — see onChangeRef above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [penColor, backgroundColor]);

  const clear = useCallback(() => {
    padRef.current?.clear();
    setEmpty(true);
    onChange?.(true);
  }, [onChange]);

  useImperativeHandle(
    ref,
    () => ({
      getImageDataURL: () => {
        if (!padRef.current || padRef.current.isEmpty()) return null;
        return padRef.current.toDataURL("image/png");
      },
      clear,
      isEmpty: () => padRef.current?.isEmpty() ?? true,
    }),
    [clear],
  );

  return (
    <div className={cn("space-y-2", className)}>
      <div className="rounded-md border border-input bg-background">
        <canvas
          ref={canvasRef}
          data-testid="signature-pad-canvas"
          style={{ width: `${width}px`, height: `${height}px`, maxWidth: "100%" }}
          className="block touch-none"
          aria-label="Signature canvas — sign here with mouse, finger, or stylus"
        />
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{empty ? hintEmpty : hintFilled}</span>
        <button
          type="button"
          onClick={clear}
          disabled={empty}
          data-testid="signature-pad-clear"
          className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs hover:bg-muted disabled:opacity-50"
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M20 20H7L3 16a1 1 0 0 1 0-1.41l9.6-9.6a2 2 0 0 1 2.8 0l4.6 4.6a2 2 0 0 1 0 2.82L11 20" />
            <path d="m5.5 13.5 5 5" />
          </svg>
          {clearLabel}
        </button>
      </div>
    </div>
  );
});
