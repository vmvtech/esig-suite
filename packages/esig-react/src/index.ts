// @e-sig/react
//
// Framework-agnostic React UI for the self-contained PDF e-sign flow:
//  - SignaturePadCanvas — draw-to-sign canvas (PNG data URL out)
//  - SelfSignFlow       — preview + canvas + consent + POST to your sign endpoint
//  - SelfSignedReceipt  — post-sign receipt (download + signature + crypto metadata)
//  - VerifyPanel        — verification report for core's verifyPdfSignature() output
//
// No Next.js / Supabase / design-system coupling. Tailwind utility classes are
// used but degrade gracefully; restyle via className / props. Pair the sign
// endpoint with @e-sig/core's signDocument() + @e-sig/supabase.

export {
  SignaturePadCanvas,
  type SignaturePadCanvasHandle,
  type SignaturePadCanvasProps,
} from "./SignaturePadCanvas.js";
export {
  SelfSignFlow,
  type SelfSignFlowProps,
  type SignResult,
} from "./SelfSignFlow.js";
export {
  SelfSignedReceipt,
  type SelfSignedReceiptProps,
} from "./SelfSignedReceipt.js";
export {
  VerifyPanel,
  type VerifyPanelProps,
  type VerifyPanelResult,
} from "./VerifyPanel.js";
