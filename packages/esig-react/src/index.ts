// @vmvtech/esig-react
//
// Framework-agnostic React UI for the self-contained PDF e-sign flow:
//  - SignaturePadCanvas — draw-to-sign canvas (PNG data URL out)
//  - SelfSignFlow       — preview + canvas + consent + POST to your sign endpoint
//  - SelfSignedReceipt  — post-sign receipt (download + signature + crypto metadata)
//
// No Next.js / Supabase / design-system coupling. Tailwind utility classes are
// used but degrade gracefully; restyle via className / props. Pair the sign
// endpoint with @vmvtech/esig-core's signDocument() + @vmvtech/esig-supabase.

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
