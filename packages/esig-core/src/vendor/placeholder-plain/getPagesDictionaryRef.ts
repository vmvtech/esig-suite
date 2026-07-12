// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
import { SignPdfError } from "@signpdf/utils";
import type { ReadPdfReturnType } from "./readPdf.js";

export default function getPagesDictionaryRef(info: ReadPdfReturnType): string {
  const pagesRefRegex = /\/Pages\s+(\d+\s+\d+\s+R)/g;
  const match = pagesRefRegex.exec(info.root);
  if (match === null) {
    throw new SignPdfError(
      "Failed to find the pages descriptor. This is probably a problem in node-signpdf.",
      SignPdfError.TYPE_PARSE,
    );
  }
  return match[1];
}
