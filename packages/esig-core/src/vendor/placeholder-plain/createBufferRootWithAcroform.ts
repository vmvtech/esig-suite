// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
import getIndexFromRef from "./getIndexFromRef.js";
import type { ReadPdfReturnType } from "./readPdf.js";

const createBufferRootWithAcroform = (
  pdf: Buffer,
  info: ReadPdfReturnType,
  form: { toString(): string },
): Buffer => {
  const rootIndex = getIndexFromRef(info.xref, info.rootRef);
  return Buffer.concat([
    Buffer.from(`${rootIndex} 0 obj\n`),
    Buffer.from("<<\n"),
    Buffer.from(`${info.root}\n`),
    Buffer.from(`/AcroForm ${form}`),
    Buffer.from("\n>>\nendobj\n"),
  ]);
};

export default createBufferRootWithAcroform;
