// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
import { SignPdfError } from "@signpdf/utils";
import type { ReadRefTableReturnType } from "./readRefTable.js";

const getIndexFromRef = (refTable: ReadRefTableReturnType, ref: string): number => {
  const [indexString] = ref.split(" ");
  const index = parseInt(indexString);
  if (!refTable.offsets.has(index)) {
    throw new SignPdfError(`Failed to locate object "${ref}".`, SignPdfError.TYPE_PARSE);
  }
  return index;
};

export default getIndexFromRef;
