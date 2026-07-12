// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
// (Upstream passed 'utf8' as the second argument to indexOf/lastIndexOf; Node
// treats a string byteOffset as the encoding, i.e. identical to the defaults
// used here.)
import getIndexFromRef from "./getIndexFromRef.js";
import type { ReadRefTableReturnType } from "./readRefTable.js";

const findObject = (pdf: Buffer, refTable: ReadRefTableReturnType, ref: string): Buffer => {
  const index = getIndexFromRef(refTable, ref);
  const offset = refTable.offsets.get(index) as number;
  let slice = pdf.slice(offset);
  slice = slice.slice(0, slice.indexOf("endobj"));

  // FIXME: What if it is a stream?
  slice = slice.slice(slice.indexOf("<<") + 2);
  slice = slice.slice(0, slice.lastIndexOf(">>"));
  return slice;
};

export default findObject;
