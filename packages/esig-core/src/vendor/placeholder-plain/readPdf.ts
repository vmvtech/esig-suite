// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
import readRefTable, { type ReadRefTableReturnType } from "./readRefTable.js";
import findObject from "./findObject.js";

export const getValue = (trailer: Buffer, key: string): string | undefined => {
  let index = trailer.indexOf(key);
  if (index === -1) {
    return undefined;
  }
  const slice = trailer.slice(index);
  index = slice.indexOf("/", 1);
  if (index === -1) {
    index = slice.indexOf(">", 1);
  }
  return slice
    .slice(key.length + 1, index)
    .toString()
    .trim(); // key + at least one space
};

export interface ReadPdfReturnType {
  xref: ReadRefTableReturnType;
  rootRef: string;
  root: string;
  infoRef: string | undefined;
  trailerStart: number;
  previousXrefs: unknown[];
  xRefPosition: number;
}

/**
 * Simplified parsing of a PDF Buffer.
 * Extracts reference table, root info and trailer start.
 *
 * See section 7.5.5 (File Trailer) of the PDF specs.
 */
const readPdf = (pdfBuffer: Buffer): ReadPdfReturnType => {
  // Extract the trailer dictionary.
  const trailerStart = pdfBuffer.lastIndexOf("trailer");
  // The trailer is followed by xref. Then an EOF. EOF's length is 6 characters.
  const trailer = pdfBuffer.slice(trailerStart, pdfBuffer.length - 6);
  const xRefPosition = parseInt(
    trailer.slice(trailer.lastIndexOf("startxref") + 10).toString(),
  );
  const refTable = readRefTable(pdfBuffer);
  const rootRef = getValue(trailer, "/Root") as string;
  const root = findObject(pdfBuffer, refTable, rootRef).toString();
  const infoRef = getValue(trailer, "/Info");
  return {
    xref: refTable,
    rootRef,
    root,
    infoRef,
    trailerStart,
    previousXrefs: [],
    xRefPosition,
  };
};

export default readPdf;
