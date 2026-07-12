// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
// (Upstream carried `prev` as the matched digit string and let Buffer.slice
// coerce it; parseInt of an all-digit string yields the identical position.)
import { SignPdfError } from "@signpdf/utils";
import xrefToRefMap from "./xrefToRefMap.js";

export type FullXrefTable = Map<number, number>;

export interface ReadRefTableReturnType {
  startingIndex: number;
  maxIndex: number;
  offsets: FullXrefTable;
}

interface GetXrefReturnType {
  size: number;
  prev: number | undefined;
  xRefContent: Map<number, number>;
}

export const getLastTrailerPosition = (pdf: Buffer): number => {
  const trailerStart = pdf.lastIndexOf(Buffer.from("trailer", "utf8"));
  const trailer = pdf.slice(trailerStart, pdf.length - 6);
  const xRefPosition = trailer
    .slice(trailer.lastIndexOf(Buffer.from("startxref", "utf8")) + 10)
    .toString();
  return parseInt(xRefPosition);
};

export const getXref = (pdf: Buffer, position: number): GetXrefReturnType => {
  let refTable = pdf.slice(position); // slice starting from where xref starts
  const realPosition = refTable.indexOf(Buffer.from("xref", "utf8"));
  if (realPosition === -1) {
    throw new SignPdfError(
      `Could not find xref anywhere at or after ${position}.`,
      SignPdfError.TYPE_PARSE,
    );
  }
  if (realPosition > 0) {
    const prefix = refTable.slice(0, realPosition);
    if (prefix.toString().replace(/\s*/g, "") !== "") {
      throw new SignPdfError(
        `Expected xref at ${position} but found other content.`,
        SignPdfError.TYPE_PARSE,
      );
    }
  }
  const nextEofPosition = refTable.indexOf(Buffer.from("%%EOF", "utf8"));
  if (nextEofPosition === -1) {
    throw new SignPdfError(
      "Expected EOF after xref and trailer but could not find one.",
      SignPdfError.TYPE_PARSE,
    );
  }
  refTable = refTable.slice(0, nextEofPosition);
  refTable = refTable.slice(realPosition + 4); // move ahead with the "xref"
  refTable = refTable.slice(refTable.indexOf("\n") + 1); // move after the next new line

  // extract the size
  const sizeString = refTable.toString().split("/Size")[1];
  if (!sizeString) {
    throw new SignPdfError("Size not found in xref table.", SignPdfError.TYPE_PARSE);
  }
  const sizeMatch = /^\s*(\d+)/.exec(sizeString);
  if (sizeMatch === null) {
    throw new SignPdfError("Failed to parse size of xref table.", SignPdfError.TYPE_PARSE);
  }
  const size = parseInt(sizeMatch[1]);
  const [objects, infos] = refTable.toString().split("trailer");
  const isContainingPrev = infos.split("/Prev")[1] != null;
  let prev: number | undefined;
  if (isContainingPrev) {
    const pagesRefRegex = /Prev (\d+)/g;
    const match = pagesRefRegex.exec(infos) as RegExpExecArray;
    const [, prevPosition] = match;
    prev = parseInt(prevPosition);
  }
  const xRefContent = xrefToRefMap(objects);
  return {
    size,
    prev,
    xRefContent,
  };
};

const getFullXref = (pdf: Buffer, xRefPosition: number): FullXrefTable => {
  const lastXrefTable = getXref(pdf, xRefPosition);
  if (lastXrefTable.prev === undefined) {
    return lastXrefTable.xRefContent;
  }
  const partOfXrefTable = getFullXref(pdf, lastXrefTable.prev);
  const mergedXrefTable = new Map([...partOfXrefTable, ...lastXrefTable.xRefContent]);
  return mergedXrefTable;
};

export const getFullXrefTable = (pdf: Buffer): FullXrefTable => {
  const lastTrailerPosition = getLastTrailerPosition(pdf);
  return getFullXref(pdf, lastTrailerPosition);
};

const readRefTable = (pdf: Buffer): ReadRefTableReturnType => {
  const fullXrefTable = getFullXrefTable(pdf);
  const startingIndex = 0;
  const maxIndex = Math.max(...fullXrefTable.keys());
  return {
    startingIndex,
    maxIndex,
    offsets: fullXrefTable,
  };
};

export default readRefTable;
