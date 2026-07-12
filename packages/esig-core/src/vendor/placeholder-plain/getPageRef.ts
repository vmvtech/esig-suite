// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
import getPagesDictionaryRef from "./getPagesDictionaryRef.js";
import findObject from "./findObject.js";
import type { ReadPdfReturnType } from "./readPdf.js";

/**
 * Finds the reference to a page.
 */
export default function getPageRef(pdfBuffer: Buffer, info: ReadPdfReturnType): string {
  const pagesRef = getPagesDictionaryRef(info);
  const pagesDictionary = findObject(pdfBuffer, info.xref, pagesRef);
  const kidsPosition = pagesDictionary.indexOf("/Kids");
  const kidsStart = pagesDictionary.indexOf("[", kidsPosition) + 1;
  const kidsEnd = pagesDictionary.indexOf("]", kidsPosition);
  const pages = pagesDictionary.slice(kidsStart, kidsEnd).toString();
  const split = pages.trim().split(" ", 3);
  return `${split[0]} ${split[1]} ${split[2]}`;
}
