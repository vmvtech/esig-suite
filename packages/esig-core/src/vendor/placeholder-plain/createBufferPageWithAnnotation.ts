// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
import findObject from "./findObject.js";
import getIndexFromRef from "./getIndexFromRef.js";
import type { ReadPdfReturnType } from "./readPdf.js";

const createBufferPageWithAnnotation = (
  pdf: Buffer,
  info: ReadPdfReturnType,
  pagesRef: string,
  widget: { toString(): string },
): Buffer => {
  const pagesDictionary = findObject(pdf, info.xref, pagesRef).toString();

  // Extend page dictionary with newly created annotations
  let annotsStart: number;
  let annotsEnd: number;
  let annots: string;
  annotsStart = pagesDictionary.indexOf("/Annots");
  if (annotsStart > -1) {
    annotsEnd = pagesDictionary.indexOf("]", annotsStart);
    annots = pagesDictionary.substr(annotsStart, annotsEnd + 1 - annotsStart);
    annots = annots.substr(0, annots.length - 1); // remove the trailing ]
  } else {
    annotsStart = pagesDictionary.length;
    annotsEnd = pagesDictionary.length;
    annots = "/Annots [";
  }
  const pagesDictionaryIndex = getIndexFromRef(info.xref, pagesRef);
  const widgetValue = widget.toString();
  annots = `${annots} ${widgetValue}]`; // add the trailing ] back

  const preAnnots = pagesDictionary.substr(0, annotsStart);
  let postAnnots = "";
  if (pagesDictionary.length > annotsEnd) {
    postAnnots = pagesDictionary.substr(annotsEnd + 1);
  }
  return Buffer.concat([
    Buffer.from(`${pagesDictionaryIndex} 0 obj\n`),
    Buffer.from("<<\n"),
    Buffer.from(`${preAnnots + annots + postAnnots}\n`),
    Buffer.from("\n>>\nendobj\n"),
  ]);
};

export default createBufferPageWithAnnotation;
