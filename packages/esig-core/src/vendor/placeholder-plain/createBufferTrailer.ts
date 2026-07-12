// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
// (rows is deliberately sparse-indexed by object index, then filtered, so
// entries are ordered by object index ascending exactly as upstream.)
import type { ReadPdfReturnType } from "./readPdf.js";

const createBufferTrailer = (
  pdf: Buffer,
  info: ReadPdfReturnType,
  addedReferences: Map<number, number>,
): Buffer => {
  const sparseRows: Array<string | undefined> = [];
  sparseRows[0] = "0000000000 65535 f "; // info.xref.tableRows[0];

  addedReferences.forEach((offset, index) => {
    const paddedOffset = `0000000000${offset}`.slice(-10);
    sparseRows[index + 1] = `${index} 1\n${paddedOffset} 00000 n `;
  });
  const rows = sparseRows.filter((row): row is string => row !== undefined);
  return Buffer.concat([
    Buffer.from("xref\n"),
    Buffer.from(`${info.xref.startingIndex} 1\n`),
    Buffer.from(rows.join("\n")),
    Buffer.from("\ntrailer\n"),
    Buffer.from("<<\n"),
    Buffer.from(`/Size ${info.xref.maxIndex + 1}\n`),
    Buffer.from(`/Root ${info.rootRef}\n`),
    Buffer.from(info.infoRef ? `/Info ${info.infoRef}\n` : ""),
    Buffer.from(`/Prev ${info.xRefPosition}\n`),
    Buffer.from(">>\n"),
    Buffer.from("startxref\n"),
    Buffer.from(`${pdf.length}\n`),
    Buffer.from("%%EOF"),
  ]);
};

export default createBufferTrailer;
