// Vendored from @signpdf/placeholder-plain@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
/* eslint-disable no-underscore-dangle */
import {
  DEFAULT_SIGNATURE_LENGTH,
  SUBFILTER_ADOBE_PKCS7_DETACHED,
  removeTrailingNewLine,
  PDFKitReferenceMock,
} from "@signpdf/utils";
// NOT @signpdf/utils' PDFObject: that one splices any value containing "<<"
// into the dictionary raw and emits names unescaped, which lets caller-supplied
// option strings inject keys into the signature dictionary. See pdfObject.ts.
import { PDFObject } from "./pdfObject.js";
import { pdfkitAddPlaceholder, type PdfKitMock } from "./pdfkitAddPlaceholder.js";
import getIndexFromRef from "./getIndexFromRef.js";
import readPdf from "./readPdf.js";
import getPageRef from "./getPageRef.js";
import createBufferRootWithAcroform from "./createBufferRootWithAcroform.js";
import createBufferPageWithAnnotation from "./createBufferPageWithAnnotation.js";
import createBufferTrailer from "./createBufferTrailer.js";

const getAcroFormRef = (slice: string): string | undefined => {
  const bufferRootWithAcroformRefRegex = /\/AcroForm\s+(\d+\s\d+\sR)/g;
  const match = bufferRootWithAcroformRefRegex.exec(slice);
  if (match != null && match[1] != null && match[1] !== "") {
    return match[1];
  }
  return undefined;
};

export interface PlainAddPlaceholderInput {
  pdfBuffer: Buffer;
  reason: string;
  contactInfo: string;
  name: string;
  location: string;
  signingTime?: Date;
  signatureLength?: number;
  /** One of SUBFILTER_* from @signpdf/utils */
  subFilter?: string;
  /**
   * [x1, y1, x2, y2] widget rectangle.
   *
   * ATTRIBUTION INTEROP: the UUAID provenance verifier's PDF attribution-scope
   * whitelist (IAASO-0004) requires the invisible `[0 0 0 0]` /Rect and denies
   * any other value. `signPdf` never passes this, so today every document we
   * emit is in scope — but a visible-signature feature would drop attribution
   * on day one. Coordinate with the UUAID lane before wiring it up.
   */
  widgetRect?: number[];
  /**
   * Name of the application generating the signature (emitted as
   * `/Prop_Build /App <</Name ...>>`).
   *
   * ATTRIBUTION INTEROP: `App` is not in that verifier's allowed nested
   * Prop_Build key set, so setting this denies attribution. Same rule as
   * `widgetRect` — `signPdf` never passes it; coordinate before it does.
   */
  appName?: string;
}

/**
 * Adds a signature placeholder to a PDF Buffer.
 *
 * This contrasts with the default pdfkit-based implementation.
 * Parsing is done using simple string operations.
 * Adding is done with `Buffer.concat`.
 * This allows node-signpdf to be used on any PDF and
 * not only on a freshly created through PDFKit one.
 */
export const plainAddPlaceholder = ({
  pdfBuffer,
  reason,
  contactInfo,
  name,
  location,
  signingTime = undefined,
  signatureLength = DEFAULT_SIGNATURE_LENGTH,
  subFilter = SUBFILTER_ADOBE_PKCS7_DETACHED,
  widgetRect = [0, 0, 0, 0],
  appName = undefined,
}: PlainAddPlaceholderInput): Buffer => {
  let pdf = removeTrailingNewLine(pdfBuffer);
  const info = readPdf(pdf);
  const pageRef = getPageRef(pdf, info);
  const pageIndex = getIndexFromRef(info.xref, pageRef);
  const addedReferences = new Map<number, number>();
  const pdfKitMock: PdfKitMock = {
    ref: (input, knownIndex) => {
      info.xref.maxIndex += 1;
      const index = knownIndex != null ? knownIndex : info.xref.maxIndex;
      addedReferences.set(index, pdf.length + 1); // + 1 new line

      pdf = Buffer.concat([
        pdf,
        Buffer.from("\n"),
        Buffer.from(`${index} 0 obj\n`),
        Buffer.from(PDFObject.convert(input)),
        Buffer.from("\nendobj\n"),
      ]);
      return new PDFKitReferenceMock(info.xref.maxIndex);
    },
    page: {
      dictionary: new PDFKitReferenceMock(pageIndex, {
        data: {
          Annots: [],
        },
      }) as PDFKitReferenceMock & { data: { Annots: unknown[] } },
    },
    _root: {
      data: {},
    },
  };
  const acroFormRef = getAcroFormRef(info.root);
  if (acroFormRef) {
    pdfKitMock._root.data.AcroForm = acroFormRef;
  }
  const { form, widget } = pdfkitAddPlaceholder({
    pdf: pdfKitMock,
    pdfBuffer,
    reason,
    contactInfo,
    name,
    location,
    signingTime,
    signatureLength,
    subFilter,
    widgetRect,
    appName,
  });
  if (!getAcroFormRef(pdf.toString())) {
    const rootIndex = getIndexFromRef(info.xref, info.rootRef);
    addedReferences.set(rootIndex, pdf.length + 1);
    pdf = Buffer.concat([pdf, Buffer.from("\n"), createBufferRootWithAcroform(pdf, info, form)]);
  }
  addedReferences.set(pageIndex, pdf.length + 1);
  pdf = Buffer.concat([
    pdf,
    Buffer.from("\n"),
    createBufferPageWithAnnotation(pdf, info, pageRef, widget),
  ]);
  pdf = Buffer.concat([pdf, Buffer.from("\n"), createBufferTrailer(pdf, info, addedReferences)]);
  return pdf;
};
