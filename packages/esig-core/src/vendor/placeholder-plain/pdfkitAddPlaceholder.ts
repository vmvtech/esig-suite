// Vendored from @signpdf/placeholder-pdfkit010@3.3.0 (MIT). See LICENSE-signpdf.md.
// Faithful TypeScript port — logic and byte-emitting paths are unchanged.
// This is the only module @signpdf/placeholder-plain used from
// @signpdf/placeholder-pdfkit010; vendoring it severs the
// pdfkit@0.10.0 (peer) -> crypto-js@3.3.0 dependency chain.
import {
  DEFAULT_BYTE_RANGE_PLACEHOLDER,
  DEFAULT_SIGNATURE_LENGTH,
  SUBFILTER_ADOBE_PKCS7_DETACHED,
  ANNOTATION_FLAGS,
  SIG_FLAGS,
  PDFKitReferenceMock,
} from "@signpdf/utils";

/**
 * The minimal PDFDocument-shaped surface that plainAddPlaceholder feeds in.
 * (Upstream typed this as `object PDFDocument`.)
 */
export interface PdfKitMock {
  ref(input: Record<string, unknown>, knownIndex?: number): PDFKitReferenceMock;
  page: {
    dictionary: PDFKitReferenceMock & { data: { Annots: unknown[] } };
  };
  _root: {
    data: { AcroForm?: unknown };
  };
}

export interface PdfkitAddPlaceholderInput {
  pdf: PdfKitMock;
  pdfBuffer: Buffer;
  reason: string;
  contactInfo: string;
  name: string;
  location: string;
  signingTime?: Date;
  signatureLength?: number;
  byteRangePlaceholder?: string;
  /** One of SUBFILTER_* from @signpdf/utils */
  subFilter?: string;
  /** [x1, y1, x2, y2] widget rectangle */
  widgetRect?: number[];
  /** Name of the application generating the signature */
  appName?: string;
}

export interface PdfkitAddPlaceholderReturnType {
  signature: PDFKitReferenceMock;
  form: PDFKitReferenceMock;
  widget: PDFKitReferenceMock;
}

/**
 * Adds the objects that are needed for Adobe.PPKLite to read the signature.
 * Also includes a placeholder for the actual signature.
 * Returns an Object with all the added PDFReferences.
 */
export const pdfkitAddPlaceholder = ({
  pdf,
  pdfBuffer,
  reason,
  contactInfo,
  name,
  location,
  signingTime = undefined,
  signatureLength = DEFAULT_SIGNATURE_LENGTH,
  byteRangePlaceholder = DEFAULT_BYTE_RANGE_PLACEHOLDER,
  subFilter = SUBFILTER_ADOBE_PKCS7_DETACHED,
  widgetRect = [0, 0, 0, 0],
  appName = undefined,
}: PdfkitAddPlaceholderInput): PdfkitAddPlaceholderReturnType => {
  /* eslint-disable no-underscore-dangle,no-param-reassign */
  // Generate the signature placeholder
  const signature = pdf.ref({
    Type: "Sig",
    Filter: "Adobe.PPKLite",
    SubFilter: subFilter,
    ByteRange: [0, byteRangePlaceholder, byteRangePlaceholder, byteRangePlaceholder],
    Contents: Buffer.from(String.fromCharCode(0).repeat(signatureLength)),
    Reason: new String(reason), // eslint-disable-line no-new-wrappers
    M: signingTime ?? new Date(),
    ContactInfo: new String(contactInfo), // eslint-disable-line no-new-wrappers
    Name: new String(name), // eslint-disable-line no-new-wrappers
    Location: new String(location), // eslint-disable-line no-new-wrappers
    Prop_Build: {
      Filter: {
        Name: "Adobe.PPKLite",
      },
      ...(appName
        ? {
            App: {
              Name: appName,
            },
          }
        : {}),
    },
  });

  // Check if pdf already contains acroform field
  const isAcroFormExists = typeof pdf._root.data.AcroForm !== "undefined";
  let fieldIds: PDFKitReferenceMock[] = [];
  let acroFormId: number | undefined;
  if (isAcroFormExists) {
    /* FIXME: We're working with a PDFDocument.
     * Needing to work with strings here doesn't make sense.
     * It only exists to support plainAddPlaceholder the reference to /AcroForm
     * would be external to PDFKit at this point.
     */

    const acroFormPosition = pdfBuffer.lastIndexOf("/Type /AcroForm");
    let acroFormStart = acroFormPosition;
    // 10 is the distance between "/Type /AcroForm" and AcroFrom ID
    const charsUntilIdEnd = 10;
    const acroFormIdEnd = acroFormPosition - charsUntilIdEnd;
    // Let's find AcroForm ID by trying to find the "\n" before the ID
    // 12 is a enough space to find the "\n"
    // (generally it's 2 or 3, but I'm giving a big space though)
    const maxAcroFormIdLength = 12;
    let index = charsUntilIdEnd + 1;
    for (index; index < charsUntilIdEnd + maxAcroFormIdLength; index += 1) {
      const acroFormIdString = pdfBuffer.slice(acroFormPosition - index, acroFormIdEnd).toString();
      if (acroFormIdString[0] === "\n") {
        break;
      }
      acroFormStart = acroFormPosition - index;
    }
    const pdfSlice = pdfBuffer.slice(acroFormStart);
    const acroForm = pdfSlice.slice(0, pdfSlice.indexOf("endobj")).toString();
    acroFormId = parseInt((pdf._root.data.AcroForm as { toString(): string }).toString());
    const acroFormFields = acroForm.slice(acroForm.indexOf("/Fields [") + 9, acroForm.indexOf("]"));
    fieldIds = acroFormFields
      .split(" ")
      .filter(Boolean)
      .filter((element, i) => i % 3 === 0)
      .map((fieldId) => new PDFKitReferenceMock(fieldId));
  }
  const signatureName = "Signature";

  // Generate signature annotation widget
  const widget = pdf.ref({
    Type: "Annot",
    Subtype: "Widget",
    FT: "Sig",
    Rect: widgetRect,
    V: signature,
    T: new String(signatureName + (fieldIds.length + 1)), // eslint-disable-line no-new-wrappers
    F: ANNOTATION_FLAGS.PRINT,
    P: pdf.page.dictionary, // eslint-disable-line no-underscore-dangle
  });

  pdf.page.dictionary.data.Annots = [widget];
  // Include the widget in a page
  let form: PDFKitReferenceMock;
  if (!isAcroFormExists) {
    // Create a form (with the widget) and link in the _root
    form = pdf.ref({
      Type: "AcroForm",
      SigFlags: SIG_FLAGS.SIGNATURES_EXIST | SIG_FLAGS.APPEND_ONLY,
      Fields: [...fieldIds, widget],
    });
  } else {
    // Use existing acroform and extend the fields with newly created widgets
    form = pdf.ref(
      {
        Type: "AcroForm",
        SigFlags: SIG_FLAGS.SIGNATURES_EXIST | SIG_FLAGS.APPEND_ONLY,
        Fields: [...fieldIds, widget],
      },
      acroFormId,
    );
  }
  pdf._root.data.AcroForm = form;
  return {
    signature,
    form,
    widget,
  };
  /* eslint-enable no-underscore-dangle,no-param-reassign */
};
