// Hardened replacement for `PDFObject.convert` from @signpdf/utils@3.x
// (itself derived from pdfkit's PDFObject by Devon Govett, MIT — see
// LICENSE-signpdf.md). This is the ONE file in this directory that
// DELIBERATELY DIVERGES from upstream. Two changes, both security fixes:
//
//  1. Upstream's dictionary branch does:
//         if (val.toString().indexOf('<<') !== -1) checkedValue = val;
//     i.e. any value whose string form contains "<<" is spliced into the
//     dictionary RAW — no conversion, no escaping, not even PDF-string
//     parens. A caller-supplied `reason` / `name` / `location` /
//     `contactInfo` containing "<<" therefore injects arbitrary keys into
//     the signature dictionary. That branch exists upstream only so pdfkit
//     can pass pre-rendered dictionary strings; nothing this package emits
//     relies on it (Prop_Build is a real object and recurses correctly), so
//     it is removed outright.
//
//  2. Upstream renders a JS string as a PDF name with `/${object}` and no
//     escaping, so a name value can carry delimiters and whitespace and end
//     the token early — the /SubFilter injection vector. Names are now
//     escaped per ISO 32000-1 §7.3.5 (#xx for every non-regular byte).
//
// Both changes are byte-identical for every legitimate input this package
// produces: the names it emits (Sig, Adobe.PPKLite, ETSI.CAdES.detached,
// Widget, Annot, the "**********" ByteRange placeholder, and every
// dictionary key) consist solely of regular characters, and no legitimate
// value's string form contains "<<". Covered by test/sig-dict-injection.test.ts
// ::"is byte-identical to upstream for legitimate input".
//
// Reported by Uuaid-Lead 2026-08-11 (found while adversarially testing an
// independent verifier against the published @e-sig/core signPdf).

import { PDFAbstractReference } from "@signpdf/utils";

const pad = (str: string | number, length: number): string =>
  (Array(length + 1).join("0") + str).slice(-length);

const escapableRe = /[\n\r\t\b\f()\\]/g;
const escapable: Record<string, string> = {
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\b": "\\b",
  "\f": "\\f",
  "\\": "\\\\",
  "(": "\\(",
  ")": "\\)",
};

/**
 * PDF name delimiters (ISO 32000-1 §7.2.2) plus '#', which introduces an
 * escape and so must itself be escaped.
 */
const NAME_DELIMITERS = new Set("()<>[]{}/%#".split("").map((c) => c.charCodeAt(0)));

/**
 * Escape a PDF name body per ISO 32000-1 §7.3.5: every byte outside the
 * regular-character range (0x21..0x7E minus the delimiters) is written as
 * `#` followed by two uppercase hex digits. Regular names pass through
 * unchanged, so this is a no-op for well-formed input.
 */
export const escapePdfName = (name: string): string => {
  let out = "";
  for (const byte of Buffer.from(name, "utf8")) {
    if (byte >= 0x21 && byte <= 0x7e && !NAME_DELIMITERS.has(byte)) {
      out += String.fromCharCode(byte);
    } else {
      out += `#${byte.toString(16).padStart(2, "0").toUpperCase()}`;
    }
  }
  return out;
};

// Convert little endian UTF-16 to big endian
const swapBytes = (buff: Buffer): Buffer => buff.swap16();

/** Converts JavaScript types into their corresponding PDF types. */
export const convert = (object: unknown): string => {
  // String literals are converted to the PDF name type
  if (typeof object === "string") {
    return `/${escapePdfName(object)}`;
  }

  // String objects are converted to PDF strings (UTF-16)
  if (object instanceof String) {
    let string = String(object);
    // Detect if this is a unicode string
    let isUnicode = false;
    for (let i = 0, end = string.length; i < end; i += 1) {
      if (string.charCodeAt(i) > 0x7f) {
        isUnicode = true;
        break;
      }
    }

    // If so, encode it as big endian UTF-16
    const stringBuffer = isUnicode
      ? swapBytes(Buffer.from(`\ufeff${string}`, "utf16le"))
      : Buffer.from(string, "ascii");
    string = stringBuffer.toString("binary");

    // Escape characters as required by the spec
    string = string.replace(escapableRe, (c) => escapable[c]!);
    return `(${string})`;
  }

  // Buffers are converted to PDF hex strings
  if (Buffer.isBuffer(object)) {
    return `<${object.toString("hex")}>`;
  }
  if (object instanceof PDFAbstractReference) {
    // String(): @signpdf/utils types the abstract base's toString() as void
    // (it throws); the concrete PDFKitReferenceMock returns "<index> 0 R".
    return String(object);
  }
  if (object instanceof Date) {
    const string =
      `D:${pad(object.getUTCFullYear(), 4)}${pad(object.getUTCMonth() + 1, 2)}` +
      `${pad(object.getUTCDate(), 2)}${pad(object.getUTCHours(), 2)}` +
      `${pad(object.getUTCMinutes(), 2)}${pad(object.getUTCSeconds(), 2)}Z`;
    return `(${string})`;
  }
  if (Array.isArray(object)) {
    const items = object.map((e) => convert(e)).join(" ");
    return `[${items}]`;
  }
  if ({}.toString.call(object) === "[object Object]") {
    const out = ["<<"];
    let streamData: string | undefined;

    Object.entries(object as Record<string, unknown>).forEach(([key, val]) => {
      if (key === "stream") {
        streamData = `${key}\n${val}\nendstream`;
      } else {
        // NOTE: no raw-splice branch here — see the header. Every value is
        // converted, and every key is escaped as a name.
        out.push(`/${escapePdfName(key)} ${convert(val)}`);
      }
    });
    out.push(">>");
    if (streamData) {
      out.push(streamData);
    }
    return out.join("\n");
  }
  if (typeof object === "number") {
    if (object > -1e21 && object < 1e21) {
      return String(Math.round(object * 1e6) / 1e6);
    }
    throw new Error(`unsupported number: ${object}`);
  }
  return `${object}`;
};

export const PDFObject = { convert };
