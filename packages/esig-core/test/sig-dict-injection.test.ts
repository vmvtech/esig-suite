// Signature-dictionary injection regression tests.
//
// Reported by Uuaid-Lead 2026-08-11 against the published @e-sig/core@0.6.0:
// `signPdf` passed `subFilter` through to @signpdf/utils' PDFObject, which
// renders a JS string as a RAW UNESCAPED PDF name (`/${value}`) — so a caller
// could splice arbitrary keys into the signature dictionary of a document the
// signature then validly covers. Reproducing it locally showed the same class
// reaching further: PDFObject's dictionary branch emits ANY value whose string
// form contains "<<" completely raw, so `reason` / `name` / `location` /
// `contactInfo` were injectable too — and those are far likelier to come
// straight from a web form.
//
// Runs against ../dist (the artifact consumers actually install).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it, expect } from "vitest";

import { generateSelfSignedCert, signPdf, verifyPdfSignature } from "../dist/index.js";
import { convert, escapePdfName } from "../dist/vendor/placeholder-plain/pdfObject.js";

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE_PDF = readFileSync(join(here, "..", "..", "..", "scripts", "sample-unsigned.pdf"));

const cert = generateSelfSignedCert({ subjectName: "Acme Inc" });

const BASE = {
  pdf: SAMPLE_PDF,
  keyPem: cert.keyPem,
  certPem: cert.certPem,
  reason: "Agreed",
  location: "",
  contactInfo: "a@b.co",
  name: "Acme Inc",
};

/** The signature dictionary as written, with the /Contents blob elided. */
function sigDict(signed: Buffer): string {
  const pdf = signed.toString("latin1");
  const start = pdf.lastIndexOf("/Type /Sig");
  expect(start).toBeGreaterThan(-1);
  const end = pdf.indexOf("endobj", start);
  return pdf.slice(start, end).replace(/\/Contents <[0-9a-f]*>/i, "/Contents <...>");
}

describe("signature dictionary injection", () => {
  it("rejects a subFilter outside the supported set", async () => {
    await expect(
      signPdf({
        ...BASE,
        // The reporter's payload: a newline ends the /SubFilter name token and
        // the rest becomes sibling keys in the signature dictionary.
        subFilter: "ETSI.CAdES.detached\n/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >>",
      } as never),
    ).rejects.toThrow(/unsupported subFilter/);

    // Space-separated sibling key — same class, no newline needed.
    await expect(
      signPdf({ ...BASE, subFilter: "ETSI.CAdES.detached /Evil (pwned)" } as never),
    ).rejects.toThrow(/unsupported subFilter/);
  });

  it("still accepts both legitimate subFilters", async () => {
    for (const sub of ["ETSI.CAdES.detached", "adbe.pkcs7.detached"] as const) {
      const { signedPdf } = await signPdf({ ...BASE, subFilter: sub });
      expect(sigDict(signedPdf)).toContain(`/SubFilter /${sub}`);
      expect((await verifyPdfSignature(signedPdf)).ok).toBe(true);
    }
  });

  it("does not let string fields splice keys into the signature dictionary", async () => {
    const { signedPdf } = await signPdf({
      ...BASE,
      reason: "hello << /OpenAction 99 0 R >> tail",
      name: "Acme << /Evil (x) >>",
      location: "HQ << /Also (bad) >>",
      contactInfo: "a@b.co << /Nope 1 >>",
    });
    const dict = sigDict(signedPdf);

    // Every one of these must land inside a PDF string literal, not as
    // free-standing dictionary syntax.
    expect(dict).toContain("/Reason (hello << /OpenAction 99 0 R >> tail)");
    // Parens inside the payload are escaped, so they cannot close the string
    // literal early and reach dictionary syntax.
    expect(dict).toContain("/Name (Acme << /Evil \\(x\\) >>)");
    expect(dict).toContain("/Location (HQ << /Also \\(bad\\) >>)");
    expect(dict).toContain("/ContactInfo (a@b.co << /Nope 1 >>)");
    expect(dict).not.toMatch(/^\/OpenAction/m);
    expect(dict).not.toMatch(/^\/Evil/m);
    expect(dict).not.toMatch(/^\/Nope/m);

    // The keys the dictionary is allowed to have, and nothing else. Deduped
    // because the nested /Prop_Build sub-dictionary legitimately repeats
    // /Filter and /Name; the property under test is that no *unexpected* key
    // ever appears.
    const keys = [...new Set([...dict.matchAll(/^\/([A-Za-z_]+)/gm)].map((m) => m[1]))].sort();
    expect(keys).toEqual(
      [
        "ByteRange",
        "ContactInfo",
        "Contents",
        "Filter",
        "Location",
        "M",
        "Name",
        "Prop_Build",
        "Reason",
        "SubFilter",
        "Type",
      ].sort(),
    );

    // And the document is still a validly signed PDF.
    expect((await verifyPdfSignature(signedPdf)).ok).toBe(true);
  });

  it("escapes parens in string fields (unchanged upstream behaviour)", async () => {
    const { signedPdf } = await signPdf({ ...BASE, reason: "a) /Evil (b" });
    expect(sigDict(signedPdf)).toContain("/Reason (a\\) /Evil \\(b)");
  });
});

describe("hardened PDFObject", () => {
  it("escapes PDF name delimiters and whitespace per ISO 32000-1 §7.3.5", () => {
    expect(escapePdfName("ETSI.CAdES.detached")).toBe("ETSI.CAdES.detached");
    expect(escapePdfName("a b")).toBe("a#20b");
    expect(escapePdfName("a\n/B")).toBe("a#0A#2FB");
    expect(escapePdfName("<<>>")).toBe("#3C#3C#3E#3E");
    expect(escapePdfName("#")).toBe("#23");
    // Multi-byte input escapes per UTF-8 byte, never per code unit.
    expect(escapePdfName("é")).toBe("#C3#A9");
  });

  it("converts a value containing << instead of splicing it raw", () => {
    // Upstream @signpdf/utils emits `/K x << /Injected 1 >>` here.
    expect(convert({ K: new String("x << /Injected 1 >>") })).toBe(
      "<<\n/K (x << /Injected 1 >>)\n>>",
    );
  });

  it("is byte-identical to upstream for legitimate input", async () => {
    // The byte-identity claim in pdfObject.ts's header, asserted rather than
    // assumed: every shape this package actually emits must round-trip the
    // same through both converters.
    const upstream = (await import("@signpdf/utils")).PDFObject;
    const { PDFKitReferenceMock } = await import("@signpdf/utils");

    const samples: unknown[] = [
      "Sig",
      "Adobe.PPKLite",
      "ETSI.CAdES.detached",
      "adbe.pkcs7.detached",
      "Widget",
      "Annot",
      [0, "**********", "**********", "**********"],
      [0, 0, 0, 0],
      new String("Agreed"),
      new String("Signature1"),
      new String("café"),
      Buffer.from(String.fromCharCode(0).repeat(32)),
      new Date(Date.UTC(2026, 7, 11, 12, 0, 0)),
      3,
      6,
      new PDFKitReferenceMock(7),
      { Type: "Sig", Filter: "Adobe.PPKLite", SubFilter: "ETSI.CAdES.detached" },
      { Filter: { Name: "Adobe.PPKLite" }, App: { Name: "esig" } },
    ];

    for (const sample of samples) {
      expect(convert(sample)).toBe(String(upstream.convert(sample)));
    }
  });
});
