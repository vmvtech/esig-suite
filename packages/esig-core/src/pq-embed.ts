// pq-embed.ts
//
// Embed a post-quantum seal (see pq-seal.ts) into a rendered PDF as an
// append-only incremental update, and extract it back out.
//
// WHY append-only: the seal signs SHA-256 of the document bytes it covers
// (`coveredBytes` = length of the pre-seal PDF, P0). An incremental update never
// rewrites prior bytes, so in the final signed file P2, the prefix P2[0:coveredBytes]
// is byte-identical to P0 — the verifier recovers exactly what the seal signed.
// This ordering (embed seal → THEN apply the RSA PAdES signature) also lets the
// classical /ByteRange signature cryptographically cover the seal.
//
// The incremental update we append is deliberately minimal and mirrors the exact
// xref/trailer byte layout @signpdf/placeholder-plain expects (it later parses
// this file to add its own signature layer): one new indirect object holding the
// base64 seal, one single-subsection classic xref, a trailer that copies the
// document's /Root (+ /Info) and points /Prev at the previous xref, and a clean
// `startxref … %%EOF` tail.
//
// Retrieval scans for the object's `/Seal(<base64>)` literal. Base64's alphabet
// (A–Z a–z 0–9 + / =) contains no PDF-string metacharacters, so no escaping is
// needed and a simple regex is unambiguous. @signpdf never rewrites these bytes,
// so the seal survives the subsequent signing pass verbatim.

import type { PqSeal } from "./pq-seal.js";

/** Marker object type; also the retrieval anchor. */
const SEAL_OBJ_TYPE = "ESigPQSeal";
const SEAL_EXTRACT_RE = new RegExp(`/Type\\s*/${SEAL_OBJ_TYPE}/V\\s+1/Seal\\(([A-Za-z0-9+/=]+)\\)`, "g");

interface LastTrailer {
  rootRef: string;
  infoRef?: string;
  size: number;
  prevStartxref: number;
}

/**
 * Parse the most recent classic trailer to recover the fields our incremental
 * update must carry forward: /Root, optional /Info, /Size (→ next free object
 * number), and the last xref offset (→ our /Prev). Throws with a clear message
 * on xref-stream PDFs, which the whole signing pipeline (@signpdf included)
 * doesn't support anyway.
 */
function readLastTrailer(pdf: Buffer): LastTrailer {
  const text = pdf.toString("latin1"); // 1 byte ↔ 1 char, so string index === byte offset
  const sxIdx = text.lastIndexOf("startxref");
  if (sxIdx < 0) throw new Error("pq-embed: no startxref found (not a classic PDF)");
  const prevMatch = text.slice(sxIdx + "startxref".length).match(/\d+/);
  if (!prevMatch) throw new Error("pq-embed: could not read previous startxref offset");
  const prevStartxref = parseInt(prevMatch[0], 10);

  const trIdx = text.lastIndexOf("trailer");
  if (trIdx < 0 || trIdx > sxIdx) {
    throw new Error("pq-embed: classic trailer not found (xref-stream PDFs are unsupported)");
  }
  const dict = text.slice(trIdx, sxIdx);
  const root = dict.match(/\/Root\s+(\d+\s+\d+\s+R)/);
  const info = dict.match(/\/Info\s+(\d+\s+\d+\s+R)/);
  const size = dict.match(/\/Size\s+(\d+)/);
  if (!root) throw new Error("pq-embed: trailer has no /Root");
  if (!size) throw new Error("pq-embed: trailer has no /Size");

  return {
    rootRef: root[1].replace(/\s+/g, " "),
    infoRef: info?.[1].replace(/\s+/g, " "),
    size: parseInt(size[1], 10),
    prevStartxref,
  };
}

/**
 * Append `seal` to `pdf` as an incremental update. Returns the new PDF; the first
 * `pdf.length` bytes are preserved verbatim, so `seal.coveredBytes` (set by the
 * caller to `pdf.length`) still points at the original document in the final file.
 */
export function embedPqSeal(pdf: Buffer, seal: PqSeal): Buffer {
  const trailer = readLastTrailer(pdf);
  const sealB64 = Buffer.from(JSON.stringify(seal), "utf8").toString("base64");
  const objNum = trailer.size; // next free object number

  // Separate our update from the prior %%EOF with a newline (harmless if the
  // file already ended in one).
  const head = Buffer.concat([pdf, Buffer.from("\n", "latin1")]);
  const objOffset = head.length;

  const objBuf = Buffer.from(
    `${objNum} 0 obj\n<</Type/${SEAL_OBJ_TYPE}/V 1/Seal(${sealB64})>>\nendobj\n`,
    "latin1",
  );
  const withObj = Buffer.concat([head, objBuf]);
  const xrefOffset = withObj.length;

  const paddedOffset = String(objOffset).padStart(10, "0");
  const xref = Buffer.from(
    "xref\n" +
      `${objNum} 1\n` +
      `${paddedOffset} 00000 n \n` + // 20-byte entry: 10 offset + gen 00000 + 'n' + trailing space + LF
      "trailer\n<<\n" +
      `/Size ${objNum + 1}\n` +
      `/Root ${trailer.rootRef}\n` +
      (trailer.infoRef ? `/Info ${trailer.infoRef}\n` : "") +
      `/Prev ${trailer.prevStartxref}\n` +
      ">>\nstartxref\n" +
      `${xrefOffset}\n%%EOF\n`,
    "latin1",
  );

  return Buffer.concat([withObj, xref]);
}

/**
 * Extract the embedded seal from a (possibly later-signed) PDF, or null if none
 * is present / it is not valid JSON. Returns the FIRST seal if several exist.
 *
 * FIRST, deliberately: the genuine seal is embedded BEFORE the RSA PAdES
 * signature, so it sits at the lowest file offset and is covered by the classical
 * /ByteRange. A seal an attacker appends AFTER signing lands at a higher offset
 * and is NOT RSA-covered — taking the first match ignores it, so even a standalone
 * `verifyPqSeal` reports the authentic signer rather than the appended identity.
 * Never throws — a malformed seal is treated as absent (fail-closed at verify).
 */
export function extractPqSeal(pdf: Buffer): PqSeal | null {
  SEAL_EXTRACT_RE.lastIndex = 0;
  const match = SEAL_EXTRACT_RE.exec(pdf.toString("latin1"));
  if (!match) return null;
  try {
    return JSON.parse(Buffer.from(match[1], "base64").toString("utf8")) as PqSeal;
  } catch {
    return null;
  }
}

/** True if the PDF carries an embedded post-quantum seal. */
export function hasPqSeal(pdf: Buffer): boolean {
  SEAL_EXTRACT_RE.lastIndex = 0;
  return SEAL_EXTRACT_RE.test(pdf.toString("latin1"));
}
