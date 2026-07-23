// Browser port of @e-sig/core's verify-pdf.ts + timestamp.ts.
//
// The Node originals use node:crypto and Buffer; this port is Uint8Array-only
// and uses node-forge for all hashing so it bundles for the browser with vite.
// Logic is line-for-line equivalent to packages/esig-core/src/verify-pdf.ts:
// ByteRange tiling, DER-sliced /Contents, PKCS#7 parse, messageDigest signed
// attribute check, RSA signature over DER(signedAttrs as SET OF), and the
// RFC 3161 §2.4.2 timestamp binding check.

import forge from "node-forge";

const asn1 = forge.asn1;

const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_COMMON_NAME = "2.5.4.3";

function u8ToBinary(bytes) {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return s;
}

function hexToU8(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function sha256U8(bytes) {
  const md = forge.md.sha256.create();
  md.update(u8ToBinary(bytes));
  return hexToU8(md.digest().toHex());
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function verifyPdfSignature(signed /* Uint8Array */) {
  const failures = [];
  const text = u8ToBinary(signed);
  const result = { ok: false, failures, timestamped: false };

  const m = text.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!m) {
    failures.push("no /ByteRange dictionary found");
    return result;
  }
  const [a, b, c, d] = m.slice(1, 5).map(Number);
  result.byteRange = [a, b, c, d];

  const covered = b + d;
  const hole = c - (a + b);
  if (covered + hole !== signed.length) {
    failures.push(`byte ranges (${covered}) + hole (${hole}) != file size (${signed.length})`);
    return result;
  }
  result.pkcs7BudgetSize = hole - 2;

  const contentsRegion = u8ToBinary(signed.subarray(a + b + 1, c - 1));
  const hexBlob = contentsRegion.replace(/[^0-9a-fA-F]/g, "");
  // The /Contents hole is zero-padded past the end of the DER. Slice at the
  // length declared in the DER's own TLV header — trimming trailing "00" pairs
  // instead truncates any signature whose final byte is legitimately 0x00.
  const contentsBytes = hexToU8(hexBlob);
  const derLen = derTotalLength(contentsBytes);
  if (derLen === null || derLen > contentsBytes.length) {
    failures.push("/Contents does not hold a well-formed DER structure");
    return result;
  }
  const pkcs7Der = u8ToBinary(contentsBytes.subarray(0, derLen));
  result.pkcs7ActualSize = pkcs7Der.length;

  try {
    const root = forge.asn1.fromDer(pkcs7Der);
    const p7 = forge.pkcs7.messageFromAsn1(root);
    if (!p7.certificates || p7.certificates.length === 0) {
      failures.push("PKCS#7 has no embedded certificates");
      return result;
    }
    const signerCert = p7.certificates[0];
    const subject = signerCert.subject;
    const cn = subject.getField("CN");
    const o = subject.getField("O");
    result.signerCommonName = cn && cn.value;
    result.signerOrganization = o && o.value;

    const coveredBytes = concatU8(signed.subarray(a, a + b), signed.subarray(c, c + d));
    const crypto_ = verifySignerCrypto(root, signerCert, coveredBytes);
    result.digestValid = crypto_.digestValid;
    result.signatureValid = crypto_.signatureValid;
    for (const f of crypto_.failures) failures.push(f);

    const ts = inspectTimestamp(root);
    if (ts.present) {
      result.timestamped = true;
      result.timestampTime = ts.timestampTime;
      result.tsaCommonName = ts.tsaCommonName;

      // §2.4.2 binding: TST messageImprint == sha256(signatureValue).
      if (ts.sigValueHex && ts.messageImprintHashHex) {
        const expected = sha256Hex(ts.sigValueHex);
        if (expected !== ts.messageImprintHashHex.toLowerCase()) {
          failures.push("timestamp messageImprint does not match signature value");
        }
      } else if (!ts.messageImprintHashHex) {
        failures.push("timestamp present but messageImprint could not be read");
      }
    }
  } catch (e) {
    failures.push(`PKCS#7 parse error: ${e.message}`);
    return result;
  }

  result.ok = failures.length === 0;
  return result;
}

function concatU8(x, y) {
  const out = new Uint8Array(x.length + y.length);
  out.set(x, 0);
  out.set(y, x.length);
  return out;
}

function verifySignerCrypto(contentInfo, signerCert, coveredContent) {
  const failures = [];
  let digestValid = false;
  let signatureValid = false;

  try {
    const signerInfo = firstSignerInfo(contentInfo);
    if (!signerInfo) {
      failures.push("could not locate SignerInfo for cryptographic verification");
      return { digestValid, signatureValid, failures };
    }

    let signedAttrs;
    let signatureValue;
    for (const child of signerInfo.value) {
      if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && child.type === 0) {
        signedAttrs = child;
      }
      if (
        child.tagClass === asn1.Class.UNIVERSAL &&
        child.type === asn1.Type.OCTETSTRING &&
        typeof child.value === "string"
      ) {
        signatureValue = child.value;
      }
    }

    if (!signedAttrs || !Array.isArray(signedAttrs.value)) {
      failures.push("SignerInfo has no signed attributes (cannot verify)");
      return { digestValid, signatureValid, failures };
    }

    const messageDigest = extractSignedAttrValue(signedAttrs, OID_MESSAGE_DIGEST);
    if (!messageDigest) {
      failures.push("messageDigest signed attribute missing");
    } else {
      const recomputed = sha256U8(coveredContent);
      const claimed = hexToU8(forge.util.bytesToHex(messageDigest));
      digestValid = constantTimeEqual(recomputed, claimed);
      if (!digestValid) {
        failures.push(
          "document digest does not match messageDigest attribute — content altered after signing",
        );
      }
    }

    if (!signatureValue) {
      failures.push("SignerInfo signature value missing");
    } else {
      const setDer = asn1.toDer(
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SET, true, signedAttrs.value),
      ).getBytes();
      const md = forge.md.sha256.create();
      md.update(setDer);
      try {
        signatureValid = signerCert.publicKey.verify(md.digest().getBytes(), signatureValue);
        if (!signatureValid) {
          failures.push("signature does not verify against the signer certificate");
        }
      } catch (e) {
        signatureValid = false;
        failures.push(`signature verification threw: ${e.message}`);
      }
    }
  } catch (e) {
    failures.push(`cryptographic verification error: ${e.message}`);
  }

  return { digestValid, signatureValid, failures };
}

function firstSignerInfo(contentInfo) {
  if (!Array.isArray(contentInfo.value)) return undefined;
  let signedData;
  for (const child of contentInfo.value) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
      signedData = child.value[0];
    }
  }
  if (!signedData || !Array.isArray(signedData.value)) return undefined;
  let signerInfos;
  for (const child of signedData.value) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.SET &&
      Array.isArray(child.value)
    ) {
      signerInfos = child; // last UNIVERSAL SET = signerInfos (first = digestAlgorithms)
    }
  }
  if (!signerInfos || !Array.isArray(signerInfos.value) || signerInfos.value.length === 0) {
    return undefined;
  }
  return signerInfos.value[0];
}

function extractSignedAttrValue(signedAttrs, oid) {
  for (const attr of signedAttrs.value) {
    if (!Array.isArray(attr.value) || attr.value.length < 2) continue;
    const oidNode = attr.value[0];
    if (oidNode.type !== asn1.Type.OID || safeOid(oidNode.value) !== oid) continue;
    const set = attr.value[1];
    if (!Array.isArray(set.value) || set.value.length === 0) return undefined;
    const val = set.value[0];
    return typeof val.value === "string" ? val.value : undefined;
  }
  return undefined;
}

function inspectTimestamp(contentInfo) {
  if (!Array.isArray(contentInfo.value)) return { present: false };

  let signedData;
  for (const child of contentInfo.value) {
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
      signedData = child.value[0];
    }
  }
  if (!signedData || !Array.isArray(signedData.value)) return { present: false };

  let signerInfos;
  for (const child of signedData.value) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.SET &&
      Array.isArray(child.value)
    ) {
      signerInfos = child;
    }
  }
  if (!signerInfos || !Array.isArray(signerInfos.value) || signerInfos.value.length === 0) {
    return { present: false };
  }

  const signerInfo = signerInfos.value[0];
  if (!Array.isArray(signerInfo.value)) return { present: false };
  const siChildren = signerInfo.value;

  let sigValueHex;
  let unsignedAttrs;
  for (const child of siChildren) {
    if (
      child.tagClass === asn1.Class.UNIVERSAL &&
      child.type === asn1.Type.OCTETSTRING &&
      typeof child.value === "string"
    ) {
      sigValueHex = forge.util.bytesToHex(child.value);
    }
    if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && child.type === 1) {
      unsignedAttrs = child;
    }
  }

  if (!unsignedAttrs || !Array.isArray(unsignedAttrs.value)) {
    return { present: false, sigValueHex };
  }

  for (const attr of unsignedAttrs.value) {
    if (!Array.isArray(attr.value) || attr.value.length < 2) continue;
    const oidNode = attr.value[0];
    if (oidNode.type !== asn1.Type.OID || safeOid(oidNode.value) !== OID_TIMESTAMP_TOKEN) {
      continue;
    }
    const setNode = attr.value[1];
    if (!Array.isArray(setNode.value) || setNode.value.length === 0) continue;
    const token = setNode.value[0];

    const info = parseTstInfo(token);
    return {
      present: true,
      sigValueHex,
      messageImprintHashHex: info.messageImprintHashHex,
      timestampTime: toIsoGeneralizedTime(info.genTime),
      tsaCommonName: info.tsaCommonName,
    };
  }

  return { present: false, sigValueHex };
}

function parseTstInfo(tokenAsn1) {
  const result = {};
  try {
    if (!Array.isArray(tokenAsn1.value)) return result;

    let signedData;
    for (const child of tokenAsn1.value) {
      if (child.type === asn1.Type.OID && safeOid(child.value) === OID_SIGNED_DATA) continue;
      if (child.tagClass === asn1.Class.CONTEXT_SPECIFIC && Array.isArray(child.value)) {
        signedData = child.value[0];
      }
    }
    if (!signedData || !Array.isArray(signedData.value)) return result;

    let tstInfoBytes;
    for (const sdChild of signedData.value) {
      if (sdChild.type !== asn1.Type.SEQUENCE || !Array.isArray(sdChild.value)) continue;
      const seq = sdChild.value;
      const first = seq[0];
      if (first && first.type === asn1.Type.OID && safeOid(first.value) === OID_TST_INFO) {
        const explicit = seq[1];
        if (explicit && Array.isArray(explicit.value)) {
          const oct = explicit.value[0];
          if (oct && oct.type === asn1.Type.OCTETSTRING) {
            if (typeof oct.value === "string") {
              tstInfoBytes = oct.value;
            } else if (Array.isArray(oct.value) && oct.value.length > 0) {
              tstInfoBytes = oct.value[0].value;
            }
          }
        }
        break;
      }
    }
    if (!tstInfoBytes) return result;

    const tstInfo = asn1.fromDer(tstInfoBytes);
    if (!Array.isArray(tstInfo.value)) return result;
    const fields = tstInfo.value;

    for (const f of fields) {
      if (f.type === asn1.Type.SEQUENCE && Array.isArray(f.value)) {
        const mi = f.value;
        const hashed = mi[mi.length - 1];
        if (hashed && hashed.type === asn1.Type.OCTETSTRING && typeof hashed.value === "string") {
          result.messageImprintHashHex = forge.util.bytesToHex(hashed.value);
          break;
        }
      }
    }

    for (const f of fields) {
      if (f.type === asn1.Type.GENERALIZEDTIME && typeof f.value === "string") {
        result.genTime = f.value;
      }
    }

    let bestSerial;
    let bestLen = 0;
    for (const f of fields) {
      if (f.type === asn1.Type.INTEGER && typeof f.value === "string" && f.value.length > bestLen) {
        bestLen = f.value.length;
        bestSerial = f.value;
      }
    }
    if (bestSerial) result.serialHex = forge.util.bytesToHex(bestSerial);

    result.tsaCommonName = extractFirstCommonName(signedData);
  } catch {
    // Best-effort: swallow parse errors, returning whatever we have.
  }
  return result;
}

function extractFirstCommonName(node) {
  let found;
  const walk = (n) => {
    if (found) return;
    if (!Array.isArray(n.value)) return;
    const children = n.value;
    for (let i = 0; i < children.length; i++) {
      const c = children[i];
      if (
        c.type === asn1.Type.OID &&
        typeof c.value === "string" &&
        safeOid(c.value) === OID_COMMON_NAME &&
        i + 1 < children.length
      ) {
        const v = children[i + 1];
        if (typeof v.value === "string" && v.value.length > 0) {
          found = v.value;
          return;
        }
      }
    }
    for (const c of children) walk(c);
  };
  walk(node);
  return found;
}

function derTotalLength(buf) {
  if (buf.length < 2 || buf[0] !== 0x30) return null; // ContentInfo is a SEQUENCE
  const l0 = buf[1];
  if (l0 < 0x80) return 2 + l0;
  const n = l0 & 0x7f;
  if (n === 0 || n > 4 || buf.length < 2 + n) return null;
  let v = 0;
  for (let k = 0; k < n; k++) v = v * 256 + buf[2 + k];
  return 2 + n + v;
}

function safeOid(der) {
  try {
    return asn1.derToOid(der);
  } catch {
    return "";
  }
}

function sha256Hex(hex) {
  const md = forge.md.sha256.create();
  md.update(forge.util.hexToBytes(hex));
  return md.digest().toHex().toLowerCase();
}

function toIsoGeneralizedTime(gt) {
  if (!gt) return undefined;
  const m = gt.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z?$/);
  if (!m) return gt;
  const [, y, mo, d, h, mi, s] = m;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? gt : parsed.toISOString();
}

// ---- Page wiring ----

const drop = document.getElementById("drop");
const fileInput = document.getElementById("file");
const resultEl = document.getElementById("result");

function esc(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function render(fileName, r) {
  const tampered = !r.ok && r.digestValid === false;
  const status = r.ok ? "valid" : tampered ? "tampered" : "invalid";
  const label = r.ok ? "Signature valid" : tampered ? "Document tampered" : "Signature invalid";
  const rows = [];
  const row = (k, v) => rows.push(`<tr><th>${k}</th><td>${v}</td></tr>`);
  row("File", esc(fileName));
  if (r.signerCommonName) row("Signer", esc(r.signerCommonName) + (r.signerOrganization ? ` <span class="dim">(${esc(r.signerOrganization)})</span>` : ""));
  if (r.digestValid !== undefined) row("Integrity (SHA-256)", r.digestValid ? '<span class="pass">intact</span>' : '<span class="fail">mismatch</span>');
  if (r.signatureValid !== undefined) row("Authenticity (RSA)", r.signatureValid ? '<span class="pass">verified</span>' : '<span class="fail">does not verify</span>');
  if (r.timestamped) {
    row("RFC 3161 timestamp", esc(r.timestampTime || "present") + (r.tsaCommonName ? ` <span class="dim">TSA: ${esc(r.tsaCommonName)}</span>` : ""));
  } else {
    row("RFC 3161 timestamp", '<span class="dim">none embedded</span>');
  }
  if (r.failures.length) {
    row("Findings", `<ul class="findings">${r.failures.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`);
  }
  resultEl.innerHTML = `
    <div class="verdict ${status}">
      <span class="dot"></span><strong>${label}</strong>
    </div>
    <table class="detail">${rows.join("")}</table>
    <p class="note">Cryptographic verification of the embedded PKCS#7 / CAdES signature against the
    certificate embedded in the document. Trust in that certificate (chain, revocation, AATL/EUTL)
    is an out-of-band concern — a self-issued cert can verify valid without being reader-trusted.
    Everything ran locally in your browser; the PDF never left this page.</p>`;
}

async function handleFile(f) {
  if (!f) return;
  resultEl.innerHTML = `<p class="dim">Verifying ${esc(f.name)}…</p>`;
  try {
    const buf = new Uint8Array(await f.arrayBuffer());
    const r = verifyPdfSignature(buf);
    render(f.name, r);
  } catch (e) {
    resultEl.innerHTML = `<div class="verdict invalid"><span class="dot"></span><strong>Could not read file</strong></div><p class="note">${esc(e.message)}</p>`;
  }
}

drop.addEventListener("click", () => fileInput.click());
drop.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
});
fileInput.addEventListener("change", () => handleFile(fileInput.files[0]));
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  handleFile(e.dataTransfer.files[0]);
});
