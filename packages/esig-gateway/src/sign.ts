// sign.ts
//
// The signing pipeline: HTML → PDF → PAdES/PKCS#7 (+ RFC-3161, + hybrid PQ
// seal) → self-verify → audit → base64 response.
//
// Why this composes core directly instead of calling `signDocument()`
// (the handoff's §3 suggestion): `signDocument()` is storage-first — it
// requires a PdfStorageStore and returns a URL, not the signed bytes. The
// frozen contract needs the BYTES back (`signed_pdf_base64`), and the handoff
// leaves archival custody an open owner decision (§6). Composing
// renderHtmlToPdf → ensureActiveCert → signPdf → AuditLogStore keeps the bytes
// in hand, makes archival an optional injected store rather than a hard
// dependency, and lets the audit row carry gateway-specific fields
// (caller identity, client-claimed timestamp, transitional-auth flag) that
// `signDocument()`'s fixed metadata shape has no slot for.
//
// ---- Algorithm note (the technical call the handoff asked for) -----------
// dsalvus' docs say "Ed25519 through the @e-sig/core PKCS#7 wrapper".
// Ed25519-in-PKCS#7 is NOT what core produces and should not be: core's
// PemSigner is RSASSA-PKCS1-v1_5/SHA-256 end to end, `ExternalSignerKeyType`
// admits only rsa-2048/3072/4096, and no mainstream PDF reader validates an
// EdDSA SignerInfo — an Ed25519 PKCS#7 would verify in our tooling and nowhere
// else, which is the opposite of what a reassurance artifact needs.
//
// What this gateway does instead gives dsalvus the Ed25519 it asked for AND a
// signature Acrobat accepts:
//
//   layer 1  hybrid seal: Ed25519 + ML-DSA-65 (FIPS 204) over SHA-256 of the
//            pre-signature PDF, embedded as an append-only incremental update
//   layer 2  classical PAdES: RSA-2048 PKCS#7 detached (ETSI.CAdES.detached)
//            applied ON TOP, so its /ByteRange cryptographically covers the seal
//   layer 3  optional RFC-3161 TST → CAdES-T
//
// So Ed25519 IS present and IS covered by the PKCS#7 signature — the design
// intent is satisfied literally — plus a post-quantum signature the original
// note did not ask for. Verified by core's `verifyDocument()` (both layers) or
// by any PDF reader (classical layer only).
// -------------------------------------------------------------------------

import crypto from "node:crypto";

import {
  ensureActiveCert,
  ensureActivePqKeys,
  renderHtmlToPdf,
  signPdf,
  verifyPdfSignature,
  type AuditLogStore,
  type CertStore,
  type PdfStorageStore,
  type PqKeyStore,
} from "@e-sig/core";

import { assertSlug, certKeyFor, resolveBinding, type GatewayConfig } from "./config.js";
import { GatewayError, asGatewayError } from "./errors.js";
import type { Principal } from "./auth.js";
import type { TsaPool } from "./tsa.js";
import type { KeyedMutex } from "./stores.js";

/** Free-form audit label from the caller. Bounded + printable ASCII because it
 *  lands in the PDF signature dictionary /Reason. Core escapes dictionary
 *  strings (and rejects unsupported /SubFilter values) as of 0.7.0; this is the
 *  caller-side half of that defence, and it also keeps the value legible in an
 *  auditor's PDF viewer. */
const PURPOSE_RE = /^[\x20-\x7e]{1,120}$/;

/** The frozen request shape — dsalvus `internal/assurance/sign.go`. */
export interface SignRequestBody {
  tenant: string;
  cert_alias: string;
  html_base64: string;
  purpose: string;
  timestamp: string;
}

/**
 * The frozen response shape. The first three fields are the contract dsalvus
 * decodes; everything after is additive and ignored by the Go client
 * (`encoding/json` drops unknown fields), so it can grow without a client
 * release.
 */
export interface SignResponseBody {
  signed_pdf_base64: string;
  cert_fingerprint: string;
  timestamped: boolean;
  // ---- additive, non-contractual ----
  audit_id?: string;
  signed_at?: string;
  pq_seal?: { alg: string; key_id: string; mldsa65_fpr: string };
  tsa_error?: string;
  transitional_auth?: boolean;
}

export interface SignerDeps {
  config: GatewayConfig;
  certStore: CertStore;
  pqKeyStore: PqKeyStore;
  auditStore: AuditLogStore;
  tsa: TsaPool;
  mutex: KeyedMutex;
  /**
   * Archive every signed artifact at sign time. OFF by default: the handoff
   * (§6) leaves custody with dsalvus until the owner decides otherwise. Wiring
   * `@e-sig/worm`'s WormPdfStorageStore here is the whole change if that flips.
   */
  archive?: PdfStorageStore;
  /** Injectable renderer — tests substitute a fixture so CI needs no Chromium. */
  render?: (html: string) => Promise<Buffer>;
  /** Injectable clock, for tests. */
  now?: () => Date;
}

/** Parse + validate the request body. Every rejection is fail-closed. */
export function parseSignRequest(raw: unknown): SignRequestBody {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new GatewayError("bad_request", "body must be a JSON object");
  }
  const o = raw as Record<string, unknown>;

  const tenant = assertSlug(o.tenant, "tenant");
  const cert_alias = assertSlug(o.cert_alias, "cert_alias");

  if (typeof o.html_base64 !== "string" || o.html_base64.length === 0) {
    throw new GatewayError("bad_request", "html_base64 must be a non-empty string");
  }
  if (typeof o.purpose !== "string" || !PURPOSE_RE.test(o.purpose)) {
    throw new GatewayError("bad_request", "purpose must be 1-120 printable ASCII characters");
  }
  if (typeof o.timestamp !== "string") {
    throw new GatewayError("bad_request", "timestamp must be an RFC3339 string");
  }
  if (Number.isNaN(Date.parse(o.timestamp))) {
    throw new GatewayError("bad_request", "timestamp is not a parseable RFC3339 instant");
  }

  return { tenant, cert_alias, html_base64: o.html_base64, purpose: o.purpose, timestamp: o.timestamp };
}

/**
 * Strict base64 decode. `Buffer.from(s, "base64")` silently ignores garbage,
 * which would let a corrupted payload be signed as though it were the dossier.
 */
function decodeHtml(b64: string): string {
  const normalized = b64.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 !== 0) {
    throw new GatewayError("bad_request", "html_base64 is not valid standard base64");
  }
  const bytes = Buffer.from(normalized, "base64");
  if (bytes.length === 0) throw new GatewayError("bad_request", "html_base64 decoded to zero bytes");
  // Round-trip: Buffer always emits canonical, padded base64, so inequality
  // means the input carried non-canonical trailing bits or dropped padding.
  if (bytes.toString("base64") !== normalized) {
    throw new GatewayError("bad_request", "html_base64 is not canonical base64");
  }
  return bytes.toString("utf8");
}

export class Signer {
  constructor(private readonly deps: SignerDeps) {}

  async sign(body: SignRequestBody, principal: Principal, requestId: string): Promise<SignResponseBody> {
    const cfg = this.deps.config;
    const now = this.deps.now ?? (() => new Date());
    const signedAt = now();

    // 1. Authorisation: the (tenant, alias, caller) triple must be in the
    //    registry. Unknown tenant and unknown alias both fail closed here —
    //    there is no path that mints an identity for an unregistered tenant.
    const binding = resolveBinding(cfg, body.tenant, body.cert_alias, principal.id);

    // A tenant-scoped credential may only sign for the tenant it names.
    if (principal.tenantClaim !== undefined && principal.tenantClaim !== body.tenant) {
      throw new GatewayError(
        "forbidden",
        `credential is scoped to tenant "${principal.tenantClaim}", request names "${body.tenant}"`,
      );
    }

    // 2. Freshness. The caller's timestamp is a CLAIM recorded in the audit
    //    trail — it never becomes the signing time, because a client-controlled
    //    signing time lets a caller backdate a signed dossier. Skew is checked
    //    so a replayed month-old request body is visible.
    const clientMs = Date.parse(body.timestamp);
    if (cfg.maxClientSkewSec > 0) {
      const skewSec = Math.abs(signedAt.getTime() - clientMs) / 1000;
      if (skewSec > cfg.maxClientSkewSec) {
        throw new GatewayError("stale_timestamp", `client timestamp skew ${Math.round(skewSec)}s`);
      }
    }

    const html = decodeHtml(body.html_base64);
    const htmlSha256 = crypto.createHash("sha256").update(html, "utf8").digest("hex");

    // 3. HTML → PDF.
    let unsignedPdf: Buffer;
    try {
      unsignedPdf = this.deps.render
        ? await this.deps.render(html)
        : await renderHtmlToPdf({ html, javascriptEnabled: false });
    } catch (e) {
      throw asGatewayError(e, "render_failed");
    }

    const certKey = certKeyFor(body.tenant, body.cert_alias);

    // 4. Signing material. Serialised per (tenant, alias) so a first-sign race
    //    cannot mint two "active" certs for the same partition.
    const material = await this.deps.mutex.run(certKey, async () => {
      const cert = await ensureActiveCert({
        store: this.deps.certStore,
        tenantId: certKey,
        subjectName: binding.subjectName,
        passphrase: cfg.passphrase,
      });
      const pq =
        binding.pqSeal !== false
          ? await ensureActivePqKeys({
              store: this.deps.pqKeyStore,
              tenantId: certKey,
              passphrase: cfg.passphrase,
            })
          : undefined;
      return { cert, pq };
    });

    // 5. Sign. Seal first (append-only), classical PAdES on top, TSA optional.
    let result;
    try {
      result = await signPdf({
        pdf: unsignedPdf,
        keyPem: material.cert.keyPem,
        certPem: material.cert.certPem,
        reason: binding.reason ?? body.purpose,
        location: binding.location ?? "",
        contactInfo: "",
        name: binding.subjectName,
        signingTime: signedAt,
        subFilter: "ETSI.CAdES.detached",
        tsa: this.deps.tsa.transport(),
        pqSeal: material.pq
          ? { keys: material.pq.keys, signedAt, uuaid: binding.uuaid }
          : undefined,
      });
    } catch (e) {
      throw asGatewayError(e, "sign_failed");
    }

    // 6. Self-verify before returning. The gateway must never hand back a PDF
    //    whose own signature does not verify — dsalvus is fail-closed on our
    //    behalf, but it cannot check this, and acceptance criterion §7.1 is
    //    exactly "verifyPdfSignature passes against the returned cert".
    const verdict = verifyPdfSignature(result.signedPdf);
    if (!verdict.ok || verdict.digestValid !== true || verdict.signatureValid !== true) {
      throw new GatewayError("sign_failed", `self-verification failed: ${verdict.failures.join("; ")}`);
    }
    if (cfg.tsa.required && !result.timestamped) {
      // Belt and braces: core aborts on a required-TSA failure, so reaching
      // here means an unexpected downgrade path. Never report timestamped=false
      // as success when the deployment declared timestamping mandatory.
      throw new GatewayError("sign_failed", "TSA required but signature is not timestamped");
    }

    const pdfSha256 = crypto.createHash("sha256").update(result.signedPdf).digest("hex");

    // 7. Optional sign-time archival (off unless the owner flips custody).
    let archivedUrl: string | undefined;
    if (this.deps.archive) {
      const key = `${body.tenant}/${body.cert_alias}/${signedAt.toISOString().replace(/[:.]/g, "-")}.pdf`;
      archivedUrl = (
        await this.deps.archive.upload({
          path: key,
          bytes: result.signedPdf,
          contentType: "application/pdf",
        })
      ).url;
    }

    // 8. Audit row — one per successful sign (acceptance criterion §7.2).
    const audit = await this.deps.auditStore.insert({
      tenantId: body.tenant,
      action: "pdf.signed",
      actorUserId: principal.id,
      targetTable: "assurance_dossier",
      targetId: `${body.tenant}:${body.purpose}`,
      certId: material.cert.cert.id,
      certFingerprint: material.cert.cert.certFingerprint,
      signedPdfUrl: archivedUrl,
      metadata: {
        gateway: "esig-assurance-gateway",
        request_id: requestId,
        cert_alias: body.cert_alias,
        cert_key: certKey,
        purpose: body.purpose,
        caller: { id: principal.id, via: principal.via, peer: principal.peer ?? null },
        transitional_auth: principal.transitional,
        client_timestamp: body.timestamp,
        signed_at: signedAt.toISOString(),
        html_sha256: htmlSha256,
        pdf_sha256: pdfSha256,
        pdf_bytes: result.signedPdf.length,
        timestamp: {
          attempted: this.deps.tsa.configured,
          present: result.timestamped,
          required: cfg.tsa.required,
          degraded: this.deps.tsa.configured && !result.timestamped,
          error: result.tsaError ?? null,
        },
        post_quantum: result.pqSealed
          ? {
              sealed: true,
              alg: "hybrid-ed25519-ml-dsa-65",
              key_id: result.pqKeyId,
              mldsa65_fpr: result.pqMldsa65Fpr,
              uuaid: result.pqUuaid ?? null,
            }
          : { sealed: false },
        archived_url: archivedUrl ?? null,
      },
    });

    return {
      signed_pdf_base64: result.signedPdf.toString("base64"),
      cert_fingerprint: material.cert.cert.certFingerprint,
      timestamped: result.timestamped,
      audit_id: audit.id,
      signed_at: signedAt.toISOString(),
      ...(result.pqSealed
        ? {
            pq_seal: {
              alg: "hybrid-ed25519-ml-dsa-65",
              key_id: result.pqKeyId!,
              mldsa65_fpr: result.pqMldsa65Fpr!,
            },
          }
        : {}),
      ...(result.tsaError ? { tsa_error: result.tsaError } : {}),
      ...(principal.transitional ? { transitional_auth: true } : {}),
    };
  }
}
