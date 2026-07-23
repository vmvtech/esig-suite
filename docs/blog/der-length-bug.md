# The bug that failed CI 6% of the time: trimming zeros from a cryptographic blob

*How a one-line "cleanup" in our PDF signature verifier became a random CI failure generator, why it took a reproducibility experiment to find, and what it taught us about treating cryptographic material as text.*

---

## The symptom: a flake that looked like a platform bug

Our first public PR for esig-suite had a CI failure that made no sense. The sign-then-verify round-trip test — sign a PDF, verify it, expect `ok: true` — failed on the Node 20 job. Node 22 passed. Re-run the workflow: pass. Run it again: fail, same job, ~1 in 16 runs.

The obvious hypothesis was wrong but seductive: *something in Node 20's crypto behaves differently*. We nearly shipped a `node-version >= 22` engine pin and moved on.

What stopped us: the entire sign/verify path is pure `node-forge`. No native modules, no OpenSSL bindings, nothing that touches the runtime's crypto implementation. A Node-version-specific failure in pure-JavaScript code is a claim that demands extraordinary evidence. So we ran the experiment instead.

## The experiment: sign until it breaks

The test signs a fresh PDF each run — fresh key, fresh RSA signature, fresh bytes. If the failure were deterministic, it would fail every time. It didn't. So the trigger had to be a property of the *random* signature bytes.

We wrote a loop: generate a signature, check its last byte, verify, repeat. If the failure correlated with any byte value, it would show up in a few hundred iterations.

It showed up at iteration ~130 of an expected ~256: **the verifier rejected a validly-signed PDF precisely when the RSA signature's final byte was `0x00`.** Same failure on Node 20 and Node 22. The "platform bug" was a 1-in-256 property of random bytes that happened to hit the Node 20 job first.

## The root cause: treating DER as if it were text

PDF digital signatures embed a PKCS#7 (CMS) blob in a hex string inside the `/Contents` entry. Because the blob's size isn't known until signing time, signers reserve a fixed-size region and **zero-pad** the remainder. Our verifier had to strip that padding before parsing:

```typescript
const trimmedHex = hexBlob.replace(/(00)+$/, "");
const pkcs7Der = Buffer.from(trimmedHex, "hex").toString("binary");
```

One regex. Reads like the obvious thing to do. It's wrong in a way that only fails probabilistically.

The padding isn't marked. "Trailing zeros" is not a property of the padding — it's a property of *whatever bytes happen to be at the end of the DER structure*, and a CMS SignedData ends with the signature value itself: 256 uniform-random bytes for a 2048-bit RSA key. When the last of those bytes is `0x00` (probability ~1/256), the regex eats real signature data. The DER no longer parses: `Too few bytes to read ASN.1 value`. One test, one CI job, ~6% of runs (four sign/verify cycles per test file × 1/256 each).

## The fix: let the format describe itself

DER is a TLV encoding. The outer structure — a ContentInfo SEQUENCE — declares its own length in bytes 1..n of its header. There is no ambiguity to resolve and no padding to guess at:

```typescript
function derTotalLength(buf: Buffer): number | null {
  if (buf.length < 2 || buf[0] !== 0x30) return null; // ContentInfo is a SEQUENCE
  const l0 = buf[1];
  if (l0 < 0x80) return 2 + l0;
  const n = l0 & 0x7f;
  if (n === 0 || n > 4 || buf.length < 2 + n) return null;
  let v = 0;
  for (let k = 0; k < n; k++) v = v * 256 + buf[2 + k];
  return 2 + n + v;
}

const derLen = derTotalLength(contentsBytes);
const pkcs7Der = contentsBytes.subarray(0, derLen).toString("binary");
```

Slice at the declared length; the zero-padding past the DER is ignored regardless of what the signature bytes happen to be. Deterministic for all inputs.

The regression test constructs the adversarial case directly — a synthetic CMS ending in an empty `signerInfos` SET, i.e. a real trailing `0x00` — so it fails deterministically against the old code instead of waiting for a 1/256 dice roll. We also found and fixed the same trim in a test helper (`signedAttrOids`) that had independently copied the pattern.

## The lessons

**1. Byte-level "cleanup" on cryptographic material is a correctness bug waiting for its probability.** Any transformation of a binary structure that isn't grounded in the format's own grammar — trim, strip, squeeze, normalize — is a guess about the data. Guesses fail at the tails of distributions, and cryptographic material is deliberately uniform. There is no "usually safe."

**2. Probabilistic failures need adversarial reproduction, not more CI retries.** Re-running a flaky workflow tells you the dice landed differently. The useful experiment is the one that converts "sometimes fails" into "fails when X" — in this case, looping until the signature ended in `0x00`. Once we could say the sentence "it fails when the last byte is zero," the fix was twenty minutes.

**3. Beware the convenient platform hypothesis.** "It's Node 20" felt like an explanation because it matched the CI matrix. But the code path was pure JavaScript, and pure JavaScript doesn't change semantics across LTS lines. When the platform explanation requires the platform to be doing something inexplicable, the bug is in your code. It almost always is.

**4. This class of bug only ever false-rejected — and that's why it survived.** A truncated DER never parses, so the failure mode was always "valid document rejected," never "invalid document accepted." Availability bugs are annoying; soundness bugs are existential. When you design verification pipelines, choose the failure direction deliberately — and then notice that the safe direction is exactly the one that lets bugs hide behind "just re-run it."

The fix shipped as [commit `3028359`](https://github.com/vmvtech/esig-suite/commit/30283594697129f4c73dbbc54376eface31c2b8f) in `@e-sig/core`. The browser verifier at [e-sig.org/verify](https://e-sig.org/verify) uses the same TLV-slicing logic — you can drop any signed PDF there and watch it not trim your zeros.
