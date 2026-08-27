# Verify e-signed PDFs in CI

`@e-sig/core` ships an `esig` CLI that wraps `verifyDocument()` — classical
PAdES/PKCS#7 verification plus the optional post-quantum (ML-DSA-65) hybrid
seal — as a scriptable command, and this repo ships a composite GitHub
Action, [`action.yml`](../action.yml), that runs it against a list of files
and posts a markdown summary. There is no key material anywhere in either
path: verification is a pure function of the document bytes plus, optionally,
an expected signer identity you pin on the command line.

## Using the CLI locally

```sh
npm i @e-sig/core   # or: npx -y -p @e-sig/core esig verify --help

npx -y -p @e-sig/core esig verify signed.pdf
# signed.pdf: OK
#   digest valid:      yes
#   signature valid:   yes
#   signer:            E-sig (Acme Inc)
#   timestamped:       no
#   post-quantum:      not present
#   failures:
```

Verify several files, require the post-quantum seal, and pin the expected
UUAID, emitting machine-readable JSON:

```sh
npx -y -p @e-sig/core esig verify contracts/*.pdf \
  --require-pq \
  --expected-uuaid uuaid:acme:agent:018f9f7a-7b4c-7cc2-9b7f-7b7d6d16a001 \
  --json
```

`--json` prints exactly one line to stdout — a JSON array of
`{file, verification}`, where `verification` is the `DocumentVerification`
shape from `@e-sig/core` (`classical`, `postQuantum`, `ok`) — and nothing
else. Everything else (usage errors, unreadable files) goes to stderr.

**Exit codes:**

| Code | Meaning |
| ---: | --- |
| `0` | every file verified ok |
| `1` | at least one file failed verification |
| `2` | usage error or I/O error (bad flag, missing/unreadable file) |

That three-way split is deliberate: a CI job can tell "the document is bad"
(1, fail the release) apart from "you called this wrong" (2, fix the
workflow) without parsing stderr text.

Run `npx -y -p @e-sig/core esig --help` for the full flag reference
(`--quiet` for one line per file instead of the full block, `--version`,
`--expected-mldsa65-fpr` to pin the post-quantum signer fingerprint directly
instead of a UUAID).

## Using the Action

Add [`action.yml`](../action.yml) to a workflow, pointing `uses:` at this
repo (or your fork of it) and listing the PDFs to verify:

```yaml
name: Verify signed contracts

on:
  pull_request:
    paths:
      - "contracts/**/*.pdf"

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: vmvtech/esig-suite@main # or a pinned tag/SHA
        with:
          files: |
            contracts/*.pdf
            legal/agreements/*.pdf
          require-pq: "false"
          # expected-uuaid: uuaid:acme:agent:018f9f7a-7b4c-7cc2-9b7f-7b7d6d16a001
          version: "^0.8.0"
```

### Inputs

| Input | Required | Default | Meaning |
| --- | --- | --- | --- |
| `files` | yes | — | Newline-separated file paths or globs to verify. Each line is glob-expanded by the action; a line matching nothing is skipped with a `::warning::`. |
| `require-pq` | no | `"false"` | Set to `"true"` to fail any file without a valid post-quantum seal (`esig verify --require-pq`). |
| `expected-uuaid` | no | `""` | Pin the post-quantum seal's asserted UUAID (`esig verify --expected-uuaid`). Empty = no pinning. |
| `version` | no | `"^0.8.0"` | npm version spec for `@e-sig/core`, passed to `npx -y -p @e-sig/core@<version> esig verify`. |

### What it does

1. `actions/setup-node@v4` with Node 22.
2. A bash step expands `files` into a flat file list, runs
   `npx -y -p @e-sig/core@<version> esig verify <files...> --json [--require-pq] [--expected-uuaid <u>]`,
   and writes a markdown table to `$GITHUB_STEP_SUMMARY` — one row per file
   (result, digest, signature, signer, post-quantum status) plus one row per
   failure reason under any file that failed.
3. Exits `1` (job fails) when any document fails verification, `2` when the
   `files` input matches nothing or the CLI itself hit a usage/I/O error, `0`
   when every document verifies.

### What the summary looks like

For one valid, sealed document and one tampered one:

| File | Result | Digest | Signature | Signer | Post-quantum |
| --- | --- | --- | --- | --- | --- |
| contracts/msa.pdf | ✅ OK | valid | valid | E-sig (Acme Inc) | ✅ ok |
| contracts/tampered.pdf | ❌ FAIL | invalid | valid | E-sig (Acme Inc) | ❌ FAIL |
| | | | | | document digest does not match messageDigest attribute — content altered after signing |
| | | | | | post-quantum digest does not match the document — content altered |

The job fails (exit `1`) whenever any row reads `❌ FAIL`.
