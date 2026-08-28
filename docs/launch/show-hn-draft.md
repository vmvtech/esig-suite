# Show HN — launch draft (approved playbook rules)

Playbook rules in force: submit **once**, disclose affiliation, answer technical
questions, **never ask for votes or coordinate comments** (see the growth
playbook's Community rules and HN's own guidelines — vote manipulation gets the
domain penalized).

Deploy the site FIRST so /agents, /press, /llms.txt, and /robots.txt are live
when traffic arrives.

## Submission

- **Submit URL:** https://news.ycombinator.com/submit
- **Title (≤80 chars, primary):**

      Show HN: e-sig – Self-hosted, MIT-licensed PDF e-signature SDK

- **Alternative title:**

      Show HN: e-sig – MIT PDF e-signatures with post-quantum seals

- **URL field:** `https://e-sig.org`
- HN submissions take a URL **or** text, not both → post the description below
  as the **first comment** from the submitting account, immediately after
  submission.

## First comment (paste-ready)

I built e-sig because every e-signature API I looked at re-meters signing at
exactly the moment you embed it into your own product — per-envelope fees, your
documents on someone else's infrastructure.

So e-sig is an SDK, not a service. MIT-licensed, runs entirely in your Node.js
process: render HTML to PDF, sign with PKCS#7/PAdES, optionally add an RFC-3161
timestamp, verify, and write to an append-only, hash-chained audit log. Your
certs, your database, your storage. No egress in the signing path — a timestamp
authority only ever receives a SHA-256 hash, never the document.

It also ships an optional post-quantum hybrid seal: Ed25519 + ML-DSA-65
(FIPS 204) attached underneath the classical signature. Honest caveat: no PDF
reader natively validates ML-DSA in PAdES yet, which is exactly why the seal
rides beneath the RSA signature readers already trust. The PDF still opens in
Acrobat today, and if RSA/ECDSA falls tomorrow, the ML-DSA half of the seal
keeps yesterday's signatures unforgeable — for signatures the quantum threat
is retroactive forgery, not decryption.

Quickstart is about 60 seconds, no signup or API keys:
`npm install && npm run build && npm run quickstart` — it issues a cert, signs,
verifies, then rejects a tampered copy. Six ready-to-sign HTML documents to
start from live in `examples/templates`.

I also just shipped @e-sig/mcp, an MCP server for agent-driven signing:
an agent can create envelopes, send reminders, and react to lifecycle
webhooks, but cryptographic control of signing stays with a human by default
— the agent can prepare a signature, never fake one. Signer identity is
checked at one of four levels (L0/L1/L1p/L2), from a self-asserted UUAID up
to a registry-verified badge.

A few other things that might be interesting:

- A client-side public verifier: check a signed PDF in the browser without
  uploading it anywhere (https://e-sig.org/verify)
- A CLI and a GitHub Action to verify signed PDFs in CI:
  `npx -y -p @e-sig/core esig verify <file.pdf> --json`
  (https://github.com/vmvtech/esig-suite/blob/main/docs/verify-in-ci.md)
- @e-sig/uuaid: stamps the acting AI agent's identity into the audit log, for
  agent-signed documents
- A bug-hunt writeup: the DER zero-padding bug that failed our CI 6% of the
  time (https://github.com/vmvtech/esig-suite/blob/main/docs/blog/der-length-bug.md)

Limitations I'd rather you hear from me: self-issued certificates are
cryptographically valid but not trusted by default in stock PDF readers, and
this is signing infrastructure, not compliance-as-a-service.

Repo: https://github.com/vmvtech/esig-suite · npm: @e-sig/core
(Disclaimer: I'm the developer, and this is my project.)

Happy to answer anything about the signing path, the PQ seal design, or the
audit chain.

## Operating checklist for launch day

1. Deploy the site (robots.txt / llms.txt / agents / press live before the post).
2. Submit once, from the owner's account, in a Tue–Thu US-morning window if
   possible; do NOT resubmit if it doesn't take off.
3. Post the first comment immediately.
4. Staff the thread for 24h: answer technical questions factually, reproduce
   reported issues, never argue tone. Convert repeated questions into
   docs/tests within 7 days (playbook rule).
5. No upvote asks, no coordinated comments, no cross-platform vote solicitation.
6. Record the submission link + 24h signals in docs/growth/evidence/ per the
   playbook's evidence rules.
