# ADR 0017: The review UI is local, read-only, inert, and writes only signed adjudication records

Status: accepted for Phase 5 (WP5.4; the adjudication write path is shared with WP5.0.8).

## Context

Phase 5 plan §2.5: a human-review UI has to display what the corpus deliberately contains —
hostile HTML, Markdown and injection payloads (`agent-indirect-html`, `agent-indirect-markdown`,
the evaluator red-team set). A UI that can write anything can, eventually, write over the
evidence it shows. And a human label that looks like a verdict invites someone to gate on it.
Plan open question 9 recommended FastAPI with server-rendered templates and no client framework.

## Decision

- **Stack.** FastAPI (already a dependency), server-rendered by `review/markup.py`, a small
  builder that escapes by default. Jinja2 is not installed. Adding it would have meant a new
  dependency only to get autoescaping that the builder already enforces, and the builder can
  enforce more than escaping: a **tag and attribute allowlist** checked at render time (no
  `script`, `style`, `iframe`, `img`, `svg`, `base`, `on*` handler or `style` attribute can be
  emitted even by mistake). Links must be same-origin absolute paths built from fixed segments
  and **integer indexes**. No bundle string ever appears in a URL.
- **No JavaScript anywhere.** Every page, not just the evidence pages, ships without script. Every
  interaction (reveal, label) is a plain form POST. The CSP on every response is
  `default-src 'none'; style-src 'self'; img-src 'none'; form-action 'self'; frame-ancestors
  'none'; base-uri 'none'`. There is no `script-src`, so scripts fall back to `'none'`. Styles come
  from one same-origin stylesheet. FastAPI's `/docs`, `/redoc` and `/openapi.json` are disabled,
  because the default docs page loads script from a CDN.
- **Read-only.** Sources are loaded and verified once at startup (`review/sources.py`). Bundle
  files are never served raw and never opened for writing. The only write is
  `review/adjudication.py::write_adjudication`, which the CLI also calls. It signs an
  `AdjudicationRecord` (contract §3.4, the ADR 0002 construction) and writes it with exclusive
  create to `<bundle>.adjudications/`. It refuses a records directory inside any bundle.
- **Local only.** `serve` refuses every bind address except `127.0.0.1` (`0.0.0.0`, `::`, `::1`,
  `localhost` and LAN addresses included). A request whose `Host` is not the bound address is
  refused with 421, to stop DNS rebinding. Every POST needs the session's random form token and,
  when the browser sends `Origin`, a same-origin one, to stop cross-site form posts from another
  tab. There are no accounts and no hosting (a non-goal).
- **Blinded by default.** The verdict-bearing parts are masked until the reviewer records a
  label or explicitly reveals the verdict. Those parts are the oracle, detector and judge events,
  the summary's oracle results, status and reason, and the finding's status, impact, severity and
  confidence. The state lives on the server, not in a form field, so the browser cannot claim
  `blinded: true`. A reveal is remembered for the session. A returning reviewer's earlier records
  count as having seen the verdict.
- **A label is not a verdict.** `AdjudicationRecord` is not `Scored` and carries no provenance.
  The precision report is a plain model. The gates refuse both by type (`GateInputError`, tested).
- **Key separation.** A reviewer key whose id or public key material is one the bundle signs or
  attests with is refused, at write time and again when precision is computed.

## Consequences

- Reviewing a run from an audit export shows decisions and reason codes, but not event bodies,
  because the export embeds no event bodies. The UI says so, and an export that repeats a finding
  id across repetitions is not adjudicable from the export.
- The UI holds blinding state in process memory, so a restart forgets an explicit reveal that
  was not followed by a label. Records already written are re-read on startup.
- Key separation is by key id and key material. It is not a claim about people: two keys held
  by one author are still one author.

## Verification of this ADR

`tests/phase5/test_review_ui.py` checks the headers on every response. It renders 1588 distinct
corpus payloads into every untrusted position and parses each of 4442 pages for executable
markup, and it asserts that each payload reached the page as text. It covers the bind refusals,
the Host, Origin, token and size guards, blinding and reveal flags, and a full adjudication
session with bundle bytes, modification times, digests and the attestation unchanged.
`tests/phase5/test_review_adjudication.py` covers the shared write path and the precision
report's refusals. Numbers are in `docs/phase5/wp5.4-acceptance.md`.
