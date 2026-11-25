# Reviewer walkthrough

The Phase 4 checkpoint asks whether an independent reviewer can reconstruct a passing run, a
denied run, and an incident from exported artifacts within 30 minutes. This is the protocol
for that session. It is measured with an actual reviewer and a timer, or the checkpoint is
recorded as **untested** — never asserted from the author's own familiarity.

## Setup (not counted against the 30 minutes)

Requirements: Python 3.12, `uv`, a checkout of this repository.

```console
uv sync --frozen
```

The three artifact sets live under `docs/samples/`:

- `docs/samples/passing-run/` — a complete, attested, verified run bundle.
- `docs/samples/denied-run/` — a run refused at admission (expired authorization).
- `docs/samples/incident/` — a run whose evidence cannot be accepted.

## The session

Start the timer. For each artifact set, answer three questions, using only the artifacts and
the commands below — not the source code and not the author.

1. **What was attempted?** (scenario, actor, objective)
2. **What was decided, and why?** (permitted/denied, by which control, with which reason code)
3. **What evidence proves it?** (which artifact, which check)

Useful commands:

```console
uv run purpleloop verify-bundle docs/samples/passing-run --attestation
uv run purpleloop audit-export docs/samples/passing-run /tmp/audit.json
uv run purpleloop verify-ledger docs/samples/passing-run/evidence.jsonl
```

Where to look:

- `summary.json` — status, reason, findings, the four oracle verdicts, teardown.
- `audit-export` output — every admission/policy/budget decision with its reason code, per
  run, plus the embedded manifest and keys; `how_to_verify` explains the digest checks.
- `report.html` — the human-readable rendering; advisory content is visually separated and
  labelled "not binding, gates nothing".
- For the denied run: the ledger's `ADMISSION` event carries the denial reason code.
- For the incident: `integrity-incident.json` and the failing `verify-bundle` output are the
  answer; the correct conclusion is that the run must not be accepted.

Stop the timer when all nine answers are written down.

## Recording the result

Record in `docs/phase4-acceptance.md`: the duration; whether each of the nine answers was
correct; every point of confusion (verbatim, not summarized into blandness); and the
reviewer's role plus their independence ("had not seen the project"), name only with consent.

If no independent reviewer was available by acceptance time, the record says **untested**, in
that word, with this protocol and the sample sets in place so it can be run later.

## The UI path (Phase 5, WP5.4)

The same session can be run in the local review UI instead of the CLI (ADR 0017). Use a
different reviewer from the CLI session, or the same reviewer on a later day, and time it the
same way. The plan (§4, 5.4.5) asks for the two durations to be compared.

```console
uv run purpleloop review docs/samples/passing-run docs/samples/denied-run docs/samples/incident
# open http://127.0.0.1:8765/ in a browser on the same machine
```

The UI binds to `127.0.0.1` only and runs no JavaScript. It is read-only: without
`--reviewer-key` it cannot write anything at all. It never modifies the sample directories.

Where to look, for the same three questions:

- **Index** lists the three sources with their verification status. The passing run shows
  *Verified: verify-bundle passed*. The denied run shows *Ledger only*: it has no sealed bundle,
  only a hash-chained ledger that verified. The incident shows **NOT VERIFIED** with the failing
  check. That banner is the answer for the incident.
- **Run page** (click the run): *What was attempted* (scenario, objectives, actor), *Decisions
  and reason codes* (for the denied run, the `ADMISSION` deny with `EXPIRED_MANIFEST`), *Oracle
  inputs* (oracle specifications and links to the redacted snapshots), and the full *Timeline*.
  Each sequence number links to that event's evidence page.
- **Blinding.** Oracle, detector and judge events, and the run's status, are hidden until you
  press *Reveal oracle verdicts for this run*. In the reconstruction session this is expected.
  You need the verdicts to answer question 2, so reveal them. The hiding exists for
  adjudication, not for this session.

The CLI commands above stay available, and `verify-bundle` is still the check of record. The UI
displays what `verify-bundle` concluded at startup and does not replace it.

### Adjudicating findings (WP5.0.8)

The UI and `purpleloop adjudicate` write the same signed `AdjudicationRecord` through the same
code. Records go to `<bundle>.adjudications/` beside the bundle, never inside it. Generate a
reviewer key that is not a harness key, then start the UI with it:

```console
uv run purpleloop adjudication-keygen ~/reviewer.pem ~/reviewer-public.pem
uv run purpleloop review <bundle> --reviewer-key ~/reviewer.pem --reviewer-key-id <your-id>
```

On a finding page the oracle's verdict stays hidden until you submit a label (true-positive,
false-positive, or cannot-tell), a rationale, and the evidence ids you relied on. If you press
*Reveal the oracle verdict before labelling*, the record says `blinded: false`.

### Recording the UI session

Record it the same way as the CLI session, in the WP5.4 acceptance note
(`docs/phase5/wp5.4-acceptance.md`). Add the CLI-vs-UI duration comparison, and note anything
that was found on one path and missed on the other. Until a reviewer runs it, the timed UI
session is **untested**.
