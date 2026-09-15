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
