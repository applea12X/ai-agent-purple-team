# WP5.0.8 — Adjudicated precision census: tooling

Date: November 24, 2026

Built on branch `worktree-agent-ae5b2a9b94bb7d7d6`, from `phase-5` at `8f000e0`, on the same
local macOS machine as WP5.0.1. Every number below comes from a command run in this session. No
model was called.

## Status

| Checkpoint (plan §6) | Threshold | Status |
| --- | --- | --- |
| Precision on adjudicated findings | ≥ 95%, Wilson bound, method stated | **Untested: needs a human adjudicator.** The tooling is built and tested. No real label exists. |

No adjudication label was produced in this work package, by any means. The checkpoint asks
whether a *human* agrees with the oracle. A label chosen by the author's AI assistant would
measure nothing, and recording one would be fabricating the checkpoint. Every
`AdjudicationRecord` in the tests was constructed by the test, with a label the test chose,
to exercise the tooling. None of those records is evidence about precision.

## What was built

- `src/purpleloop/review/sources.py` loads a run bundle, a suite bundle, or an audit export,
  and verifies it first. A bundle goes through `verify_bundle`. An audit export is checked for
  self-consistency: embedded SHA-256 values, the manifest signature, and findings against the
  embedded summary. It lists the **accepted findings**: every `Finding` in every run's
  `summary.json`, which only a binding verdict can produce. A finding's identity is
  `finding_id` within `bundle_digest`, the SHA-256 of the bundle's `inventory.json`. That is the
  attestation subject and the export's `bundle_inventory_sha256`, so a finding has the same
  identity in the bundle and in its export. Where repetitions repeat a finding id, the id is
  qualified as `<run>:<finding_id>`. A finding's **class** is its `scenario_id`: one seeded
  oracle on one scenario.
- `src/purpleloop/review/adjudication.py` is the one write path, shared with the WP5.4 UI. It
  signs an `AdjudicationRecord` 1.0 with the ADR 0002 construction (`sign_record`), checks it
  with `verify_adjudication`, and writes it with exclusive create to `<bundle>.adjudications/`
  beside the bundle. It refuses each of the following with a reason code: an unverified source;
  a citation that is not one of the finding's own evidence ids; a label that is not one of the
  three; a true-positive or false-positive label with no citation; a reviewer key whose **id or
  public key material** is the bundle's manifest, attestation or authorization key; and a
  records directory inside any bundle.
- `purpleloop adjudicate`:
  - `--list` prints each finding with its class, evidence count and bundle digest, then totals.
  - Interactive mode prints the finding's objectives, oracle *inputs* and cited evidence with
    the verdict hidden. It prompts for a label, a rationale, and citations (by number or id,
    checked and re-asked if wrong). It reveals the verdict only after the record is written.
    `--unblinded` shows the verdict first and records `blinded: false`.
  - `--labels FILE` is the non-interactive mode for tests. Each entry must state `blinded`
    explicitly, because the tool cannot observe what a reviewer saw when a label was chosen
    in a file.
  - Evidence is printed through `terminal_safe`, which neutralises ANSI, OSC and C1 control
    sequences, so a hostile payload cannot drive the reviewer's terminal.
- `purpleloop precision-report <records...> --bundle <b>... --trusted-key ID=PEM...` counts a
  record only if all of these hold: it parses, its signature verifies under a trusted key, it
  names a supplied bundle and an accepted finding in it, its citations belong to that finding,
  and its reviewer key is neither a harness key id nor harness key material. Every other record
  is listed as refused with its reason code. Per finding, the latest label from each reviewer
  counts. Reviewers who disagree make the finding *disputed*, which is reported and kept out of
  the figure. `cannot-tell` is reported and kept out of the denominator. The report gives
  `precision = tp/(tp+fp)`, the 95% Wilson interval (`scoring.phase3.wilson_interval`, the
  interval the project already uses), `n`, and the method. The method is **census** only when
  every distinct accepted-finding class in the supplied bundles has a counted label; otherwise
  it is **sample**, with the uncovered classes listed. Both the point estimate and the Wilson
  lower bound are compared with 0.95 and reported separately.
- `purpleloop adjudication-keygen` writes a reviewer Ed25519 key pair. The private key file is
  created with mode 0600 and is never overwritten.
- `PrecisionReport` and `AdjudicationRecord` are not `Scored`. Both are refused at the gate
  boundary by type (`GateInputError`, tested for the report here and for the record in the
  contracts tests).

## Measured

| Item | Command | Result |
| --- | --- | --- |
| Tooling tests | `uv run pytest tests/phase5/test_review_adjudication.py -q --no-cov` | **36 passed** in 5.40 s |
| Review package coverage (with the UI tests) | `make review-check` | 56 passed; `purpleloop.review` branch coverage 91.46% |
| The census population, real offline bundles | `uv run purpleloop agent-demo`, `supportlab-demo --fixture in-process`, `phase1-demo --fixture in-process` (each with `--output-dir` in the scratchpad), then `uv run purpleloop adjudicate --list <the three suite bundles>` | `TOTAL findings=48 classes=48 sources=3`, all three `verified`, exit 0 |
| Per lane | same | agent 25 findings / 25 classes (bundle `77696c2e…`); supportlab 18 / 18 (`e0ea2892…`); phase1 5 / 5 (`26e7ceb7…`) |
| Evidence a census reviewer reads | the `evidence=` column of the listing, summed | 371 cited evidence ids: 20 findings cite 6, 3 cite 8, 24 cite 9, 1 cites 11 |
| Bundle generation wall time | `time` on the three demo commands | 38.8 s, 13.0 s, 4.9 s |
| A perfect census cannot meet a 95% *lower bound* | `wilson_interval(48, 48)` | **[0.9259, 1.0]**. 47/48 gives 0.9792, [0.8910, 0.9963]; 46/48 gives 0.9583, [0.8602, 0.9885]. All-TP labels need n ≥ 73 before the Wilson lower bound reaches 0.95 (`wilson_interval(73, 73)` = [0.950008, 1.0]). |

The last row matters for whoever closes the checkpoint. The plan threshold is "≥ 95%, Wilson
bound, method stated". On this corpus, with every class labelled, the point estimate can meet
0.95 with at most two false positives (46/48). The Wilson lower bound cannot meet 0.95 at n = 48
even if every label is a true positive. The report gives both comparisons, and it does not
decide between them. Which comparison closes the checkpoint has to be a written decision. It
should not be picked after the labels are in.

### What the tests pin (selected)

- A record flipped after signing, an unsigned record, a record signed by an untrusted key, a
  record naming another bundle, malformed JSON, and a record signed by the manifest key under
  its own id are each refused with their own reason codes. The precision figure and `n` are
  then byte-for-byte what they were without the forgeries
  (`test_forged_unsigned_unknown_and_harness_records_are_refused`). This is the "fails when the
  metric is faked" test for this metric.
- A trusted key whose material is a harness key is refused even under a key id chosen to look
  independent (`test_a_trusted_key_that_is_harness_key_material_is_refused`).
- 19/20 gives the published Wilson interval [0.7639, 0.9911]
  (`test_the_wilson_bound_is_the_published_formula`).
- Census versus sample, disputes, the latest-label rule, and `cannot-tell` exclusion each have
  their own test.
- The 45 evidence bodies of the 24 evaluator-red-team cases (14 distinct), each used as a
  rationale, changed no stored verdict and no bundle byte, and only the reviewer's chosen label
  counted.
- Interactive mode: the verdict (`"status": "confirmed"`, `"verdict": "true"`) appears in the
  output only after `WROTE`. A wrong citation is refused and the prompt asks again.

## The checkpoint, for the human who closes it

These are the exact commands, run from the repository root. They need about one minute of
compute, then the reviewer's time for 48 findings and 371 evidence items.

```console
uv sync --frozen
uv run purpleloop agent-demo --output-dir artifacts/adjudication/agent
uv run purpleloop supportlab-demo --fixture in-process --output-dir artifacts/adjudication/supportlab
uv run purpleloop phase1-demo --fixture in-process --output-dir artifacts/adjudication/phase1
uv run purpleloop adjudicate --list artifacts/adjudication/*/*/   # expect findings=48 classes=48

# A reviewer key that is not a harness key. Keep it off the bundle host if possible.
uv run purpleloop adjudication-keygen ~/purpleloop-reviewer.pem ~/purpleloop-reviewer-public.pem

# Label every finding, blinded. Repeat for each of the three bundles (or use `purpleloop review`).
uv run purpleloop adjudicate artifacts/adjudication/agent/<timestamp> \
  --reviewer-key ~/purpleloop-reviewer.pem --reviewer-key-id <reviewer-id>

uv run purpleloop precision-report artifacts/adjudication/*/*.adjudications \
  --bundle artifacts/adjudication/agent/<timestamp> \
  --bundle artifacts/adjudication/supportlab/<timestamp> \
  --bundle artifacts/adjudication/phase1/<timestamp> \
  --trusted-key <reviewer-id>=$HOME/purpleloop-reviewer-public.pem \
  --output artifacts/adjudication/precision.json
```

The census needs every one of the 48 classes labelled. The report prints `method=census
classes=48/48` when that holds. Record the following in this note: the full `precision-report`
output, who held the reviewer key and how independent they are (key separation is by key, not
by person), how many records were blinded, and the decision on point estimate versus lower
bound.

## What this does not show

- **Precision.** No human label exists, so no precision figure exists. The checkpoint row is
  **untested: needs a human adjudicator**.
- **Blinding is per finding, not total.** A finding is listed because the binding oracle fired.
  A reviewer therefore knows the oracle said "attack succeeded" before reading anything. What
  is hidden is *how*: the oracle's observed state, the finding's impact, severity and status,
  and the detector and judge events. A blinded label tests whether the evidence supports the
  claim. It does not test whether the reviewer would have raised the claim unprompted.
- **The class is the scenario.** With one seeded finding per scenario, census over classes and
  census over findings coincide (48 = 48). A coarser grouping, for example by risk class, would
  need fewer labels and would claim less.
- **Labels-file mode trusts the file's `blinded` flag.** Interactive and UI modes set it from
  observed state. A labels file states it.
- **Key separation is structural.** It refuses harness keys by id and by material. It cannot
  tell whether two different keys are held by one person.
- **Offline bundles only.** The population counted here is the deterministic offline corpus.
  Bundles from a real-model run would have their own findings and their own census.
