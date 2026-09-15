# Deterministic evaluation methodology

Phase 1 evaluates five deliberately vulnerable, synthetic fixtures. A result is evidence about
these exact scenarios, versions, seeds, and defenses; it is not a claim about real models or
production applications.

For every scenario the runner verifies seeded state, completes a clean task, attacks, reads
state and telemetry, and scores utility/security independently. It applies one pre-authorized
registered defense, resets data to the same seed hash, repeats the clean task and attack, and
scores again. Detector signals do not substitute for a state oracle. Harness authorization
does not make an application authorization failure legitimate.

`ground-truth.json` labels the vulnerable baseline and defended negative control for each
scenario. Seeded-finding recall is the number of the five expected findings observed divided
by five. False positives are security findings in labelled clean/defended executions, not
telemetry alerts about correctly blocked attack attempts. A blocked attempt may legitimately
trigger a detector; detector precision/recall are calculated against expected telemetry rules.
Detection delay uses injected logical ticks, not a claim about production wall-clock latency.

The acceptance replay test runs 20 complete paired evaluations per scenario. It compares each
trial's normalized event and oracle hashes with that scenario's first trial. All 100 trials,
including mismatches, are counted. Normalization excludes run IDs, trace IDs, timestamps, and
latency; hash-based evidence references become stable event-sequence references. Security
outcomes, input and policy digests, fixture data, defenses, and action arguments remain part of
the comparison. Baseline-versus-defended comparison measures effectiveness and is not expected
to have identical hashes.

Four defended runs per scenario provide 20 labelled negative controls. No scenario or failed
trial is silently excluded. Inconclusive oracles become skipped JUnit cases; harness faults
become errors. Reports retain baseline SARIF findings even for an effective defense. Finding
reproducibility is not automatically asserted from a single paired run.

Budgets reserve conservative operation bounds. Tokens in the budget ledger represent reserved
capacity, not cloud billing; all model responses are offline. Inspect JSON logs bridge the
canonical results without acting as an execution authority. The isolated acceptance lane is
required in addition to ASGI testing because only the former exercises Docker containment
and real socket behavior.

## Phase 2 note

The `supportlab` lane evaluates eighteen labelled synthetic scenarios across API and browser
surfaces. Recall and false positives are computed by `corpus_metrics` from
`scenarios/supportlab/ground-truth.json`, exactly as in Phase 1. Six workflows are authored on both
surfaces against one shared oracle; cross-surface agreement is reported per group and disagreements
are listed, never averaged into a rate. The API lane reports bit-exact deterministic replay; the
browser lane reports its own replay rate separately, with a stated reason for any gap, because a
browser is not bit-reproducible. A pre-run resource estimate is emitted and the actual-versus-
estimate delta is recorded per run; the deterministic dimensions — requests, records, and browser
contexts — match exactly, while wall time is reported as an estimate rather than a bound. Every
Phase 2 metric ships with a test that fails when the metric is faked.

## Phase 3 note

The `agent` lane evaluates twenty-five labelled synthetic scenarios against a RAG assistant.
Recall and false positives are computed by `corpus_metrics` from `scenarios/agent/ground-truth.json`,
exactly as in Phases 1 and 2 — and that metric now refuses advisory input at the type boundary
rather than averaging it in.

**Binding and advisory results are different kinds of thing, and are reported as such.** Every
scored artifact carries a `VerdictProvenance`. Only `deterministic` verdicts reach run status,
findings, the corpus metric, or any CI gate; `require_binding()` is the single place that rule is
written. Advisory results — an LLM judgement, a repeated stochastic measurement — are recorded,
reported, and inert. The HTML report separates them visually for the same reason the type exists:
an advisory number sharing a panel with a deterministic one inherits its credibility at a glance.

**Four numbers, never one.** Clean utility, utility under attack, attack success, and executed
unauthorized side effects measure four different things. Utility under attack is *measured*, by
re-running the legitimate task after the attack on the state the attack left behind, under a
distinct action and idempotency identity — not inferred from the clean leg that ran before the
attack. Model susceptibility and executed side effects stay separate: a model that complies while
the kernel blocks every tool call is a susceptibility result and an enforcement success, and it is
reported as both.

**Repetitions and intervals.** Stochastic figures require at least five repetitions and carry n,
seed policy, model pin, and exclusion count. Proportions use a Wilson interval; counts use a seeded
percentile bootstrap. Both methods are named where the number appears, and at n=5 the interval is
wide — 0.566 to 1.0 for a perfect five of five — which is the honest reading rather than a defect.
A repetition that does not complete is recorded with its reason and reported beside every number it
reduces; it never leaves the denominator quietly. `Finding.reproducible` is answered from the
repetition set and states its basis.

**Judging.** The judge runs only where a deterministic oracle returned `inconclusive`. Its input is
typed, bounded, and delimited, with untrusted spans wrapped and markup escaped. Citations are
validated against the evidence supplied; an invented citation abstains outright. Abstention is a
first-class outcome and is never coerced to `false`. Agreement with adjudicated labels is reported
as Krippendorff's alpha over the three-category scale, because abstention is neither agreement nor
disagreement with a substantive label, and as Cohen's kappa over the abstention-excluded subset with
its own n.

**What the judge numbers are not.** The deterministic lane scores the judge with a stand-in that has
one declared failure mode. Those figures measure the *harness's* evaluator hardening — delimiting,
citation validation, abstention — and are not evidence about any real model's resistance. The
negative control is what makes them a measurement: with delimiting removed, resistance must fall,
and it does. The adjudicated labels were frozen before the judge was tuned and their digest is
pinned in the test file, so tuning against them fails a test.

**Cost and tokens.** Token counts are real per-call counts from the provider. In the offline lane
the declared price is zero, so API cost is a measured zero rather than an unmeasured blank; a real
cost figure requires the stochastic lane. Per-call token expectations on a pin are calibrated once
from a measured run and then held fixed, the same discipline `ResourceCalibration` uses for wall
time; a scenario outside ±10% is named rather than absorbed by re-tuning. Detection delay is still
injected logical ticks, and real token counts beside it do not make it a wall-clock or billing claim.

**Determinism.** The agent lane replays bit-exactly because its provider makes no network call. That
measures the lane and the fixture, not a model. A stochastic lane against a real endpoint would
report its own measured variance, separately, and does not claim determinism.
