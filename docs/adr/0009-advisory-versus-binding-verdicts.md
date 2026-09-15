# ADR 0009: Advisory verdicts are separated from binding ones by type

Status: accepted for Phase 3.

## Context

Phases 0–2 produced one kind of verdict, so its provenance never had to be written down. Phase 3
adds real model calls, an adaptive attacker, and an LLM judge, and their results appear in the same
summary, the same bundle, and the same report as the deterministic ones. The failure mode to design
against is *silent promotion*: an advisory number leaking into a denominator, a status field, or a
gate, and inheriting the credibility of the deterministic ones.

## Decision

`VerdictProvenance` — `deterministic`, `advisory`, `pinned-stochastic` — is a required field on
every scored artifact: `OracleResult`, `JudgeResult`, `Finding`, `Measurement`, `RepetitionRecord`.
Existing results default to `deterministic`, which is what they have always been.

`require_binding()` is the single place the gate rule is written, and it is called at all three
gates: run status and mitigation credit in `PurpleTeamRunner`, and `corpus_metrics`. It raises
`AdvisoryVerdictError` rather than coercing or skipping.

`JudgeResult` refuses to be anything but `advisory`, by validator rather than by convention. It
cannot name a target, propose an action, alter a budget, or change a finding's status: no field on
it could carry any of those.

A `Measurement` that is not `deterministic` will not serialize without a model pin, so a stochastic
figure cannot be reported without saying what produced it.

## Verification

The central test builds the same summary twice — once with a judge that disagrees with the
deterministic oracle, once without — and asserts `corpus_metrics` is identical. Further tests assert
an advisory finding and an advisory negative control are each refused at the corpus gate, and that
an end-to-end run with the judge enabled produces the same status, mitigation credit, and finding
count as one without it.

## Consequence

No stochastic result gates a release-blocking invariant, and that is enforced by types and
assertions rather than by review. The cost is that advisory results are visible but inert: a judge
that spots something the oracles missed produces a recorded observation and nothing else. That is
the intended trade. The HTML report separates the two kinds visually for the same reason — an
advisory number sharing a panel with a deterministic one inherits its credibility at a glance.
