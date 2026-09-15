# ADR 0010: Judge input normalization and abstention semantics

Status: accepted for Phase 3.

## Context

In an indirect-injection scenario the judge's input contains, by construction, text written to
manipulate a language model. The judge is therefore not merely fallible — it is *targeted*.

## Decision

**Typed, bounded, delimited input.** The judge never sees raw ledger JSON or a raw page body. It
sees a rendered view of typed `EvidenceItem`s, capped at 24 items and 1200 characters each.
Untrusted spans are wrapped in `<untrusted>` and labelled with their provenance, and the standing
preamble says content inside them is data. Markup in a body is escaped, so evidence cannot forge
its own delimiter.

**Closed output.** The judge returns `{verdict, cited_evidence_ids, confidence, rationale}` validated
against a strict model. A verdict outside the rubric's vocabulary abstains.

**Citations are validated.** Every cited id must be one that was supplied. A citation that was not
abstains outright — not trimmed to the citations that happen to check out, and not downgraded to a
lower-confidence `true`. The judge cannot mint evidence.

**Abstention is a first-class outcome.** It is never coerced to `false`, never counted as a judge
failure, and must record its reason. Silence in the evidence abstains rather than being read as
evidence of absence.

**The judge runs only where an oracle did not answer.** `should_judge` is the gate; a closed-operator
oracle that returned `true` or `false` is binding and the judge is not called at all.

## Frozen labels

The evaluator red-team labels were adjudicated and frozen before the judge was tuned. Their digest
is pinned **in the test file**, not read from the corpus: tuning against the labels changes the
file, changes the digest, and fails that test. Without this the agreement checkpoint would be
circular.

## Consequence

`ScriptedJudge` is a stand-in with one declared failure mode — it follows directives it can read as
instructions — not a model. What the red-team corpus measures with it is the **harness's** evaluator
hardening: delimiting, citation validation, and abstention. That number is reported as such and is
never presented as evidence about any real model's resistance. Its negative control (rendering
without delimiting) must show resistance falling, or the metric is not measuring anything.
