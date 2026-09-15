# ADR 0013: Enforcing gates are pure decision functions, proven by red branches

Status: accepted for Phase 4.

## Context

Phase 4 turns the project's checkpoint discipline into CI enforcement: scope bypasses,
critical regressions, schema drift, budget failures, and per-risk-class regressions must
*block*, not merely be reported. Phase 4 also introduces the first real-model numbers, and the
two must never meet: a gate fed by a stochastic figure inherits its noise and destroys the
credibility of both. Separately, a gate that has never fired is exactly as trustworthy as a
metric that cannot fail.

## Decision

1. **Each gate is a pure, unit-tested decision function** in `reporting/gates.py`: typed inputs
   in, a typed `GateDecision` out, with a reason code and the fact that produced it. CI (the
   `purpleloop gates` command) calls exactly the functions the tests call.
2. **Gates read binding verdicts only.** Every summary entering a gate passes
   `require_binding`; an advisory or pinned-stochastic verdict is rejected at the type boundary
   (`AdvisoryVerdictError`), never averaged in. This extends ADR 0009's rule to every new gate,
   and `tests/phase4/test_gates.py` asserts it per gate.
3. **A gate handed nothing blocks.** An empty ledger, a missing JUnit report, or an absent
   pinning test blocks rather than passing vacuously: "the gate saw no evidence" and "the
   evidence was clean" are different facts.
4. **The per-risk-class regression test is pre-registered** (see
   `docs/evaluation-methodology.md`): deterministic per-class corpus metrics against a
   committed baseline; any newly missed seeded true positive blocks regardless of p-value; new
   false positives and defended-replay side effects block as deterministic facts; otherwise
   Fisher's exact at alpha = 0.05 blocks only a statistically meaningful loss. The baseline is
   updated only by an explicit `corpus-baseline` bump commit.
5. **The red-branch protocol proves the wiring.** For each gate class, a branch carries one
   minimal, loudly-labelled violation (the `gates --inject <class>` knob feeds a violating
   input through the same decision function), is pushed, and its CI run is observed red at the
   intended gate and green everywhere earlier, with the run URL recorded in the acceptance
   record. The unit tests prove the logic; the red branches prove the wiring; neither
   substitutes for the other.

## Consequences

- The gates cannot drift from the tests, because they are the same code.
- A real model can make a report worse; it can never make CI red.
- The `--inject` path is visibly labelled in output ("INJECTED <class> … red-branch proof") so
  an injected run can never be mistaken for a clean one.
