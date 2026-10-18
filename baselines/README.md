# Committed gate baselines

These files are the committed reference the Phase 4 enforcing gates compare against
(ADR 0013). They change only through an explicit, reviewed baseline-bump commit — never as a
side effect of a run.

- `schema-digests.json` — canonical digests of frozen reference documents, written by
  `purpleloop schema-baseline`. The `schema-drift` gate blocks when the current code produces
  different canonical bytes for any reference, and when a new reference exists that this file
  does not record. An intended schema change ships its version bump and the regenerated
  baseline in the same commit. `tests/phase4/test_gates.py::
  test_committed_schema_baseline_matches_the_current_code` keeps this file and the code in
  agreement at test time.

- `corpus-baseline.json` — per-risk-class corpus metrics over the agent corpus, written by
  `purpleloop corpus-baseline` from a real offline run of all 25 scenarios. The
  `risk-class-regression` gate compares current metrics against it under the pre-registered
  test in `docs/evaluation-methodology.md` (absolute floor on lost seeded findings; Fisher's
  exact at alpha = 0.05 otherwise). To bump after deliberate corpus growth, re-run
  `uv run purpleloop corpus-baseline` and commit the diff with the change that motivated it.
