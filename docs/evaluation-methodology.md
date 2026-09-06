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
