# PurpleLoop telemetry namespace

The PRD §4 "versioned project event namespace" (plan §3.6). Every span, attribute, and metric
PurpleLoop exports is named here. The tables between the `GENERATED` markers are rendered from
`purpleloop.schemas.event.EventKind` and `purpleloop.reporting.telemetry` by

```
uv run purpleloop telemetry-namespace --write   # regenerate
uv run purpleloop telemetry-namespace --check   # exit 1 on drift
```

and `tests/phase5/test_telemetry.py` fails when this file and the code disagree, so a new event
kind cannot ship without its row. Do not edit the generated block by hand.

## Rules

- **Source.** Every value is read from a persisted, redacted `EvidenceEvent` — the value
  `EvidenceLedger.append` returned. Nothing is read from an adapter, the model plane, or the
  fixture (ADR 0016). The resource attribute `purpleloop.telemetry.source = ledger-projection`
  says so on every payload.
- **Data minimization.** Free-text event `data` is never exported. An event span carries the
  SHA-256 of its `data` (JCS), the identifier-shaped top-level keys, and numeric or boolean leaves
  to depth two whose keys are identifiers. Detector events additionally carry the observed rule
  ids and their logical-tick detection times, which the wall-clock latency figure needs.
- **Identifiers.** `traceId` is derived from the run's first event hash; an event span's
  `spanId` is the first 16 hex digits of its `event_hash`. The same ledger always projects to the
  same bytes, whether exported live or later with `purpleloop telemetry-export`.
- **Unknown kinds.** An event kind not in this table still exports, as
  `purpleloop.event.<kind>`. The mapping is a rule, not a lookup, so a new kind never breaks a
  run; it only fails the drift test until this document is regenerated.
- **Versioning.** `NAMESPACE_VERSION` is semantic: renaming, removing, or changing the meaning
  of a name is a major bump; adding a name is a minor bump. A new `EventKind` member adds a span
  name and is therefore a minor bump.
- **Wall clock.** Span timestamps are the ledger's event timestamps. Any latency computed from
  them is advisory and labelled *wall clock on this machine*; the logical-tick detection figure
  remains the reported one.

<!-- BEGIN GENERATED: purpleloop telemetry-namespace -->

Namespace version **1.0.0**, instrumentation scope `purpleloop.telemetry`.

### Spans

| Span name | One per | Parent |
| --- | --- | --- |
| `purpleloop.run` | run (`run_id`) | — |
| `purpleloop.stage` | run of consecutive events in one `stage` | `purpleloop.run` |

### Event spans, generated from `EventKind`

| `EventKind` | Wire value | Span name |
| --- | --- | --- |
| `LIFECYCLE` | `lifecycle` | `purpleloop.event.lifecycle` |
| `ORACLE` | `oracle` | `purpleloop.event.oracle` |
| `DETECTOR` | `detector` | `purpleloop.event.detector` |
| `DEFENSE` | `defense` | `purpleloop.event.defense` |
| `ADMISSION` | `admission` | `purpleloop.event.admission` |
| `POLICY` | `policy` | `purpleloop.event.policy` |
| `BUDGET` | `budget` | `purpleloop.event.budget` |
| `ADAPTER` | `adapter` | `purpleloop.event.adapter` |
| `RESULT` | `result` | `purpleloop.event.result` |
| `TERMINATION` | `termination` | `purpleloop.event.termination` |
| `MODEL` | `model` | `purpleloop.event.model` |
| `JUDGE` | `judge` | `purpleloop.event.judge` |
| `PROPOSAL` | `proposal` | `purpleloop.event.proposal` |
| *(any other value)* | `<kind>` | `purpleloop.event.<kind>` (lower-cased, `[a-z0-9_]` only) |

### Attributes

| Attribute | Type | On | Ledger source |
| --- | --- | --- | --- |
| `service.name` | string | resource | constant `purpleloop` |
| `purpleloop.telemetry.namespace_version` | string | resource | `NAMESPACE_VERSION` |
| `purpleloop.telemetry.source` | string | resource | constant `ledger-projection` |
| `purpleloop.run.id` | string | resource, run span | `run_id` |
| `purpleloop.manifest.digest` | string | resource | `manifest_digest` |
| `purpleloop.policy.digest` | string | resource | `policy_digest` |
| `purpleloop.scenario.id` | string | run span | `scenario_id` |
| `purpleloop.scenario.version` | string | run span | `scenario_version` |
| `purpleloop.run.events` | int | run span | events projected |
| `purpleloop.run.terminated` | bool | run span | a TERMINATION event seen |
| `purpleloop.run.termination_reason` | string | run span | TERMINATION `reason_code` |
| `purpleloop.run.status` | string | run span | TERMINATION `data.status` |
| `purpleloop.stage.name` | string | stage span | `stage` |
| `purpleloop.stage.events` | int | stage span | events in the stage |
| `purpleloop.event.kind` | string | event span | `kind` |
| `purpleloop.event.sequence` | int | event span | `sequence` |
| `purpleloop.event.hash` | string | event span | `event_hash` |
| `purpleloop.event.parent_hash` | string | event span | `parent_hash` |
| `purpleloop.event.actor` | string | event span | `actor` |
| `purpleloop.event.trace` | string | event span | `trace_id` |
| `purpleloop.event.stage` | string | event span | `stage` |
| `purpleloop.event.decision` | string | event span | `decision` |
| `purpleloop.event.reason_code` | string | event span | `reason_code` |
| `purpleloop.event.action_digest` | string | event span | `action_digest` |
| `purpleloop.event.schema_version` | string | event span | `schema_version` |
| `purpleloop.event.component_version` | string | event span | `component_version` |
| `purpleloop.event.data_digest` | string | event span | SHA-256 of JCS(`data`) |
| `purpleloop.event.data_keys` | string[] | event span | identifier keys of `data` |
| `purpleloop.data.<key>[.<key>]` | int, double, or bool | event span | numeric or boolean `data` leaves, depth ≤ 2, identifier keys only |
| `purpleloop.detector.rules_observed` | string[] | detector event span | `data.results[].rule_id` where `observed` |
| `purpleloop.detector.time_to_detect_ticks` | int[] | detector event span | `data.results[].time_to_detect`, aligned with `rules_observed` |
| `purpleloop.event.kind, purpleloop.event.decision` | string | `purpleloop.events` data point | count of ledger events with that kind and decision |

### Metrics

| Metric | Instrument | Unit |
| --- | --- | --- |
| `purpleloop.events` | cumulative monotonic sum, one point per (kind, decision) | `{event}` |

### Status-ledger reason codes (LIFECYCLE events, `telemetry-status.jsonl`)

- `TELEMETRY_EXPORT_FAILED` — the first export failure of a run; the circuit opens.
- `TELEMETRY_SPANS_DROPPED` — at termination, how many spans and metric payloads were never exported.

<!-- END GENERATED -->
