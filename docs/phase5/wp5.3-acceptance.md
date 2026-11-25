# WP5.3: Self-hosted observability profile

Date: November 25, 2026

Measured on branch `worktree-agent-a5503ba061923ea25` (from `phase-5` = `8f000e0`), on the same
local macOS machine as WP5.0.1, with Docker Desktop running. Every number below comes from a
command run in this session, and the command is written next to it. No model was called. Every
run used the offline scripted provider and the in-process fixture.

## What was built

| Plan task | Where |
| --- | --- |
| 5.3.1 Ledger-derived OTel export | `src/purpleloop/reporting/telemetry.py`: `TelemetryLedger` (an `EvidenceLedger` subclass swapped in by `attach_telemetry`), `RunProjector`, `project_events`, OTLP/JSON encoding in the standard library, `FileExporter` (the default) and `OtlpHttpExporter` (built only from a signed Manifest 1.5 telemetry grant). |
| Namespace (plan §3.6) | [docs/telemetry-namespace.md](../telemetry-namespace.md). Its tables are generated from `EventKind` (`purpleloop telemetry-namespace --write/--check`). The event mapping is the rule `purpleloop.event.<kind>`, so it also covers kinds added later. |
| 5.3.2 Local collector profile | `compose.observability.yaml` (profile `observability`) and `targets/observability/collector.yaml` (OTLP/HTTP in, file out, no network exporter). |
| 5.3.3 Leak tests | `tests/phase5/test_telemetry_runs.py` imports the Phase 4 scanner `tests/phase4/test_sample_hygiene.py::scan` rather than copying it. |
| 5.3.4 Export failure is non-fatal | Per-run circuit, time budget, and the `telemetry-status.jsonl` status ledger ([ADR 0016](../adr/0016-telemetry-outside-the-tcb.md)). |
| 5.3.5 Wall-clock detection latency | `WallClockDetectionLatency` (advisory by type, labelled "wall clock on this machine") and `purpleloop telemetry-latency`. |
| 5.3.6 `purpleloop analyze` | `src/purpleloop/reporting/analysis.py`: verified bundles to Parquet via DuckDB (`duckdb==2.0.1`, a new pinned dependency, no pyarrow), plus `analyze-query`. |
| CLI | `src/purpleloop/telemetry_cli.py`, registered by one line in `phase5_cli.py`: `observe-suite`, `telemetry-export`, `telemetry-latency`, `telemetry-namespace`, `analyze`, `analyze-query`. |
| CI | `phase5.yml` job `observability`: namespace check plus the three telemetry test modules. It never starts the collector, and a test asserts that no workflow references the profile. Make targets: `observability-check`, `observability-up`, `observability-down`. |

### The bundle-digest decision

`TELEMETRY_EXPORT_FAILED` is **not** written to `evidence.jsonl`. Writing it there would shift
every later sequence number and parent hash, change `event_replay_hash`, and let a collector's
health move the replay-determinism figure. Instead it is a LIFECYCLE event in a separate
hash-chained, anchored `telemetry-status.jsonl` in the run directory. A `TELEMETRY_SPANS_DROPPED`
event follows it at termination. The consequences, each asserted by a test below:

- **Healthy sink:** the bundle is byte-identical with telemetry on and off, inventory included.
- **Failing sink:** the run directory gains `telemetry-status.jsonl` and its anchor, both
  inventoried. Every other member is byte-identical. The inventory, and anything that digests
  it, differs by exactly those two entries. We chose to seal the failure into the bundle so a
  reviewer holding only the bundle can see that the telemetry is incomplete.

## Plan §6 rows for WP5.3

| Checkpoint | Threshold | Result | Measurement |
| --- | --- | --- | --- |
| No leak through telemetry | 0 findings | **0 findings** on the full agent export (25 scenarios) and the full supportlab export (18 scenarios), including `agent-canary-exfiltration` and every brokered credential. Each export was also searched for every per-run token the suite issued, every fixture canary, and both brokered values: none present. Separately, the collector's own file output from the full agent suite: 0 findings. | `test_no_secret_reaches_the_full_suite_export[agent\|supportlab]`; for the collector output, `hygiene.scan(artifacts/observability/collector)` returned `[]` |
| …scan is not vacuous | planted leak caught | A canary, a bearer token, and a 48-hex token planted in a ledger event's `reason_code` are all reported by the scan over the export. A brokered value planted in free-text `data` is in the ledger and absent from the export (data minimization). | `test_the_telemetry_scan_catches_a_planted_leak` |
| …telemetry holds nothing the ledger lacks | every string traced | Over both full exports, every exported string attribute is either found in that run's redacted `evidence.jsonl` or is a `data_digest` recomputed from it (or one of 4 namespace constants). More than 1000 strings were checked per lane. | `test_every_exported_string_comes_from_the_redacted_ledger[agent\|supportlab]` |
| Telemetry changes nothing | byte-identical outcomes and verdicts | **Byte-identical bundles** (every inventoried digest, the summary, `evidence.jsonl`) with telemetry off and on for 3 agent scenarios and 3 supportlab scenarios. An off/off control is identical too, and a different scenario yields a different bundle, so the comparison is not vacuous. | `test_bundle_is_byte_identical_with_telemetry_on_and_off` (6 cases), `test_the_comparison_detects_a_real_difference` |
| …under fault injection | no outcome change | 8 fault modes on `agent-canary-exfiltration`: file sink's directory missing, file sink is a directory, collector down (closed port), collector refusing (503), collector answering non-HTTP, collector slower than the call timeout, collector slow enough to exhaust the time budget, and an exporter that raises. In every mode the `RunSummary` equals the telemetry-off run's, every non-telemetry bundle member is byte-identical, and the status ledger verifies with exactly `[TELEMETRY_EXPORT_FAILED, TELEMETRY_SPANS_DROPPED]`. Exported plus dropped spans equal the projection's total, and telemetry time stays within budget plus one call timeout. | `test_export_failure_changes_no_outcome[*]` (8 cases) |
| …live collector down | run continues | With the compose collector stopped, `observe-suite --collector-port 24318` on 2 agent scenarios gave `{"export_failures": 2, "runs": 2, "spans_dropped": 240, "spans_exported": 0, "statuses": {"passed": 2}}`, and each run directory holds `telemetry-status.jsonl`. | `docker compose -f compose.observability.yaml --profile observability down`, then `uv run purpleloop observe-suite --lane agent --collector-port 24318 --out artifacts/observability/collector-down --scenario agent-canary-exfiltration --scenario agent-indirect-ticket` |

## Other measurements

| Item | Command | Result |
| --- | --- | --- |
| Full agent suite, file sink | `time uv run purpleloop observe-suite --lane agent` | 25 of 25 passed, **2990 spans exported, 0 dropped, 0 failures**, verified suite bundle; 36.2 s wall |
| Full supportlab suite, file sink | `time uv run purpleloop observe-suite --lane supportlab --out artifacts/observability/supportlab-suite --spans artifacts/observability/supportlab-spans.jsonl` | 18 of 18 passed, **1708 spans exported, 0 dropped**; 14.6 s wall |
| Collector profile up | `docker compose -f compose.observability.yaml --profile observability up -d` (image `otel/opentelemetry-collector-contrib:0.128.0@sha256:1ab0baba…27bc7`, pulled in this session) | container up, `127.0.0.1:24318->4318/tcp`, log "Everything is ready" |
| Spans flowing to the collector | `time uv run purpleloop observe-suite --lane agent --collector-port 24318 --out artifacts/observability/collector-suite` | 25 of 25 passed, 2990 spans exported, 0 dropped; 32.3 s wall |
| What the collector wrote | `read_export` on `artifacts/observability/collector/collector-spans.jsonl` | 75 OTLP lines, **2990 spans**, 25 metric payloads. The set of (traceId, spanId, parentSpanId, name, start, end) **equals** the bundle ledgers' `project_events` projection. The bundle verifies (`valid: True, scenarios: 25`). |
| Live vs after-the-fact projection | `test_bundle_is_byte_identical_…`, `test_a_healthy_collector_receives_exactly_the_projection` | the exported spans (file and HTTP) equal `project_events` over the verified ledger, span for span |
| Namespace drift | `uv run purpleloop telemetry-namespace --check` | "matches EventKind". `test_every_event_kind_maps_to_a_distinct_namespaced_span` covers all 13 kinds, and `test_an_unknown_future_kind_maps_generically_and_projects` maps `shadow_suppressed` with no code change |
| Analysis export | `time uv run purpleloop analyze <agent suite bundle> --out artifacts/observability/analysis --query "SELECT status, count(*) AS runs, sum(findings) AS findings FROM runs GROUP BY status"` | rows: runs 25, events 2590, findings 25, detections 98; query `passed 25 25`; 5.7 s wall |
| Analysis refuses unverified | one space appended to `agent-goal-hijack/summary.json` in a copy of that bundle, then `uv run purpleloop analyze artifacts/observability/tampered --out artifacts/observability/analysis-refused` | exit 1, `REFUSED: BUNDLE_NOT_VERIFIED: … artifact digest mismatch: agent-goal-hijack/summary.json`; the output directory was not created |
| Analysis tests | `test_analysis.py` | table row counts checked against ledgers and summaries; tampered bundle, incomplete bundle (without `--allow-partial`), tampered Parquet, and forged `analysis.json` table names refused; analyst SQL cannot `read_csv`, `COPY … TO`, or re-enable external access |

### 5.3.5: wall-clock detection latency, beside the tick figure

Definition: for each detector rule that was observed, the time from the first ledger event of
the attack stage (`attack` for the baseline leg, `replay` for the replay leg) to the DETECTOR
event that recorded it. The timestamps come from the spans, which carry the ledger's event
timestamps. It includes the harness's own scoring work and the in-process fixture's speed, so it
is an upper bound on pipeline detection latency **on this machine**, not a detector property.
It is advisory by type and refused at every gate input (`test_a_wall_clock_figure_is_refused_at_every_gate`).

| Corpus | Detections | Logical ticks (the reported figure) | Wall clock on this machine | Command |
| --- | --- | --- | --- | --- |
| agent (file sink run) | 82 | median 2, max 4 | median 226.3 ms, min 138.7 ms, max 707.6 ms | `uv run purpleloop observe-suite --lane agent` |
| agent (collector run) | 82 | median 2, max 4 | median 164.6 ms, min 126.5 ms, max 382.4 ms | `latency_summary` over the collector's file output |
| supportlab | 36 | median 0, max 0 | median 63.2 ms, min 38.9 ms, max 99.5 ms | the supportlab `observe-suite` run above |

The two agent runs differ by about 60 ms at the median, on the same machine, the same day, and
the same corpus. That spread is why this figure stays advisory. Neither run replaces the tick
figure. Faking the figure is caught: `test_wall_clock_latency_moves_with_the_timestamps_so_it_cannot_be_faked`
pins it to exact timestamp differences, and `test_wall_clock_latency_from_a_real_export_matches_the_ledger`
recomputes every figure of a full-suite export from the ledger events directly.

## Test and suite results

| Command | Result |
| --- | --- |
| `uv run ruff check . && uv run ruff format --check . && uv run mypy` | all checks passed; 231 files formatted; mypy: no issues in 95 source files |
| `time uv run pytest tests/phase5 -q --no-cov` | **324 passed** in 198.05 s |
| `uv run pytest tests/phase5/test_telemetry.py tests/phase5/test_telemetry_runs.py tests/phase5/test_analysis.py -q --no-cov` (the CI job) | FILLED-BELOW |
| `uv run pytest --junitxml=artifacts/junit-wp5.3.xml` (full suite, under `nohup`) | FILLED-BELOW |

## Defects found

None in earlier phases' code. Two defects were found in this package's own first drafts, and a
test now covers each:

- The analysis query loaded tables by iterating over `analysis.json`'s own table names, which
  would have put file-supplied text into SQL. Fixed: names come only from the `TABLES` constant.
  Pinned by the forged-name case in `test_a_tampered_parquet_file_is_refused`.
- The first slow-collector case expected `TIME_BUDGET_EXHAUSTED`. Because the per-call timeout
  is clipped to the remaining budget, the last call can instead end as `TIMEOUT`. Both are
  correct, and the test now accepts either and asserts that some spans were exported (slow, not
  down).

## What this does not show

- **No lane admits Manifest 1.5 yet**, so the run manifest cannot carry the collector grant.
  The collector is authorized by a separate 1.5 manifest (`collector_manifest`) that the CLI
  signs with the **same ephemeral key** it signs the run manifest with. That shows the grant
  mechanism (signature, validity, named loopback asset, no URL accepted). It is not a second
  party's approval, and one author held every key. When WP5.1 widens the lanes, the grant should
  move into the run manifest.
- **The collector profile was run by hand on this machine only**, once up, once down. No CI lane
  starts it, by design. The pinned digest is the one Docker reported for the pulled tag
  (`docker inspect --format '{{json .RepoDigests}}'`). It was pulled and run on arm64 only.
- **Not run: the collector combined with `compose.phase2.yaml`.** `compose.observability.yaml`
  was validated (`docker compose … config -q`) and run standalone. The merged two-file
  configuration with the containerized fixture was not brought up.
- **Telemetry is lossy by design.** When the circuit opens, nothing is retried or buffered. The
  recovery path is `telemetry-export`, which rebuilds the projection from a verified bundle.
- **The byte-identity tests pin wall-clock seams** (event clock, adapter latency stopwatches,
  the runner's elapsed time) so that two runs can be compared exactly. The budget ledger and the
  telemetry time budget keep the real clock. The suite-level CLI runs (Inspect bridge, real
  clocks) were compared by status and verification only, not byte for byte.
- **Wall-clock latency is not detector latency.** It measures the harness pipeline on an
  in-process fixture. No real detector or SIEM is involved.
- **The leak scan is the Phase 4 pattern scanner** (shapes, the fixture canaries, the brokered
  values, the exact per-run tokens). It cannot find a secret of a shape it does not know. The
  contract test (every exported string traced to the ledger) bounds telemetry by the ledger's
  own redaction. It does not prove that redaction.
