"""WP5.3 unit and contract tests: the namespace, the span projection, exporters, and latency.

Run-level properties (byte identity with telemetry on and off, fault injection, leak scans over
a full suite) are in ``test_telemetry_runs.py``; the analysis export is in ``test_analysis.py``.
"""

from __future__ import annotations

import ast
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.control.manifest import ManifestError, ManifestVerifier
from purpleloop.reporting import telemetry
from purpleloop.reporting.gates import (
    GateInputError,
    _reference_event,
    budget_gate,
    critical_regression_gate,
    scope_gate,
)
from purpleloop.reporting.telemetry import (
    EVENT_SPAN_PREFIX,
    EXPORT_FAILED,
    NAMESPACE_VERSION,
    RUN_SPAN,
    SPAN_NAMES,
    SPANS_DROPPED,
    STAGE_SPAN,
    STATUS_LEDGER,
    WALL_CLOCK_LABEL,
    FileExporter,
    OtlpHttpExporter,
    RunProjector,
    TelemetryExportError,
    TelemetryLedger,
    TelemetryNotAuthorized,
    WallClockDetectionLatency,
    event_attributes,
    event_span_name,
    export_spans,
    namespace_doc_drift,
    project_events,
    read_export,
    read_status,
    render_namespace_tables,
    span_attributes,
    unix_nanos,
    wall_clock_detection_latency,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.supportlab import KEY_ID, supportlab_agent_manifest
from purpleloop.schemas.authorization import BudgetLimits
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.telemetry_cli import COLLECTOR_ASSET, collector_manifest

T0 = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
DIGEST = "a" * 64


def event(
    sequence: int,
    *,
    kind: EventKind | str = EventKind.LIFECYCLE,
    stage: str | None = "admission",
    ms: int = 0,
    run_id: str = "run-1",
    data: dict[str, Any] | None = None,
    reason: str | None = "TEST",
    decision: str | None = None,
) -> EvidenceEvent:
    return EvidenceEvent(
        schema_version="1.1.0",
        scenario_id="scenario-1",
        scenario_version="1.0.0",
        stage=stage,
        run_id=run_id,
        trace_id="trace-1",
        sequence=sequence,
        timestamp=T0 + timedelta(milliseconds=ms),
        actor="purple-team-runner",
        kind=kind,  # type: ignore[arg-type]
        manifest_digest=DIGEST,
        policy_digest=DIGEST,
        decision=decision,
        reason_code=reason,
        data=data or {},
    )


def write_ledger(path: Path, events: list[EvidenceEvent]) -> list[EvidenceEvent]:
    ledger = EvidenceLedger(path)
    return [ledger.append(item) for item in events]


class RecordingExporter:
    sink = "recording"

    def __init__(self) -> None:
        self.payloads: list[tuple[str, dict[str, Any]]] = []

    def export(self, signal: Any, payload: dict[str, Any], *, timeout: float) -> None:
        self.payloads.append((signal, payload))


# --- namespace ----------------------------------------------------------------------------------


def test_every_event_kind_maps_to_a_distinct_namespaced_span() -> None:
    assert set(SPAN_NAMES) == {kind.value for kind in EventKind}
    assert len(set(SPAN_NAMES.values())) == len(EventKind)
    for kind in EventKind:
        assert SPAN_NAMES[kind.value] == f"{EVENT_SPAN_PREFIX}{kind.value.replace('-', '_')}"
        assert event_span_name(kind) == SPAN_NAMES[kind.value]
    assert RUN_SPAN not in SPAN_NAMES.values() and STAGE_SPAN not in SPAN_NAMES.values()


def test_an_unknown_future_kind_maps_generically_and_projects(tmp_path: Path) -> None:
    """A kind added after this module was written must map without a code change."""
    assert event_span_name("some-future-kind") == "purpleloop.event.some_future_kind"
    assert event_span_name("Weird Kind!") == "purpleloop.event.weird_kind"
    assert event_span_name("") == "purpleloop.event.unknown"
    future = event(0).model_copy(update={"kind": "some-future-kind"})
    projector = RunProjector()
    spans = projector.feed(future) + projector.finish()
    names = [span["name"] for span in spans]
    assert "purpleloop.event.some_future_kind" in names
    assert span_attributes(spans[0])["purpleloop.event.kind"] == "some-future-kind"


def test_the_wp51_shadow_suppressed_kind_projects(tmp_path: Path) -> None:
    """WP5.1's SHADOW_SUPPRESSED arrived after this module; the generic rule covers it."""
    from purpleloop.schemas.event import SHADOW_EVENT_SCHEMA

    shadow = event(0, kind=EventKind.SHADOW_SUPPRESSED, stage="attack", decision="allow")
    shadow = shadow.model_copy(update={"schema_version": SHADOW_EVENT_SCHEMA})
    written = write_ledger(tmp_path / "evidence.jsonl", [shadow])
    spans = project_events(written).spans
    assert spans[0]["name"] == "purpleloop.event.shadow_suppressed"
    assert SPAN_NAMES["shadow-suppressed"] == "purpleloop.event.shadow_suppressed"
    assert span_attributes(spans[0])["purpleloop.event.kind"] == "shadow-suppressed"
    assert span_attributes(spans[0])["purpleloop.event.schema_version"] == SHADOW_EVENT_SCHEMA


def test_the_namespace_document_matches_the_enum() -> None:
    document = (ROOT / "docs" / "telemetry-namespace.md").read_text(encoding="utf-8")
    assert not namespace_doc_drift(document), "run: uv run purpleloop telemetry-namespace --write"
    for kind in EventKind:
        assert f"`{SPAN_NAMES[kind.value]}`" in document
    assert f"**{NAMESPACE_VERSION}**" in document


def test_namespace_drift_is_detected() -> None:
    document = (ROOT / "docs" / "telemetry-namespace.md").read_text(encoding="utf-8")
    assert namespace_doc_drift(document.replace("purpleloop.event.oracle", "purpleloop.x"))
    assert namespace_doc_drift("no generated block")
    assert not namespace_doc_drift(f"prefix\n{render_namespace_tables()}suffix")


def test_namespace_cli_check_and_print() -> None:
    runner = CliRunner()
    checked = runner.invoke(app, ["telemetry-namespace", "--check"])
    assert checked.exit_code == 0, checked.output
    printed = runner.invoke(app, ["telemetry-namespace"])
    assert printed.exit_code == 0 and "purpleloop.event.termination" in printed.output


def test_namespace_cli_reports_drift(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from purpleloop import telemetry_cli

    stale = tmp_path / "namespace.md"
    stale.write_text(
        "old\n<!-- BEGIN GENERATED: purpleloop telemetry-namespace -->\n<!-- END GENERATED -->\n"
    )
    monkeypatch.setattr(telemetry_cli, "NAMESPACE_DOC", stale)
    runner = CliRunner()
    assert runner.invoke(app, ["telemetry-namespace", "--check"]).exit_code == 1
    assert runner.invoke(app, ["telemetry-namespace", "--write"]).exit_code == 0
    assert not namespace_doc_drift(stale.read_text())


# --- projection ---------------------------------------------------------------------------------


def test_projection_shape_ids_and_parents(tmp_path: Path) -> None:
    events = write_ledger(
        tmp_path / "evidence.jsonl",
        [
            event(0, stage="admission", ms=0),
            event(1, kind=EventKind.POLICY, stage="attack", ms=5, decision="allow"),
            event(2, kind=EventKind.RESULT, stage="attack", ms=9, data={"data": {"tokens": 3}}),
            event(
                3, kind=EventKind.TERMINATION, stage="terminated", ms=12, data={"status": "passed"}
            ),
        ],
    )
    projection = project_events(events)
    spans = projection.spans
    by_id = {span["spanId"]: span for span in spans}
    assert len(spans) == 4 + 3 + 1  # events, stages, run
    trace_ids = {span["traceId"] for span in spans}
    assert len(trace_ids) == 1 and len(trace_ids.pop()) == 32
    for span in spans:
        assert len(span["spanId"]) == 16
        assert int(span["startTimeUnixNano"]) <= int(span["endTimeUnixNano"])
        if "parentSpanId" in span:
            assert span["parentSpanId"] in by_id
    roots = [span for span in spans if "parentSpanId" not in span]
    assert [root["name"] for root in roots] == [RUN_SPAN]
    run = span_attributes(roots[0])
    assert run["purpleloop.run.terminated"] is True and run["purpleloop.run.status"] == "passed"
    assert run["purpleloop.run.events"] == 4
    assert roots[0]["startTimeUnixNano"] == str(unix_nanos(events[0].timestamp))
    assert roots[0]["endTimeUnixNano"] == str(unix_nanos(events[-1].timestamp))
    for item in events:
        span = by_id[(item.event_hash or "")[:16]]
        assert span["name"] == SPAN_NAMES[item.kind.value]
        assert span_attributes(span)["purpleloop.event.hash"] == item.event_hash
    stages = [span_attributes(s)["purpleloop.stage.name"] for s in spans if s["name"] == STAGE_SPAN]
    assert sorted(stages) == ["admission", "attack", "terminated"]
    assert (
        span_attributes(by_id[(events[2].event_hash or "")[:16]])["purpleloop.data.data.tokens"]
        == 3
    )


def test_projection_is_deterministic_and_stable_across_batching(tmp_path: Path) -> None:
    events = write_ledger(
        tmp_path / "evidence.jsonl",
        [event(i, stage=("a" if i < 5 else "b"), ms=i) for i in range(9)]
        + [event(9, kind=EventKind.TERMINATION, stage="terminated", ms=10)],
    )
    assert project_events(events) == project_events(events)
    exporter = RecordingExporter()
    live = TelemetryLedger(tmp_path / "live" / "evidence.jsonl", exporter, batch_size=3)
    for item in events:
        live.append(item)
    assert len([p for s, p in exporter.payloads if s == "traces"]) > 1
    assert export_spans(p for s, p in exporter.payloads if s == "traces") == (
        project_events(live.verify()).spans
    )


def test_free_text_data_is_never_exported() -> None:
    item = event(
        0,
        data={
            "note": "free text that must stay in the ledger",
            "Bad Key": 1,
            "count": 2,
            "ratio": 0.5,
            "flag": True,
            "nested": {"inner": 4, "text": "hidden", "deeper": {"x": 1}},
        },
    )
    values = event_attributes(item)
    rendered = json.dumps(values)
    assert "free text" not in rendered and "hidden" not in rendered
    assert values["purpleloop.data.count"] == 2 and values["purpleloop.data.flag"] is True
    assert values["purpleloop.data.ratio"] == 0.5
    assert values["purpleloop.data.nested.inner"] == 4
    assert "purpleloop.data.nested.deeper.x" not in values
    assert values["purpleloop.event.data_keys"] == [
        "count",
        "flag",
        "nested",
        "note",
        "ratio",
    ]


def test_the_events_metric_counts_the_ledger_and_cannot_be_faked(tmp_path: Path) -> None:
    kinds = [EventKind.POLICY, EventKind.POLICY, EventKind.RESULT, EventKind.TERMINATION]
    decisions = ["allow", "deny", None, None]
    events = write_ledger(
        tmp_path / "evidence.jsonl",
        [
            event(i, kind=k, decision=d, ms=i)
            for i, (k, d) in enumerate(zip(kinds, decisions, strict=True))
        ],
    )
    metrics = [p for s, p in project_events(events).payloads if s == "metrics"]
    points = metrics[0]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"]
    observed = Counter(
        {
            (
                span_attributes(p)["purpleloop.event.kind"],
                span_attributes(p)["purpleloop.event.decision"],
            ): int(p["asInt"])
            for p in points
        }
    )
    expected = Counter((e.kind.value, e.decision or "none") for e in events)
    assert observed == expected
    assert sum(observed.values()) == len(events)


def test_a_second_run_in_one_ledger_gets_its_own_trace(tmp_path: Path) -> None:
    events = write_ledger(
        tmp_path / "evidence.jsonl",
        [event(0), event(1, kind=EventKind.TERMINATION), event(2, run_id="run-2")],
    )
    projection = project_events(events)
    assert len({span["traceId"] for span in projection.spans}) == 2
    assert [signal for signal, _ in projection.payloads] == ["traces", "metrics"] * 2
    with pytest.raises(ValueError):
        projector = RunProjector()
        projector.feed(events[0])
        projector.feed(events[2])


# --- the evidence-writer hook -------------------------------------------------------------------


def test_telemetry_ledger_writes_the_same_bytes_and_returns_the_same_events(
    tmp_path: Path,
) -> None:
    source = [event(i, ms=i) for i in range(4)] + [event(4, kind=EventKind.TERMINATION, ms=5)]
    plain = write_ledger(tmp_path / "plain" / "evidence.jsonl", source)
    live = TelemetryLedger(tmp_path / "live" / "evidence.jsonl", RecordingExporter())
    observed = [live.append(item) for item in source]
    assert observed == plain
    assert (tmp_path / "live" / "evidence.jsonl").read_bytes() == (
        tmp_path / "plain" / "evidence.jsonl"
    ).read_bytes()
    assert not (tmp_path / "live" / STATUS_LEDGER).exists()
    assert live.exported_spans == len(project_events(plain).spans) and live.failure is None


class FailingExporter:
    sink = "failing"

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls = 0

    def export(self, signal: Any, payload: dict[str, Any], *, timeout: float) -> None:
        self.calls += 1
        raise self.exc


@pytest.mark.parametrize(
    ("exc", "reason"),
    [
        (TelemetryExportError("HTTP_503"), "HTTP_503"),
        (RuntimeError("boom"), "EXPORTER_RuntimeError"),
        (MemoryError(), "EXPORTER_MemoryError"),
    ],
)
def test_export_failure_opens_the_circuit_and_is_recorded_once(
    tmp_path: Path, exc: Exception, reason: str
) -> None:
    exporter = FailingExporter(exc)
    live = TelemetryLedger(tmp_path / "evidence.jsonl", exporter, batch_size=2)
    source = [event(i, ms=i) for i in range(5)] + [event(5, kind=EventKind.TERMINATION, ms=6)]
    plain = write_ledger(tmp_path / "plain" / "evidence.jsonl", source)
    assert [live.append(item) for item in source] == plain
    assert exporter.calls == 1
    status = read_status(tmp_path)
    assert [s.reason_code for s in status] == [EXPORT_FAILED, SPANS_DROPPED]
    assert status[0].data["failure"] == reason and status[0].data["sink"] == "failing"
    total = len(project_events(plain).spans)
    assert status[1].data == {
        "spans_exported": 0,
        "spans_dropped": total,
        "payloads_dropped": 1,
        "at_event": plain[-1].event_hash,
    }
    assert live.dropped_spans == total


def test_a_projection_fault_never_reaches_the_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: RunProjector, item: EvidenceEvent) -> list[dict[str, Any]]:
        raise KeyError("bug")

    monkeypatch.setattr(RunProjector, "feed", broken)
    live = TelemetryLedger(tmp_path / "evidence.jsonl", RecordingExporter())
    written = live.append(event(0))
    assert live.verify() == [written]
    assert read_status(tmp_path)[0].data["failure"] == "PROJECTION_KeyError"


def test_a_status_ledger_fault_is_swallowed(tmp_path: Path) -> None:
    live = TelemetryLedger(tmp_path / "evidence.jsonl", FailingExporter(RuntimeError()))
    (tmp_path / STATUS_LEDGER).mkdir()  # the status ledger cannot be written at all
    for item in [event(0), event(1, kind=EventKind.TERMINATION)]:
        live.append(item)
    assert len(live.verify()) == 2 and live.failure == "EXPORTER_RuntimeError"


def test_time_budget_bounds_what_a_slow_sink_can_cost(tmp_path: Path) -> None:
    ticks = iter(range(0, 1000, 1))

    class SlowExporter(RecordingExporter):
        pass

    exporter = SlowExporter()
    live = TelemetryLedger(
        tmp_path / "evidence.jsonl",
        exporter,
        batch_size=1,
        time_budget_seconds=3,
        monotonic=lambda: float(next(ticks)),  # every export "takes" one second
    )
    for item in [event(i, ms=i) for i in range(6)]:
        live.append(item)
    assert live.failure == "TIME_BUDGET_EXHAUSTED"
    assert len(exporter.payloads) == 3
    assert live.exported_spans == 3


# --- exporters ----------------------------------------------------------------------------------


def test_file_exporter_writes_otlp_json_lines(tmp_path: Path) -> None:
    target = tmp_path / "spans.jsonl"
    exporter = FileExporter(target)
    exporter.export("traces", {"resourceSpans": []}, timeout=0)
    exporter.export("metrics", {"resourceMetrics": []}, timeout=0)
    assert read_export(target) == [{"resourceSpans": []}, {"resourceMetrics": []}]
    with pytest.raises(TelemetryExportError, match="FILE_WRITE_FAILED"):
        FileExporter(tmp_path / "missing" / "spans.jsonl").export("traces", {}, timeout=0)


def test_http_exporter_only_from_a_signed_telemetry_grant() -> None:
    key = Ed25519PrivateKey.generate()
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    granted = collector_manifest(key, port=24999, now=T0)
    exporter = OtlpHttpExporter.from_manifest(granted, verifier, now=T0 + timedelta(minutes=1))
    assert (exporter.host, exporter.port) == ("127.0.0.1", 24999)
    assert exporter.sink == f"otlp-http:{COLLECTOR_ASSET}"
    with pytest.raises(TelemetryNotAuthorized):
        OtlpHttpExporter.from_manifest(
            supportlab_agent_manifest(key, now=T0), verifier, now=T0 + timedelta(minutes=1)
        )
    with pytest.raises(ManifestError):
        OtlpHttpExporter.from_manifest(
            granted,
            ManifestVerifier({KEY_ID: Ed25519PrivateKey.generate().public_key()}),
            now=T0 + timedelta(minutes=1),
        )
    with pytest.raises(ManifestError):
        OtlpHttpExporter.from_manifest(granted, verifier, now=T0 + timedelta(days=365))
    assert "url" not in OtlpHttpExporter.from_manifest.__code__.co_varnames


def test_collector_manifest_adds_exactly_one_asset_and_the_grant() -> None:
    key = Ed25519PrivateKey.generate()
    base = supportlab_agent_manifest(key, now=T0)
    granted = collector_manifest(key, now=T0)
    assert granted.schema_version == "1.5.0"
    assert granted.phase5 is not None and granted.phase5.telemetry == COLLECTOR_ASSET
    assert {a.asset_id for a in granted.assets} - {a.asset_id for a in base.assets} == {
        COLLECTOR_ASSET
    }
    assert granted.allowed_operations == base.allowed_operations


def test_attach_refuses_unsafe_placements(tmp_path: Path) -> None:
    class Runtime:
        def __init__(self, ledger: EvidenceLedger) -> None:
            self.ledger = ledger

    class Runner:
        def __init__(self, ledger: EvidenceLedger) -> None:
            self.runtime = Runtime(ledger)

    bundle = tmp_path / "bundle"
    runner: Any = Runner(EvidenceLedger(bundle / "evidence.jsonl"))
    with pytest.raises(ValueError, match="outside the evidence bundle"):
        telemetry.attach_telemetry(runner, FileExporter(bundle / "spans.jsonl"))
    attached = telemetry.attach_telemetry(runner, FileExporter(tmp_path / "spans.jsonl"))
    assert runner.runtime.ledger is attached and attached.path == bundle / "evidence.jsonl"
    with pytest.raises(ValueError, match="already attached"):
        telemetry.attach_telemetry(runner, FileExporter(tmp_path / "spans.jsonl"))
    written: Any = Runner(EvidenceLedger(tmp_path / "other" / "evidence.jsonl"))
    written.runtime.ledger.append(event(0))
    with pytest.raises(ValueError, match="before the run"):
        telemetry.attach_telemetry(written, FileExporter(tmp_path / "spans.jsonl"))


# --- 5.3.5 wall-clock detection latency ---------------------------------------------------------


def _detector(sequence: int, ms: int, results: list[dict[str, Any]]) -> EvidenceEvent:
    return event(
        sequence, kind=EventKind.DETECTOR, stage="detect", ms=ms, data={"results": results}
    )


def latency_ledger(tmp_path: Path, *, detect_ms: int = 250) -> list[EvidenceEvent]:
    rule = {"rule_id": "rule-a", "expected": True, "observed": True, "time_to_detect": 2}
    quiet = {"rule_id": "rule-b", "expected": False, "observed": False, "time_to_detect": None}
    return write_ledger(
        tmp_path / "evidence.jsonl",
        [
            event(0, stage="clean", ms=0),
            event(1, stage="attack", ms=100),
            event(2, stage="attack", ms=180),
            event(3, stage="score", ms=200),
            _detector(4, detect_ms, [rule, quiet]),
            event(5, stage="replay", ms=1000),
            _detector(6, 1040, [quiet]),
            event(7, kind=EventKind.TERMINATION, stage="terminated", ms=1100),
        ],
    )


def test_wall_clock_latency_is_the_span_timestamp_difference(tmp_path: Path) -> None:
    figures = wall_clock_detection_latency(project_events(latency_ledger(tmp_path)).spans)
    assert figures == [
        WallClockDetectionLatency(
            run_id="run-1",
            scenario_id="scenario-1",
            leg="baseline",
            rule_id="rule-a",
            logical_ticks=2,
            wall_clock_ms=150.0,
        )
    ]
    assert figures[0].label == WALL_CLOCK_LABEL == "wall clock on this machine"
    assert figures[0].provenance == "advisory"


def test_wall_clock_latency_moves_with_the_timestamps_so_it_cannot_be_faked(
    tmp_path: Path,
) -> None:
    later = wall_clock_detection_latency(
        project_events(latency_ledger(tmp_path, detect_ms=730)).spans
    )
    assert [f.wall_clock_ms for f in later] == [630.0]
    assert [f.logical_ticks for f in later] == [2]  # the tick figure is untouched


def test_latency_summary_keeps_both_figures_labelled(tmp_path: Path) -> None:
    figures = wall_clock_detection_latency(project_events(latency_ledger(tmp_path)).spans)
    summary = telemetry.latency_summary(figures)
    assert summary["wall_clock_ms"]["label"] == WALL_CLOCK_LABEL
    assert "logical ticks" in summary["logical_ticks"]["label"]
    assert summary["logical_ticks"]["median"] == 2 and summary["wall_clock_ms"]["median"] == 150.0
    assert telemetry.latency_summary([])["detections"] == 0


def test_latency_cli_reads_an_export(tmp_path: Path) -> None:
    events = latency_ledger(tmp_path)
    exporter = FileExporter(tmp_path / "spans.jsonl")
    for signal, payload in project_events(events).payloads:
        exporter.export(signal, payload, timeout=0)
    result = CliRunner().invoke(app, ["telemetry-latency", str(tmp_path / "spans.jsonl"), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)[0]["wall_clock_ms"] == 150.0


def test_a_wall_clock_figure_is_refused_at_every_gate(tmp_path: Path) -> None:
    figure = wall_clock_detection_latency(project_events(latency_ledger(tmp_path)).spans)[0]
    with pytest.raises(GateInputError):
        scope_gate([_reference_event(), figure])  # type: ignore[list-item]
    with pytest.raises(GateInputError):
        budget_gate([], BudgetLimits(requests=1, records=1), [figure])  # type: ignore[list-item]
    with pytest.raises(GateInputError):
        budget_gate([figure], BudgetLimits(requests=1, records=1), [])  # type: ignore[list-item]
    with pytest.raises(GateInputError):
        budget_gate([], figure, [])  # type: ignore[arg-type]
    with pytest.raises(GateInputError):
        critical_regression_gate(figure, {})  # type: ignore[arg-type]


# --- isolation from the producing planes --------------------------------------------------------


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def test_telemetry_is_imported_only_by_the_reporting_and_cli_layers() -> None:
    """Spans come from the evidence writer, never from adapters, the model plane, or the fixture."""
    package = ROOT / "src" / "purpleloop"
    importers = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if "purpleloop.reporting.telemetry" in _imports(path)
    }
    assert importers == {"reporting/analysis.py", "telemetry_cli.py"}
    for plane in ("adapters", "fixture", "runtime", "control", "scoring", "schemas"):
        for path in (package / plane).rglob("*.py"):
            assert not any("telemetry" in name for name in _imports(path)), path


# --- 5.3.2 the collector profile ----------------------------------------------------------------


def test_the_collector_profile_is_off_by_default_pinned_and_loopback_only() -> None:
    import yaml

    from purpleloop.telemetry_cli import COLLECTOR_PORT

    compose = yaml.safe_load((ROOT / "compose.observability.yaml").read_text())
    service = compose["services"]["otel-collector"]
    assert service["profiles"] == ["observability"]  # never started by a plain `up`
    image = service["image"]
    assert image.startswith("otel/opentelemetry-collector-contrib:") and "@sha256:" in image
    assert all(port.startswith("127.0.0.1:") for port in service["ports"])
    assert int(service["ports"][0].split(":")[1]) == COLLECTOR_PORT
    assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
    assert compose["networks"]["supportlab-isolated"]["internal"] is True
    config = yaml.safe_load((ROOT / "targets" / "observability" / "collector.yaml").read_text())
    assert set(config["exporters"]) == {"file"}  # nothing leaves the machine
    for pipeline in config["service"]["pipelines"].values():
        assert pipeline["exporters"] == ["file"]


def test_no_ci_lane_starts_the_collector() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = workflow.read_text()
        assert "compose.observability.yaml" not in text, workflow.name
        assert "--collector-port" not in text, workflow.name
