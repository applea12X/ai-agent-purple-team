"""WP5.3 run-level checkpoints on real lane runs (offline provider, in-process fixture).

- **Telemetry changes nothing.** The same scenario, run with telemetry off and on, yields
  byte-identical bundles: every inventoried member, the summary, the ledger. The wall-clock seams
  that differ between *any* two runs (event timestamps, adapter latencies, elapsed seconds) are
  pinned first, so the comparison is exact rather than normalized -- and the off/off control
  shows the comparison would catch a real difference.
- **Export failure is non-fatal and recorded.** File sink missing or unwritable; collector down,
  slow, refusing, or answering garbage; an exporter that raises. Every outcome is byte-identical
  to the telemetry-off run, and the only bundle difference is the telemetry status ledger.
- **No leak through telemetry.** The Phase 4 sample-hygiene scanner (imported, not copied) runs
  over the export of the full agent and supportlab corpora, which include the canary and
  brokered-credential cases; a planted leak proves the scan is not vacuous; every exported string
  is shown to come from the redacted ledger.
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import socket
import threading
import time
import types
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import purpleloop.adapters.agent as agent_adapter
import purpleloop.adapters.browser as browser_adapter
import purpleloop.adapters.phase1 as phase1_adapter
import purpleloop.runtime.runner as runner_module
from purpleloop import telemetry_cli
from purpleloop.control import phase2_tools
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.reporting.bundle import inventory, verify_bundle
from purpleloop.reporting.telemetry import (
    EXPORT_FAILED,
    RUN_SPAN,
    SPANS_DROPPED,
    STATUS_LEDGER,
    FileExporter,
    OtlpHttpExporter,
    TelemetryExporter,
    TelemetryLedger,
    attach_telemetry,
    event_attributes,
    export_spans,
    project_events,
    read_export,
    read_status,
    span_attributes,
    wall_clock_detection_latency,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.supportlab import (
    ALL_CANARIES,
    KEY_ID,
    InProcessSupportlab,
    build_agent_runner,
    build_supportlab_runner,
    supportlab_agent_manifest,
    supportlab_manifest,
)
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import RunSummary, load_scenario
from purpleloop.telemetry_cli import ObservedLane, collector_manifest, observe_suite

_spec = importlib.util.spec_from_file_location(
    "phase4_sample_hygiene", ROOT / "tests" / "phase4" / "test_sample_hygiene.py"
)
assert _spec is not None and _spec.loader is not None
hygiene = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hygiene)

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
#: Fixed high-entropy-shaped actor tokens, so two runs redact identical values identically.
TOKENS = {actor: f"{index:02x}" * 24 for index, actor in enumerate(phase2_tools.ACTORS)}
CONTROL = "c0" * 24

AGENT_CASES = ("agent-canary-exfiltration", "agent-indirect-ticket", "agent-confused-deputy")
SUPPORTLAB_CASES = ("bola-ticket", "ssrf-link-preview", "refund-approval")


@pytest.fixture
def frozen_wall_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the monotonic reads that make two otherwise identical runs differ.

    Only the adapters' latency stopwatches and the runner's elapsed-seconds stopwatch: the
    budget ledger and the telemetry exporter keep the real clock, so wall-time budgets and the
    telemetry time budget still behave as they do in production.
    """
    frozen = types.SimpleNamespace(monotonic=lambda: 0.0)
    for module in (agent_adapter, browser_adapter, phase1_adapter, runner_module):
        monkeypatch.setattr(module, "time", frozen)


async def run_case(
    directory: Path,
    lane: str,
    scenario_id: str,
    exporter: TelemetryExporter | None = None,
    **options: Any,
) -> tuple[RunSummary, TelemetryLedger | None]:
    manifest = (
        supportlab_agent_manifest(KEY, seed=42, now=NOW)
        if lane == "agent"
        else supportlab_manifest(KEY, seed=42, now=NOW)
    )
    verifier = ManifestVerifier({KEY_ID: KEY.public_key()})
    fixture = InProcessSupportlab(dict(TOKENS), CONTROL)
    build = build_agent_runner if lane == "agent" else build_supportlab_runner
    runner = build(
        directory, manifest, verifier, actor_tokens=dict(TOKENS), control=CONTROL, fixture=fixture
    )
    counter = itertools.count()
    runner.runtime.clock = lambda: NOW + timedelta(milliseconds=next(counter))
    ledger = attach_telemetry(runner, exporter, **options) if exporter is not None else None
    scenario = load_scenario(ROOT / "scenarios" / lane / f"{scenario_id}.yaml")
    try:
        summary = await runner.run(scenario, manifest, run_id=scenario_id, output_dir=directory)
    finally:
        if not fixture.closed:
            await fixture.close()
    inventory(directory, complete=False)
    verify_bundle(directory, allow_partial=True)
    return summary, ledger


def artifacts(directory: Path) -> dict[str, str]:
    digests: dict[str, str] = json.loads((directory / "inventory.json").read_text())["artifacts"]
    return digests


TELEMETRY_ONLY = {STATUS_LEDGER, f"{STATUS_LEDGER}.anchor"}


def without_telemetry_members(digests: dict[str, str]) -> dict[str, str]:
    return {name: digest for name, digest in digests.items() if name not in TELEMETRY_ONLY}


# --- telemetry changes nothing ------------------------------------------------------------------


CASES = [("agent", case) for case in AGENT_CASES] + [
    ("supportlab", case) for case in SUPPORTLAB_CASES
]


@pytest.mark.parametrize(("lane", "scenario_id"), CASES)
async def test_bundle_is_byte_identical_with_telemetry_on_and_off(
    tmp_path: Path, frozen_wall_clock: None, lane: str, scenario_id: str
) -> None:
    off, _ = await run_case(tmp_path / "off", lane, scenario_id)
    control, _ = await run_case(tmp_path / "off-again", lane, scenario_id)
    spans = tmp_path / "export" / "spans.jsonl"
    spans.parent.mkdir()
    on, ledger = await run_case(tmp_path / "on", lane, scenario_id, FileExporter(spans))
    assert artifacts(tmp_path / "off") == artifacts(tmp_path / "off-again")  # the control
    assert control == off
    assert on == off
    assert artifacts(tmp_path / "on") == artifacts(tmp_path / "off")
    assert (tmp_path / "on" / "evidence.jsonl").read_bytes() == (
        tmp_path / "off" / "evidence.jsonl"
    ).read_bytes()
    # The export happened, completely, and is exactly the ledger's projection.
    assert ledger is not None and ledger.failure is None and ledger.dropped_spans == 0
    events = EvidenceLedger(tmp_path / "on" / "evidence.jsonl").verify()
    projection = project_events(events)
    exported = read_export(spans)
    assert export_spans(exported) == projection.spans
    assert [p for p in exported if "resourceMetrics" in p] == [
        p for s, p in projection.payloads if s == "metrics"
    ]
    assert ledger.exported_spans == len(projection.spans)
    assert not (tmp_path / "on" / STATUS_LEDGER).exists()


async def test_the_comparison_detects_a_real_difference(
    tmp_path: Path, frozen_wall_clock: None
) -> None:
    """The identity above is not vacuous: a different scenario yields a different bundle."""
    first, _ = await run_case(tmp_path / "a", "agent", AGENT_CASES[0])
    other = await run_case(tmp_path / "b", "agent", AGENT_CASES[1])
    assert artifacts(tmp_path / "a") != artifacts(tmp_path / "b") and first != other[0]


# --- fault injection: export failure is non-fatal and recorded ----------------------------------


class Collector:
    """A loopback OTLP/HTTP stub with a failure mode, served on a background thread."""

    def __init__(self, mode: str, delay: float = 0.0) -> None:
        self.mode = mode
        self.delay = delay
        self.bodies: list[tuple[str, dict[str, Any]]] = []
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if collector.delay:
                    time.sleep(collector.delay)
                if collector.mode == "refusing":
                    self.send_response(503)
                    self.end_headers()
                    return
                if collector.mode == "garbage":
                    self.wfile.write(b"not http at all\r\n\r\n")
                    return
                collector.bodies.append((self.path, json.loads(body)))
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b"{}")
                except BrokenPipeError:  # the exporter already gave up on a slow reply
                    return

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Collector:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def http_exporter(port: int) -> OtlpHttpExporter:
    grant = collector_manifest(KEY, port=port, now=NOW)
    return OtlpHttpExporter.from_manifest(
        grant, ManifestVerifier({KEY_ID: KEY.public_key()}), now=NOW + timedelta(minutes=1)
    )


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


class RaisingExporter:
    sink = "raising"

    def export(self, signal: Any, payload: dict[str, Any], *, timeout: float) -> None:
        raise RuntimeError("exporter bug")


@pytest.fixture
def fault_sinks(tmp_path: Path) -> Iterator[Callable[[str], tuple[TelemetryExporter, str]]]:
    collectors: list[Collector] = []

    def make(mode: str) -> tuple[TelemetryExporter, str]:
        if mode == "file-missing-directory":
            return FileExporter(tmp_path / "gone" / "spans.jsonl"), "FILE_WRITE_FAILED"
        if mode == "file-is-a-directory":
            (tmp_path / "spans-dir").mkdir()
            return FileExporter(tmp_path / "spans-dir"), "FILE_WRITE_FAILED"
        if mode == "collector-down":
            return http_exporter(closed_port()), "CONNECTION_REFUSED"
        if mode == "exporter-raises":
            return RaisingExporter(), "EXPORTER_RuntimeError"
        collector = {
            "collector-refusing": lambda: Collector("refusing"),
            "collector-garbage": lambda: Collector("garbage"),
            "collector-slow-timeout": lambda: Collector("ok", delay=1.0),
            "collector-slow-budget": lambda: Collector("ok", delay=0.08),
        }[mode]()
        collectors.append(collector.__enter__())
        expected = {
            "collector-refusing": "HTTP_503",
            "collector-garbage": "CONNECTION_FAILED",
            "collector-slow-timeout": "TIMEOUT",
            # Each call succeeds slowly until the remaining budget is shorter than a call; the
            # last one is then cut off by the clipped timeout, or the budget is already spent.
            "collector-slow-budget": "TIME_BUDGET_EXHAUSTED|TIMEOUT",
        }[mode]
        return http_exporter(collector.port), expected

    yield make
    for collector in collectors:
        collector.__exit__()


FAULTS = (
    "file-missing-directory",
    "file-is-a-directory",
    "collector-down",
    "collector-refusing",
    "collector-garbage",
    "collector-slow-timeout",
    "collector-slow-budget",
    "exporter-raises",
)


@pytest.mark.parametrize("fault", FAULTS)
async def test_export_failure_changes_no_outcome(
    tmp_path: Path,
    frozen_wall_clock: None,
    fault_sinks: Callable[[str], tuple[TelemetryExporter, str]],
    fault: str,
) -> None:
    exporter, expected_failure = fault_sinks(fault)
    off, _ = await run_case(tmp_path / "off", "agent", "agent-canary-exfiltration")
    started = time.monotonic()
    on, ledger = await run_case(
        tmp_path / "on",
        "agent",
        "agent-canary-exfiltration",
        exporter,
        batch_size=8,
        call_timeout_seconds=0.2,
        time_budget_seconds=0.3,
    )
    elapsed = time.monotonic() - started
    assert on == off  # status, verdicts, findings, budgets, hashes -- everything
    on_members, off_members = artifacts(tmp_path / "on"), artifacts(tmp_path / "off")
    assert without_telemetry_members(on_members) == off_members
    assert set(on_members) - set(off_members) == TELEMETRY_ONLY
    assert ledger is not None and ledger.failure in expected_failure.split("|")
    status = read_status(tmp_path / "on")
    assert [event.reason_code for event in status] == [EXPORT_FAILED, SPANS_DROPPED]
    assert status[0].data["failure"] == ledger.failure
    if fault == "collector-slow-budget":
        assert status[1].data["spans_exported"] > 0  # it was slow, not down
    assert all(event.manifest_digest == on.manifest_digest for event in status)
    total = len(project_events(EvidenceLedger(tmp_path / "on" / "evidence.jsonl").verify()).spans)
    assert status[1].data["spans_exported"] + status[1].data["spans_dropped"] == total
    assert status[1].data["spans_dropped"] > 0
    # A slow sink costs at most its time budget plus one call timeout, never the run.
    assert ledger._spent <= 0.3 + 0.2 + 0.1
    assert elapsed < 30


async def test_a_healthy_collector_receives_exactly_the_projection(
    tmp_path: Path, frozen_wall_clock: None
) -> None:
    off, _ = await run_case(tmp_path / "off", "agent", "agent-canary-exfiltration")
    with Collector("ok") as collector:
        on, ledger = await run_case(
            tmp_path / "on", "agent", "agent-canary-exfiltration", http_exporter(collector.port)
        )
    assert on == off and artifacts(tmp_path / "on") == artifacts(tmp_path / "off")
    assert ledger is not None and ledger.failure is None
    projection = project_events(EvidenceLedger(tmp_path / "on" / "evidence.jsonl").verify())
    traces = [body for path, body in collector.bodies if path == "/v1/traces"]
    metrics = [body for path, body in collector.bodies if path == "/v1/metrics"]
    assert export_spans(traces) == projection.spans
    assert metrics == [p for s, p in projection.payloads if s == "metrics"]


# --- leak tests over a full-suite export --------------------------------------------------------


@pytest.fixture(scope="module")
def full_suite_exports(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, tuple[Path, Path, list[str]]]:
    """Both offline corpora, end to end through the Inspect bridge, with a file export each.

    Every per-run credential the suite issues is captured, so the scan can look for the exact
    values and not only for their shape.
    """
    import asyncio

    issued: list[str] = []
    original = telemetry_cli.actor_credentials

    def recording() -> dict[str, str]:
        tokens = original()
        issued.extend(tokens.values())
        return tokens

    telemetry_cli.actor_credentials = recording  # type: ignore[assignment]
    results: dict[str, tuple[Path, Path, list[str]]] = {}
    try:
        for lane in (ObservedLane.AGENT, ObservedLane.SUPPORTLAB):
            root = tmp_path_factory.mktemp(f"suite-{lane.value}")
            export = tmp_path_factory.mktemp(f"export-{lane.value}")
            issued.clear()
            observed = asyncio.run(
                observe_suite(lane, root / "bundle", FileExporter(export / "spans.jsonl"))
            )
            assert observed.counts()["export_failures"] == 0
            results[lane.value] = (root / "bundle", export, list(issued))
    finally:
        telemetry_cli.actor_credentials = original  # type: ignore[assignment]
    return results


@pytest.mark.parametrize("lane", ["agent", "supportlab"])
def test_no_secret_reaches_the_full_suite_export(
    full_suite_exports: dict[str, tuple[Path, Path, list[str]]], lane: str
) -> None:
    bundle, export, issued = full_suite_exports[lane]
    suite = json.loads((bundle / "suite.json").read_text())
    expected = 25 if lane == "agent" else 18
    assert len(suite["scenarios"]) == expected
    if lane == "agent":
        assert "agent-canary-exfiltration" in suite["scenarios"]
    # The suite really did handle secret material: the ledgers show it was redacted.
    ledgers = "".join(p.read_text() for p in bundle.rglob("evidence.jsonl"))
    assert "[REDACTED]" in ledgers
    assert issued and len(issued) >= 2 * expected
    problems = hygiene.scan(export)
    assert problems == [], problems
    text = (export / "spans.jsonl").read_text()
    exported = export_spans(read_export(export / "spans.jsonl"))
    assert len(exported) > (2000 if lane == "agent" else 500), len(exported)
    for value in (*issued, *ALL_CANARIES, *hygiene.BROKERED_VALUES):
        assert value not in text


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


@pytest.mark.parametrize("lane", ["agent", "supportlab"])
def test_every_exported_string_comes_from_the_redacted_ledger(
    full_suite_exports: dict[str, tuple[Path, Path, list[str]]], lane: str
) -> None:
    """Contract (plan §5): telemetry contains nothing absent from the redacted ledger."""
    bundle, export, _ = full_suite_exports[lane]
    ledgers = {
        run.name: (run / "evidence.jsonl").read_text() for run in bundle.iterdir() if run.is_dir()
    }
    constants = {"purpleloop", "ledger-projection", "1.0.0", "unstaged"}
    checked = 0
    for payload in read_export(export / "spans.jsonl"):
        for resource_spans in payload.get("resourceSpans", []):
            resource = span_attributes(resource_spans["resource"])
            ledger = ledgers[resource["purpleloop.run.id"]]
            events = [EvidenceEvent.model_validate_json(line) for line in ledger.splitlines()]
            digests = {event_attributes(e)["purpleloop.event.data_digest"] for e in events}
            for scope in resource_spans["scopeSpans"]:
                for span in scope["spans"]:
                    for key, value in span_attributes(span).items():
                        for text in _strings(value):
                            checked += 1
                            if key == "purpleloop.event.data_digest":
                                assert text in digests
                            else:
                                assert (
                                    text in constants
                                    or json.dumps(text) in ledger
                                    or (f'"{text}":' in ledger)
                                ), (key, text)
    assert checked > 1000


def test_the_telemetry_scan_catches_a_planted_leak(tmp_path: Path) -> None:
    """A writer that failed to redact would leak through telemetry exactly as it leaks into the
    ledger -- no more: free-text data is never exported -- and the scanner sees it."""
    token = "ab" * 24
    export = tmp_path / "export"
    export.mkdir()
    ledger = TelemetryLedger(tmp_path / "run" / "evidence.jsonl", FileExporter(export / "s.jsonl"))
    base: dict[str, Any] = {
        "run_id": "planted",
        "trace_id": "planted",
        "sequence": 0,
        "timestamp": NOW,
        "actor": "purple-team-runner",
        "manifest_digest": "a" * 64,
        "policy_digest": "a" * 64,
    }
    ledger.append(
        EvidenceEvent(
            **base,
            kind=EventKind.LIFECYCLE,
            reason_code=f"LEAK {ALL_CANARIES[0]} Bearer {'z' * 24} {token}",
            data={"note": f"unredacted {hygiene.BROKERED_VALUES[0]}"},
        )
    )
    ledger.append(EvidenceEvent(**base, kind=EventKind.TERMINATION, reason_code="DONE"))
    problems = "\n".join(hygiene.scan(export))
    assert "canary or brokered credential" in problems
    assert "bearer header" in problems
    assert "token-shaped 48-hex value" in problems
    # The free-text data field carried a brokered value; it stayed out of the export.
    assert hygiene.BROKERED_VALUES[0] not in (export / "s.jsonl").read_text()
    assert hygiene.BROKERED_VALUES[0] in (tmp_path / "run" / "evidence.jsonl").read_text()


def test_wall_clock_latency_from_a_real_export_matches_the_ledger(
    full_suite_exports: dict[str, tuple[Path, Path, list[str]]],
) -> None:
    """5.3.5 on the real suite: recomputed independently from ledger events, not from spans."""
    bundle, export, _ = full_suite_exports["agent"]
    figures = wall_clock_detection_latency(export_spans(read_export(export / "spans.jsonl")))
    assert figures and all(f.label == "wall clock on this machine" for f in figures)
    expected = []
    for run in sorted(p for p in bundle.iterdir() if p.is_dir()):
        attack_started: datetime | None = None
        current: str | None = None
        for event in EvidenceLedger(run / "evidence.jsonl").verify():
            if event.stage != current:
                current = event.stage
                if event.stage in {"attack", "replay"}:
                    attack_started = event.timestamp
            if event.kind == EventKind.DETECTOR and attack_started is not None:
                for result in event.data["results"]:
                    if result["observed"]:
                        delta = (event.timestamp - attack_started) / timedelta(milliseconds=1)
                        expected.append((run.name, result["rule_id"], delta))
    assert sorted((f.run_id, f.rule_id, f.wall_clock_ms) for f in figures) == sorted(expected)
    runs = {f.run_id for f in figures}
    spans = export_spans(read_export(export / "spans.jsonl"))
    assert runs <= {span_attributes(s)["purpleloop.run.id"] for s in spans if s["name"] == RUN_SPAN}
