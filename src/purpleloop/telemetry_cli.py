"""Observability CLI (WP5.3): ledger-derived telemetry, the namespace document, and analysis.

Every command is offline by default. ``observe-suite`` writes OTLP JSON lines to a local file;
it posts to a collector only when ``--collector-port`` is given, and then only to the collector a
signed Manifest 1.5 names as an asset (:func:`collector_manifest`). The suite's own runs are still
admitted under the lane's usual manifest; the 1.5 manifest authorizes the telemetry sink and
nothing else, because no lane admits a 1.5 manifest until WP5.1 widens the lane contracts.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.control.lanes import AGENT_LANE, SUPPORTLAB_LANE
from purpleloop.control.manifest import ManifestVerifier, sign_manifest
from purpleloop.control.plan_compiler import compile_plan
from purpleloop.reporting.analysis import AnalysisRefused, analyze, query
from purpleloop.reporting.bundle import BundleError, inventory, reports, verify_bundle, write_json
from purpleloop.reporting.telemetry import (
    FileExporter,
    OtlpHttpExporter,
    TelemetryExporter,
    TelemetryLedger,
    attach_telemetry,
    export_spans,
    latency_summary,
    namespace_doc_drift,
    project_events,
    read_export,
    render_namespace_doc,
    wall_clock_detection_latency,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.supportlab import (
    KEY_ID,
    MODEL_FIXTURE,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
    build_supportlab_runner,
    supportlab_agent_manifest,
    supportlab_manifest,
)
from purpleloop.schemas.authorization import AssetScope, AuthorizationManifest
from purpleloop.schemas.phase1 import RunSummary, load_scenario, scenario_paths
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import ActionClass, Phase5Grants

NAMESPACE_DOC = ROOT / "docs" / "telemetry-namespace.md"
COLLECTOR_ASSET = "otel-collector"
#: Host port ``compose.observability.yaml`` publishes the collector's OTLP/HTTP receiver on.
COLLECTOR_PORT = 24318


class ObservedLane(StrEnum):
    AGENT = "agent"
    SUPPORTLAB = "supportlab"


def collector_manifest(
    key: Ed25519PrivateKey,
    *,
    port: int = COLLECTOR_PORT,
    now: datetime | None = None,
    seed: int = 42,
) -> AuthorizationManifest:
    """A signed Manifest 1.5 whose only addition over the agent manifest is the collector grant.

    Built from :func:`supportlab_agent_manifest` so it names the same engagement and fixture
    assets, plus one loopback collector asset that ``phase5.telemetry`` points at. Its Phase 4
    attestation key id is a placeholder because nothing attests with this manifest.
    """
    base = supportlab_agent_manifest(key, seed=seed, now=now)
    data = base.model_dump(mode="python", exclude_none=True)
    data.update(
        schema_version="1.5.0",
        signature="",
        phase4=Phase4Grants(
            attestation_key_ids=frozenset({"observability-unused"}),
            retention=(
                RetentionRule(
                    artifact_kind="raw-ledgers", days=0, rationale="local observability profile"
                ),
            ),
        ),
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ, ActionClass.WRITE}),
            telemetry=COLLECTOR_ASSET,
        ),
        assets=(
            *base.assets,
            AssetScope(
                asset_id=COLLECTOR_ASSET,
                scheme="http",
                host="127.0.0.1",
                port=port,
                tenant_ids=frozenset({"org-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
    )
    return sign_manifest(AuthorizationManifest.model_validate(data), key)


@dataclass
class ObservedSuite:
    summaries: list[RunSummary] = field(default_factory=list)
    ledgers: list[TelemetryLedger] = field(default_factory=list)

    def counts(self) -> dict[str, Any]:
        return {
            "runs": len(self.summaries),
            "statuses": {
                status: sum(s.status == status for s in self.summaries)
                for status in sorted({s.status for s in self.summaries})
            },
            "spans_exported": sum(ledger.exported_spans for ledger in self.ledgers),
            "spans_dropped": sum(ledger.dropped_spans for ledger in self.ledgers),
            "export_failures": sum(ledger.failure is not None for ledger in self.ledgers),
        }


async def observe_suite(
    lane: ObservedLane,
    root: Path,
    exporter: TelemetryExporter,
    *,
    scenario_ids: tuple[str, ...] = (),
    seed: int = 42,
    key: Ed25519PrivateKey | None = None,
    **telemetry_options: Any,
) -> ObservedSuite:
    """Run a lane's corpus in-process, offline, with telemetry attached to every run's ledger."""
    key = key or Ed25519PrivateKey.generate()
    manifest = (
        supportlab_agent_manifest(key, seed=seed)
        if lane == ObservedLane.AGENT
        else supportlab_manifest(key, seed=seed)
    )
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    verifier.verify(manifest)
    contract = AGENT_LANE if lane == ObservedLane.AGENT else SUPPORTLAB_LANE
    paths = [
        path
        for path in scenario_paths(ROOT / "scenarios" / lane.value)
        if not scenario_ids or path.stem in scenario_ids
    ]
    observed = ObservedSuite()
    for path in paths:
        scenario = load_scenario(path)
        compile_plan(scenario, manifest, lane=contract)
        tokens = actor_credentials()
        control = actor_credentials()["customer-a"]
        fixture = InProcessSupportlab(tokens, control)
        build = build_agent_runner if lane == ObservedLane.AGENT else build_supportlab_runner
        directory = root / scenario.scenario_id
        runner = build(
            directory, manifest, verifier, actor_tokens=tokens, control=control, fixture=fixture
        )
        observed.ledgers.append(attach_telemetry(runner, exporter, **telemetry_options))
        try:
            observed.summaries.append(
                await evaluate_runner(
                    runner,
                    scenario,
                    manifest,
                    run_id=scenario.scenario_id,
                    output_dir=directory,
                    model_fixture=MODEL_FIXTURE,
                )
            )
        finally:
            if not fixture.closed:
                await fixture.close()
    reports(root, observed.summaries)
    (root / "authorization-public.pem").write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    write_json(
        root / "suite.json",
        {
            "schema_version": "1.1.0",
            "lane": lane.value,
            "fixture_mode": "in-process",
            "scenarios": [s.scenario_id for s in observed.summaries],
        },
    )
    inventory(root, complete=True)
    verify_bundle(root)
    return observed


def _bundle_runs(bundle: Path) -> list[Path]:
    verify_bundle(bundle)
    suite = bundle / "suite.json"
    if suite.exists():
        return [bundle / name for name in json.loads(suite.read_text())["scenarios"]]
    return [bundle]


def register(app: typer.Typer) -> None:
    @app.command("telemetry-namespace")
    def telemetry_namespace(
        check: bool = typer.Option(False, "--check", help="Exit 1 if the document has drifted."),
        write: bool = typer.Option(False, "--write", help="Regenerate the document in place."),
    ) -> None:
        """Print, check, or regenerate docs/telemetry-namespace.md from the event-kind enum."""
        document = NAMESPACE_DOC.read_text(encoding="utf-8")
        if write:
            NAMESPACE_DOC.write_text(render_namespace_doc(document), encoding="utf-8")
            typer.echo(f"wrote {NAMESPACE_DOC}")
            return
        if check:
            if namespace_doc_drift(document):
                typer.echo("telemetry namespace document has drifted from EventKind", err=True)
                raise typer.Exit(1)
            typer.echo("telemetry namespace document matches EventKind")
            return
        typer.echo(render_namespace_doc(document))

    @app.command("observe-suite")
    def observe_suite_command(
        lane: ObservedLane = ObservedLane.AGENT,
        output_dir: Path = typer.Option(Path("artifacts/observability/suite"), "--out"),  # noqa: B008 -- typer option declaration
        spans: Path = typer.Option(Path("artifacts/observability/spans.jsonl"), "--spans"),  # noqa: B008 -- typer option declaration
        collector_port: int | None = typer.Option(
            None, "--collector-port", help="Post to the loopback collector instead of a file."
        ),
        scenario: list[str] = typer.Option([], "--scenario"),  # noqa: B008 -- typer option declaration
        seed: int = 42,
    ) -> None:
        """Run a corpus offline with ledger-derived telemetry; print counts and latency."""
        root = output_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        key = Ed25519PrivateKey.generate()
        exporter: TelemetryExporter
        if collector_port is not None:
            grant = collector_manifest(key, port=collector_port)
            exporter = OtlpHttpExporter.from_manifest(
                grant, ManifestVerifier({KEY_ID: key.public_key()})
            )
        else:
            spans.parent.mkdir(parents=True, exist_ok=True)
            exporter = FileExporter(spans)
        try:
            observed = asyncio.run(
                observe_suite(
                    lane, root, exporter, scenario_ids=tuple(scenario), seed=seed, key=key
                )
            )
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}; partial evidence: {root.resolve()}", err=True)
            raise typer.Exit(1) from None
        typer.echo(json.dumps({"bundle": str(root), **observed.counts()}, sort_keys=True))
        if collector_port is None:
            figures = wall_clock_detection_latency(export_spans(read_export(spans)))
            typer.echo(json.dumps(latency_summary(figures), sort_keys=True))

    @app.command("telemetry-export")
    def telemetry_export(
        bundle: Path,
        spans: Path = typer.Option(..., "--spans"),  # noqa: B008 -- typer option declaration
    ) -> None:
        """Project a verified bundle's ledgers to OTLP JSON lines, after the fact."""
        try:
            runs = _bundle_runs(bundle)
        except (BundleError, OSError, ValueError) as exc:
            typer.echo(f"REFUSED: bundle does not verify: {exc}", err=True)
            raise typer.Exit(1) from None
        if spans.resolve().is_relative_to(bundle.resolve()):
            typer.echo("REFUSED: the export must live outside the bundle", err=True)
            raise typer.Exit(1)
        spans.parent.mkdir(parents=True, exist_ok=True)
        exporter = FileExporter(spans)
        count = 0
        for run in runs:
            projection = project_events(EvidenceLedger(run / "evidence.jsonl").verify())
            for signal, payload in projection.payloads:
                exporter.export(signal, payload, timeout=0)
            count += len(projection.spans)
        typer.echo(json.dumps({"runs": len(runs), "spans": count}))

    @app.command("telemetry-latency")
    def telemetry_latency(
        spans: Path, as_json: bool = typer.Option(False, "--json", help="Every figure.")
    ) -> None:
        """Advisory wall-clock detection latency from span timestamps, beside logical ticks."""
        figures = wall_clock_detection_latency(export_spans(read_export(spans)))
        if as_json:
            typer.echo(json.dumps([f.model_dump(mode="json") for f in figures], sort_keys=True))
            return
        typer.echo(json.dumps(latency_summary(figures), sort_keys=True))

    @app.command("analyze")
    def analyze_command(
        bundles: list[Path],
        output_dir: Path = typer.Option(..., "--out"),  # noqa: B008 -- typer option declaration
        allow_partial: bool = typer.Option(False, "--allow-partial"),
        sql: str | None = typer.Option(None, "--query"),
    ) -> None:
        """Verified bundles to Parquet; optionally run one DuckDB query over the result."""
        try:
            export = analyze(bundles, output_dir, allow_partial=allow_partial)
            typer.echo(
                json.dumps(
                    {"bundles": export.bundles, "runs": export.runs, "rows": export.rows},
                    sort_keys=True,
                )
            )
            if sql is not None:
                _print_query(output_dir, sql)
        except AnalysisRefused as exc:
            typer.echo(f"REFUSED: {exc}", err=True)
            raise typer.Exit(1) from None

    @app.command("analyze-query")
    def analyze_query(export_dir: Path, sql: str) -> None:
        """Run read-only SQL over a verified analysis export."""
        try:
            _print_query(export_dir, sql)
        except AnalysisRefused as exc:
            typer.echo(f"REFUSED: {exc}", err=True)
            raise typer.Exit(1) from None


def _print_query(export_dir: Path, sql: str) -> None:
    columns, rows = query(export_dir, sql)
    typer.echo("\t".join(columns))
    for row in rows:
        typer.echo("\t".join("" if value is None else str(value) for value in row))
