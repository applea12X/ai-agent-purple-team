"""Phase 4 CLI: gates, attestation, audit export, holdout, baselines, and the smoke demo.

The ``gates`` command wires CI to the same pure decision functions the unit tests exercise
(ADR 0013). Its ``--inject`` option exists for the red-branch protocol: it feeds a deliberately
violating input through the *same* decision function so a gate-proof branch demonstrates the
gate blocking end to end, and the output says loudly that the violation was injected.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from purpleloop.agent_cli import run_offline_corpus, run_offline_scenario
from purpleloop.control.holdout import HoldoutError, load_holdout, run_holdout
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.phase1_cli import FixtureMode as Phase1FixtureMode
from purpleloop.phase1_cli import run_one as phase1_run_one
from purpleloop.reporting.attestation import AttestationError, attest_bundle, verify_attestation
from purpleloop.reporting.audit_export import AuditExportError, export_audit
from purpleloop.reporting.bundle import inventory, reports, verify_bundle, write_json
from purpleloop.reporting.gates import (
    budget_gate,
    critical_regression_gate,
    outcomes_from_junit,
    risk_class_gate,
    schema_digests,
    schema_drift_gate,
    scope_gate,
)
from purpleloop.runtime.demo import ROOT, demo_manifest
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.supportlab import KEY_ID, supportlab_manifest
from purpleloop.schemas.authorization import AuthorizationManifest, BudgetLimits
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase1 import RunSummary, load_ground_truth
from purpleloop.schemas.phase4 import (
    GateDecision,
    RegressionRegistry,
    RiskClassBaseline,
    RiskClassMetrics,
    SmokeSet,
)
from purpleloop.scoring.phase4 import build_baseline, risk_class_metrics
from purpleloop.supportlab_cli import SupportlabMode
from purpleloop.supportlab_cli import run_one as supportlab_run_one

REGISTRY_PATH = ROOT / "scenarios" / "regression-registry.json"
SMOKE_PATH = ROOT / "scenarios" / "smoke.json"
HOLDOUT_PATH = ROOT / "scenarios" / "holdout" / "mutations.json"
SCHEMA_BASELINE_PATH = ROOT / "baselines" / "schema-digests.json"
CORPUS_BASELINE_PATH = ROOT / "baselines" / "corpus-baseline.json"
AGENT_GROUND_TRUTH = ROOT / "scenarios" / "agent" / "ground-truth.json"

INJECTABLE = (
    "scope-bypass",
    "critical-regression",
    "schema-drift",
    "budget-failure",
    "risk-class-regression",
)


def _bundle_summaries(bundle: Path) -> list[RunSummary]:
    inventory_raw = json.loads((bundle / "inventory.json").read_text())
    if "suite.json" in inventory_raw.get("artifacts", {}):
        suite = json.loads((bundle / "suite.json").read_text())
        return [
            RunSummary.model_validate_json((bundle / name / "summary.json").read_text())
            for name in suite.get("scenarios", [])
        ]
    return [RunSummary.model_validate_json((bundle / "summary.json").read_text())]


def _bundle_events(bundle: Path) -> list[EvidenceEvent]:
    events: list[EvidenceEvent] = []
    for ledger_path in sorted(bundle.rglob("evidence.jsonl")):
        events.extend(EvidenceLedger(ledger_path).verify())
    return events


def _bundle_limits(bundle: Path) -> BudgetLimits:
    manifest_path = next(iter(sorted(bundle.rglob("manifest.json"))), None)
    if manifest_path is None:
        raise ValueError("bundle carries no manifest to read budget limits from")
    return AuthorizationManifest.model_validate_json(manifest_path.read_text()).budgets


def _injected_bypass_event(reference: EvidenceEvent) -> EvidenceEvent:
    """A RESULT permit whose action digest no guard ever permitted -- a fabricated bypass."""
    return EvidenceEvent(
        run_id="gate-proof",
        trace_id="gate-proof",
        sequence=reference.sequence + 1,
        timestamp=datetime.now(UTC),
        actor="gate-proof-injection",
        kind=EventKind.RESULT,
        manifest_digest=reference.manifest_digest,
        policy_digest=reference.policy_digest,
        action_digest="f" * 64,
        decision="permit",
        reason_code="COMPLETED",
    )


def register(app: typer.Typer) -> None:
    @app.command("gates")
    def gates(  # noqa: PLR0913 -- the gate inputs are deliberately explicit
        bundle: Path,
        junit: Path = typer.Option(  # noqa: B008 -- typer option declaration
            ..., help="JUnit XML of the suite that just ran"
        ),
        risk_current: Path = typer.Option(  # noqa: B008 -- typer option declaration
            ..., help="Current per-risk-class metrics (corpus-baseline --output format)"
        ),
        registry_path: Path = REGISTRY_PATH,
        schema_baseline: Path = SCHEMA_BASELINE_PATH,
        risk_baseline: Path = CORPUS_BASELINE_PATH,
        inject: list[str] = typer.Option(  # noqa: B008 -- typer option declaration
            [], help="Red-branch proof: deliberately violate the named gate class"
        ),
        output: Path | None = None,
    ) -> None:
        """Evaluate the five enforcing gates over a bundle; exit 1 when any gate blocks."""
        try:
            for name in inject:
                if name not in INJECTABLE:
                    raise ValueError(f"not an injectable gate class: {name}")
            events = _bundle_events(bundle)
            summaries = _bundle_summaries(bundle)
            limits = _bundle_limits(bundle)
            registry = RegressionRegistry.model_validate_json(registry_path.read_text())
            outcomes = dict(outcomes_from_junit(junit))
            baseline_digests = dict(json.loads(schema_baseline.read_text())["digests"])
            corpus_baseline = RiskClassBaseline.model_validate_json(risk_baseline.read_text())
            current_doc = RiskClassBaseline.model_validate_json(risk_current.read_text())
            current: list[RiskClassMetrics] = list(current_doc.classes)

            if "scope-bypass" in inject and events:
                events = [*events, _injected_bypass_event(events[-1])]
            if "critical-regression" in inject:
                first = registry.covered()[0]
                outcomes[first.test] = False
            if "schema-drift" in inject:
                name = next(iter(sorted(baseline_digests)))
                baseline_digests[name] = "0" * 64
            if "budget-failure" in inject and summaries:
                summaries = [
                    *summaries,
                    summaries[0].model_copy(
                        update={
                            "run_id": "gate-proof",
                            "budget_used": summaries[0].budget_used.model_copy(
                                update={"requests": limits.requests + 1}
                            ),
                        }
                    ),
                ]
            if "risk-class-regression" in inject and current:
                current[0] = current[0].model_copy(
                    update={
                        "seeded_true_positives": max(current[0].seeded_true_positives - 1, 0),
                        "seeded_false_negatives": current[0].seeded_false_negatives + 1,
                    }
                )

            decisions: tuple[GateDecision, ...] = (
                scope_gate(events),
                critical_regression_gate(registry, outcomes),
                schema_drift_gate(baseline_digests, schema_digests()),
                budget_gate(events, limits, summaries),
                risk_class_gate(corpus_baseline, current),
            )
        except (OSError, ValueError, KeyError, IndexError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        for name in inject:
            typer.echo(f"INJECTED {name}: a deliberately violating input (red-branch proof)")
        for decision in decisions:
            marker = "BLOCKED" if decision.blocked else "pass   "
            typer.echo(f"{marker} {decision.gate}: {decision.reason_code} — {decision.detail}")
        if output is not None:
            write_json(
                output,
                {
                    "schema_version": "1.4.0",
                    "injected": sorted(inject),
                    "decisions": [d.model_dump(mode="json") for d in decisions],
                },
            )
        if any(decision.blocked for decision in decisions):
            raise typer.Exit(1)

    @app.command("attest-bundle")
    def attest(
        bundle: Path,
        key_path: Path | None = typer.Option(  # noqa: B008 -- typer option declaration
            None, help="Ed25519 private key PEM"
        ),
        key_id: str = "ephemeral-local",
        builder: str = "local",
        commit: str | None = None,
    ) -> None:
        """Sign a run attestation for a complete bundle and write it beside the inventory."""
        try:
            if key_path is not None:
                loaded = load_pem_private_key(key_path.read_bytes(), password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("attestation key must be Ed25519")
                private_key, provenance = loaded, "provided"
            else:
                private_key, provenance = Ed25519PrivateKey.generate(), "ephemeral"
            attestation = attest_bundle(
                bundle,
                private_key,
                key_id=key_id,
                builder=builder,
                key_provenance=provenance,  # type: ignore[arg-type]
                code_commit=commit,
                lockfile=ROOT / "uv.lock",
            )
        except (OSError, ValueError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(
            f"ATTESTED {attestation.subject_kind} {attestation.subject_digest} "
            f"key={attestation.key_id} ({attestation.key_provenance})"
        )

    @app.command("audit-export")
    def audit(bundle: Path, out_path: Path) -> None:
        """Write the self-contained, redacted audit export for a bundle."""
        try:
            export = export_audit(bundle, out_path)
        except (OSError, ValueError, AuditExportError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"EXPORTED runs={len(export['runs'])} -> {out_path.resolve()}")

    @app.command("holdout-check")
    def holdout_check(holdout_path: Path = HOLDOUT_PATH, seed: int = 42) -> None:
        """Run the held-out mutation set against the real policy engine; any permit fails."""
        try:
            holdout = load_holdout(holdout_path)
            key = Ed25519PrivateKey.generate()
            manifest = supportlab_manifest(key, seed=seed)
            ManifestVerifier({KEY_ID: key.public_key()}).verify(manifest)
            base, results = run_holdout(holdout, manifest)
        except (OSError, ValueError, HoldoutError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"holdout digest {holdout.holdout_digest()}")
        typer.echo(f"base action permitted (positive control): {base.action_id}")
        permitted = [result for result in results if result.permitted]
        for result in results:
            marker = "PERMITTED" if result.permitted else "denied  "
            typer.echo(f"{marker} {result.case_id} [{result.denied_by}] {result.reason_code}")
        typer.echo(f"{len(results) - len(permitted)}/{len(results)} mutations denied")
        if permitted:
            raise typer.Exit(1)

    @app.command("schema-baseline")
    def schema_baseline_command(output: Path = SCHEMA_BASELINE_PATH) -> None:
        """Write the canonical reference digests. A deliberate, reviewed baseline bump."""
        write_json(
            output,
            {
                "schema_version": "1.4.0",
                "recorded_at": datetime.now(UTC).isoformat(),
                "digests": schema_digests(),
            },
        )
        typer.echo(f"WROTE {output}")

    @app.command("corpus-baseline")
    def corpus_baseline_command(
        output: Path = CORPUS_BASELINE_PATH,
        seed: int = 42,
        commit: str | None = None,
    ) -> None:
        """Run the agent corpus offline and record per-risk-class metrics.

        Writing to the committed baseline path is the explicit baseline-bump step; writing to
        another path produces the current-metrics document the gates compare against it.
        """
        import tempfile

        try:
            resolved_commit = commit or _git_commit()
            with tempfile.TemporaryDirectory() as scratch:
                scenarios, summaries = asyncio.run(run_offline_corpus(Path(scratch), seed=seed))
            metrics = risk_class_metrics(
                scenarios, load_ground_truth(AGENT_GROUND_TRUTH), summaries
            )
            baseline = build_baseline(metrics, corpus="scenarios/agent", commit=resolved_commit)
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        write_json(output, baseline.model_dump(mode="json", exclude_none=True))
        failed = [s.scenario_id for s in summaries if s.status != "passed"]
        typer.echo(
            f"WROTE {output} classes={len(metrics)} scenarios={len(summaries)} "
            f"failed={failed or 'none'}"
        )
        if failed:
            raise typer.Exit(1)

    @app.command("smoke-demo")
    def smoke_demo(
        output_dir: Path = Path("artifacts/smoke"),
        seed: int = 42,
        smoke_path: Path = SMOKE_PATH,
    ) -> None:
        """Run the named PR-lane smoke set across all three lanes, in process and offline."""
        try:
            smoke = SmokeSet.model_validate(json.loads(smoke_path.read_text()))
        except (OSError, ValueError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        root = output_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        started = time.monotonic()

        async def run_suite() -> list[RunSummary]:
            summaries: list[RunSummary] = []
            for member in smoke.scenarios:
                path = ROOT / "scenarios" / member.lane / f"{member.scenario_id}.yaml"
                directory = root / member.scenario_id
                if member.lane == "phase1":
                    key = Ed25519PrivateKey.generate()
                    manifest = demo_manifest(key)
                    verifier = ManifestVerifier({"demo-key": key.public_key()})
                    summary = await phase1_run_one(
                        path, manifest, verifier, directory, Phase1FixtureMode.IN_PROCESS
                    )
                elif member.lane == "supportlab":
                    summary = await supportlab_run_one(
                        path, directory, SupportlabMode.IN_PROCESS, seed=seed
                    )
                else:
                    summary = await run_offline_scenario(path, directory, seed=seed)
                summaries.append(summary)
                typer.echo(f"{member.lane}/{member.scenario_id}: {summary.status}")
            return summaries

        try:
            summaries = asyncio.run(run_suite())
            elapsed = round(time.monotonic() - started, 3)
            reports(root, summaries)
            write_json(
                root / "suite.json",
                {
                    "schema_version": "1.4.0",
                    "lane": "smoke",
                    "wall_time_target_seconds": smoke.wall_time_target_seconds,
                    "wall_time_seconds": elapsed,
                    "scenarios": [member.scenario_id for member in smoke.scenarios],
                },
            )
            inventory(root, complete=True)
            verify_bundle(root)
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}; partial evidence: {root.resolve()}", err=True)
            raise typer.Exit(1) from None
        within = elapsed <= smoke.wall_time_target_seconds
        typer.echo(
            f"wall time {elapsed}s against the stated {smoke.wall_time_target_seconds}s target"
            + ("" if within else " — EXCEEDED (reported, not hidden)")
        )
        typer.echo(f"Verified smoke bundle: {root.resolve()}")
        if any(summary.status != "passed" for summary in summaries):
            raise typer.Exit(1)

    @app.command("verify-attestation")
    def verify_attestation_command(
        bundle: Path,
        public_key: Path | None = typer.Option(  # noqa: B008 -- typer option declaration
            None, help="Pin the expected attestation key instead of the one beside the bundle"
        ),
    ) -> None:
        """Verify a bundle's attestation: signature, then the recomputed subject digest."""
        try:
            attestation = verify_attestation(
                bundle,
                public_key_pem=public_key.read_bytes() if public_key else None,
            )
        except (OSError, ValueError, AttestationError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(
            f"VALID {attestation.subject_kind} {attestation.subject_digest} "
            f"key={attestation.key_id} ({attestation.key_provenance}) "
            f"builder={attestation.builder}"
        )


def _git_commit() -> str | None:
    try:
        result = subprocess.run(  # noqa: S603 -- fixed argv, no user input
            ["git", "rev-parse", "HEAD"],  # noqa: S607 -- resolved from PATH deliberately
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError:  # pragma: no cover - git absent
        return None
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and len(commit) == 40 else None
