"""supportlab lane CLI: the offline demo entry point and per-scenario run/estimate commands."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.control.lanes import SUPPORTLAB_LANE
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.plan_compiler import compile_plan
from purpleloop.reporting.bundle import inventory, reports, verify_bundle, write_json
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    MODEL_FIXTURE,
    ComposeSupportlab,
    InProcessSupportlab,
    ServedSupportlab,
    actor_credentials,
    build_supportlab_runner,
    supportlab_manifest,
)
from purpleloop.schemas.phase1 import RunSummary, load_scenario, scenario_paths
from purpleloop.scoring.phase2 import cross_surface_agreement, estimate_resources

SCENARIOS = ROOT / "scenarios" / "supportlab"


class SupportlabMode(StrEnum):
    IN_PROCESS = "in-process"
    SERVED = "served"
    COMPOSE = "compose"


async def run_one(
    scenario_path: Path,
    output_dir: Path,
    mode: SupportlabMode,
    *,
    seed: int = 42,
    project: str | None = None,
) -> RunSummary:
    if await asyncio.to_thread(lambda: output_dir.exists() and any(output_dir.iterdir())):
        raise ValueError("output directory is not empty; evidence is never overwritten")
    scenario = load_scenario(scenario_path)
    key = Ed25519PrivateKey.generate()
    manifest = supportlab_manifest(key, seed=seed)
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    verifier.verify(manifest)
    compile_plan(scenario, manifest, lane=SUPPORTLAB_LANE)
    tokens = actor_credentials()
    control = actor_credentials()["customer-a"]  # a distinct high-entropy control token
    fixture: InProcessSupportlab | ServedSupportlab | ComposeSupportlab
    if mode == SupportlabMode.IN_PROCESS:
        fixture = InProcessSupportlab(tokens, control)
    elif mode == SupportlabMode.SERVED:
        fixture = ServedSupportlab(tokens, control)
    else:  # pragma: no cover - container lane
        database = actor_credentials()["customer-b"]
        fixture = ComposeSupportlab(
            tokens, control, database, project=project or "purpleloop-supportlab"
        )
    try:
        if isinstance(fixture, (ServedSupportlab, ComposeSupportlab)):
            await fixture.start()
        runner = build_supportlab_runner(
            output_dir, manifest, verifier, actor_tokens=tokens, control=control, fixture=fixture
        )
        return await evaluate_runner(
            runner,
            scenario,
            manifest,
            run_id=scenario.scenario_id,
            output_dir=output_dir,
            model_fixture=MODEL_FIXTURE,
        )
    finally:
        if not fixture.closed:
            await fixture.close()


def register(app: typer.Typer) -> None:
    @app.command("supportlab-estimate")
    def supportlab_estimate(scenario_path: Path, seed: int = 42) -> None:
        """Print the pre-run resource estimate for a supportlab scenario."""
        try:
            scenario = load_scenario(scenario_path)
            key = Ed25519PrivateKey.generate()
            manifest = supportlab_manifest(key, seed=seed)
            plan = compile_plan(scenario, manifest, lane=SUPPORTLAB_LANE)
            estimate = estimate_resources(plan, SUPPORTLAB_LANE)
        except (OSError, ValueError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(estimate.model_dump_json())

    @app.command("supportlab-run")
    def supportlab_run(
        scenario_path: Path,
        output_dir: Path,
        fixture: SupportlabMode = SupportlabMode.IN_PROCESS,
        seed: int = 42,
    ) -> None:
        """Run one supportlab scenario and verify its evidence bundle."""
        try:
            summary = asyncio.run(run_one(scenario_path, output_dir, fixture, seed=seed))
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"{summary.status.upper()} {output_dir.resolve()}")
        if summary.status != "passed":
            raise typer.Exit(1)

    @app.command("supportlab-demo")  # pragma: no cover - container lane driver
    def supportlab_demo(
        output_dir: Path = Path("artifacts/supportlab-demo"),
        fixture: SupportlabMode = SupportlabMode.COMPOSE,
        seed: int = 42,
    ) -> None:
        """Run the whole supportlab corpus, write the suite bundle, and verify it."""
        root = output_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        key = Ed25519PrivateKey.generate()

        async def run_suite() -> list[RunSummary]:
            summaries: list[RunSummary] = []
            scenarios = []
            for path in scenario_paths(SCENARIOS):
                summary = await run_one(path, root / path.stem, fixture, seed=seed)
                summaries.append(summary)
                scenarios.append(load_scenario(path))
                typer.echo(f"{path.stem}: {summary.status}")
            agreement = cross_surface_agreement(scenarios, summaries)
            write_json(root / "cross-surface.json", agreement)
            return summaries

        try:
            summaries = asyncio.run(run_suite())
            reports(root, summaries)
            (root / "authorization-public.pem").write_bytes(
                key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            )
            write_json(
                root / "suite.json",
                {
                    "schema_version": "1.1.0",
                    "lane": "supportlab",
                    "fixture_mode": fixture.value,
                    "scenarios": [s.scenario_id for s in summaries],
                },
            )
            inventory(root, complete=True)
            verify_bundle(root)
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}; partial evidence: {root.resolve()}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"Verified report: {(root / 'report.html').resolve()}")
        if any(summary.status != "passed" for summary in summaries):
            raise typer.Exit(1)
