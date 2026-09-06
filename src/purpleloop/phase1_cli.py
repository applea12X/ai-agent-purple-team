from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

from purpleloop.control.manifest import ManifestVerifier, load_manifest
from purpleloop.control.plan_compiler import compile_plan
from purpleloop.reporting.bundle import inventory, reports, verify_bundle, write_json
from purpleloop.runtime.demo import (
    MODEL_FIXTURE,
    ROOT,
    ComposeFixture,
    build_runner,
    credentials,
    demo_manifest,
)
from purpleloop.runtime.fixture import InProcessFixture
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import RunSummary, load_scenario


class FixtureMode(StrEnum):
    COMPOSE = "compose"
    IN_PROCESS = "in-process"


async def run_one(
    scenario_path: Path,
    manifest: AuthorizationManifest,
    verifier: ManifestVerifier,
    output_dir: Path,
    mode: FixtureMode,
) -> RunSummary:
    if await asyncio.to_thread(lambda: output_dir.exists() and any(output_dir.iterdir())):
        raise ValueError("output directory is not empty; evidence is never overwritten")
    scenario = load_scenario(scenario_path)
    verifier.verify(manifest)
    compile_plan(scenario, manifest)
    customer, control = credentials()
    fixture: InProcessFixture | ComposeFixture = (
        InProcessFixture(customer, control)
        if mode == FixtureMode.IN_PROCESS
        else ComposeFixture(customer, control)
    )
    # Physical containment is host-owned; signed target admission above precedes startup.
    try:
        if isinstance(fixture, ComposeFixture):
            await fixture.start()
        runner = build_runner(
            output_dir, manifest, verifier, customer=customer, control=control, fixture=fixture
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
    @app.command("validate-scenario")
    def validate_scenario(scenario_path: Path) -> None:
        """Validate the current schema, or explain missing legacy conversion inputs."""
        try:
            scenario = load_scenario(scenario_path)
            scenario.require_runnable()
        except (OSError, ValueError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"VALID {scenario.digest()}")

    @app.command("verify-bundle")
    def verify(directory: Path) -> None:
        try:
            result = verify_bundle(directory)
        except (OSError, ValueError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"VALID {result}")

    @app.command("run-scenario")
    def run_scenario(
        scenario_path: Path,
        manifest_path: Path,
        public_key: Path,
        output_dir: Path,
        key_id: str = typer.Option(...),
        fixture: FixtureMode = FixtureMode.COMPOSE,
    ) -> None:
        """Run one signed, fixture-only scenario and verify its Inspect evidence bundle."""
        try:
            manifest = load_manifest(manifest_path)
            key = load_pem_public_key(public_key.read_bytes())
            verifier = ManifestVerifier({key_id: key})  # type: ignore[dict-item]
            summary = asyncio.run(run_one(scenario_path, manifest, verifier, output_dir, fixture))
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"{summary.status.upper()} {output_dir.resolve()}")
        if summary.status != "passed":
            raise typer.Exit(1)

    @app.command("phase1-demo")
    def phase1_demo(
        output_dir: Path = Path("artifacts/phase1-demo"), fixture: FixtureMode = FixtureMode.COMPOSE
    ) -> None:
        """Execute the five seeded cases with ephemeral fixture-only authorization."""
        root = output_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        key = Ed25519PrivateKey.generate()
        manifest = demo_manifest(key)
        verifier = ManifestVerifier({"demo-key": key.public_key()})

        async def run_suite() -> list[RunSummary]:
            summaries = []
            for scenario in sorted((ROOT / "scenarios" / "phase1").glob("*.yaml")):
                summary = await run_one(scenario, manifest, verifier, root / scenario.stem, fixture)
                summaries.append(summary)
                typer.echo(f"{scenario.stem}: {summary.status}")
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
