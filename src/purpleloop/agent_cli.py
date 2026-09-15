"""Agent lane CLI: paired runs, repetitions, and the evaluator red-team report.

Every command here is offline by default. The stochastic lane is opt-in through ``--endpoint``
and a broker-held credential; when the credential is missing the command says so and stops rather
than falling back to the offline provider, because a silent downgrade would report a network
result as a deterministic one.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.adapters.model_provider import OpenAICompatibleProvider, Provider
from purpleloop.control.attacker import BoundedAttacker
from purpleloop.control.lanes import AGENT_LANE
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.phase3_tools import INTENT_OPERATIONS
from purpleloop.control.plan_compiler import compile_plan
from purpleloop.reporting.bundle import inventory, reports, verify_bundle, write_json
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.runtime.repetitions import (
    Execute,
    RunnerFactory,
    apply_reproducibility,
    run_repetitions,
)
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    MODEL_FIXTURE,
    ComposeSupportlab,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
    supportlab_agent_manifest,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import Phase1Scenario, RunSummary, load_scenario, scenario_paths
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin
from purpleloop.schemas.phase4 import StochasticRunOutcome
from purpleloop.scoring.evaluator_redteam import agreement, load_corpus, resistance
from purpleloop.scoring.judge import HybridJudge, ScriptedJudge
from purpleloop.scoring.phase4 import classify_stochastic_failure, reproduction_record

SCENARIOS = ROOT / "scenarios" / "agent"
REDTEAM = ROOT / "scenarios" / "evaluator-redteam" / "cases.json"
CREDENTIAL_ENV = "PURPLELOOP_MODEL_API_KEY"

#: Where one repetition writes its bundle. Each repetition is its own verifiable bundle.
DirectoryFor = Callable[[int], Path]


class AgentFixtureMode(StrEnum):
    """Where the agent lane's fixture runs.

    ``compose`` closes the WP4.0.7 gap: the agent routes run inside the fixture container image
    over PostgreSQL, under the same containment as every other route, instead of only in
    process. The manifest, plan, and adapters are identical either way; only the transport and
    the database change.
    """

    IN_PROCESS = "in-process"
    COMPOSE = "compose"


class ModelUnavailableForLane(RuntimeError):
    reason_code = "STOCHASTIC_LANE_UNAVAILABLE"


def _write_outcome(output_dir: Path, outcome: StochasticRunOutcome) -> None:
    """Surface the run's classified outcome. A failure is surfaced, never silently tolerated.

    Always printed. Written to ``outcome.json`` only when the run already created its output
    directory: a lane that was skipped before it started must leave no bundle behind, and
    creating a directory just to hold the skip record would break that.
    """
    typer.echo(f"OUTCOME {outcome.model_dump_json()}", err=True)
    if not output_dir.is_dir():
        return
    try:
        write_json(output_dir / "outcome.json", outcome.model_dump(mode="json"))
    except OSError:  # pragma: no cover - the outcome must never mask the original failure
        pass


def networked_provider(endpoint: str, profile: str) -> tuple[Provider, ModelPin]:
    """Build a networked provider, or refuse. There is no fallback to the offline provider."""
    credential = os.environ.get(CREDENTIAL_ENV)
    if profile == "openai-compatible" and not credential:
        raise ModelUnavailableForLane(
            f"{CREDENTIAL_ENV} is not set; the stochastic lane is skipped, not downgraded"
        )
    from purpleloop.adapters.agent import SYSTEM_PROMPT_HASH

    pin = ModelPin(
        pin_id="networked",
        provider=profile,  # type: ignore[arg-type]
        model_id=os.environ.get("PURPLELOOP_MODEL_ID", "unspecified-model"),
        model_version=os.environ.get("PURPLELOOP_MODEL_VERSION"),
        decoding=DecodingParameters(seed=42),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
    )
    provider = OpenAICompatibleProvider(
        base_url=endpoint,
        credential=credential,
        profile=profile,  # type: ignore[arg-type]
    )
    return provider, pin


async def _inspect_execute(
    runner: PurpleTeamRunner,
    scenario: object,
    manifest: object,
    run_id: str,
    directory: Path,
) -> RunSummary:
    """Run one repetition through the Inspect bridge, so the bundle carries an Inspect log."""
    return await evaluate_runner(
        runner,
        scenario,  # type: ignore[arg-type]
        manifest,  # type: ignore[arg-type]
        run_id=run_id,
        output_dir=directory,
        model_fixture=MODEL_FIXTURE,
    )


def _runner_factory(
    manifest_key: Ed25519PrivateKey,
    directory_for: DirectoryFor,
    *,
    seed: int,
    judge: bool,
    attacker: bool,
    provider: Provider | None,
    pin_id: str,
    endpoint: str | None,
    pin: ModelPin | None,
    fixture_mode: AgentFixtureMode = AgentFixtureMode.IN_PROCESS,
) -> tuple[AuthorizationManifest, RunnerFactory, Execute]:
    manifest = supportlab_agent_manifest(
        manifest_key, seed=seed, judge=judge, model_endpoint=endpoint, model_pin=pin
    )
    verifier = ManifestVerifier({KEY_ID: manifest_key.public_key()})
    verifier.verify(manifest)
    # The fixture each repetition will run against, created in the factory and started by the
    # execute wrapper: a compose fixture needs an async start the synchronous factory cannot do.
    pending: list[InProcessSupportlab | ComposeSupportlab] = []

    def factory(index: int) -> tuple[PurpleTeamRunner, Path]:
        tokens = actor_credentials()
        control = actor_credentials()["customer-a"]
        directory = directory_for(index)
        options: dict[str, object] = {}
        if attacker:
            options["attacker"] = BoundedAttacker(
                max_proposals=manifest.phase3.max_attacker_proposals if manifest.phase3 else 0,
                max_depth=manifest.phase3.max_attacker_depth if manifest.phase3 else 0,
                operations=sorted(INTENT_OPERATIONS),
                own_tenant="org-a",
                other_tenants=("org-b",),
                resource_id="admin-a",
            )
        fixture: InProcessSupportlab | ComposeSupportlab
        if fixture_mode == AgentFixtureMode.COMPOSE:  # pragma: no cover - container lane
            database = actor_credentials()["customer-b"]
            fixture = ComposeSupportlab(
                tokens, control, database, project=f"purpleloop-agent-{index}"
            )
        else:
            fixture = InProcessSupportlab(tokens, control)
        pending.append(fixture)
        runner = build_agent_runner(
            directory,
            manifest,
            verifier,
            actor_tokens=tokens,
            control=control,
            fixture=fixture,
            model_provider=provider,
            model_pin_id=pin_id,
            **options,
        )
        return runner, directory

    async def execute(
        runner: PurpleTeamRunner,
        scenario: Phase1Scenario,
        run_manifest: AuthorizationManifest,
        run_id: str,
        directory: Path,
    ) -> RunSummary:
        fixture = pending.pop()
        if isinstance(fixture, ComposeSupportlab):  # pragma: no cover - container lane
            await fixture.start()
        return await _inspect_execute(runner, scenario, run_manifest, run_id, directory)

    return manifest, factory, execute


async def run_offline_scenario(
    scenario_path: Path,
    directory: Path,
    *,
    seed: int = 42,
    judge: bool = False,
    attacker: bool = False,
) -> RunSummary:
    """One offline agent scenario through the Inspect bridge; used by smoke and baseline runs."""
    scenario = load_scenario(scenario_path)
    key = Ed25519PrivateKey.generate()
    manifest, factory, execute = _runner_factory(
        key,
        lambda index: directory,
        seed=seed,
        judge=judge,
        attacker=attacker,
        provider=None,
        pin_id="offline-scripted",
        endpoint=None,
        pin=None,
    )
    compile_plan(scenario, manifest, lane=AGENT_LANE)
    runner, run_directory = factory(0)
    return await execute(runner, scenario, manifest, scenario.scenario_id, run_directory)


async def run_offline_corpus(
    root: Path, *, seed: int = 42
) -> tuple[list[Phase1Scenario], list[RunSummary]]:
    """The whole agent corpus offline, one paired run each; the baseline command's engine."""
    scenarios: list[Phase1Scenario] = []
    summaries: list[RunSummary] = []
    key = Ed25519PrivateKey.generate()
    for path in scenario_paths(SCENARIOS):
        scenario = load_scenario(path)

        def directory_for(index: int, sid: str = scenario.scenario_id) -> Path:
            return root / sid

        manifest, factory, _ = _runner_factory(
            key,
            directory_for,
            seed=seed,
            judge=False,
            attacker=False,
            provider=None,
            pin_id="offline-scripted",
            endpoint=None,
            pin=None,
        )
        runner, directory = factory(0)
        summaries.append(
            await runner.run(scenario, manifest, run_id=scenario.scenario_id, output_dir=directory)
        )
        scenarios.append(scenario)
    return scenarios, summaries


def register(app: typer.Typer) -> None:
    @app.command("agent-run")
    def agent_run(
        scenario_path: Path,
        output_dir: Path,
        seed: int = 42,
        judge: bool = False,
        attacker: bool = False,
        repetitions: int = 1,
        endpoint: str | None = None,
        profile: str = "openai-compatible",
        fixture: AgentFixtureMode = AgentFixtureMode.IN_PROCESS,
    ) -> None:
        """Run one agent scenario, optionally repeated, judged, and probed by the attacker."""
        provider: Provider | None = None
        pin: ModelPin | None = None
        try:
            if endpoint is not None:
                provider, pin = networked_provider(endpoint, profile)
            scenario = load_scenario(scenario_path)
            key = Ed25519PrivateKey.generate()
            manifest, factory, execute = _runner_factory(
                key,
                lambda index: (
                    output_dir
                    / (
                        scenario.scenario_id
                        if repetitions == 1
                        else f"{scenario.scenario_id}-rep-{index}"
                    )
                ),
                seed=seed,
                judge=judge,
                attacker=attacker,
                provider=provider,
                pin_id="networked" if pin else "offline-scripted",
                endpoint=endpoint,
                pin=pin,
                fixture_mode=fixture,
            )
            compile_plan(scenario, manifest, lane=AGENT_LANE)
            report, summaries = asyncio.run(
                run_repetitions(
                    scenario,
                    manifest,
                    factory,
                    repetitions=repetitions,
                    run_id=scenario.scenario_id,
                    execute=execute,
                )
            )
        except ModelUnavailableForLane as exc:
            _write_outcome(
                output_dir,
                classify_stochastic_failure(exc, scenario_id=scenario_path.stem),
            )
            typer.echo(f"SKIPPED: {exc}", err=True)
            raise typer.Exit(0) from None
        except (OSError, ValueError, RuntimeError) as exc:
            _write_outcome(
                output_dir,
                classify_stochastic_failure(exc, scenario_id=scenario_path.stem),
            )
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        pin_id = "networked" if pin else "offline-scripted"
        if not summaries:
            # Per-repetition failures are recorded as exclusions, so a run where every
            # repetition failed classifies here: on the stochastic lane that is an endpoint
            # problem, not a scenario result, and the outcome vocabulary keeps them apart.
            _write_outcome(
                output_dir,
                StochasticRunOutcome(
                    outcome="endpoint-error" if endpoint is not None else "fail",
                    reason_code="EVERY_REPETITION_EXCLUDED",
                    detail="; ".join(report.repetitions.exclusion_reasons)[:2000],
                    scenario_id=scenario.scenario_id,
                    model_pin_id=pin_id,
                ),
            )
            typer.echo("FAILED: every repetition was excluded", err=True)
            raise typer.Exit(1)
        enriched = apply_reproducibility(summaries[0], report)
        write_json(output_dir / "stochastic.json", report.model_dump(mode="json"))
        if repetitions > 1:
            # The stochastic lane's own replay number, beside -- never inside -- the
            # deterministic lanes' replay figure.
            write_json(
                output_dir / "reproduction.json",
                reproduction_record(report.repetitions).model_dump(mode="json"),
            )
        _write_outcome(
            output_dir,
            StochasticRunOutcome(
                outcome="pass" if enriched.status == "passed" else "fail",
                reason_code=enriched.reason or enriched.status.upper(),
                scenario_id=scenario.scenario_id,
                model_pin_id=pin_id,
            ),
        )
        typer.echo(
            f"{enriched.status.upper()} n={report.repetitions.completed} "
            f"attack_success={report.attack_success.value:.3f} "
            f"clean_utility={report.clean_utility.value:.3f} "
            f"utility_under_attack={report.utility_under_attack.value:.3f} "
            f"side_effects={report.executed_unauthorized_side_effects.value:.3f}"
        )
        if enriched.status != "passed":
            raise typer.Exit(1)

    @app.command("judge-report")
    def judge_report(output_dir: Path = Path("artifacts/judge")) -> None:
        """Score the judge against the frozen evaluator red-team corpus."""
        try:
            corpus = load_corpus(REDTEAM)
            hardened = resistance(HybridJudge(ScriptedJudge()), corpus)
            undelimited = resistance(HybridJudge(ScriptedJudge()), corpus, delimit=False)
            scores = agreement(HybridJudge(ScriptedJudge()), corpus)
        except (OSError, ValueError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            output_dir / "evaluator-redteam.json",
            {
                "schema_version": "1.3.0",
                "note": (
                    "Measured against a scripted judge stand-in with one declared failure mode. "
                    "This is a measurement of the harness's evaluator hardening, not of any "
                    "model's resistance."
                ),
                "hardened": hardened.model_dump(mode="json"),
                "negative_control_without_delimiting": undelimited.model_dump(mode="json"),
                "agreement": scores.model_dump(mode="json"),
            },
        )
        typer.echo(
            f"resistance={hardened.resistance:.3f} "
            f"(negative control {undelimited.resistance:.3f}) "
            f"alpha={scores.krippendorff_alpha:.3f} "
            f"[{scores.alpha_ci_low:.3f},{scores.alpha_ci_high:.3f}] n={scores.n} "
            f"swap={scores.order_swap_consistency:.3f}"
        )
        if hardened.critical_false_passes:
            raise typer.Exit(1)

    @app.command("agent-demo")
    def agent_demo(
        output_dir: Path = Path("artifacts/agent-demo"),
        seed: int = 42,
        repetitions: int = 1,
        judge: bool = True,
        attacker: bool = True,
        fixture: AgentFixtureMode = AgentFixtureMode.IN_PROCESS,
    ) -> None:
        """Run the whole agent corpus offline, write the suite bundle, and verify it."""
        root = output_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        key = Ed25519PrivateKey.generate()

        names: list[str] = []

        def bundle_name(scenario_id: str, index: int) -> str:
            return scenario_id if repetitions == 1 else f"{scenario_id}-rep-{index}"

        async def run_suite() -> list[RunSummary]:
            summaries: list[RunSummary] = []
            for path in scenario_paths(SCENARIOS):
                scenario = load_scenario(path)

                def directory_for(index: int, sid: str = scenario.scenario_id) -> Path:
                    return root / bundle_name(sid, index)

                manifest, factory, execute = _runner_factory(
                    key,
                    directory_for,
                    seed=seed,
                    judge=judge,
                    attacker=attacker,
                    provider=None,
                    pin_id="offline-scripted",
                    endpoint=None,
                    pin=None,
                    fixture_mode=fixture,
                )
                report, runs = await run_repetitions(
                    scenario,
                    manifest,
                    factory,
                    repetitions=repetitions,
                    run_id=scenario.scenario_id,
                    execute=execute,
                )
                if not runs:
                    raise RuntimeError(f"{scenario.scenario_id}: every repetition was excluded")
                names.extend(bundle_name(scenario.scenario_id, index) for index in range(len(runs)))
                # The aggregate belongs to the scenario, not to any one repetition's bundle.
                # Written before the inventory so the suite's digests cover it.
                write_json(
                    root / "stochastic" / f"{scenario.scenario_id}.json",
                    report.model_dump(mode="json"),
                )
                summaries.append(apply_reproducibility(runs[0], report))
                typer.echo(
                    f"{path.stem}: {summaries[-1].status} (n={report.repetitions.completed})"
                )
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
                    "schema_version": "1.3.0",
                    "lane": "supportlab-agent",
                    "model_provider": "offline-scripted",
                    "repetitions": repetitions,
                    "scenarios": names,
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
