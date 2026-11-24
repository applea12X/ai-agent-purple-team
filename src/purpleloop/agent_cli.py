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
from typing import Annotated, Literal

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.adapters.model_provider import OpenAICompatibleProvider, Provider
from purpleloop.control.attacker import BoundedAttacker
from purpleloop.control.lanes import AGENT_LANE
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.model_config import (
    ModelConfigError,
    ModelSettings,
    build_pin,
    with_seed,
)
from purpleloop.control.phase3_tools import INTENT_OPERATIONS
from purpleloop.control.plan_compiler import compile_plan
from purpleloop.judge_report import (
    DEFAULT_JUDGE_TIMEOUT_SECONDS,
    DEFAULT_JUDGE_TOKEN_BUDGET,
    JudgeRunConfig,
    JudgeUnavailable,
    run_networked_judge_report,
)
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
from purpleloop.schemas.phase3 import ModelPin
from purpleloop.schemas.phase4 import StochasticRunOutcome
from purpleloop.scoring.evaluator_redteam import (
    agreement,
    load_corpus,
    require_frozen,
    resistance,
)
from purpleloop.scoring.judge import HybridJudge, ScriptedJudge
from purpleloop.scoring.phase4 import (
    BUDGET_REASONS,
    classify_stochastic_failure,
    reproduction_record,
)

SCENARIOS = ROOT / "scenarios" / "agent"
REDTEAM = ROOT / "scenarios" / "evaluator-redteam" / "cases.json"
CREDENTIAL_ENV = "PURPLELOOP_MODEL_API_KEY"

#: Where one repetition writes its bundle. Each repetition is its own verifiable bundle.
DirectoryFor = Callable[[int], Path]

# Model-plane options shared by every networked command. Each names its environment variable;
# the command line wins over the environment, and the environment over the earlier default.
TemperatureOption = Annotated[
    float | None, typer.Option(help="Sampling temperature (env PURPLELOOP_MODEL_TEMPERATURE; 0)")
]
TopPOption = Annotated[
    float | None, typer.Option(help="Nucleus top_p (env PURPLELOOP_MODEL_TOP_P; 1)")
]
ModelSeedOption = Annotated[
    str | None,
    typer.Option(help="Model decoding seed, or 'none' (env PURPLELOOP_MODEL_SEED; 42)"),
]
MaxTokensOption = Annotated[
    int | None,
    typer.Option(help="Output token cap per call (env PURPLELOOP_MODEL_MAX_OUTPUT_TOKENS; 512)"),
]
PriceInputOption = Annotated[
    int | None,
    typer.Option(
        help=(
            "Input price, micro-USD per 1k tokens "
            "(env PURPLELOOP_MODEL_PRICE_INPUT_MICROUSD_PER_1K)"
        )
    ),
]
PriceOutputOption = Annotated[
    int | None,
    typer.Option(
        help=(
            "Output price, micro-USD per 1k tokens "
            "(env PURPLELOOP_MODEL_PRICE_OUTPUT_MICROUSD_PER_1K)"
        )
    ),
]
DeclaredFreeOption = Annotated[
    str | None,
    typer.Option(
        help="Acknowledge a hosted model as free by naming its model id (command line only)"
    ),
]
ModelIdOption = Annotated[str | None, typer.Option(help="Model id (env PURPLELOOP_MODEL_ID)")]
ModelVersionOption = Annotated[
    str | None, typer.Option(help="Model version or digest (env PURPLELOOP_MODEL_VERSION)")
]
CostBudgetOption = Annotated[
    int | None,
    typer.Option(
        help="Signed per-run cost cap, micro-USD (env PURPLELOOP_MODEL_COST_BUDGET_MICROUSD; 1e6)"
    ),
]


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


def run_outcome(summary: RunSummary) -> Literal["pass", "fail", "budget-stop"]:
    """A completed run's outcome. A run its signed cap stopped is a budget stop, not a failure.

    Before the price was configurable no networked run could exhaust its cost cap, so a stop
    here was never seen; with a priced hosted pin it is the expected way a cap shows itself, and
    reporting it as a scenario failure would conflate the budget with the defense.
    """
    if summary.status == "passed":
        return "pass"
    if summary.reason in BUDGET_REASONS:
        return "budget-stop"
    return "fail"


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


class SeedPolicy(StrEnum):
    """How the model seed varies across the repetitions of one scenario.

    ``fixed`` is the earlier behaviour: every repetition runs under the same seed. Under sampling
    that makes a seeded provider return the same reply every time, so a repetition set would
    report a reproduction of 1.0 that measures the seed, not the model. ``per-repetition`` gives
    repetition *i* the seed ``seed + i``; each repetition's manifest signs its own pin, so every
    repetition is still individually reproducible and the set measures sampling variance.
    """

    FIXED = "fixed"
    PER_REPETITION = "per-repetition"


SeedPolicyOption = Annotated[
    SeedPolicy | None,
    typer.Option(help="Seed across repetitions (env PURPLELOOP_MODEL_SEED_POLICY; fixed)"),
]

#: Signed per-run cost cap when none is configured: the value every earlier manifest carried.
DEFAULT_COST_BUDGET_MICROUSD = 1_000_000


def resolve_seed_policy(value: SeedPolicy | None) -> SeedPolicy:
    if value is not None:
        return value
    raw = os.environ.get("PURPLELOOP_MODEL_SEED_POLICY")
    try:
        return SeedPolicy(raw) if raw else SeedPolicy.FIXED
    except ValueError as exc:
        raise ModelConfigError(f"unknown seed policy {raw!r}") from exc


def resolve_cost_budget(value: int | None, *, name: str = "PURPLELOOP_MODEL") -> int:
    if value is not None:
        return value
    raw = os.environ.get(f"{name}_COST_BUDGET_MICROUSD")
    if not raw:
        return DEFAULT_COST_BUDGET_MICROUSD
    try:
        return int(raw)
    except ValueError as exc:
        raise ModelConfigError(f"{name}_COST_BUDGET_MICROUSD must be an integer") from exc


def seed_policy_label(policy: SeedPolicy, pin: ModelPin | None) -> dict[str, str]:
    """The repetition set's ``seed_policy`` argument; empty (the old label) under a fixed seed."""
    if policy == SeedPolicy.FIXED or pin is None:
        return {}
    return {"seed_policy": f"model-seed-{pin.decoding.seed}-plus-repetition-index"}


def refuse_offline_model_options(
    settings: ModelSettings, seed_policy: SeedPolicy | None, cost_budget: int | None
) -> None:
    """A model option on an offline run would be silently ignored, so it is refused instead.

    Only command-line options are checked: environment variables configure the networked lane
    and are legitimately present in a shell that also runs offline commands.
    """
    given = [
        name
        for name, value in (
            *vars(settings).items(),
            ("seed_policy", seed_policy),
            ("cost_budget_microusd", cost_budget),
        )
        if value is not None
    ]
    if given:
        raise ModelConfigError(
            f"{', '.join(given)} configure a networked model and need --endpoint; the offline "
            "provider would ignore them"
        )


def networked_provider(
    endpoint: str, profile: str, settings: ModelSettings | None = None
) -> tuple[Provider, ModelPin]:
    """Build a networked provider, or refuse. There is no fallback to the offline provider.

    The credential is checked first, so a hosted lane without one is still a recorded skip. A
    hosted lane *with* one but without a declared price is then refused outright: running it
    would record its cost as zero and leave the signed cost cap unable to fire.
    """
    credential = os.environ.get(CREDENTIAL_ENV)
    if profile == "openai-compatible" and not credential:
        raise ModelUnavailableForLane(
            f"{CREDENTIAL_ENV} is not set; the stochastic lane is skipped, not downgraded"
        )
    from purpleloop.adapters.agent import SYSTEM_PROMPT_HASH

    pin = build_pin(
        pin_id="networked",
        profile=profile,
        system_prompt_hash=SYSTEM_PROMPT_HASH,
        settings=settings or ModelSettings(),
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
    pin: ModelPin | None = None,
) -> RunSummary:
    """Run one repetition through the Inspect bridge, so the bundle carries an Inspect log."""
    return await evaluate_runner(
        runner,
        scenario,  # type: ignore[arg-type]
        manifest,  # type: ignore[arg-type]
        run_id=run_id,
        output_dir=directory,
        model_fixture=MODEL_FIXTURE,
        model_pin=pin,
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
    pin: ModelPin | None,
    fixture_mode: AgentFixtureMode = AgentFixtureMode.IN_PROCESS,
    seed_policy: SeedPolicy = SeedPolicy.FIXED,
    cost_microusd_budget: int = DEFAULT_COST_BUDGET_MICROUSD,
) -> tuple[AuthorizationManifest, RunnerFactory, Execute]:
    def sign(run_pin: ModelPin | None) -> AuthorizationManifest:
        # The manifest signs the origin the provider will actually connect to, not the URL it was
        # given: a base URL carries an API path (Ollama's and most hosted APIs' ``/v1``) that a
        # signed model asset may not, and signing anything else would let the two disagree.
        return supportlab_agent_manifest(
            manifest_key,
            seed=seed,
            judge=judge,
            model_endpoint=provider.endpoint if provider is not None else None,
            model_pin=run_pin,
            cost_microusd_budget=cost_microusd_budget,
        )

    manifest = sign(pin)
    verifier = ManifestVerifier({KEY_ID: manifest_key.public_key()})
    verifier.verify(manifest)
    if seed_policy == SeedPolicy.PER_REPETITION and (pin is None or pin.decoding.seed is None):
        raise ModelConfigError("the per-repetition seed policy needs a seeded networked pin")
    # The fixture each repetition will run against, created in the factory and started by the
    # execute wrapper: a compose fixture needs an async start the synchronous factory cannot do.
    # Each entry carries the manifest that repetition was built under.
    pending: list[tuple[InProcessSupportlab | ComposeSupportlab, AuthorizationManifest]] = []

    def factory(index: int) -> tuple[PurpleTeamRunner, Path]:
        run_manifest = manifest
        if seed_policy == SeedPolicy.PER_REPETITION:
            assert pin is not None and pin.decoding.seed is not None
            run_manifest = sign(with_seed(pin, pin.decoding.seed + index))
            verifier.verify(run_manifest)
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
        pending.append((fixture, run_manifest))
        runner = build_agent_runner(
            directory,
            run_manifest,
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
        fixture, built_under = pending.pop()
        if isinstance(fixture, ComposeSupportlab):  # pragma: no cover - container lane
            await fixture.start()
        # Under a fixed seed this is the manifest passed in. Under per-repetition seeding it is
        # the repetition's own, so the signed pin and the pin the model client calls with agree.
        run_pin = pin
        if built_under is not run_manifest and built_under.phase3 is not None and pin is not None:
            run_pin = built_under.phase3.pin(pin.pin_id)
        return await _inspect_execute(runner, scenario, built_under, run_id, directory, run_pin)

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
            pin=None,
        )
        runner, directory = factory(0)
        summaries.append(
            await runner.run(scenario, manifest, run_id=scenario.scenario_id, output_dir=directory)
        )
        scenarios.append(scenario)
    return scenarios, summaries


def _networked_judge_report(output_dir: Path, config: JudgeRunConfig) -> None:
    try:
        payload = run_networked_judge_report(load_corpus(REDTEAM), config, output_dir)
    except JudgeUnavailable as exc:
        typer.echo(f"SKIPPED: {exc}", err=True)
        raise typer.Exit(0) from None
    except Exception as exc:  # noqa: BLE001 -- every stop is reported with its reason code
        reason = str(getattr(exc, "reason_code", "") or type(exc).__name__)
        typer.echo(f"FAILED: {reason}: {exc}", err=True)
        raise typer.Exit(1) from None
    for trial in payload["trials"]:
        agreement_ = trial["agreement"]
        control = trial.get("negative_control_without_delimiting")
        typer.echo(
            f"trial={trial['trial']} seed={trial['seed']} "
            f"resistance={trial['hardened']['resistance']:.3f} "
            + (f"(negative control {control['resistance']:.3f}) " if control else "")
            + f"alpha={agreement_['krippendorff_alpha']:.3f} "
            f"[{agreement_['alpha_ci_low']:.3f},{agreement_['alpha_ci_high']:.3f}] "
            f"n={agreement_['n']} kappa={agreement_['cohen_kappa']} "
            f"kappa_n={agreement_['kappa_n']} swap={agreement_['order_swap_consistency']:.3f} "
            f"critical_false_passes={len(trial['hardened']['critical_false_passes'])}"
        )
    pooled = payload["pooled_agreement"]
    calls = payload["model_calls"]
    typer.echo(
        f"pooled alpha={pooled['krippendorff_alpha']:.3f} n={pooled['n']} (case-trials) "
        f"calls={calls['calls']} tokens={calls['tokens']} cost_microusd={calls['cost_microusd']} "
        f"thinking_stripped={payload['thinking']['stripped']} "
        f"unparseable={payload['thinking']['unparseable_replies']} (advisory)"
    )


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
        temperature: TemperatureOption = None,
        top_p: TopPOption = None,
        model_seed: ModelSeedOption = None,
        max_output_tokens: MaxTokensOption = None,
        price_input_microusd_per_1k: PriceInputOption = None,
        price_output_microusd_per_1k: PriceOutputOption = None,
        declared_free: DeclaredFreeOption = None,
        model_id: ModelIdOption = None,
        model_version: ModelVersionOption = None,
        seed_policy: SeedPolicyOption = None,
        cost_budget_microusd: CostBudgetOption = None,
    ) -> None:
        """Run one agent scenario, optionally repeated, judged, and probed by the attacker."""
        provider: Provider | None = None
        pin: ModelPin | None = None
        settings = ModelSettings(
            temperature=temperature,
            top_p=top_p,
            seed=model_seed,
            max_output_tokens=max_output_tokens,
            price_input_microusd_per_1k=price_input_microusd_per_1k,
            price_output_microusd_per_1k=price_output_microusd_per_1k,
            declared_free=declared_free,
            model_id=model_id,
            model_version=model_version,
        )
        try:
            policy = SeedPolicy.FIXED
            cost_budget = DEFAULT_COST_BUDGET_MICROUSD
            if endpoint is not None:
                provider, pin = networked_provider(endpoint, profile, settings)
                policy = resolve_seed_policy(seed_policy)
                cost_budget = resolve_cost_budget(cost_budget_microusd)
            else:
                refuse_offline_model_options(settings, seed_policy, cost_budget_microusd)
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
                pin=pin,
                fixture_mode=fixture,
                seed_policy=policy,
                cost_microusd_budget=cost_budget,
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
                    **seed_policy_label(policy, pin),
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
                outcome=run_outcome(enriched),
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
    def judge_report(
        output_dir: Path = Path("artifacts/judge"),
        judge_endpoint: Annotated[
            str | None,
            typer.Option(
                envvar="PURPLELOOP_JUDGE_ENDPOINT",
                help="Networked judge base URL; omitted, the scripted stand-in is scored",
            ),
        ] = None,
        judge_profile: Annotated[
            str, typer.Option(envvar="PURPLELOOP_JUDGE_PROFILE")
        ] = "openai-compatible",
        trials: Annotated[
            int, typer.Option(envvar="PURPLELOOP_JUDGE_TRIALS", help="Passes over the corpus")
        ] = 1,
        negative_control: bool = True,
        judge_model_id: Annotated[
            str | None, typer.Option(help="(env PURPLELOOP_JUDGE_MODEL_ID)")
        ] = None,
        judge_model_version: Annotated[
            str | None, typer.Option(help="(env PURPLELOOP_JUDGE_MODEL_VERSION)")
        ] = None,
        judge_temperature: Annotated[
            float | None, typer.Option(help="(env PURPLELOOP_JUDGE_TEMPERATURE; 0)")
        ] = None,
        judge_top_p: Annotated[
            float | None, typer.Option(help="(env PURPLELOOP_JUDGE_TOP_P; 1)")
        ] = None,
        judge_seed: Annotated[
            str | None, typer.Option(help="Seed or 'none' (env PURPLELOOP_JUDGE_SEED; 42)")
        ] = None,
        judge_max_output_tokens: Annotated[
            int | None, typer.Option(help="(env PURPLELOOP_JUDGE_MAX_OUTPUT_TOKENS; 512)")
        ] = None,
        judge_price_input_microusd_per_1k: Annotated[
            int | None, typer.Option(help="(env PURPLELOOP_JUDGE_PRICE_INPUT_MICROUSD_PER_1K)")
        ] = None,
        judge_price_output_microusd_per_1k: Annotated[
            int | None, typer.Option(help="(env PURPLELOOP_JUDGE_PRICE_OUTPUT_MICROUSD_PER_1K)")
        ] = None,
        judge_declared_free: Annotated[
            str | None, typer.Option(help="Acknowledge a hosted judge as free by its model id")
        ] = None,
        judge_timeout_seconds: Annotated[
            float, typer.Option(envvar="PURPLELOOP_JUDGE_TIMEOUT_SECONDS")
        ] = DEFAULT_JUDGE_TIMEOUT_SECONDS,
        judge_token_budget: Annotated[
            int, typer.Option(envvar="PURPLELOOP_JUDGE_TOKEN_BUDGET")
        ] = DEFAULT_JUDGE_TOKEN_BUDGET,
        judge_cost_budget_microusd: Annotated[
            int | None, typer.Option(help="(env PURPLELOOP_JUDGE_COST_BUDGET_MICROUSD; 1e6)")
        ] = None,
    ) -> None:
        """Score the judge against the frozen evaluator red-team corpus.

        Without ``--judge-endpoint`` this scores the scripted stand-in, exactly as in Phase 3.
        With it, a real pinned judge is scored over ``--trials`` passes with order swaps; the
        result is advisory and the command exits zero when it completes.
        """
        if judge_endpoint is not None:
            settings = ModelSettings(
                temperature=judge_temperature,
                top_p=judge_top_p,
                seed=judge_seed,
                max_output_tokens=judge_max_output_tokens,
                price_input_microusd_per_1k=judge_price_input_microusd_per_1k,
                price_output_microusd_per_1k=judge_price_output_microusd_per_1k,
                declared_free=judge_declared_free,
                model_id=judge_model_id,
                model_version=judge_model_version,
            )
            _networked_judge_report(
                output_dir,
                JudgeRunConfig(
                    endpoint=judge_endpoint,
                    profile=judge_profile,
                    settings=settings,
                    trials=trials,
                    negative_control=negative_control,
                    timeout_seconds=judge_timeout_seconds,
                    token_budget=judge_token_budget,
                    cost_microusd_budget=resolve_cost_budget(
                        judge_cost_budget_microusd, name="PURPLELOOP_JUDGE"
                    ),
                ),
            )
            return
        try:
            corpus = require_frozen(load_corpus(REDTEAM))
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
