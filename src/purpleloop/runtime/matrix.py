"""The pinned evaluation matrix: models x defenses x scenarios x repetitions (WP5.2, plan §2.3).

The question the matrix answers is narrow on purpose: **does a defense still work when the model
stops cooperating?** It is not a model leaderboard, and nothing here computes a per-model score.

How it executes, and why that shape:

- **Spend authority is signed data.** A run starts from a signed :class:`EvaluationMatrix`. Before
  the first call, :func:`preflight` estimates cost *and* wall time for every row from the spec's
  own signed figures and refuses the whole matrix -- recording why -- when either estimate is
  over its cap, or when a real pin declares no per-call time (an unknown time is refused, never
  estimated as zero, the same rule the model plane applies to an undeclared price).
- **One paired run supplies two cells.** The runner's baseline leg runs with no defense and its
  replay leg under the scenario's defense, against the same seeded state and the same model seed.
  So ``no-defense`` and the defense's own column come from one run, paired by construction.
- **Applicability is the registry's, not the matrix's.** A defense profile names the scenarios it
  applies to (``control.phase3_tools.AGENT_DEFENSES``); the runner refuses any other pairing at the
  ``DEFENSE`` stage and the fixture refuses it again with a 403. On the 25-scenario agent corpus
  every scenario is in exactly one defense's set, so each single-defense column is populated only
  on that defense's own scenarios and every other pairing is recorded ``not-applicable`` -- never
  executed, never a failure. Measuring a defense off its own scenarios would need a signed widening
  of that registry; the matrix does not do it behind the registry's back.
- **The manifest pre-authorizes exactly the columns.** Each trial's manifest 1.3 is the agent
  lane's manifest with ``defense_profiles`` narrowed to the agent defenses the matrix exercises.
- **Deterministic anchors.** ``ScriptedAgentModel`` (compliant), ``DelimitationBlindModel``, and
  ``HostileModel`` are rows beside any real pin. They run in process, cost nothing, and replay
  exactly, so they give every real-pin cell a known floor and ceiling.

Outputs are advisory by type (``MatrixCell``/``DefenseDependence``) and the gates refuse them.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field

from purpleloop.adapters.agent import SYSTEM_PROMPT, SYSTEM_PROMPT_HASH
from purpleloop.adapters.model_provider import Provider
from purpleloop.adapters.scripted_model import (
    DelimitationBlindModel,
    HostileModel,
    ScriptedAgentModel,
)
from purpleloop.control.manifest import ManifestVerifier, sign_manifest
from purpleloop.control.phase3_tools import AGENT_DEFENSES
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    MODEL_FIXTURE,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
    supportlab_agent_manifest,
)
from purpleloop.schemas.authorization import AuthorizationManifest, Phase1Grants
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase1 import Phase1Scenario, RunSummary
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, ProviderProfile
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import (
    ActionClass,
    AnchorModel,
    DefenseDependence,
    EnforcementKind,
    EvaluationMatrix,
    MatrixCell,
    MatrixRow,
    Phase5Grants,
)
from purpleloop.scoring.matrix import (
    MatrixContrast,
    MatrixTrial,
    NotApplicable,
    Unclassified,
    contrast,
    dependence,
    make_cell,
    registered_contrasts,
)
from purpleloop.scoring.phase3 import estimate_is_a_bound, estimate_tokens

BASELINE_COLUMN = "no-defense"
ASSIGNED_COLUMN = "scenario-assigned"
#: The seven agent defenses, in registry order.
DEFENSE_COLUMNS: tuple[str, ...] = tuple(AGENT_DEFENSES)
MATRIX_COLUMNS: tuple[str, ...] = (BASELINE_COLUMN, *DEFENSE_COLUMNS, ASSIGNED_COLUMN)

#: The fixture seed every agent scenario is authored against. The model seed varies per
#: repetition; the seeded application state does not.
FIXTURE_SEED = 42

#: Measured harness time per trial with an in-process stand-in, Inspect bridge included: 45
#: trials (3 stand-ins x 3 scenarios x 5 repetitions) in 66.9 s on 2026-11-25 (UTC), Apple M3 Pro,
#: rounded to 1.5. Calibrated once, before the first full matrix run, and held fixed; each run
#: reports its measured time beside the estimate (``docs/phase5/wp5.2-acceptance.md``).
HARNESS_SECONDS_PER_TRIAL = 1.5
#: Characters of task and retrieved context per call, beside the system prompt, for the token
#: *bound* of a pin with no calibration. A bound, labelled as one; it matters only to a priced pin.
PROMPT_ALLOWANCE_CHARS = 4000

ANCHOR_PROVIDERS: dict[AnchorModel, Callable[[], Provider]] = {
    "scripted-compliant": ScriptedAgentModel,
    "delimitation-blind": DelimitationBlindModel,
    "hostile": HostileModel,
}


# --- enforcement kinds -------------------------------------------------------------------------


@dataclass(frozen=True)
class Enforcement:
    """How a defense is enforced, read from the fixture code. ``application_sinks`` lists the
    state tables at which the application itself refuses; ``None`` means every sink."""

    mechanism: str
    application_sinks: frozenset[str] | None


#: One entry per agent defense. Each was read from ``fixture/supportlab/agent_api.py``,
#: ``fixture/supportlab/app.py``, and ``adapters/agent.py``; a test checks the keys match the
#: registry exactly, so a new defense cannot ship without a stated enforcement kind.
ENFORCEMENT: dict[str, Enforcement] = {
    "retrieval-provenance-guard": Enforcement(
        "Prompt marking on every sink: the agent adapter wraps untrusted chunks in <untrusted> "
        "blocks under a quarantine notice. Application-side only at /api/agent/email (f20f482): "
        "once the actor's latest assistant run retrieved untrusted content, a message that leaves "
        "the organisation or carries the tracer is refused. Exports, refunds, and CRM writes are "
        "not gated by provenance, so there the defense is the prompt alone.",
        frozenset({"emails"}),
    ),
    "memory-write-guard": Enforcement(
        "Application-side: /api/agent/memory refuses a write labelled derived_from=untrusted. The "
        "label comes from the model's own intent, so the check trusts the model to report "
        "provenance; every stand-in here reports it honestly.",
        None,
    ),
    "output-sanitization": Enforcement(
        "Application-side: /api/agent/email refuses an external destination or a body carrying "
        "the tracer, unconditionally.",
        None,
    ),
    "capability-scoping": Enforcement(
        "Application-side: every agent tool route refuses an operation outside the task's "
        "declared capability set.",
        None,
    ),
    "prompt-isolation": Enforcement(
        "Application-side data withholding: the context response omits the operating notes, so "
        "the model has nothing to leak (it is also told not to disclose them).",
        None,
    ),
    "schema-validation": Enforcement(
        "Application-side: /api/agent/email refuses control characters in a subject, closing "
        "the header-injection path. It does not restrict a destination named directly.",
        None,
    ),
    "workflow-approval": Enforcement(
        "Application-side: the refund and export routes refuse an operation without a matching "
        "approval record.",
        None,
    ),
}


def scenario_sink(scenario: Phase1Scenario) -> str:
    """Where the scenario's security oracle looks: a state table, or ``responses``."""
    oracle = scenario.security_oracle
    assert oracle is not None
    if oracle.source != "state":
        return oracle.source
    return str(oracle.path[0])


def enforcement_for(defense: str, scenario: Phase1Scenario) -> EnforcementKind:
    """The enforcement kind of ``defense`` at the sink ``scenario`` attacks."""
    sinks = ENFORCEMENT[defense].application_sinks
    return (
        "application-side" if sinks is None or scenario_sink(scenario) in sinks else "prompt-only"
    )


def applies(column: str, scenario: Phase1Scenario) -> bool:
    """Whether a column can be measured on a scenario under the defense registry."""
    if column in (BASELINE_COLUMN, ASSIGNED_COLUMN):
        return True
    return scenario.scenario_id in AGENT_DEFENSES[column][0]


# --- rows --------------------------------------------------------------------------------------


def anchor_row(anchor: AnchorModel, *, seeds: Sequence[int]) -> MatrixRow:
    pin = ModelPin(
        pin_id=f"standin-{anchor}",
        provider="offline",
        model_id=f"standin-{anchor}",
        model_version="scripted-v1",
        decoding=DecodingParameters(seed=seeds[0]),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
    )
    return MatrixRow(
        row_id=anchor,
        kind="deterministic-anchor",
        anchor=anchor,
        pin=pin,
        seeds=tuple(seeds),
        decoding_label="greedy",
    )


def real_row(
    row_id: str,
    *,
    profile: ProviderProfile,
    model_id: str,
    model_version: str | None,
    decoding: DecodingParameters,
    seeds: Sequence[int],
    expected_seconds_per_call: float,
    price_input_microusd_per_1k: int = 0,
    price_output_microusd_per_1k: int = 0,
) -> MatrixRow:
    pin = ModelPin(
        pin_id=row_id,
        provider=profile,
        model_id=model_id,
        model_version=model_version,
        decoding=decoding,
        system_prompt_hash=SYSTEM_PROMPT_HASH,
        price_input_microusd_per_1k=price_input_microusd_per_1k,
        price_output_microusd_per_1k=price_output_microusd_per_1k,
    )
    return MatrixRow(
        row_id=row_id,
        kind="real-pin",
        pin=pin,
        seeds=tuple(seeds),
        decoding_label="greedy" if decoding.temperature == 0.0 else "sampled",
        expected_seconds_per_call=expected_seconds_per_call,
    )


def blind_row_id(spec: EvaluationMatrix) -> str:
    return next(row.row_id for row in spec.rows if row.anchor == "delimitation-blind")


# --- pre-flight --------------------------------------------------------------------------------


def defenses_to_run(spec: EvaluationMatrix, scenario: Phase1Scenario) -> tuple[str, ...]:
    """The replay defenses a scenario needs: its assigned one first, then any other applicable
    single-defense column. Each is one paired run; the assigned run supplies ``no-defense``."""
    extra = sorted(
        column
        for column in spec.defense_columns
        if column in AGENT_DEFENSES
        and column != scenario.defense_profile
        and applies(column, scenario)
    )
    return (scenario.defense_profile, *extra)


def model_calls_per_trial(scenario: Phase1Scenario) -> int:
    """Model calls one paired run makes: per leg, the clean task, the attack, and the clean task
    again for utility under attack. Fixed by the plan, whatever the model replies."""
    clean = sum(step.adapter == "agent" for step in scenario.clean_steps)
    attack = sum(step.adapter == "agent" for step in scenario.attack_steps)
    return 2 * (2 * clean + attack)


class RowEstimate(StrictModel):
    row_id: str
    kind: str
    trials: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    tokens: int = Field(ge=0)
    tokens_are_a_bound: bool
    cost_microusd: int = Field(ge=0)
    wall_seconds: float = Field(ge=0.0)
    seconds_per_call: float | None = None


RefusalReason = Literal[
    "COST_CAP_EXCEEDED",
    "WALL_TIME_CAP_EXCEEDED",
    "WALL_TIME_CAP_UNDECLARED",
    "CALL_TIME_UNDECLARED",
    "UNKNOWN_SCENARIO",
    "UNKNOWN_COLUMN",
    "BASELINE_COLUMN_INVALID",
]


class MatrixPreflight(StrictModel):
    """The pre-flight decision, written before the first call whatever it decides."""

    matrix_id: str
    matrix_digest: str
    decision: Literal["accepted", "refused"]
    reasons: tuple[RefusalReason, ...] = ()
    detail: tuple[str, ...] = ()
    scenarios: int = Field(ge=0)
    repetitions: int = Field(ge=0)
    rows: tuple[RowEstimate, ...]
    trials: int = Field(ge=0)
    cost_microusd: int = Field(ge=0)
    cost_cap_microusd: int = Field(ge=0)
    wall_seconds: float = Field(ge=0.0)
    wall_time_cap_seconds: int | None = None
    harness_seconds_per_trial: float
    created_at: datetime


def preflight(
    spec: EvaluationMatrix, corpus: Mapping[str, Phase1Scenario], *, now: datetime | None = None
) -> MatrixPreflight:
    """Estimate every row's cost and wall time and decide, before anything is called."""
    reasons: list[RefusalReason] = []
    detail: list[str] = []
    unknown = sorted(spec.scenario_ids - set(corpus))
    if unknown:
        reasons.append("UNKNOWN_SCENARIO")
        detail.append(f"not in the agent corpus: {', '.join(unknown)}")
    columns = set(spec.defense_columns) - set(MATRIX_COLUMNS)
    if columns:
        reasons.append("UNKNOWN_COLUMN")
        detail.append(f"not a matrix column: {', '.join(sorted(columns))}")
    if spec.baseline_column != BASELINE_COLUMN:
        reasons.append("BASELINE_COLUMN_INVALID")
        detail.append(f"the baseline column must be {BASELINE_COLUMN}")
    scenarios = [corpus[sid] for sid in sorted(spec.scenario_ids) if sid in corpus]
    estimates: list[RowEstimate] = []
    for row in spec.rows:
        trials = calls = 0
        for scenario in scenarios:
            runs = len(defenses_to_run(spec, scenario)) * spec.repetitions
            trials += runs
            calls += runs * model_calls_per_trial(scenario)
        tokens, cost = estimate_tokens(
            row.pin, model_calls=calls, prompt_chars=len(SYSTEM_PROMPT) + PROMPT_ALLOWANCE_CHARS
        )
        per_call = row.expected_seconds_per_call if row.kind == "real-pin" else None
        if row.kind == "real-pin" and per_call is None:
            reasons.append("CALL_TIME_UNDECLARED")
            detail.append(f"{row.row_id}: a real pin must declare expected_seconds_per_call")
        estimates.append(
            RowEstimate(
                row_id=row.row_id,
                kind=row.kind,
                trials=trials,
                model_calls=calls,
                tokens=tokens,
                tokens_are_a_bound=estimate_is_a_bound(row.pin),
                cost_microusd=cost,
                wall_seconds=round(trials * HARNESS_SECONDS_PER_TRIAL + calls * (per_call or 0), 3),
                seconds_per_call=per_call,
            )
        )
    cost = sum(item.cost_microusd for item in estimates)
    wall = round(sum(item.wall_seconds for item in estimates), 3)
    if cost > spec.cost_cap_microusd:
        reasons.append("COST_CAP_EXCEEDED")
        detail.append(f"estimated {cost} micro-USD > cap {spec.cost_cap_microusd}")
    real = any(row.kind == "real-pin" for row in spec.rows)
    if spec.wall_time_cap_seconds is None:
        if real:
            reasons.append("WALL_TIME_CAP_UNDECLARED")
            detail.append("a spec with a real pin must sign a wall-time cap")
    elif wall > spec.wall_time_cap_seconds:
        reasons.append("WALL_TIME_CAP_EXCEEDED")
        detail.append(f"estimated {wall:.0f} s > cap {spec.wall_time_cap_seconds} s")
    return MatrixPreflight(
        matrix_id=spec.matrix_id,
        matrix_digest=spec.matrix_digest(),
        decision="refused" if reasons else "accepted",
        reasons=tuple(reasons),
        detail=tuple(detail),
        scenarios=len(scenarios),
        repetitions=spec.repetitions,
        rows=tuple(estimates),
        trials=sum(item.trials for item in estimates),
        cost_microusd=cost,
        cost_cap_microusd=spec.cost_cap_microusd,
        wall_seconds=wall,
        wall_time_cap_seconds=spec.wall_time_cap_seconds,
        harness_seconds_per_trial=HARNESS_SECONDS_PER_TRIAL,
        created_at=(now or datetime.now(UTC)).astimezone(UTC),
    )


class MatrixRefused(RuntimeError):
    reason_code = "MATRIX_PREFLIGHT_REFUSED"


# --- execution ---------------------------------------------------------------------------------


def trial_manifest(
    key: Ed25519PrivateKey,
    row: MatrixRow,
    seed: int,
    *,
    endpoint: str | None,
    cost_budget: int,
    calls: int,
) -> AuthorizationManifest:
    """The agent lane's manifest 1.3 for one trial, authorizing exactly the agent defenses.

    The model pin is the row's pin under this repetition's seed. A real pin gets a per-run wall
    budget scaled from its signed per-call expectation (three times the estimate, never under
    the lane's 120 s); an anchor keeps the lane's own budget.
    """
    pin = row.pin.model_copy(
        update={"decoding": row.pin.decoding.model_copy(update={"seed": seed})}
    )
    wall = None
    if row.expected_seconds_per_call is not None:
        wall = max(120.0, math.ceil(3 * calls * row.expected_seconds_per_call) + 60.0)
    manifest = supportlab_agent_manifest(
        key,
        seed=FIXTURE_SEED,
        model_endpoint=endpoint,
        model_pin=pin,
        cost_microusd_budget=cost_budget,
        wall_time_seconds=wall,
    )
    narrowed = manifest.model_copy(
        update={
            "signature": "",
            "phase1": Phase1Grants(defense_profiles=frozenset(AGENT_DEFENSES)),
        }
    )
    return sign_manifest(AuthorizationManifest.model_validate(narrowed.model_dump()), key)


def bundle_name(row_id: str, scenario_id: str, repetition: int, defense: str, assigned: str) -> str:
    suffix = "" if defense == assigned else f"--{defense}"
    return f"{row_id}--{scenario_id}--rep-{repetition}{suffix}"


def _verdict(summary: RunSummary, leg: Literal["baseline", "replay"]) -> bool | None:
    result = summary.baseline if leg == "baseline" else summary.replay
    if result is None or result.security.verdict not in ("true", "false"):
        return None
    return result.security.verdict == "true"


@dataclass
class MatrixRun:
    trials: list[MatrixTrial] = field(default_factory=list)
    bundles: list[str] = field(default_factory=list)
    not_run: list[str] = field(default_factory=list)
    cost_microusd: int = 0
    elapsed_seconds: float = 0.0


async def run_matrix(
    spec: EvaluationMatrix,
    corpus: Mapping[str, Phase1Scenario],
    root: Path,
    key: Ed25519PrivateKey,
    *,
    providers: Mapping[str, Provider] | None = None,
    progress: Callable[[str], None] | None = None,
) -> MatrixRun:
    """Execute every trial the spec names. ``providers`` supplies each real-pin row's provider.

    The matrix stops *starting* trials once the spend reaches the cost cap or the elapsed time
    reaches the wall-time cap; everything not started is listed as not run, and its repetitions
    are exclusions in the cells. A trial that raises is recorded as an excluded trial, not a crash.
    """
    run = MatrixRun()
    started = time.monotonic()
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    supplied = dict(providers or {})
    for row in spec.rows:
        if row.kind == "real-pin" and row.row_id not in supplied:
            raise ValueError(f"no provider was supplied for real-pin row {row.row_id}")
    for row in spec.rows:
        for scenario_id in sorted(spec.scenario_ids):
            scenario = corpus[scenario_id]
            calls = model_calls_per_trial(scenario)
            for defense in defenses_to_run(spec, scenario):
                variant = (
                    scenario
                    if defense == scenario.defense_profile
                    else scenario.model_copy(update={"defense_profile": defense})
                )
                for index, seed in enumerate(row.seeds):
                    name = bundle_name(
                        row.row_id, scenario_id, index, defense, scenario.defense_profile
                    )
                    elapsed = time.monotonic() - started
                    if run.cost_microusd >= spec.cost_cap_microusd > 0 or (
                        spec.wall_time_cap_seconds is not None
                        and elapsed >= spec.wall_time_cap_seconds
                    ):
                        run.not_run.append(name)
                        continue
                    if row.row_id in supplied:
                        provider = supplied[row.row_id]
                    else:
                        assert row.anchor is not None
                        provider = ANCHOR_PROVIDERS[row.anchor]()
                    trial = await _run_trial(
                        spec,
                        row,
                        variant,
                        index,
                        seed,
                        defense,
                        name,
                        root,
                        key,
                        verifier,
                        provider=provider,
                        calls=calls,
                    )
                    run.trials.append(trial)
                    run.cost_microusd += trial.cost_microusd
                    if trial.status != "excluded":
                        run.bundles.append(name)
                    if progress is not None:
                        progress(
                            f"{name}: {trial.status} baseline={trial.baseline_success} "
                            f"replay={trial.replay_success}"
                        )
    run.elapsed_seconds = round(time.monotonic() - started, 3)
    return run


async def _run_trial(
    spec: EvaluationMatrix,
    row: MatrixRow,
    scenario: Phase1Scenario,
    index: int,
    seed: int,
    defense: str,
    name: str,
    root: Path,
    key: Ed25519PrivateKey,
    verifier: ManifestVerifier,
    *,
    provider: Provider,
    calls: int,
) -> MatrixTrial:
    started = time.monotonic()
    cost_budget = min(1_000_000, spec.cost_cap_microusd)
    manifest = trial_manifest(
        key, row, seed, endpoint=provider.endpoint, cost_budget=cost_budget, calls=calls
    )
    verifier.verify(manifest)
    tokens = actor_credentials()
    control = actor_credentials()["customer-a"]
    directory = root / name
    timeout = (
        max(30.0, 4 * row.expected_seconds_per_call)
        if row.expected_seconds_per_call is not None
        else None
    )
    runner = build_agent_runner(
        directory,
        manifest,
        verifier,
        actor_tokens=tokens,
        control=control,
        fixture=InProcessSupportlab(tokens, control),
        model_provider=provider,
        model_pin_id=row.pin.pin_id,
        model_timeout_seconds=timeout,
    )
    assert manifest.phase3 is not None
    pin = manifest.phase3.pin(row.pin.pin_id)
    base = {
        "row_id": row.row_id,
        "scenario_id": scenario.scenario_id,
        "repetition": index,
        "seed": seed,
        "defense_profile": defense,
        "bundle": name,
    }
    try:
        summary = await evaluate_runner(
            runner,
            scenario,
            manifest,
            run_id=name,
            output_dir=directory,
            model_fixture=MODEL_FIXTURE,
            model_pin=None if row.kind == "deterministic-anchor" else pin,
        )
    except Exception as exc:  # noqa: BLE001 -- an excluded trial is data, not a crash
        return MatrixTrial.model_validate(
            {
                **base,
                "status": "excluded",
                "reason": str(getattr(exc, "reason_code", "") or type(exc).__name__),
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
        )
    return MatrixTrial.model_validate(
        {
            **base,
            "status": summary.status,
            "reason": summary.reason,
            "baseline_success": _verdict(summary, "baseline"),
            "replay_success": _verdict(summary, "replay"),
            "model_calls": sum(
                leg.model_calls for leg in (summary.baseline, summary.replay) if leg is not None
            ),
            "tokens": summary.tokens_used,
            "cost_microusd": summary.cost_microusd,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    )


# --- analysis ----------------------------------------------------------------------------------


class DefenseSummary(StrictModel):
    """Per defense (never per model): how its scenarios classified, and how it is enforced."""

    defense_column: str
    scenarios: int = Field(ge=0)
    model_independent: int = Field(ge=0)
    model_dependent: int = Field(ge=0)
    ineffective: int = Field(ge=0)
    unclassified: int = Field(ge=0)
    enforcement: dict[str, int]
    mechanism: str


class MatrixResults(StrictModel):
    matrix_digest: str
    cells: tuple[MatrixCell, ...]
    not_applicable: tuple[NotApplicable, ...]
    contrasts: tuple[MatrixContrast, ...]
    exploratory: tuple[MatrixContrast, ...]
    dependence: tuple[DefenseDependence, ...]
    unclassified: tuple[Unclassified, ...]
    defenses: tuple[DefenseSummary, ...]
    #: Per row, the defended cells in which the attack still succeeded, worst first.
    worst_cases: dict[str, tuple[MatrixCell, ...]]


def analyse(
    spec: EvaluationMatrix, corpus: Mapping[str, Phase1Scenario], trials: Sequence[MatrixTrial]
) -> MatrixResults:
    """Cells, the registered contrasts, exploratory contrasts, and the dependence classification."""
    grouped: dict[tuple[str, str, str], list[MatrixTrial]] = defaultdict(list)
    for trial in trials:
        grouped[(trial.row_id, trial.scenario_id, trial.defense_profile)].append(trial)
    scenarios = [corpus[sid] for sid in sorted(spec.scenario_ids)]
    cells: dict[tuple[str, str, str], MatrixCell] = {}
    missing: list[NotApplicable] = []

    def place(row_id: str, column: str, scenario_id: str, cell: MatrixCell | None) -> None:
        if cell is None:
            missing.append(
                NotApplicable(
                    row_id=row_id,
                    defense_column=column,
                    scenario_id=scenario_id,
                    reason="NO_COMPLETED_REPETITION",
                )
            )
        else:
            cells[(row_id, column, scenario_id)] = cell

    for row in spec.rows:
        for scenario in scenarios:
            sid = scenario.scenario_id
            assigned = grouped.get((row.row_id, sid, scenario.defense_profile), [])
            for column in spec.defense_columns:
                if not applies(column, scenario):
                    missing.append(
                        NotApplicable(
                            row_id=row.row_id,
                            defense_column=column,
                            scenario_id=sid,
                            reason="DEFENSE_NOT_APPLICABLE",
                        )
                    )
                    continue
                if column == BASELINE_COLUMN:
                    source, leg = assigned, "baseline"
                elif column == ASSIGNED_COLUMN:
                    source, leg = assigned, "replay"
                else:
                    source, leg = grouped.get((row.row_id, sid, column), []), "replay"
                place(
                    row.row_id,
                    column,
                    sid,
                    make_cell(
                        spec,
                        row_id=row.row_id,
                        column=column,
                        scenario_id=sid,
                        trials=source,
                        leg=leg,  # type: ignore[arg-type]
                    ),
                )
    applicable = {
        column: frozenset(s.scenario_id for s in scenarios if applies(column, s))
        for column in spec.defense_columns
    }
    blind = blind_row_id(spec)
    exploratory = tuple(
        contrast(
            cells,
            row_id=row.row_id,
            column=column,
            against=column,
            against_row=blind,
            scenarios=applicable[column],
            exploratory=True,
        )
        for column in spec.defense_columns
        if column != spec.baseline_column
        for row in spec.rows
        if row.row_id != blind
    )
    classified: list[DefenseDependence] = []
    unclassified: list[Unclassified] = []
    summaries: list[DefenseSummary] = []
    for column in spec.defense_columns:
        if column not in AGENT_DEFENSES:
            continue
        own = [s for s in scenarios if applies(column, s)]
        counts = {"model-independent": 0, "model-dependent": 0, "ineffective": 0}
        kinds: dict[str, int] = defaultdict(int)
        open_count = 0
        for scenario in own:
            kind = enforcement_for(column, scenario)
            kinds[kind] += 1
            result = dependence(
                spec,
                cells,
                column=column,
                scenario_id=scenario.scenario_id,
                enforcement=kind,
                blind_row=blind,
            )
            if isinstance(result, Unclassified):
                unclassified.append(result)
                open_count += 1
            else:
                classified.append(result)
                counts[result.classification] += 1
        summaries.append(
            DefenseSummary(
                defense_column=column,
                scenarios=len(own),
                model_independent=counts["model-independent"],
                model_dependent=counts["model-dependent"],
                ineffective=counts["ineffective"],
                unclassified=open_count,
                enforcement=dict(kinds),
                mechanism=ENFORCEMENT[column].mechanism,
            )
        )
    worst = {
        row.row_id: tuple(
            sorted(
                (
                    cell
                    for (row_id, column, _), cell in cells.items()
                    if row_id == row.row_id and column in AGENT_DEFENSES and cell.successes > 0
                ),
                key=lambda cell: (-cell.value, cell.defense_column, cell.scenario_id),
            )
        )
        for row in spec.rows
    }
    return MatrixResults(
        matrix_digest=spec.matrix_digest(),
        cells=tuple(cells.values()),
        not_applicable=tuple(missing),
        contrasts=registered_contrasts(spec, cells, applicable),
        exploratory=exploratory,
        dependence=tuple(classified),
        unclassified=tuple(unclassified),
        defenses=tuple(summaries),
        worst_cases=worst,
    )


def cell_table(results: MatrixResults) -> list[dict[str, object]]:
    """The flat per-cell table (the Parquet-shaped export, written as JSON). One row per cell;
    there is deliberately no column that aggregates across scenarios."""
    return [
        {
            "matrix_digest": cell.matrix_digest,
            "row_id": cell.row_id,
            "defense_column": cell.defense_column,
            "scenario_id": cell.scenario_id,
            "metric": cell.metric,
            "successes": cell.successes,
            "n": cell.n,
            "excluded": cell.excluded,
            "value": cell.value,
            "ci_low": cell.ci_low,
            "ci_high": cell.ci_high,
            "interval_method": cell.interval_method,
            "model_pin_id": cell.model_pin_id,
            "seed_policy": cell.seed_policy,
            "provenance": cell.provenance,
            "exploratory": cell.exploratory,
        }
        for cell in sorted(
            results.cells,
            key=lambda c: (c.row_id, c.scenario_id, MATRIX_COLUMNS.index(c.defense_column)),
        )
    ]


# --- spend authorization -----------------------------------------------------------------------


def authorization_manifest(
    spec: EvaluationMatrix,
    key: Ed25519PrivateKey,
    *,
    key_id: str,
    endpoint: str | None,
    valid_for: timedelta,
    now: datetime | None = None,
) -> AuthorizationManifest:
    """A manifest 1.5 that authorizes exactly this spec for unattended spend.

    ``phase5.matrix_scope`` is the spec's digest, so ``verify_matrix_spec`` accepts this spec and
    no other; ``phase3`` signs every real pin the spec names and the one model origin they may
    reach. No lane admits a 1.5 manifest yet, so it is never a trial's run manifest: it is the
    authority ``matrix-run`` checks before the first trial, and each trial still runs under its
    own lane-admitted 1.3 manifest signing the same pin.
    """
    current = (now or datetime.now(UTC)).astimezone(UTC)
    real = [row.pin for row in spec.rows if row.kind == "real-pin"]
    base = supportlab_agent_manifest(
        key,
        seed=FIXTURE_SEED,
        now=current,
        model_endpoint=endpoint if real else None,
        model_pin=real[0] if real else None,
    )
    assert base.phase3 is not None
    data = base.model_dump(mode="python", exclude_none=True)
    data.update(
        schema_version="1.5.0",
        engagement_id=spec.engagement_id,
        key_id=key_id,
        issued_at=current - timedelta(seconds=1),
        valid_from=current - timedelta(seconds=1),
        valid_until=current + valid_for,
        signature="",
        phase1=Phase1Grants(defense_profiles=frozenset(AGENT_DEFENSES)),
        phase3=base.phase3.model_copy(update={"model_pins": tuple(real) or base.phase3.model_pins}),
        phase4=Phase4Grants(
            # Required by 1.4+. The matrix attests nothing; the id names no key that exists.
            attestation_key_ids=frozenset({f"{key_id}-no-attestation"}),
            retention=(
                RetentionRule(artifact_kind="bundles", days=0, rationale="matrix evidence is kept"),
            ),
        ),
        phase5=Phase5Grants(
            action_classes=frozenset({ActionClass.READ, ActionClass.WRITE}),
            matrix_scope=spec.matrix_digest(),
        ),
    )
    return sign_manifest(AuthorizationManifest.model_validate(data), key)
