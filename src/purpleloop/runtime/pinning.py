"""Run one corpus scenario on its own lane, exactly as that lane's corpus test does (WP5.0.10).

The Phase 4 regression registry pinned every finding to one of three corpus-level tests, so a
failure could not say which finding regressed. The per-scenario pinning tests in
``tests/phase5/test_regression_pinning.py`` run each scenario through this module instead. It
builds the same runner, fixture, manifest, and verifier the Phase 1-3 test fixtures build, from
the same helpers (``build_runner``, ``build_supportlab_runner``, ``build_agent_runner``), with a
fresh signing key and a fresh fixture per run. Nothing here is a new execution path: it is the
corpus tests' setup lifted out of their ``conftest.py`` files so one scenario can run alone.

``PinnedOutcome`` is the part of a run that is a fact about the code rather than about the run:
verdicts, finding count, and the run summary's ``oracle_hash`` (per-run identifiers are already
excluded from it by ``leg_semantics``). The committed record of those facts lives in
``baselines/regression-outcomes.json``; the pinning tests assert each run reproduces its row.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field

from purpleloop.control.manifest import ManifestVerifier
from purpleloop.runtime.demo import ROOT, build_runner, demo_manifest
from purpleloop.runtime.fixture import InProcessFixture
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
    build_supportlab_runner,
    supportlab_agent_manifest,
    supportlab_manifest,
)
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase1 import Phase1Scenario, RunSummary, load_scenario, scenario_paths

Lane = Literal["phase1", "supportlab", "agent"]
LANES: tuple[Lane, ...] = ("phase1", "supportlab", "agent")
OUTCOMES_PATH = ROOT / "baselines" / "regression-outcomes.json"

# The synthetic secrets each lane's corpus test plants, so a leak check can look for them.
PHASE1_CUSTOMER = "CUSTOMER-SECRET-123"
PHASE1_CONTROL = "CONTROL-SECRET-456"
SUPPORTLAB_CONTROL = "SUPPORTLAB-CONTROL-SECRET"


@dataclass(frozen=True)
class PinnedScenario:
    lane: Lane
    path: Path
    scenario: Phase1Scenario

    @property
    def scenario_id(self) -> str:
        return self.scenario.scenario_id


@dataclass(frozen=True)
class PinnedRun:
    """A finished run plus the handles a pinning test inspects after it."""

    summary: RunSummary
    runner: PurpleTeamRunner
    fixture: InProcessFixture | InProcessSupportlab
    directory: Path
    manifest: AuthorizationManifest


class PinnedOutcome(StrictModel):
    """The recorded, run-independent facts of one scenario's paired loop."""

    scenario_id: str
    lane: Lane
    status: str
    baseline_security: str
    replay_security: str
    baseline_utility: str
    replay_utility: str
    findings: int = Field(ge=0)
    oracle_hash: str


class PinnedOutcomes(StrictModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    outcomes: tuple[PinnedOutcome, ...]

    def by_scenario(self) -> dict[str, PinnedOutcome]:
        return {outcome.scenario_id: outcome for outcome in self.outcomes}


def lane_directory(lane: Lane) -> Path:
    return ROOT / "scenarios" / lane


def pinned_scenarios() -> tuple[PinnedScenario, ...]:
    """Every corpus scenario, lane by lane, in each lane's corpus-test order."""
    return tuple(
        PinnedScenario(lane, path, load_scenario(path))
        for lane in LANES
        for path in scenario_paths(lane_directory(lane))
    )


def outcome_of(lane: Lane, summary: RunSummary) -> PinnedOutcome:
    if summary.baseline is None or summary.replay is None or summary.oracle_hash is None:
        raise ValueError(f"{summary.scenario_id}: a pinned run must complete both legs")
    return PinnedOutcome(
        scenario_id=summary.scenario_id,
        lane=lane,
        status=summary.status,
        baseline_security=summary.baseline.security.verdict,
        replay_security=summary.replay.security.verdict,
        baseline_utility=summary.baseline.utility.verdict,
        replay_utility=summary.replay.utility.verdict,
        findings=len(summary.findings),
        oracle_hash=summary.oracle_hash,
    )


def load_outcomes(path: Path = OUTCOMES_PATH) -> PinnedOutcomes:
    return PinnedOutcomes.model_validate_json(path.read_text())


async def run_pinned(pinned: PinnedScenario, directory: Path) -> PinnedRun:
    """One paired loop for one scenario, set up as its lane's corpus test sets it up."""
    key = Ed25519PrivateKey.generate()
    runner: PurpleTeamRunner
    fixture: InProcessFixture | InProcessSupportlab
    if pinned.lane == "phase1":
        manifest = demo_manifest(key)
        phase1_fixture = InProcessFixture(PHASE1_CUSTOMER, PHASE1_CONTROL)
        runner = build_runner(
            directory,
            manifest,
            ManifestVerifier({"demo-key": key.public_key()}),
            customer=PHASE1_CUSTOMER,
            control=PHASE1_CONTROL,
            fixture=phase1_fixture,
        )
        fixture = phase1_fixture
    else:
        build = build_supportlab_runner if pinned.lane == "supportlab" else build_agent_runner
        sign = supportlab_manifest if pinned.lane == "supportlab" else supportlab_agent_manifest
        manifest = sign(key, seed=42)
        tokens = actor_credentials()
        lab = InProcessSupportlab(tokens, SUPPORTLAB_CONTROL)
        runner = build(
            directory,
            manifest,
            ManifestVerifier({KEY_ID: key.public_key()}),
            actor_tokens=tokens,
            control=SUPPORTLAB_CONTROL,
            fixture=lab,
        )
        fixture = lab
    summary = await runner.run(
        pinned.scenario, manifest, run_id=pinned.scenario_id, output_dir=directory
    )
    return PinnedRun(summary, runner, fixture, directory, manifest)
