"""Canonical Phase 1 data. Executable instructions are never accepted in these contracts."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import Field, JsonValue, model_validator

from purpleloop.schemas.action import ActionRequest, BudgetRequest
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase2 import (
    BrowserStep,
    EvidenceCompleteness,
    ResourceReport,
    Surface,
)
from purpleloop.schemas.phase3 import (
    BINDING_PROVENANCE,
    AgentTask,
    InjectionChannel,
    JudgeResult,
    ProposalRecord,
    RiskClass,
    Scored,
    StochasticReport,
    TokenAccounting,
    VerdictProvenance,
)
from purpleloop.schemas.scenario import Scenario


class Versioned(StrictModel):
    schema_version: Literal["1.1.0", "1.2.0", "1.3.0"] = "1.1.0"


class Stage(StrEnum):
    ADMISSION = "admission"
    PROVISION = "provision"
    SEED = "seed"
    CLEAN = "clean"
    ATTACK = "attack"
    SCORE = "score"
    DETECT = "detect"
    DEFENSE = "defense"
    RESET = "reset"
    REPLAY_CLEAN = "replay_clean"
    REPLAY = "replay"
    TEARDOWN = "teardown"
    TERMINATED = "terminated"


class Actor(Versioned):
    actor_id: str
    role: Literal["customer", "agent", "admin"]
    tenant_id: str
    credential_handle: str


class Step(Versioned):
    node_id: str
    adapter: Literal["http", "tool", "chat", "browser", "agent"]
    operation: str
    asset_id: str
    target_tenant: str
    resource_id: str | None = None
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    depends_on: tuple[str, ...] = ()


class OracleSpec(Versioned):
    operator: Literal["equals", "exists", "contains", "count", "delta"]
    source: Literal["state", "responses", "telemetry"] = "state"
    path: tuple[str | int, ...]
    expected: JsonValue = None
    comparison: Literal["eq", "gt", "ge", "lt", "le"] = "eq"
    oracle_version: str = "state-v1"


class ResetSpec(Versioned):
    operation: Literal["fixture.reset"] = "fixture.reset"
    verify_hash: Literal[True] = True


class Phase1Scenario(Versioned):
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    scenario_version: str = "1.0.0"
    authorization_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    fixture_seed: int = Field(ge=0, le=2**32 - 1)
    actor: Actor
    legitimate_objective: str
    attacker_objective: str
    capabilities: frozenset[str]
    clean_steps: tuple[Step, ...]
    attack_steps: tuple[Step, ...]
    security_oracle: OracleSpec | None
    utility_oracle: OracleSpec | None
    expected_telemetry: tuple[str, ...]
    defense_profile: str
    reset: ResetSpec = ResetSpec()
    attack_budget: BudgetRequest = BudgetRequest(requests=8, writes=4, records=16, tokens=4096)
    taxonomy_mappings: dict[str, tuple[str, ...]]
    provenance: str = "PurpleLoop synthetic authored corpus"
    license: str = "CC0-1.0"
    conversion_issues: tuple[str, ...] = ()
    legacy_actions: tuple[ActionRequest, ...] | None = None
    # Scenario 1.2 additions. ``None`` on a 1.1 document keeps its canonical bytes unchanged.
    surface: Surface | None = None
    shared_oracle: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    # Scenario 1.3 additions. Same rule: absent on 1.1 and 1.2 documents.
    risk_class: RiskClass | None = None
    injection_channel: InjectionChannel | None = None
    agent_task: AgentTask | None = None
    judge_rubric_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    repetitions: int | None = Field(default=None, ge=1, le=100)

    @model_validator(mode="after")
    def validate_steps(self) -> Phase1Scenario:
        if not self.attack_steps and not self.legacy_actions:
            raise ValueError("an attack step is required")
        browser_steps = any(
            step.adapter == "browser" for step in (*self.clean_steps, *self.attack_steps)
        )
        if browser_steps and self.schema_version != "1.2.0":
            raise ValueError("browser steps require scenario 1.2")
        if browser_steps and self.surface not in {"browser", "both"}:
            raise ValueError("browser steps require a browser surface declaration")
        if self.surface == "browser" and not browser_steps:
            raise ValueError("a browser-surface scenario needs a browser step")
        agent_steps = any(
            step.adapter == "agent" for step in (*self.clean_steps, *self.attack_steps)
        )
        if agent_steps and self.schema_version != "1.3.0":
            raise ValueError("agent steps require scenario 1.3")
        if agent_steps and self.surface != "agent":
            raise ValueError("agent steps require an agent surface declaration")
        if self.surface == "agent" and not agent_steps:
            raise ValueError("an agent-surface scenario needs an agent step")
        if agent_steps and self.agent_task is None:
            raise ValueError("an agent scenario must declare its task and capability set")
        if self.agent_task is not None and self.injection_channel is None:
            raise ValueError("an agent scenario must name the channel its hostile content uses")
        return self

    @property
    def effective_surface(self) -> Surface:
        return self.surface or "api"

    def require_runnable(self) -> None:
        if (
            self.conversion_issues
            or not self.clean_steps
            or not self.security_oracle
            or not self.utility_oracle
        ):
            raise ValueError(
                "scenario requires clean tasks and typed oracles: "
                + "; ".join(self.conversion_issues)
            )


class PlanNode(Versioned):
    node_id: str
    stage: Literal["clean", "attack"]
    action: ActionRequest
    depends_on: tuple[str, ...]
    # Resolved typed browser steps for inspection. The adapter re-derives them from the trusted
    # flow registry; nothing here can name a URL, selector, or script.
    browser_steps: tuple[BrowserStep, ...] | None = None


class ExecutionPlan(Versioned):
    scenario_id: str
    scenario_digest: str
    manifest_digest: str
    nodes: tuple[PlanNode, ...]


class OracleResult(Versioned, Scored):
    """A closed-operator oracle verdict. Deterministic by construction and by default."""

    provenance: VerdictProvenance = BINDING_PROVENANCE
    verdict: Literal["true", "false", "inconclusive"]
    oracle_version: str
    observed: JsonValue = None
    evidence_ids: tuple[str, ...] = ()


class DetectorResult(Versioned):
    rule_id: str
    expected: bool
    observed: bool
    evidence_ids: tuple[str, ...]
    time_to_detect: int | None


class DefenseSelection(Versioned):
    profile: str
    version: str = "defense-v1"
    scenario_id: str
    configuration: dict[str, bool]
    verified: bool = False


class Finding(Versioned, Scored):
    """An accepted finding. Only a binding verdict can produce one; see ``require_binding``."""

    provenance: VerdictProvenance = BINDING_PROVENANCE
    finding_id: str
    scenario_id: str
    asset_id: str
    attacker_goal: str
    observed_impact: str
    evidence_ids: tuple[str, ...]
    oracle_version: str
    manifest_digest: str
    scenario_digest: str
    seed_hash: str
    reproducible: bool
    #: Why reproducibility is or is not asserted. A single paired run cannot establish it, and
    #: saying so is part of the finding rather than a footnote elsewhere.
    reproducibility_basis: str = "single paired run; repetitions not executed"
    confidence: Literal["high", "low"] = "high"
    severity: Literal["high", "medium"] = "high"
    severity_rationale: str
    taxonomy_mappings: dict[str, tuple[str, ...]]
    status: Literal["confirmed", "likely", "inconclusive", "test-system incident"]
    mitigation: str


class LegResult(Versioned):
    seed_hash: str
    utility: OracleResult
    security: OracleResult
    susceptible: bool
    unauthorized_side_effects: int
    detectors: tuple[DetectorResult, ...]
    # Phase 3 additions. ``utility_under_attack`` re-runs the clean task after the attack on the
    # same state, so utility during compromise is a measured number rather than an inference.
    utility_under_attack: OracleResult | None = None
    judge: JudgeResult | None = None
    model_calls: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)


class RunSummary(Versioned):
    run_id: str
    scenario_id: str
    status: Literal["passed", "regression", "error", "inconclusive", "not-evaluated"]
    reason: str
    manifest_digest: str
    scenario_digest: str
    plan_digest: str | None = None
    baseline: LegResult | None = None
    replay: LegResult | None = None
    defense: DefenseSelection | None = None
    findings: tuple[Finding, ...] = ()
    mitigation_effective: bool = False
    utility_regression: bool = False
    budget_used: BudgetRequest = BudgetRequest(requests=0, records=0)
    teardown_complete: bool = False
    event_replay_hash: str | None = None
    oracle_hash: str | None = None
    evidence_integrity_incident: bool = False
    elapsed_seconds: float = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    executed_actions: int = Field(default=0, ge=0)
    # Phase 2 additions, absent from Phase 1 summaries.
    surface: Surface | None = None
    lane: str | None = None
    resources: ResourceReport | None = None
    evidence_completeness: EvidenceCompleteness | None = None
    browser_driver: str | None = None
    browser_artifacts: tuple[str, ...] | None = None
    # Phase 3 additions, absent from Phase 1 and Phase 2 summaries.
    risk_class: RiskClass | None = None
    injection_channel: InjectionChannel | None = None
    model_pin_id: str | None = None
    cost_microusd: int = Field(default=0, ge=0)
    token_accounting: TokenAccounting | None = None
    stochastic: StochasticReport | None = None
    proposals: tuple[ProposalRecord, ...] = ()


SHARED_ORACLES = "oracles.yaml"


def scenario_paths(directory: Path) -> list[Path]:
    """Scenario YAML files in a directory, excluding the shared-oracle catalogue."""
    return sorted(p for p in directory.glob("*.yaml") if p.name != SHARED_ORACLES)


def resolve_shared_oracle(raw: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Bind a 1.2 scenario's ``shared_oracle`` reference to the exact specification it names.

    Cross-surface scenarios score both surfaces against one oracle. The reference resolves from
    a sibling ``oracles.yaml``; an inline oracle that disagrees with the shared one is an error
    rather than a silent override.
    """
    name = raw.get("shared_oracle")
    if name is None:
        return raw
    catalogue_path = directory / SHARED_ORACLES
    if not catalogue_path.exists():
        raise ValueError(f"shared oracle catalogue missing: {catalogue_path}")
    catalogue = yaml.safe_load(catalogue_path.read_text())
    if not isinstance(catalogue, dict) or name not in catalogue:
        raise ValueError(f"shared oracle is not catalogued: {name}")
    shared = catalogue[name]
    if not isinstance(shared, dict) or "security_oracle" not in shared:
        raise ValueError("a shared oracle entry must define security_oracle")
    inline = raw.get("security_oracle")
    if inline is not None and inline != shared["security_oracle"]:
        raise ValueError("inline security oracle disagrees with the shared oracle")
    return {**raw, "security_oracle": shared["security_oracle"]}


def load_scenario(path: Path) -> Phase1Scenario:
    raw = (
        yaml.safe_load(path.read_text())
        if path.suffix in {".yaml", ".yml"}
        else json.loads(path.read_text())
    )
    if not isinstance(raw, dict):
        raise ValueError("scenario must be an object")
    if raw.get("schema_version") == "1.2.0":
        raw = resolve_shared_oracle(raw, path.parent)
    if raw.get("schema_version", "1.0.0") == "1.0.0":
        legacy = Scenario.model_validate(raw)
        return Phase1Scenario(
            scenario_id=legacy.scenario_id,
            scenario_version=legacy.scenario_version,
            authorization_digest=legacy.authorization_digest,
            fixture_seed=legacy.fixture_seed,
            actor=Actor(
                actor_id=legacy.actor_id,
                role=cast(Literal["customer", "admin"], legacy.actor_role),
                tenant_id=legacy.tenant_id,
                credential_handle=legacy.actions[0].credential_handle or "missing",
            ),
            legitimate_objective=legacy.legitimate_objective,
            attacker_objective=legacy.attacker_objective,
            capabilities=frozenset(),
            clean_steps=(),
            attack_steps=(),
            legacy_actions=legacy.actions,
            security_oracle=None,
            utility_oracle=None,
            expected_telemetry=tuple(sorted(legacy.expected_telemetry)),
            defense_profile=legacy.defense_profile,
            taxonomy_mappings=legacy.taxonomy_mappings,
            provenance=legacy.provenance,
            license=legacy.license,
            conversion_issues=(
                "1.0 actions retained as legacy_actions; asset bindings must be supplied",
                "clean steps and typed security/utility oracles must be supplied",
            ),
        )
    return Phase1Scenario.model_validate(raw)


class GroundTruthCase(Versioned):
    """One explicitly labelled corpus case: a seeded positive and its negative control."""

    scenario_id: str
    positive_control: Literal["baseline"]
    expected_findings: int = Field(ge=0)
    negative_control: Literal["defended-replay"]
    expected_negative_findings: int = Field(ge=0)


class GroundTruth(Versioned):
    cases: tuple[GroundTruthCase, ...]

    @model_validator(mode="after")
    def _unique_scenarios(self) -> GroundTruth:
        ids = [case.scenario_id for case in self.cases]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("ground truth requires unique, non-empty scenario cases")
        return self

    def case(self, scenario_id: str) -> GroundTruthCase:
        for case in self.cases:
            if case.scenario_id == scenario_id:
                return case
        raise KeyError(f"unlabelled scenario: {scenario_id}")


def load_ground_truth(path: Path) -> GroundTruth:
    raw = (
        yaml.safe_load(path.read_text())
        if path.suffix in {".yaml", ".yml"}
        else json.loads(path.read_text())
    )
    if not isinstance(raw, dict):
        raise ValueError("ground truth must be an object")
    return GroundTruth.model_validate(raw)
