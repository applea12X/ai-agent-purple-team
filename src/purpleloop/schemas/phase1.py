"""Canonical Phase 1 data. Executable instructions are never accepted in these contracts."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

import yaml
from pydantic import Field, JsonValue, model_validator

from purpleloop.schemas.action import ActionRequest, BudgetRequest
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.scenario import Scenario


class Versioned(StrictModel):
    schema_version: Literal["1.1.0"] = "1.1.0"


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
    role: Literal["customer", "admin"]
    tenant_id: str
    credential_handle: str


class Step(Versioned):
    node_id: str
    adapter: Literal["http", "tool", "chat"]
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

    @model_validator(mode="after")
    def validate_steps(self) -> Phase1Scenario:
        if not self.attack_steps and not self.legacy_actions:
            raise ValueError("an attack step is required")
        return self

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


class ExecutionPlan(Versioned):
    scenario_id: str
    scenario_digest: str
    manifest_digest: str
    nodes: tuple[PlanNode, ...]


class OracleResult(Versioned):
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


class Finding(Versioned):
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


class RunSummary(Versioned):
    run_id: str
    scenario_id: str
    status: Literal["passed", "regression", "error", "inconclusive"]
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


def load_scenario(path: Path) -> Phase1Scenario:
    raw = (
        yaml.safe_load(path.read_text())
        if path.suffix in {".yaml", ".yml"}
        else json.loads(path.read_text())
    )
    if not isinstance(raw, dict):
        raise ValueError("scenario must be an object")
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
