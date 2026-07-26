from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from purpleloop.schemas.action import ActionRequest
from purpleloop.schemas.common import StrictModel, require_identifier


class Scenario(StrictModel):
    schema_version: str = "1.0.0"
    scenario_id: str
    scenario_version: str
    authorization_digest: str
    target_mode: str
    fixture_seed: int
    actor_id: str
    actor_role: str
    tenant_id: str
    taxonomy_mappings: dict[str, tuple[str, ...]]
    legitimate_objective: str
    attacker_objective: str
    preconditions: tuple[str, ...] = ()
    attack_budget: dict[str, int] = Field(default_factory=dict)
    actions: tuple[ActionRequest, ...]
    expected_evidence: frozenset[str]
    expected_telemetry: frozenset[str] = frozenset()
    deterministic_oracle: str
    utility_oracle: str
    defense_profile: str
    reset_fixture: str
    provenance: str
    license: str

    @field_validator(
        "scenario_id",
        "actor_id",
        "actor_role",
        "tenant_id",
        "target_mode",
        "deterministic_oracle",
        "utility_oracle",
        "defense_profile",
        "reset_fixture",
    )
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("authorization_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("authorization digest must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_scenario(self) -> Scenario:
        if not self.actions:
            raise ValueError("scenario requires at least one action")
        if any(action.target.tenant_id != self.tenant_id for action in self.actions):
            raise ValueError("scenario actions must use the scenario tenant")
        return self
