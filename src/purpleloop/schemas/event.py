from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from purpleloop.schemas.common import StrictModel, require_identifier, require_utc


class EventKind(StrEnum):
    LIFECYCLE = "lifecycle"
    ORACLE = "oracle"
    DETECTOR = "detector"
    DEFENSE = "defense"
    ADMISSION = "admission"
    POLICY = "policy"
    BUDGET = "budget"
    ADAPTER = "adapter"
    RESULT = "result"
    TERMINATION = "termination"
    # Phase 3. A MODEL event records a pinned model call and the provenance of what it was shown;
    # a JUDGE event records an advisory semantic judgement; a PROPOSAL event records one adaptive
    # attacker proposal and the decision on it.
    MODEL = "model"
    JUDGE = "judge"
    PROPOSAL = "proposal"


class EvidenceEvent(StrictModel):
    schema_version: str | None = None
    scenario_id: str | None = None
    scenario_version: str | None = None
    stage: str | None = None
    component_version: str | None = None
    oracle_version: str | None = None
    snapshot_hash: str | None = None
    run_id: str
    trace_id: str
    sequence: int = Field(ge=0)
    timestamp: datetime
    actor: str
    kind: EventKind
    manifest_digest: str
    policy_digest: str
    action_digest: str | None = None
    decision: str | None = None
    reason_code: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    parent_hash: str | None = None
    event_hash: str | None = None

    @field_validator("run_id", "trace_id", "actor")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("timestamp")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @field_validator(
        "manifest_digest", "policy_digest", "action_digest", "parent_hash", "event_hash"
    )
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ValueError("digest must be lowercase SHA-256")
        return value

    def unsigned_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"event_hash"})

    def calculated_hash(self) -> str:
        return self.digest(exclude={"event_hash"})
