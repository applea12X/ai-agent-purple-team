from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, field_validator, model_validator

from purpleloop.schemas.common import StrictModel, require_identifier


class SideEffectClass(StrEnum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class ActionTarget(StrictModel):
    url: str
    tenant_id: str
    resource_id: str | None = None

    _validate_tenant = field_validator("tenant_id")(require_identifier)

    @field_validator("resource_id")
    @classmethod
    def validate_resource(cls, value: str | None) -> str | None:
        return require_identifier(value) if value is not None else value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("target must be an absolute HTTP(S) URL")
        if parts.username or parts.password or parts.fragment:
            raise ValueError("userinfo and fragments are forbidden")
        return value


class TargetObservation(StrictModel):
    """Connection metadata produced by a trusted adapter immediately before I/O."""

    url: str
    resolved_addresses: tuple[IPv4Address | IPv6Address, ...] = Field(min_length=1)
    hop_index: int = Field(ge=0)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return ActionTarget.validate_url(value)


class BudgetRequest(StrictModel):
    requests: int = Field(default=1, ge=0)
    writes: int = Field(default=0, ge=0)
    records: int = Field(default=1, ge=0)
    tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)


class ActionRequest(StrictModel):
    schema_version: Literal["1.0.0", "1.1.0"] | None = None
    arguments: dict[str, JsonValue] | None = None
    action_id: str
    adapter: str
    operation: str
    method: str
    target: ActionTarget
    side_effect: SideEffectClass
    credential_handle: str | None = None
    idempotency_key: str
    budget: BudgetRequest = BudgetRequest()

    @field_validator("action_id", "adapter", "operation", "idempotency_key")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("credential_handle")
    @classmethod
    def validate_credential(cls, value: str | None) -> str | None:
        return require_identifier(value) if value is not None else value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT"}:
            raise ValueError("unsupported HTTP method")
        return method

    @model_validator(mode="after")
    def enforce_read_only(self) -> ActionRequest:
        if self.side_effect == SideEffectClass.DESTRUCTIVE:
            raise ValueError("destructive actions are forbidden")
        if self.schema_version != "1.1.0" and (
            self.side_effect != SideEffectClass.READ
            or self.budget.writes
            or self.method not in {"GET", "HEAD", "OPTIONS"}
            or self.arguments is not None
        ):
            raise ValueError("Phase 0 actions must be read-only")
        return self
