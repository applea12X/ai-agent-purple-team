from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.common import StrictModel, require_identifier, require_utc


class AssetScope(StrictModel):
    asset_id: str
    scheme: str
    host: str
    port: int
    path_prefix: str = "/"
    tenant_ids: frozenset[str]
    resource_ids: frozenset[str] = frozenset()
    allowed_resolved_addresses: frozenset[IPv4Address | IPv6Address] = Field(min_length=1)

    @field_validator("asset_id")
    @classmethod
    def validate_asset_id(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("scheme")
    @classmethod
    def validate_scheme(cls, value: str) -> str:
        if value not in {"http", "https"}:
            raise ValueError("unsupported scheme")
        return value

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        host = value.rstrip(".").lower()
        if not host or "*" in host or "@" in host:
            raise ValueError("host must be exact and unambiguous")
        return host.encode("idna").decode("ascii")

    @field_validator("path_prefix")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or ".." in value:
            raise ValueError("path prefix must be absolute and normalized")
        return value

    @field_validator("tenant_ids", "resource_ids")
    @classmethod
    def validate_id_sets(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)


class ExactExclusion(StrictModel):
    host: str | None = None
    tenant_id: str | None = None
    resource_id: str | None = None
    operation: str | None = None
    path: str | None = None

    @model_validator(mode="after")
    def require_selector(self) -> ExactExclusion:
        if all(
            value is None
            for value in (self.host, self.tenant_id, self.resource_id, self.operation, self.path)
        ):
            raise ValueError("an exclusion must select at least one exact field")
        return self

    @field_validator("tenant_id", "resource_id", "operation")
    @classmethod
    def validate_optional_identifier(cls, value: str | None) -> str | None:
        return require_identifier(value) if value is not None else None

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str | None) -> str | None:
        return value.rstrip(".").lower().encode("idna").decode("ascii") if value else None

    @field_validator("path")
    @classmethod
    def validate_exact_path(cls, value: str | None) -> str | None:
        if value is not None and (not value.startswith("/") or ".." in value):
            raise ValueError("exclusion path must be absolute and normalized")
        return value


class BudgetLimits(StrictModel):
    requests: int = Field(ge=0)
    writes: int = Field(default=0, ge=0)
    records: int = Field(ge=0)
    tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)
    concurrency: int = Field(default=1, ge=1)
    wall_time_seconds: float = Field(default=60.0, gt=0)


class AuthorizationManifest(StrictModel):
    schema_version: str = "1.0.0"
    engagement_id: str
    owner: str
    approvers: tuple[str, ...]
    key_id: str
    issued_at: datetime
    valid_from: datetime
    valid_until: datetime
    assets: tuple[AssetScope, ...]
    allowed_adapters: frozenset[str]
    allowed_operations: frozenset[str]
    denied_operations: frozenset[str] = frozenset()
    allowed_methods: frozenset[str] = frozenset({"GET"})
    allowed_side_effects: frozenset[SideEffectClass] = frozenset({SideEffectClass.READ})
    credential_handles: frozenset[str] = frozenset()
    credential_scopes: dict[str, frozenset[str]] = Field(default_factory=dict)
    egress_hosts: frozenset[str] = frozenset()
    model_endpoints: frozenset[str] = frozenset()
    exact_exclusions: tuple[ExactExclusion, ...] = ()
    budgets: BudgetLimits
    synthetic_secrets: tuple[str, ...] = ()
    data_classification: str = "synthetic"
    retention_days: int = Field(default=7, ge=0)
    redaction_required: bool = True
    required_evidence: frozenset[str] = frozenset()
    stop_conditions: frozenset[str] = frozenset()
    cleanup_procedure: str = "fixture-reset"
    stop_on_error: bool = True
    signature: str

    @field_validator("engagement_id", "owner", "key_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("approvers", "allowed_adapters", "allowed_operations", "denied_operations")
    @classmethod
    def validate_identifier_sets(
        cls, values: tuple[str, ...] | frozenset[str]
    ) -> tuple[str, ...] | frozenset[str]:
        validated = tuple(require_identifier(value) for value in values)
        return validated if isinstance(values, tuple) else frozenset(validated)

    @field_validator("credential_handles")
    @classmethod
    def validate_credentials(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)

    @field_validator("credential_scopes")
    @classmethod
    def validate_credential_scopes(
        cls, values: dict[str, frozenset[str]]
    ) -> dict[str, frozenset[str]]:
        return {
            require_identifier(handle): frozenset(
                require_identifier(operation) for operation in operations
            )
            for handle, operations in values.items()
        }

    @field_validator("model_endpoints")
    @classmethod
    def validate_model_endpoints(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            parts = urlsplit(value)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ValueError("model endpoints must be absolute HTTP(S) URLs")
        return values

    @field_validator("issued_at", "valid_from", "valid_until")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @model_validator(mode="after")
    def validate_manifest(self) -> AuthorizationManifest:
        if not self.approvers:
            raise ValueError("at least one approver is required")
        if not self.assets:
            raise ValueError("at least one asset is required")
        if self.valid_from >= self.valid_until:
            raise ValueError("validity window is inverted")
        if self.issued_at > self.valid_from:
            raise ValueError("manifest cannot be issued after it becomes valid")
        if self.denied_operations & self.allowed_operations:
            raise ValueError("an operation cannot be both allowed and denied")
        if self.allowed_side_effects != frozenset({SideEffectClass.READ}):
            raise ValueError("Phase 0 permits read-only effects only")
        if set(self.credential_scopes) != set(self.credential_handles):
            raise ValueError("every credential handle requires one exact scope")
        if any(not operations for operations in self.credential_scopes.values()):
            raise ValueError("credential scopes cannot be empty")
        if not self.redaction_required:
            raise ValueError("Phase 0 requires redaction")
        return self

    def signed_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"signature"})

    def manifest_digest(self) -> str:
        return self.digest(exclude={"signature"})
