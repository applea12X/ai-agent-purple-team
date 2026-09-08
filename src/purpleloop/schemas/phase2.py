"""Phase 2 contracts: manifest 1.2 grants, typed browser steps, and resource accounting.

Everything here is additive. Phase 0 and Phase 1 documents never carry these fields, and every
new field on an existing model defaults to ``None`` so legacy canonical bytes are unchanged.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from purpleloop.schemas.common import StrictModel, require_identifier

Surface = Literal["api", "browser", "both"]

# Typed selector vocabularies. A browser step can only name an entry from these closed sets; the
# CSS selector each name resolves to lives in trusted registry code, never in planner output.
PageId = Literal["ticket", "document", "admin-users", "refund", "exports"]
FieldId = Literal["refund-amount", "refund-approval", "export-destination", "export-approval"]
ControlId = Literal["refund-submit", "export-submit"]
RegionId = Literal[
    "outcome",
    "ticket-id",
    "ticket-org",
    "ticket-subject",
    "document-id",
    "document-org",
    "document-title",
    "users-count",
    "users-orgs",
    "refund-created",
    "refund-approved",
    "export-created",
    "export-canary-exposed",
]


class NavigateStep(StrictModel):
    kind: Literal["navigate"] = "navigate"
    page: PageId
    resource_id: str | None = None

    @field_validator("resource_id")
    @classmethod
    def validate_resource(cls, value: str | None) -> str | None:
        return require_identifier(value) if value is not None else None


class FillStep(StrictModel):
    kind: Literal["fill"] = "fill"
    field: FieldId
    value: str = Field(max_length=200)

    @field_validator("value")
    @classmethod
    def printable(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("browser input must be printable")
        return value


class ClickStep(StrictModel):
    kind: Literal["click"] = "click"
    control: ControlId


class ReadStep(StrictModel):
    kind: Literal["read"] = "read"
    region: RegionId


BrowserStep = Annotated[NavigateStep | FillStep | ClickStep | ReadStep, Field(discriminator="kind")]


class OwnershipScope(StrictModel):
    """Signed resource ownership: which tenant owns which seeded resource identifiers."""

    tenant_id: str
    resource_ids: frozenset[str] = Field(min_length=1)

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("resource_ids")
    @classmethod
    def validate_resources(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)


class Phase2Grants(StrictModel):
    """Manifest 1.2 additions. Ownership is signed data; the fixture's opinion never feeds it."""

    ownership_seed: int = Field(ge=0, le=2**32 - 1)
    ownership: tuple[OwnershipScope, ...] = Field(min_length=1)
    database_credential_handle: str
    containment_prefix: str = Field(pattern=r"^[a-z][a-z0-9-]{2,31}$")
    browser_assets: frozenset[str] = frozenset()
    subresource_origins: frozenset[str] = frozenset()
    max_browser_contexts: int = Field(default=16, ge=0, le=256)

    @field_validator("database_credential_handle")
    @classmethod
    def validate_handle(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("browser_assets")
    @classmethod
    def validate_assets(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)

    @field_validator("subresource_origins")
    @classmethod
    def validate_origins(cls, values: frozenset[str]) -> frozenset[str]:
        for origin in values:
            scheme, separator, rest = origin.partition("://")
            if scheme not in {"http", "https"} or not separator or "/" in rest or not rest:
                raise ValueError("subresource origins must be scheme://host:port with no path")
        return values

    @model_validator(mode="after")
    def unique_ownership(self) -> Phase2Grants:
        seen: set[str] = set()
        tenants: set[str] = set()
        for scope in self.ownership:
            if scope.tenant_id in tenants:
                raise ValueError("each tenant appears in exactly one ownership scope")
            tenants.add(scope.tenant_id)
            if seen & scope.resource_ids:
                raise ValueError("a resource cannot be owned by two tenants")
            seen |= scope.resource_ids
        return self

    def owner_of(self, resource_id: str) -> str | None:
        for scope in self.ownership:
            if resource_id in scope.resource_ids:
                return scope.tenant_id
        return None


class ResourceUsage(StrictModel):
    requests: int = Field(ge=0)
    records: int = Field(ge=0)
    browser_contexts: int = Field(ge=0)
    wall_time_seconds: float = Field(ge=0)


class ResourceReport(StrictModel):
    """Pre-run estimate beside measured use; the delta is reported, never hidden."""

    schema_version: Literal["1.2.0"] = "1.2.0"
    estimated: ResourceUsage
    actual: ResourceUsage
    delta_percent: dict[str, float]
    within_tolerance: dict[str, bool]


class EvidenceCompleteness(StrictModel):
    schema_version: Literal["1.2.0"] = "1.2.0"
    required_fields: int = Field(ge=0)
    present_fields: int = Field(ge=0)
    completeness: float = Field(ge=0, le=1)
    missing: tuple[str, ...] = ()


class BrowserArtifact(StrictModel):
    action_id: str
    driver: str
    kind: Literal["trace", "screenshot", "html"]
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
