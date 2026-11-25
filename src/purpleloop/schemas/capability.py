"""The capability surface and the signed approved baseline (WP5.1, ADR 0014).

A :class:`CapabilitySurface` is the projection of an authorization manifest onto the axes a
capability increase can happen along: action classes, adapters and operations, targets, egress,
proposal caps, and the proposal source. It deliberately leaves out everything that is not a
capability -- validity windows, signing keys, budgets, retention -- and
``control.capabilities.FIELD_CLASSIFICATION`` names every manifest field one way or the other,
so a field added later cannot be silently ignored.

A :class:`CapabilityBaseline` is a human-signed record of one approved surface. Every capability
delta a 1.5 manifest is admitted on is computed against the most recent baseline, never against
the previous run (plan §2.2). It is signed with the same Ed25519/JCS construction as every other
Phase 5 record (``control.phase5_signing``).

This module imports ``schemas.authorization`` (for :class:`ExactExclusion`), so neither that
module nor ``schemas.phase5`` may import it.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import Field, field_validator

from purpleloop.schemas.authorization import ExactExclusion
from purpleloop.schemas.common import StrictModel, require_identifier, require_utc
from purpleloop.schemas.phase5 import ActionClass, ProposalSource, SignedRecord


class TargetSurface(StrictModel):
    """One signed target asset, as a capability: where requests may go and for whom.

    ``resource_ids`` keeps the manifest's meaning -- empty is *unrestricted* -- so a surface that
    names resources is narrower than one that names none, never wider.
    """

    asset_id: str
    scheme: str
    host: str
    port: int
    path_prefix: str
    tenant_ids: frozenset[str]
    resource_ids: frozenset[str] = frozenset()
    allowed_resolved_addresses: frozenset[IPv4Address | IPv6Address]

    @field_validator("asset_id")
    @classmethod
    def validate_asset(cls, value: str) -> str:
        return require_identifier(value)


class CapabilitySurface(StrictModel):
    """Everything a manifest lets the harness do, as comparable sets and caps.

    Sets are compared by inclusion and caps by magnitude; ``exact_exclusions`` is the one axis
    where *more* is narrower. ``credential_scopes`` and ``ownership`` map a handle (or tenant) to
    the operations (or resources) it may touch, and are compared pair by pair.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    action_classes: frozenset[ActionClass]
    adapters: frozenset[str]
    operations: frozenset[str]
    methods: frozenset[str]
    credential_scopes: dict[str, frozenset[str]] = Field(default_factory=dict)
    targets: tuple[TargetSurface, ...]
    browser_assets: frozenset[str] = frozenset()
    ownership: dict[str, frozenset[str]] = Field(default_factory=dict)
    exact_exclusions: tuple[ExactExclusion, ...] = ()
    egress_hosts: frozenset[str] = frozenset()
    model_endpoints: frozenset[str] = frozenset()
    model_assets: frozenset[str] = frozenset()
    subresource_origins: frozenset[str] = frozenset()
    telemetry_collectors: frozenset[str] = frozenset()
    max_attacker_proposals: int = Field(ge=0)
    max_attacker_depth: int = Field(ge=0)
    max_tool_intents_per_turn: int = Field(ge=0)
    max_agent_steps: int = Field(ge=0)
    max_nodes: int = Field(ge=0)
    max_depth: int = Field(ge=0)
    proposal_source: ProposalSource = "bounded-search"

    def target(self, asset_id: str) -> TargetSurface | None:
        for candidate in self.targets:
            if candidate.asset_id == asset_id:
                return candidate
        return None


KeyProvenance = Literal["provided", "ephemeral"]


class CapabilityBaseline(SignedRecord):
    """The signed, approved capability surface (plan §2.2: "the approved baseline").

    ``key_provenance`` says, as ADR 0012's attestation does, whether the signing key was held
    beyond the signing call. An ``ephemeral`` baseline binds the surface to a key that no longer
    exists: it proves the bytes were signed once and not edited since, and nothing about who
    approved them. ``derived_from`` names, in plain words, the manifests the surface was taken
    from, so a reviewer can rebuild it.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    baseline_id: str
    surface: CapabilitySurface
    derived_from: tuple[str, ...] = Field(min_length=1)
    #: Who approved, in plain words. A key id is not a person; this field says who held it.
    approver: str = Field(min_length=1, max_length=200)
    key_id: str
    key_provenance: KeyProvenance
    issued_at: datetime
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("baseline_id", "key_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("derived_from")
    @classmethod
    def validate_sources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value or len(value) > 300 for value in values):
            raise ValueError("each source is a short plain-words description")
        return values

    @field_validator("issued_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @property
    def signing_key_id(self) -> str:
        return self.key_id

    def baseline_digest(self) -> str:
        """What a :class:`~purpleloop.schemas.phase5.RiskApproval` names as ``baseline_digest``."""
        return self.record_digest()
