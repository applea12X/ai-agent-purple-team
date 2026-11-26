"""``capability_delta``: what a requested manifest may do that the approved surface may not.

Plan §2.2 and ADR 0014. "Every autonomy or action-class increase needs a signed approval" is
enforceable only if deciding what counts as an increase is not left to whoever writes the
manifest. So the decision is a pure function over two surfaces, returning a set drawn from the
closed :class:`~purpleloop.schemas.phase5.CapabilityIncrease` enum, and it fails closed:

- every manifest field is classified in :data:`FIELD_CLASSIFICATION` as either *projected*
  onto a capability axis or *not a capability* (with the reason in the ADR). A field that is in
  neither list -- one added after this module was written -- and that is set to anything but its
  default is treated as **every** kind of increase at once, so an approval would have to name
  all six to cover it;
- on each projected axis, only an exact narrowing (subset, lower cap, stricter prefix, more
  exclusions) is recognized as not-an-increase. Anything else is an increase.

Nothing here reads a clock, a file, or a key. Admission (``control.approvals``) calls it with the
signed baseline's surface and the requested manifest.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel

from purpleloop.schemas.authorization import (
    SIDE_EFFECT_ACTION_CLASS,
    AssetScope,
    AuthorizationManifest,
    ExactExclusion,
)
from purpleloop.schemas.capability import CapabilitySurface, TargetSurface
from purpleloop.schemas.phase5 import (
    CAPABILITY_INCREASES,
    PROPOSAL_SOURCE_ORDER,
    ActionClass,
    CapabilityIncrease,
    ProposalSource,
)

Classification = Literal["projected", "not-capability"]

#: Every field of the manifest and of each grant section, classified. ``projected`` fields feed
#: :func:`capability_surface`; ``not-capability`` fields are deliberately outside it (validity
#: windows, keys, budgets, retention, evidence and stop rules -- ADR 0014 gives each reason). A
#: test asserts this table names exactly the current fields, so adding a field forces a decision.
FIELD_CLASSIFICATION: Mapping[str, Mapping[str, Classification]] = MappingProxyType(
    {
        "manifest": MappingProxyType(
            {
                "schema_version": "not-capability",
                "phase1": "projected",
                "phase2": "projected",
                "phase3": "projected",
                "phase4": "not-capability",
                "phase5": "projected",
                "engagement_id": "not-capability",
                "owner": "not-capability",
                "approvers": "not-capability",
                "key_id": "not-capability",
                "issued_at": "not-capability",
                "valid_from": "not-capability",
                "valid_until": "not-capability",
                "assets": "projected",
                "allowed_adapters": "projected",
                "allowed_operations": "projected",
                "denied_operations": "projected",
                "allowed_methods": "projected",
                "allowed_side_effects": "projected",
                # Subsumed by credential_scopes: the schema requires one scope per handle.
                "credential_handles": "not-capability",
                "credential_scopes": "projected",
                "egress_hosts": "projected",
                "model_endpoints": "projected",
                "exact_exclusions": "projected",
                "budgets": "not-capability",
                "synthetic_secrets": "not-capability",
                "data_classification": "not-capability",
                "retention_days": "not-capability",
                "redaction_required": "not-capability",
                "required_evidence": "not-capability",
                "stop_conditions": "not-capability",
                "cleanup_procedure": "not-capability",
                "stop_on_error": "not-capability",
                "signature": "not-capability",
            }
        ),
        "phase1": MappingProxyType(
            {
                "max_nodes": "projected",
                "max_depth": "projected",
                "defense_profiles": "not-capability",
            }
        ),
        "phase2": MappingProxyType(
            {
                # The seed is carried by the ownership pairs it produces.
                "ownership_seed": "not-capability",
                "ownership": "projected",
                "database_credential_handle": "not-capability",
                "containment_prefix": "not-capability",
                "browser_assets": "projected",
                "subresource_origins": "projected",
                "max_browser_contexts": "not-capability",
            }
        ),
        "phase3": MappingProxyType(
            {
                "model_assets": "projected",
                "model_credential_handle": "not-capability",
                "model_pins": "not-capability",
                "token_budget": "not-capability",
                "cost_microusd_budget": "not-capability",
                "max_agent_steps": "projected",
                "max_tool_intents_per_turn": "projected",
                "max_attacker_proposals": "projected",
                "max_attacker_depth": "projected",
                "judge_enabled": "not-capability",
                "judge_model_pin": "not-capability",
                "min_repetitions": "not-capability",
            }
        ),
        "phase4": MappingProxyType(
            {
                "attestation_key_ids": "not-capability",
                "retention": "not-capability",
                "nightly_scope": "not-capability",
            }
        ),
        "phase5": MappingProxyType(
            {
                "action_classes": "projected",
                "risk_approvals": "not-capability",
                "run_mode": "not-capability",
                "matrix_scope": "not-capability",
                "telemetry": "projected",
                "proposal_source": "projected",
            }
        ),
    }
)

#: Operations whose action class is higher than their side-effect class implies. Empty in v1,
#: where every operation is ``read`` or ``write``; a work package that adds a code-execution or
#: external-send operation registers it here (WP5.5: the codelab snippet operation is
#: ``code-exec``), so the class is derived from the operation as well as declared -- a manifest
#: cannot grant the operation while declaring only ``read`` and ``write``.
OPERATION_ACTION_CLASSES: Mapping[str, ActionClass] = MappingProxyType({})


def _section_objects(manifest: AuthorizationManifest) -> dict[str, BaseModel]:
    sections: dict[str, BaseModel] = {"manifest": manifest}
    for name in ("phase1", "phase2", "phase3", "phase4", "phase5"):
        value = getattr(manifest, name)
        if value is not None:
            sections[name] = value
    return sections


def unclassified_fields(manifest: AuthorizationManifest) -> tuple[str, ...]:
    """Manifest fields that are in neither classification and are set to a non-default value.

    Empty for every manifest the current schema can express. Non-empty only when a field was
    added to a model without being classified here -- which :func:`capability_delta` treats as
    every kind of increase.
    """
    found: list[str] = []
    for section, obj in _section_objects(manifest).items():
        known = FIELD_CLASSIFICATION.get(section, {})
        for name, info in type(obj).model_fields.items():
            if name in known:
                continue
            value = getattr(obj, name)
            default = None if info.is_required() else info.get_default(call_default_factory=True)
            if info.is_required() or value != default:
                found.append(f"{section}.{name}" if section != "manifest" else name)
    return tuple(sorted(found))


def action_classes_of(manifest: AuthorizationManifest) -> frozenset[ActionClass]:
    """Declared (1.5), side-effect-derived, and operation-derived action classes, together."""
    classes = {SIDE_EFFECT_ACTION_CLASS[effect] for effect in manifest.allowed_side_effects}
    if manifest.phase5 is not None:
        classes |= manifest.phase5.action_classes
    for operation in manifest.allowed_operations - manifest.denied_operations:
        if operation in OPERATION_ACTION_CLASSES:
            classes.add(OPERATION_ACTION_CLASSES[operation])
    return frozenset(classes)


def _target(asset: AssetScope) -> TargetSurface:
    return TargetSurface(
        asset_id=asset.asset_id,
        scheme=asset.scheme,
        host=asset.host,
        port=asset.port,
        path_prefix=asset.path_prefix,
        tenant_ids=asset.tenant_ids,
        resource_ids=asset.resource_ids,
        allowed_resolved_addresses=asset.allowed_resolved_addresses,
    )


def capability_surface(manifest: AuthorizationManifest) -> CapabilitySurface:
    """Project a manifest onto the capability axes. Pure; reads only signed manifest data.

    A manifest without Phase 3 grants has no attacker and no agent (caps 0) and one tool intent
    per chat turn, which is what the runner allows it; one without Phase 1 grants runs no plan
    graph (caps 0). A manifest without ``phase5.proposal_source`` uses the bounded search.
    """
    phase1, phase2, phase3, phase5 = (
        manifest.phase1,
        manifest.phase2,
        manifest.phase3,
        manifest.phase5,
    )
    ownership: dict[str, frozenset[str]] = {}
    if phase2 is not None:
        for scope in phase2.ownership:
            ownership[scope.tenant_id] = ownership.get(scope.tenant_id, frozenset()) | (
                scope.resource_ids
            )
    return CapabilitySurface(
        action_classes=action_classes_of(manifest),
        adapters=manifest.allowed_adapters,
        operations=manifest.allowed_operations - manifest.denied_operations,
        methods=manifest.allowed_methods,
        credential_scopes=dict(manifest.credential_scopes),
        targets=tuple(
            sorted((_target(asset) for asset in manifest.assets), key=lambda t: t.asset_id)
        ),
        browser_assets=phase2.browser_assets if phase2 is not None else frozenset(),
        ownership=ownership,
        exact_exclusions=_sorted_exclusions(manifest.exact_exclusions),
        egress_hosts=manifest.egress_hosts,
        model_endpoints=manifest.model_endpoints,
        model_assets=phase3.model_assets if phase3 is not None else frozenset(),
        subresource_origins=phase2.subresource_origins if phase2 is not None else frozenset(),
        telemetry_collectors=(
            frozenset({phase5.telemetry})
            if phase5 is not None and phase5.telemetry is not None
            else frozenset()
        ),
        max_attacker_proposals=phase3.max_attacker_proposals if phase3 is not None else 0,
        max_attacker_depth=phase3.max_attacker_depth if phase3 is not None else 0,
        max_tool_intents_per_turn=(
            phase3.max_tool_intents_per_turn if phase3 is not None else (1 if phase1 else 0)
        ),
        max_agent_steps=phase3.max_agent_steps if phase3 is not None else 0,
        max_nodes=phase1.max_nodes if phase1 is not None else 0,
        max_depth=phase1.max_depth if phase1 is not None else 0,
        proposal_source=(
            phase5.proposal_source
            if phase5 is not None and phase5.proposal_source is not None
            else "bounded-search"
        ),
    )


def _sorted_exclusions(exclusions: Iterable[ExactExclusion]) -> tuple[ExactExclusion, ...]:
    unique = {exclusion.canonical_bytes(): exclusion for exclusion in exclusions}
    return tuple(unique[key] for key in sorted(unique))


def _pairs(mapping: Mapping[str, frozenset[str]]) -> frozenset[tuple[str, str]]:
    return frozenset((key, item) for key, values in mapping.items() for item in values)


def _within(prefix: str, approved: str) -> bool:
    """``prefix`` is the approved path prefix or strictly inside it (segment-aligned)."""
    base = approved.rstrip("/") or "/"
    narrowed = prefix.rstrip("/") or "/"
    if base == "/":
        return narrowed.startswith("/")
    return narrowed == base or narrowed.startswith(f"{base}/")


def _target_widened(requested: TargetSurface, approved: TargetSurface | None) -> bool:
    if approved is None:
        return True
    if (requested.scheme, requested.host, requested.port) != (
        approved.scheme,
        approved.host,
        approved.port,
    ):
        return True
    if not _within(requested.path_prefix, approved.path_prefix):
        return True
    if not requested.tenant_ids <= approved.tenant_ids:
        return True
    if not requested.allowed_resolved_addresses <= approved.allowed_resolved_addresses:
        return True
    # Empty resource_ids means unrestricted, so only an approved restriction can be widened.
    if approved.resource_ids and (
        not requested.resource_ids or not requested.resource_ids <= approved.resource_ids
    ):
        return True
    return False


SurfaceLike = AuthorizationManifest | CapabilitySurface


def _surface(value: SurfaceLike) -> CapabilitySurface:
    if isinstance(value, CapabilitySurface):
        return value
    if isinstance(value, AuthorizationManifest):
        return capability_surface(value)
    raise TypeError(f"{type(value).__name__} is not a manifest or a capability surface")


def surface_delta(
    approved: CapabilitySurface, requested: CapabilitySurface
) -> frozenset[CapabilityIncrease]:
    """The increase kinds ``requested`` has over ``approved``, axis by axis."""
    found: set[CapabilityIncrease] = set()
    if not requested.action_classes <= approved.action_classes:
        found.add(CapabilityIncrease.NEW_ACTION_CLASS)
    if (
        not requested.adapters <= approved.adapters
        or not requested.operations <= approved.operations
        or not requested.methods <= approved.methods
        or not _pairs(requested.credential_scopes) <= _pairs(approved.credential_scopes)
        or not requested.browser_assets <= approved.browser_assets
    ):
        found.add(CapabilityIncrease.NEW_ADAPTER_OR_OPERATION)
    approved_exclusions = {item.canonical_bytes() for item in approved.exact_exclusions}
    requested_exclusions = {item.canonical_bytes() for item in requested.exact_exclusions}
    if (
        any(_target_widened(t, approved.target(t.asset_id)) for t in requested.targets)
        or not _pairs(requested.ownership) <= _pairs(approved.ownership)
        or not approved_exclusions <= requested_exclusions
    ):
        found.add(CapabilityIncrease.NEW_TARGET_FIXTURE)
    if (
        not requested.egress_hosts <= approved.egress_hosts
        or not requested.model_endpoints <= approved.model_endpoints
        or not requested.model_assets <= approved.model_assets
        or not requested.subresource_origins <= approved.subresource_origins
        or not requested.telemetry_collectors <= approved.telemetry_collectors
    ):
        found.add(CapabilityIncrease.WIDENED_EGRESS)
    if any(
        getattr(requested, cap) > getattr(approved, cap)
        for cap in (
            "max_attacker_proposals",
            "max_attacker_depth",
            "max_tool_intents_per_turn",
            "max_agent_steps",
            "max_nodes",
            "max_depth",
        )
    ):
        found.add(CapabilityIncrease.RAISED_ATTACKER_CAPS)
    if _source_rank(requested.proposal_source) > _source_rank(approved.proposal_source):
        found.add(CapabilityIncrease.PROPOSAL_SOURCE_CHANGE)
    return frozenset(found)


def _source_rank(source: ProposalSource) -> int:
    return PROPOSAL_SOURCE_ORDER.index(source)


def capability_delta(
    approved: SurfaceLike, requested: SurfaceLike
) -> frozenset[CapabilityIncrease]:
    """Every kind of increase ``requested`` has over ``approved``; empty when it has none.

    Pure. Either argument may be a manifest or an already-projected surface. A requested
    manifest that sets a field this module does not classify yields every increase kind, so the
    unknown fails closed rather than passing as "no change".
    """
    if isinstance(requested, AuthorizationManifest) and unclassified_fields(requested):
        return frozenset(CAPABILITY_INCREASES)
    return surface_delta(_surface(approved), _surface(requested))


def union_surfaces(surfaces: Iterable[CapabilitySurface]) -> CapabilitySurface:
    """The smallest surface every input is within: sets unioned, caps maxed, exclusions shared.

    Used once, to build the approved baseline from the v1 lane manifests. Two targets with the
    same asset id must name the same location; a conflict is an error rather than a silent
    widening to whichever came last.
    """
    items = list(surfaces)
    if not items:
        raise ValueError("a union needs at least one surface")
    targets: dict[str, TargetSurface] = {}
    for surface in items:
        for target in surface.targets:
            existing = targets.get(target.asset_id)
            if existing is None:
                targets[target.asset_id] = target
                continue
            if (existing.scheme, existing.host, existing.port, existing.path_prefix) != (
                target.scheme,
                target.host,
                target.port,
                target.path_prefix,
            ):
                raise ValueError(f"conflicting definitions of target {target.asset_id}")
            targets[target.asset_id] = existing.model_copy(
                update={
                    "tenant_ids": existing.tenant_ids | target.tenant_ids,
                    "allowed_resolved_addresses": existing.allowed_resolved_addresses
                    | target.allowed_resolved_addresses,
                    # Either side unrestricted makes the union unrestricted.
                    "resource_ids": (
                        existing.resource_ids | target.resource_ids
                        if existing.resource_ids and target.resource_ids
                        else frozenset()
                    ),
                }
            )
    shared_exclusions = set.intersection(
        *({item.canonical_bytes() for item in surface.exact_exclusions} for surface in items)
    )
    exclusions = _sorted_exclusions(
        item
        for surface in items
        for item in surface.exact_exclusions
        if item.canonical_bytes() in shared_exclusions
    )

    def union_set(name: str) -> frozenset[Any]:
        return frozenset().union(*(getattr(surface, name) for surface in items))

    def union_map(name: str) -> dict[str, frozenset[str]]:
        merged: dict[str, frozenset[str]] = {}
        for surface in items:
            for key, values in getattr(surface, name).items():
                merged[key] = merged.get(key, frozenset()) | values
        return merged

    return CapabilitySurface(
        action_classes=union_set("action_classes"),
        adapters=union_set("adapters"),
        operations=union_set("operations"),
        methods=union_set("methods"),
        credential_scopes=union_map("credential_scopes"),
        targets=tuple(targets[key] for key in sorted(targets)),
        browser_assets=union_set("browser_assets"),
        ownership=union_map("ownership"),
        exact_exclusions=exclusions,
        egress_hosts=union_set("egress_hosts"),
        model_endpoints=union_set("model_endpoints"),
        model_assets=union_set("model_assets"),
        subresource_origins=union_set("subresource_origins"),
        telemetry_collectors=union_set("telemetry_collectors"),
        max_attacker_proposals=max(s.max_attacker_proposals for s in items),
        max_attacker_depth=max(s.max_attacker_depth for s in items),
        max_tool_intents_per_turn=max(s.max_tool_intents_per_turn for s in items),
        max_agent_steps=max(s.max_agent_steps for s in items),
        max_nodes=max(s.max_nodes for s in items),
        max_depth=max(s.max_depth for s in items),
        proposal_source=max(
            (s.proposal_source for s in items), key=lambda source: _source_rank(source)
        ),
    )
