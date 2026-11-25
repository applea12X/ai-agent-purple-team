"""``capability_delta`` (WP5.1.1): every widening is an increase, nothing else is.

Unit cases name the exact increase kind each widening must produce; property cases compose
random widenings, narrowings, reorderings, and JSON round-trips. The fail-closed rule for a field
the classifier does not know is tested by adding one.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from ipaddress import IPv4Address
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from purpleloop.control.capabilities import (
    FIELD_CLASSIFICATION,
    capability_delta,
    capability_surface,
    surface_delta,
    unclassified_fields,
    union_surfaces,
)
from purpleloop.runtime.governance import (
    agent_manifest_15,
    v1_capability_surface,
    v1_lane_manifests,
)
from purpleloop.schemas.authorization import AuthorizationManifest, Phase1Grants
from purpleloop.schemas.phase2 import Phase2Grants
from purpleloop.schemas.phase3 import Phase3Grants
from purpleloop.schemas.phase4 import Phase4Grants
from purpleloop.schemas.phase5 import (
    CAPABILITY_INCREASES,
    ActionClass,
    CapabilityIncrease,
    Phase5Grants,
)

Kind = CapabilityIncrease
Mutation = Callable[[dict[str, Any]], None]

BASELINE = v1_capability_surface()
BASE = agent_manifest_15(Ed25519PrivateKey.generate())


def base_data() -> dict[str, Any]:
    return BASE.model_dump(mode="python", exclude_none=True)


def build(*mutations: Mutation) -> AuthorizationManifest:
    """Apply ``mutations`` to the base manifest. Raises if the schema refuses the result."""
    data = base_data()
    for mutation in mutations:
        mutation(data)
    return AuthorizationManifest.model_validate(data)


def _attack_handle(data: dict[str, Any]) -> str:
    return sorted(handle for handle in data["credential_scopes"] if "control" not in handle)[0]


def _add(path: tuple[str, ...], values: Any) -> Mutation:
    def mutate(data: dict[str, Any]) -> None:
        target = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = frozenset(target[path[-1]]) | frozenset(values)

    return mutate


def _set(path: tuple[str, ...], value: Any) -> Mutation:
    def mutate(data: dict[str, Any]) -> None:
        target = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value(target[path[-1]]) if callable(value) else value

    return mutate


def _scope(data: dict[str, Any]) -> None:
    handle = _attack_handle(data)
    data["credential_scopes"][handle] = frozenset(data["credential_scopes"][handle]) | {
        "fixture.reset"
    }


def _new_asset(data: dict[str, Any]) -> None:
    data["assets"] = (
        *data["assets"],
        {
            "asset_id": "codelab-data",
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 38080,
            "tenant_ids": frozenset({"org-a"}),
            "allowed_resolved_addresses": frozenset({IPv4Address("127.0.0.1")}),
        },
    )


def _asset_field(index: int, name: str, value: Any) -> Mutation:
    def mutate(data: dict[str, Any]) -> None:
        assets = [dict(asset) for asset in data["assets"]]
        current = assets[index].get(name)
        assets[index][name] = value(current) if callable(value) else value
        data["assets"] = tuple(assets)

    return mutate


def _control_index() -> int:
    return [asset.asset_id for asset in BASE.assets].index("supportlab-control")


def _data_index() -> int:
    return [asset.asset_id for asset in BASE.assets].index("supportlab-data")


def _ownership(data: dict[str, Any]) -> None:
    scopes = [dict(scope) for scope in data["phase2"]["ownership"]]
    scopes[0]["resource_ids"] = frozenset(scopes[0]["resource_ids"]) | {"ticket-new"}
    data["phase2"]["ownership"] = tuple(scopes)


def _deny(data: dict[str, Any]) -> None:
    data["allowed_operations"] = frozenset(data["allowed_operations"]) - {"export.create"}
    data["denied_operations"] = frozenset(data.get("denied_operations", ())) | {"export.create"}


#: Every widening, with the single increase kind it must produce.
WIDENINGS: dict[str, tuple[Kind, Mutation]] = {
    "action-class-code-exec": (
        Kind.NEW_ACTION_CLASS,
        _add(("phase5", "action_classes"), {ActionClass.CODE_EXEC}),
    ),
    "action-class-external-send": (
        Kind.NEW_ACTION_CLASS,
        _add(("phase5", "action_classes"), {ActionClass.EXTERNAL_SEND}),
    ),
    "new-adapter": (Kind.NEW_ADAPTER_OR_OPERATION, _add(("allowed_adapters",), {"sandbox"})),
    "new-operation": (
        Kind.NEW_ADAPTER_OR_OPERATION,
        _add(("allowed_operations",), {"snippet.run"}),
    ),
    "new-method": (Kind.NEW_ADAPTER_OR_OPERATION, _add(("allowed_methods",), {"DELETE"})),
    "credential-scope": (Kind.NEW_ADAPTER_OR_OPERATION, _scope),
    "browser-asset": (
        Kind.NEW_ADAPTER_OR_OPERATION,
        _add(("phase2", "browser_assets"), {"supportlab-control"}),
    ),
    "new-asset": (Kind.NEW_TARGET_FIXTURE, _new_asset),
    "new-tenant": (
        Kind.NEW_TARGET_FIXTURE,
        _asset_field(0, "tenant_ids", lambda tenants: frozenset(tenants) | {"org-c"}),
    ),
    "wider-path": (Kind.NEW_TARGET_FIXTURE, _asset_field(_control_index(), "path_prefix", "/")),
    "new-address": (
        Kind.NEW_TARGET_FIXTURE,
        _asset_field(
            0,
            "allowed_resolved_addresses",
            lambda addresses: frozenset(addresses) | {IPv4Address("127.0.0.2")},
        ),
    ),
    "new-ownership": (Kind.NEW_TARGET_FIXTURE, _ownership),
    "egress-host": (Kind.WIDENED_EGRESS, _add(("egress_hosts",), {"10.0.0.1"})),
    "model-endpoint": (
        Kind.WIDENED_EGRESS,
        _add(("model_endpoints",), {"http://127.0.0.1:9999/v1"}),
    ),
    "subresource-origin": (
        Kind.WIDENED_EGRESS,
        _add(("phase2", "subresource_origins"), {"http://127.0.0.1:28090"}),
    ),
    "attacker-proposals": (
        Kind.RAISED_ATTACKER_CAPS,
        _set(("phase3", "max_attacker_proposals"), lambda value: value + 1),
    ),
    "attacker-depth": (
        Kind.RAISED_ATTACKER_CAPS,
        _set(("phase3", "max_attacker_depth"), lambda value: value + 1),
    ),
    "intents-per-turn": (
        Kind.RAISED_ATTACKER_CAPS,
        _set(("phase3", "max_tool_intents_per_turn"), lambda value: value + 1),
    ),
    "agent-steps": (
        Kind.RAISED_ATTACKER_CAPS,
        _set(("phase3", "max_agent_steps"), lambda value: value + 1),
    ),
    "plan-nodes": (Kind.RAISED_ATTACKER_CAPS, _set(("phase1", "max_nodes"), lambda v: v + 1)),
    "plan-depth": (Kind.RAISED_ATTACKER_CAPS, _set(("phase1", "max_depth"), lambda v: v + 1)),
    "proposal-source": (
        Kind.PROPOSAL_SOURCE_CHANGE,
        _set(("phase5", "proposal_source"), "model-driven"),
    ),
}


def _read_only(data: dict[str, Any]) -> None:
    data["allowed_side_effects"] = frozenset({"read"})
    data["phase5"]["action_classes"] = frozenset({ActionClass.READ})


def _drop_scope_op(data: dict[str, Any]) -> None:
    handle = _attack_handle(data)
    data["credential_scopes"][handle] = frozenset(data["credential_scopes"][handle]) - {
        "email.send"
    }


#: Narrowings and non-capability changes: none may produce any increase.
NARROWINGS: dict[str, Mutation] = {
    "drop-operation": _set(("allowed_operations",), lambda ops: frozenset(ops) - {"email.send"}),
    "deny-operation": _deny,
    "drop-adapter": _set(("allowed_adapters",), lambda items: frozenset(items) - {"browser"}),
    "drop-method": _set(("allowed_methods",), lambda items: frozenset(items) - {"PATCH"}),
    "drop-scope-operation": _drop_scope_op,
    "read-only": _read_only,
    "fewer-proposals": _set(("phase3", "max_attacker_proposals"), lambda v: v - 1),
    "shallower-attacker": _set(("phase3", "max_attacker_depth"), lambda v: v - 1),
    "fewer-intents": _set(("phase3", "max_tool_intents_per_turn"), lambda v: v - 1),
    "fewer-steps": _set(("phase3", "max_agent_steps"), lambda v: v - 1),
    "fewer-nodes": _set(("phase1", "max_nodes"), lambda v: v - 1),
    "add-exclusion": _set(
        ("exact_exclusions",), lambda items: (*items, {"operation": "export.create"})
    ),
    "drop-egress": _set(("egress_hosts",), frozenset()),
    "narrower-path": _asset_field(_control_index(), "path_prefix", "/control/fixture"),
    "restrict-resources": _asset_field(_data_index(), "resource_ids", frozenset({"x-1"})),
    "drop-browser-asset": _set(("phase2", "browser_assets"), frozenset()),
    # Not capabilities at all: spend, time, keys, mode, and approvals.
    "raise-budget": _set(("budgets",), lambda b: {**dict(b), "requests": 10_000}),
    "longer-window": _set(("valid_until",), lambda t: t.replace(year=t.year + 1)),
    "other-key-id": _set(("key_id",), "another-key"),
    "shadow-mode": _set(("phase5", "run_mode"), "shadow"),
    "name-approval": _set(("phase5", "risk_approvals"), frozenset({"a" * 64})),
    "matrix-scope": _set(("phase5", "matrix_scope"), "b" * 64),
    "more-tokens": _set(("phase3", "token_budget"), lambda v: v + 1),
}


def test_the_classification_names_exactly_every_current_field() -> None:
    models = {
        "manifest": AuthorizationManifest,
        "phase1": Phase1Grants,
        "phase2": Phase2Grants,
        "phase3": Phase3Grants,
        "phase4": Phase4Grants,
        "phase5": Phase5Grants,
    }
    assert set(FIELD_CLASSIFICATION) == set(models)
    for section, model in models.items():
        assert set(FIELD_CLASSIFICATION[section]) == set(model.model_fields), section
    assert unclassified_fields(BASE) == ()


def test_every_v1_lane_manifest_is_inside_the_baseline() -> None:
    for manifest in v1_lane_manifests():
        assert capability_delta(BASELINE, manifest) == frozenset(), manifest.engagement_id
    assert capability_delta(BASELINE, BASE) == frozenset()


@pytest.mark.parametrize("name", sorted(WIDENINGS))
def test_each_widening_is_exactly_its_increase_kind(name: str) -> None:
    kind, mutation = WIDENINGS[name]
    assert capability_delta(BASELINE, build(mutation)) == frozenset({kind})
    # Against the requested manifest's own base, too: the delta is relative, not absolute.
    assert capability_delta(BASE, build(mutation)) == frozenset({kind})


def test_every_increase_kind_has_a_widening() -> None:
    assert {kind for kind, _ in WIDENINGS.values()} == set(CAPABILITY_INCREASES)


@pytest.mark.parametrize("name", sorted(NARROWINGS))
def test_narrowings_and_non_capability_changes_are_not_increases(name: str) -> None:
    assert capability_delta(BASELINE, build(NARROWINGS[name])) == frozenset()


def test_reallowing_a_denied_operation_is_an_increase() -> None:
    denied = build(NARROWINGS["deny-operation"])
    assert capability_delta(denied, BASE) == frozenset({Kind.NEW_ADAPTER_OR_OPERATION})


def test_dropping_an_exclusion_is_an_increase() -> None:
    excluded = build(NARROWINGS["add-exclusion"])
    assert capability_delta(excluded, BASE) == frozenset({Kind.NEW_TARGET_FIXTURE})


def test_unrestricting_a_restricted_asset_is_an_increase() -> None:
    restricted = build(NARROWINGS["restrict-resources"])
    assert capability_delta(restricted, BASE) == frozenset({Kind.NEW_TARGET_FIXTURE})
    other = build(_asset_field(_data_index(), "resource_ids", frozenset({"x-2"})))
    assert capability_delta(restricted, other) == frozenset({Kind.NEW_TARGET_FIXTURE})


def test_a_prefix_that_only_shares_characters_is_not_narrower() -> None:
    sibling = build(_asset_field(_control_index(), "path_prefix", "/controlx"))
    assert capability_delta(BASELINE, sibling) == frozenset({Kind.NEW_TARGET_FIXTURE})


def test_an_operation_with_a_registered_class_derives_that_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import MappingProxyType

    from purpleloop.control import capabilities

    monkeypatch.setattr(
        capabilities,
        "OPERATION_ACTION_CLASSES",
        MappingProxyType({"snippet.run": ActionClass.CODE_EXEC}),
    )
    requested = build(WIDENINGS["new-operation"][1])
    # Declared only read and write, yet the operation is code execution: both kinds.
    assert capability_delta(BASELINE, requested) == frozenset(
        {Kind.NEW_ADAPTER_OR_OPERATION, Kind.NEW_ACTION_CLASS}
    )


def test_an_unclassified_field_fails_closed_as_every_increase() -> None:
    class FutureGrants(Phase5Grants):
        new_power: int = 0

    grants = FutureGrants(action_classes=frozenset({ActionClass.READ, ActionClass.WRITE}))
    assert capability_delta(BASELINE, BASE.model_copy(update={"phase5": grants})) == frozenset()
    powered = grants.model_copy(update={"new_power": 5})
    requested = BASE.model_copy(update={"phase5": powered})
    assert unclassified_fields(requested) == ("phase5.new_power",)
    assert capability_delta(BASELINE, requested) == frozenset(CAPABILITY_INCREASES)


def test_the_delta_refuses_anything_but_a_manifest_or_a_surface() -> None:
    with pytest.raises(TypeError):
        capability_delta(BASELINE, {"operations": []})  # type: ignore[arg-type]


def test_a_union_with_conflicting_targets_is_refused() -> None:
    moved = capability_surface(build(_asset_field(0, "port", 1)))
    with pytest.raises(ValueError, match="conflicting"):
        union_surfaces([BASELINE, moved])
    with pytest.raises(ValueError):
        union_surfaces([])


def test_the_union_is_the_smallest_surface_containing_each_input() -> None:
    surfaces = [capability_surface(manifest) for manifest in v1_lane_manifests()]
    union = union_surfaces(surfaces)
    assert union == BASELINE
    for surface in surfaces:
        assert surface_delta(union, surface) == frozenset()
    # And no smaller: dropping any operation from the union excludes some v1 lane.
    for operation in sorted(union.operations)[:10]:
        smaller = union.model_copy(update={"operations": union.operations - {operation}})
        assert any(surface_delta(smaller, surface) for surface in surfaces), operation


# --- properties ----------------------------------------------------------------------------------


def build_or_discard(*mutations: Mutation) -> AuthorizationManifest:
    """Build a generated combination, discarding one the manifest schema itself refuses.

    Some combinations are not manifests at all (subresource origins with no browser asset); the
    schema refuses them before ``capability_delta`` could be asked, so they are not cases.
    """
    try:
        return build(*mutations)
    except ValidationError:
        assume(False)
        raise


widening_names = st.sets(st.sampled_from(sorted(WIDENINGS)), min_size=1, max_size=5)
narrowing_names = st.sets(st.sampled_from(sorted(NARROWINGS)), max_size=6)

#: The narrowing that moves the same cap the other way, for each cap widening.
SAME_CAP = {
    "attacker-proposals": "fewer-proposals",
    "attacker-depth": "shallower-attacker",
    "intents-per-turn": "fewer-intents",
    "agent-steps": "fewer-steps",
    "plan-nodes": "fewer-nodes",
}
SETTINGS = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])


@SETTINGS
@given(widening_names)
def test_any_composed_widening_is_exactly_the_union_of_its_kinds(names: set[str]) -> None:
    requested = build_or_discard(*(WIDENINGS[name][1] for name in sorted(names)))
    expected = frozenset(WIDENINGS[name][0] for name in names)
    delta = capability_delta(BASELINE, requested)
    assert delta and delta == expected


@SETTINGS
@given(narrowing_names)
def test_any_composed_narrowing_needs_no_approval(names: set[str]) -> None:
    assert capability_delta(
        BASELINE, build_or_discard(*(NARROWINGS[name] for name in sorted(names)))
    ) == (frozenset())


@SETTINGS
@given(widening_names, narrowing_names)
def test_narrowing_elsewhere_never_hides_a_widening(widen: set[str], narrow: set[str]) -> None:
    # A cap lowered by one and then raised by one is the baseline cap again: not "elsewhere".
    assume(not any(SAME_CAP.get(name) in narrow for name in widen))
    requested = build_or_discard(
        *(NARROWINGS[name] for name in sorted(narrow)),
        *(WIDENINGS[name][1] for name in sorted(widen)),
    )
    assert capability_delta(BASELINE, requested) >= frozenset(WIDENINGS[name][0] for name in widen)


@SETTINGS
@given(widening_names, st.randoms(use_true_random=False))
def test_the_delta_is_invariant_to_order_and_canonicalization(names: set[str], rng: Any) -> None:
    requested = build_or_discard(*(WIDENINGS[name][1] for name in sorted(names)))
    data = requested.model_dump(mode="python", exclude_none=True)
    assets = list(data["assets"])
    rng.shuffle(assets)
    data["assets"] = tuple(assets)
    reordered = AuthorizationManifest.model_validate(data)
    round_tripped = AuthorizationManifest.model_validate(json.loads(requested.model_dump_json()))
    delta = capability_delta(BASELINE, requested)
    assert capability_delta(BASELINE, reordered) == delta
    assert capability_delta(BASELINE, round_tripped) == delta
    assert capability_surface(reordered) == capability_surface(requested)
    assert capability_surface(round_tripped).canonical_bytes() == (
        capability_surface(requested).canonical_bytes()
    )
