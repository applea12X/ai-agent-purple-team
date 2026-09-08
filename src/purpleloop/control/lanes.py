"""Lane contracts: the trusted bindings that differ between the Phase 1 and supportlab fixtures.

A lane names its tool registry, defense registry, signed asset expectations, actor bindings, and
registered cross-tenant exercises. The runner and compiler are parameterized by a lane so the
Phase 1 lane keeps exactly its earlier behavior while the supportlab lane adds a second fixture
and a browser surface without a second runner.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from purpleloop.control import phase2_tools
from purpleloop.control.actors import ActorBinding
from purpleloop.control.phase1_tools import PHASE1_TOOLS
from purpleloop.control.tools import ToolRegistry
from purpleloop.fixture.app import DEFENSES as PHASE1_DEFENSES
from purpleloop.schemas.phase1 import Phase1Scenario


@dataclass(frozen=True)
class ResourceCalibration:
    """Per-unit wall-time constants used for the pre-run estimate. Reported, never tuned to fit."""

    seconds_per_request: float
    seconds_per_browser_context: float
    fixed_seconds: float


@dataclass(frozen=True)
class LaneContract:
    name: str
    tools: ToolRegistry
    defenses: Mapping[str, tuple[frozenset[str], dict[str, bool]]]
    data_asset_id: str
    control_asset_id: str
    control_credential_handle: str
    expected_assets: Mapping[str, int]
    actors: Mapping[str, ActorBinding]
    cross_tenant_operations: frozenset[str]
    manifest_versions: frozenset[str]
    scenario_versions: frozenset[str]
    seed_arguments: Callable[[Phase1Scenario], dict[str, Any]]
    calibration: ResourceCalibration
    resource_resolver: Callable[[int, str], str] | None = None
    flows: Mapping[str, phase2_tools.Flow] = field(default_factory=lambda: MappingProxyType({}))
    requires_phase2: bool = False
    control_calls_per_run: int = 15


def _phase1_seed_arguments(scenario: Phase1Scenario) -> dict[str, Any]:
    return {
        "seed": scenario.fixture_seed,
        "scenario_id": scenario.scenario_id,
        "capabilities": sorted(scenario.capabilities),
    }


def _supportlab_seed_arguments(scenario: Phase1Scenario) -> dict[str, Any]:
    return {"seed": scenario.fixture_seed, "scenario_id": scenario.scenario_id}


def _supportlab_resource(seed: int, key: str) -> str:
    """Map a scenario's logical resource key to the concrete seed-derived identifier.

    Scenarios name ``ticket-b1``; the seeded fixture assigns it a seed-derived id, and the
    signed ownership is enumerated over the same ids. A key that is not a logical name is a
    concrete id already (a row created during the run) and passes through unchanged.
    """
    from purpleloop.fixture.supportlab import seed as seeding

    return seeding.build(seed).ids.get(key, key)


PHASE1_LANE = LaneContract(
    name="phase1",
    tools=PHASE1_TOOLS,
    defenses=MappingProxyType(PHASE1_DEFENSES),
    data_asset_id="fixture-data",
    control_asset_id="fixture-control",
    control_credential_handle="fixture-control",
    expected_assets=MappingProxyType({"fixture-data": 18080, "fixture-control": 18081}),
    actors=MappingProxyType(
        {"customer-a": ActorBinding("customer-a", "customer", "tenant-a", "fixture-customer")}
    ),
    cross_tenant_operations=frozenset({"record.read"}),
    manifest_versions=frozenset({"1.1.0"}),
    scenario_versions=frozenset({"1.1.0"}),
    seed_arguments=_phase1_seed_arguments,
    calibration=ResourceCalibration(0.004, 0.0, 0.05),
)

SUPPORTLAB_LANE = LaneContract(
    name=phase2_tools.LANE,
    tools=phase2_tools.SUPPORTLAB_TOOLS,
    defenses=MappingProxyType(phase2_tools.DEFENSES),
    data_asset_id=phase2_tools.DATA_ASSET,
    control_asset_id=phase2_tools.CONTROL_ASSET,
    control_credential_handle=phase2_tools.CONTROL_HANDLE,
    expected_assets=MappingProxyType(
        {
            phase2_tools.DATA_ASSET: phase2_tools.DATA_PORT,
            phase2_tools.CONTROL_ASSET: phase2_tools.CONTROL_PORT,
        }
    ),
    actors=phase2_tools.ACTORS,
    cross_tenant_operations=phase2_tools.CROSS_TENANT_OPERATIONS,
    manifest_versions=frozenset({"1.2.0"}),
    scenario_versions=frozenset({"1.2.0"}),
    seed_arguments=_supportlab_seed_arguments,
    calibration=ResourceCalibration(0.006, 0.02, 0.08),
    resource_resolver=_supportlab_resource,
    flows=phase2_tools.FLOWS,
    requires_phase2=True,
)

LANES: MappingProxyType[str, LaneContract] = MappingProxyType(
    {PHASE1_LANE.name: PHASE1_LANE, SUPPORTLAB_LANE.name: SUPPORTLAB_LANE}
)
