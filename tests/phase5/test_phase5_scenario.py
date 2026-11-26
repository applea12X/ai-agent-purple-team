"""Scenario 1.4: origin, import provenance, public exposure, and the codelab lane.

The corpus digests below were recorded at the phase base (``a79f185``) with the pre-Phase-5
code: per lane, the digest over the sorted ``(file name, scenario digest)`` pairs of every
scenario. A deliberate corpus edit changes them and must update this table in the same commit,
with the reason; a schema change must never change them.
"""

from __future__ import annotations

from typing import Any, get_args

import pytest
from pydantic import ValidationError

from purpleloop.reporting.gates import _reference_scenario
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.common import digest_data
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario, scenario_paths
from purpleloop.schemas.phase4 import SMOKE_LANES, SmokeLane
from purpleloop.schemas.phase5 import SCENARIO_LANES, ImportSource, ScenarioLane

PINNED_CORPUS_DIGESTS = {
    "phase1": (5, "7a9bce82368ad478926b9de7e8f728f8e981cf4a14124af5faa8c31f97a85278"),
    "supportlab": (18, "216585ea4495b5a5df6e12b33cac4b28c4296aff8487f2276f5d73c0c5832611"),
    "agent": (25, "e40a5ce190641f675c5343cbedb2bf3b0962f788962bd42ef70b85bb171558e5"),
}
PHASE5_FIELDS = {"origin", "import_source", "public_exposure", "lane"}
#: WP5.5: the codelab corpus, recorded when it was authored (10 Scenario 1.4 documents). A
#: deliberate edit to it changes this digest and updates it here in the same commit.
PINNED_PHASE5_CORPUS_DIGESTS = {
    "codelab": (10, "f8fe2f396fe595cab61091c1b79de06963226794f945c5bfb817b7a0019ca488"),
}


@pytest.mark.parametrize("lane", sorted(PINNED_PHASE5_CORPUS_DIGESTS))
def test_phase5_corpus_is_pinned(lane: str) -> None:
    scenarios = {
        path.name: load_scenario(path) for path in scenario_paths(ROOT / "scenarios" / lane)
    }
    count, digest = PINNED_PHASE5_CORPUS_DIGESTS[lane]
    assert len(scenarios) == count
    assert digest_data(sorted((name, s.digest()) for name, s in scenarios.items())) == digest
    assert all(s.schema_version == "1.4.0" and s.lane == lane for s in scenarios.values())


@pytest.mark.parametrize("lane", sorted(PINNED_CORPUS_DIGESTS))
def test_existing_corpus_loads_unchanged(lane: str) -> None:
    paths = scenario_paths(ROOT / "scenarios" / lane)
    scenarios = {path.name: load_scenario(path) for path in paths}
    count, digest = PINNED_CORPUS_DIGESTS[lane]
    assert len(scenarios) == count
    assert digest_data(sorted((name, s.digest()) for name, s in scenarios.items())) == digest
    for scenario in scenarios.values():
        dumped = scenario.model_dump(mode="json", exclude_none=True)
        assert not PHASE5_FIELDS & dumped.keys(), "absent 1.4 fields must not serialize"
        assert Phase1Scenario.model_validate(dumped).canonical_bytes() == scenario.canonical_bytes()


def scenario_14(**overrides: Any) -> Phase1Scenario:
    data = _reference_scenario().model_dump(mode="python", exclude_none=True)
    data.update(schema_version="1.4.0", origin="authored", public_exposure=False)
    data.update(overrides)
    return Phase1Scenario.model_validate(data)


def source(**overrides: Any) -> ImportSource:
    fields: dict[str, Any] = {
        "framework": "agentdojo",
        "upstream_version": "v1.2",
        "license": "MIT",
        "case_id": "workspace/injection_task_3",
    }
    fields.update(overrides)
    return ImportSource.model_validate(fields)


def test_authored_and_imported_14_scenarios_round_trip() -> None:
    authored = scenario_14(lane="codelab")
    imported = scenario_14(
        origin="imported", import_source=source(), public_exposure=True, license="MIT"
    )
    for scenario in (authored, imported):
        reloaded = Phase1Scenario.model_validate_json(scenario.model_dump_json())
        assert reloaded.canonical_bytes() == scenario.canonical_bytes()
    assert imported.import_source is not None and imported.public_exposure is True
    # 1.4 keeps the agent surface 1.3 introduced.
    assert authored.effective_surface == "agent"


def test_imported_origin_requires_an_import_source() -> None:
    with pytest.raises(ValidationError, match="import source is required"):
        scenario_14(origin="imported", public_exposure=True)


def test_authored_origin_forbids_an_import_source() -> None:
    with pytest.raises(ValidationError, match="import source is required"):
        scenario_14(import_source=source(), license="MIT")


def test_a_14_scenario_states_origin_and_exposure_explicitly() -> None:
    with pytest.raises(ValidationError, match="state its origin and public exposure"):
        scenario_14(origin=None)
    with pytest.raises(ValidationError, match="state its origin and public exposure"):
        scenario_14(public_exposure=None)


def test_import_source_license_must_match_the_scenario() -> None:
    with pytest.raises(ValidationError, match="license must match"):
        scenario_14(
            origin="imported", import_source=source(license="GPL-3.0"), public_exposure=True
        )


def test_import_source_names_an_upstream_version_or_commit() -> None:
    with pytest.raises(ValidationError, match="upstream version or commit"):
        source(upstream_version=None)
    assert source(upstream_version=None, upstream_commit="abc1234").upstream_commit
    with pytest.raises(ValidationError):
        source(upstream_commit="not-hex")
    with pytest.raises(ValidationError):
        source(framework="unknown-framework")


@pytest.mark.parametrize(
    "field,value",
    [("origin", "authored"), ("public_exposure", False), ("lane", "agent")],
)
def test_14_fields_are_refused_on_earlier_versions(field: str, value: object) -> None:
    data = _reference_scenario().model_dump(mode="python", exclude_none=True)
    data[field] = value
    with pytest.raises(ValidationError, match="require scenario 1.4"):
        Phase1Scenario.model_validate(data)


def test_lane_enum_gains_codelab_without_widening_the_smoke_vocabulary() -> None:
    assert SCENARIO_LANES == ("phase1", "supportlab", "agent", "codelab")
    assert set(get_args(ScenarioLane)) == set(SCENARIO_LANES)
    assert scenario_14(lane="codelab").lane == "codelab"
    with pytest.raises(ValidationError):
        scenario_14(lane="elsewhere")
    # The Phase 4 smoke set's lane vocabulary is a frozen 1.4 contract and is not widened.
    assert set(get_args(SmokeLane)) == set(SMOKE_LANES) == {"phase1", "supportlab", "agent"}
