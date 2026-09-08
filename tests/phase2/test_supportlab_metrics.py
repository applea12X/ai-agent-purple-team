"""Every Phase 2 metric ships with a test that fails when the metric is faked."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from purpleloop.control.lanes import SUPPORTLAB_LANE
from purpleloop.schemas.event import EventKind, EvidenceEvent
from purpleloop.schemas.phase2 import ResourceUsage
from purpleloop.scoring.phase2 import (
    cross_surface_agreement,
    evidence_completeness,
    replay_rate,
    resource_report,
)


def _event(**kwargs: object) -> EvidenceEvent:
    base = dict(
        schema_version="1.1.0",
        scenario_id="s",
        scenario_version="1.0.0",
        stage="attack",
        component_version="runner-v1",
        run_id="r",
        trace_id="t",
        sequence=0,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        actor="safety-kernel",
        kind=EventKind.LIFECYCLE,
        manifest_digest="0" * 64,
        policy_digest="1" * 64,
        reason_code="X",
        event_hash="e" * 64,
    )
    base.update(kwargs)
    return EvidenceEvent(**base)  # type: ignore[arg-type]


def test_completeness_is_one_when_every_required_field_present() -> None:
    events = [
        _event(sequence=0, parent_hash=None),
        _event(sequence=1, parent_hash="a" * 64),
    ]
    metric = evidence_completeness(events)
    assert metric.completeness == 1.0 and metric.missing == ()


def test_completeness_drops_when_a_required_field_is_missing() -> None:
    good = _event(sequence=0, kind=EventKind.RESULT, action_digest="d" * 64, decision="permit")
    bad = _event(sequence=1, kind=EventKind.RESULT, decision="permit", parent_hash="a" * 64)
    metric = evidence_completeness([good, bad])
    assert metric.completeness < 1.0
    assert any("action_digest" in name for name in metric.missing)


def test_resource_report_flags_out_of_tolerance() -> None:
    estimated = ResourceUsage(requests=100, records=100, browser_contexts=2, wall_time_seconds=1.0)
    actual = ResourceUsage(requests=100, records=100, browser_contexts=2, wall_time_seconds=2.0)
    report = resource_report(estimated, actual)
    assert report.within_tolerance["requests"] is True
    assert report.within_tolerance["wall_time_seconds"] is False
    assert report.delta_percent["wall_time_seconds"] == pytest.approx(100.0)


def test_cross_surface_disagreement_is_listed_not_averaged() -> None:
    class FakeScenario:
        def __init__(self, sid: str, surface: str) -> None:
            self.scenario_id = sid
            self.shared_oracle = "shared"
            self.effective_surface = surface

    class FakeLeg:
        def __init__(self, verdict: str) -> None:
            self.security = type("O", (), {"verdict": verdict})()

    class FakeSummary:
        def __init__(self, sid: str, base: str, replay: str) -> None:
            self.scenario_id = sid
            self.baseline = FakeLeg(base)
            self.replay = FakeLeg(replay)

    scenarios = [FakeScenario("a", "api"), FakeScenario("b", "browser")]
    summaries = [FakeSummary("a", "true", "false"), FakeSummary("b", "true", "true")]
    report = cross_surface_agreement(scenarios, summaries)  # type: ignore[arg-type]
    assert report["disagreements"] == ["shared"]
    assert report["agreed_groups"] == 0


def test_replay_rate_counts_every_trial() -> None:
    fingerprints = [("a", "x"), ("a", "x"), ("b", "y"), ("a", "x")]
    rate = replay_rate(fingerprints)
    assert rate["trials"] == 4 and rate["matches"] == 3
    assert rate["rate"] == pytest.approx(0.75) and rate["mismatches"] == [2]


def test_estimate_matches_deterministic_dimensions() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from purpleloop.control.plan_compiler import compile_plan
    from purpleloop.runtime.demo import ROOT
    from purpleloop.runtime.supportlab import supportlab_manifest
    from purpleloop.schemas.phase1 import load_scenario
    from purpleloop.scoring.phase2 import estimate_resources

    scenario = load_scenario(ROOT / "scenarios/supportlab/bola-ticket.yaml")
    manifest = supportlab_manifest(Ed25519PrivateKey.generate(), seed=42)
    plan = compile_plan(scenario, manifest, lane=SUPPORTLAB_LANE)
    estimate = estimate_resources(plan, SUPPORTLAB_LANE)
    # Two legs of one request each, plus the fixed control-plane calls.
    assert estimate.requests == 2 * 2 + SUPPORTLAB_LANE.control_calls_per_run
    assert estimate.browser_contexts == 0
