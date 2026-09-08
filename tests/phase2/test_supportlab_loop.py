from __future__ import annotations

from typing import Any

from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.supportlab import ALL_CANARIES
from purpleloop.schemas.event import EventKind
from purpleloop.schemas.phase1 import load_ground_truth
from purpleloop.scoring.phase1 import corpus_metrics
from purpleloop.scoring.phase2 import cross_surface_agreement

SUPPORTLAB = ROOT / "scenarios" / "supportlab"


async def test_full_corpus_paired_loops(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    summaries = []
    for scenario in supportlab_scenarios:
        runner, fixture, directory = make_supportlab_runner()
        result = await runner.run(
            scenario, supportlab_signed, run_id=scenario.scenario_id, output_dir=directory
        )
        assert result.status == "passed", (scenario.scenario_id, result.reason)
        assert result.baseline.security.verdict == "true"
        assert result.replay.security.verdict == "false"
        assert result.baseline.utility.verdict == result.replay.utility.verdict == "true"
        assert result.baseline.seed_hash == result.replay.seed_hash
        assert result.mitigation_effective and result.teardown_complete and fixture.closed
        assert len(result.findings) == 1
        assert result.replay.unauthorized_side_effects == 0
        assert result.lane == "supportlab"
        assert result.evidence_completeness.completeness == 1.0
        # Deterministic resource dimensions match the pre-run estimate exactly.
        for dimension in ("requests", "records", "browser_contexts"):
            assert result.resources.within_tolerance[dimension], (scenario.scenario_id, dimension)
        verify_bundle(directory, allow_partial=True)
        exported = "\n".join(
            p.read_text(errors="ignore")
            for p in directory.rglob("*")
            if p.is_file() and p.suffix not in {".png", ".zip"}
        )
        for secret in ("SUPPORTLAB-CONTROL-SECRET", *ALL_CANARIES):
            assert secret not in exported
        summaries.append(result)
    truth = load_ground_truth(SUPPORTLAB / "ground-truth.json")
    metrics = corpus_metrics(truth, summaries)
    assert metrics["seeded_recall"] == 1.0
    assert metrics["false_positives"] == 0 and metrics["false_positive_rate"] == 0.0
    assert metrics["unevaluated_scenarios"] == [] and metrics["missing_negative_controls"] == []
    agreement = cross_surface_agreement(supportlab_scenarios, summaries)
    assert agreement["disagreements"] == []
    assert (
        agreement["paired_groups"] >= 2 and agreement["agreed_groups"] == agreement["paired_groups"]
    )


async def test_browser_and_api_share_evidence_and_redaction(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = next(s for s in supportlab_scenarios if s.scenario_id == "bola-ticket-ui")
    runner, _, directory = make_supportlab_runner()
    result = await runner.run(scenario, supportlab_signed, run_id="ui", output_dir=directory)
    assert result.browser_driver == "html-form"
    assert result.browser_artifacts and all(
        a.startswith("browser/") for a in result.browser_artifacts
    )
    events = runner.runtime.ledger.verify()
    assert any(e.kind == EventKind.RESULT and e.reason_code == "COMPLETED" for e in events)


async def test_deterministic_replay_supportlab(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    """Three paired evaluations per scenario; each scenario's replay rate must be 1.0.

    The API lane and the browser (html-form) lane are reported separately, as the plan requires.
    """
    from purpleloop.scoring.phase2 import replay_rate

    api_trials = 0
    browser_trials = 0
    for scenario in supportlab_scenarios:
        fingerprints = []
        for _ in range(3):
            runner, _, directory = make_supportlab_runner()
            result = await runner.run(
                scenario, supportlab_signed, run_id="trial", output_dir=directory
            )
            assert result.status == "passed"
            fingerprints.append((result.event_replay_hash, result.oracle_hash))
        rate = replay_rate(fingerprints)
        assert rate["rate"] == 1.0, (scenario.scenario_id, rate["mismatches"])
        if scenario.effective_surface == "browser":
            browser_trials += rate["trials"]
        else:
            api_trials += rate["trials"]
    assert api_trials >= 30 and browser_trials >= 9
