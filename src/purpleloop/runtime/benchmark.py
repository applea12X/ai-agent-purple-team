"""The WP5.6 benchmark subset: load, promote, run, and report it apart from the authored corpus.

**What the subset is.** No upstream AgentDojo case data was available on this machine (no
installed ``agentdojo`` package, nothing in the uv cache), and nothing was downloaded. So the
subset is *authored* here, in AgentDojo's shape: each candidate pairs a user task with an
injection task, the injection sits in content the user task reads, and both are scored by state
or response checks rather than by a model's say-so. Every scenario says ``origin: authored``, no
``import_source`` is claimed, and the provenance names the structure it borrows and says no
upstream text was copied. ``scenarios/imported/`` is reserved for real imports and does not exist.

**How it becomes runnable.** Candidates go through the same not-runnable import path every
importer uses, then through :func:`purpleloop.adapters.importers.promote` with a hand-authored
record per case. Cases the author could not promote are declined with a reason and counted. The
committed scenario YAML is the promotion output; a test rebuilds it and compares digests.

**Why it has its own lane contract.** :data:`BENCHMARK_LANE` is the agent lane with two changes:
it admits Scenario 1.4 only, and its defense registry names the subset's scenarios only. So the
authored agent lane (1.3 only) can never run a benchmark case, and this lane can never run an
authored one. Its metrics are therefore never mixed into the authored 48's.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field

from purpleloop.adapters.importers import (
    DeclinedCase,
    PromotionRecord,
    PromotionReport,
    from_agentdojo_style,
    ground_truth,
    promote_subset,
)
from purpleloop.adapters.model_provider import Provider
from purpleloop.adapters.scripted_model import DelimitationBlindModel, ScriptedAgentModel
from purpleloop.control.benchmark_tools import BENCHMARK_DEFENSES
from purpleloop.control.lanes import AGENT_LANE, LaneContract
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.reporting.bundle import inventory, reports, verify_bundle, write_json
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.runtime.supportlab import (
    KEY_ID,
    MODEL_FIXTURE,
    InProcessSupportlab,
    actor_credentials,
    build_supportlab_runner,
    supportlab_agent_manifest,
)
from purpleloop.schemas.common import StrictModel, order_sets
from purpleloop.schemas.phase1 import (
    GroundTruth,
    Phase1Scenario,
    RunSummary,
    load_scenario,
    scenario_paths,
)
from purpleloop.scoring.phase1 import corpus_metrics

BENCHMARK_ROOT = ROOT / "scenarios" / "benchmark"
SUBSET_DIR = BENCHMARK_ROOT / "agentdojo-style"
#: Reserved for cases imported from real upstream data. Absent until such data is obtained.
IMPORTED_ROOT = ROOT / "scenarios" / "imported"

CANDIDATES = "candidates.json"
PROMOTIONS = "promotions.json"
GROUND_TRUTH = "ground-truth.json"
PROMOTION_REPORT = "promotion-report.json"

BENCHMARK_LANE: LaneContract = dataclasses.replace(
    AGENT_LANE,
    name="supportlab-agent-benchmark",
    scenario_versions=frozenset({"1.4.0"}),
    defenses=MappingProxyType(BENCHMARK_DEFENSES),
)

#: The delimitation-blind stand-in, defined once in ``adapters.scripted_model`` and shared with
#: the evaluation matrix (WP5.2). It strips the ``<untrusted>`` markers before deciding, so it
#: follows an injected directive wherever it appears -- the behaviour ``qwen2.5:7b-instruct``
#: showed in WP4.0.1. The name is kept so existing references keep working.
DelimitationBlindScriptedModel = DelimitationBlindModel


STAND_INS: dict[str, type[ScriptedAgentModel]] = {
    "scripted": ScriptedAgentModel,
    "delimitation-blind": DelimitationBlindScriptedModel,
}


# --- loading and promotion -----------------------------------------------------------------------


def load_candidates(directory: Path = SUBSET_DIR) -> list[Phase1Scenario]:
    """Every candidate as a not-runnable scenario, through the AgentDojo-style import path."""
    raw = json.loads((directory / CANDIDATES).read_text(encoding="utf-8"))
    user_tasks, injection_tasks = raw["user_tasks"], raw["injection_tasks"]
    return [
        from_agentdojo_style(
            {
                "id": case["id"],
                "suite": raw["suite"],
                "user_task": user_tasks[case["user_task_id"]],
                "injection_task": injection_tasks[case["injection_task_id"]],
                "license": "CC0-1.0",
            },
            index=index,
        )
        for index, case in enumerate(raw["cases"])
    ]


def load_promotions(
    directory: Path = SUBSET_DIR,
) -> tuple[list[PromotionRecord], list[DeclinedCase]]:
    raw = json.loads((directory / PROMOTIONS).read_text(encoding="utf-8"))
    records = [PromotionRecord.model_validate(item) for item in raw["records"]]
    declined = [DeclinedCase.model_validate(item) for item in raw["declined"]]
    return records, declined


def build_subset(
    directory: Path = SUBSET_DIR,
) -> tuple[list[Phase1Scenario], PromotionReport, GroundTruth]:
    """Promote the subset from its candidates and records. Pure: reads, never writes."""
    records, declined = load_promotions(directory)
    promoted, report = promote_subset(load_candidates(directory), records, declined)
    return promoted, report, ground_truth(records, promoted)


def _ordered(model: StrictModel) -> Any:
    """A json-mode dump with set-derived arrays sorted, so the bytes never follow hash order."""
    return order_sets(
        model.model_dump(mode="python", exclude_none=True),
        model.model_dump(mode="json", exclude_none=True),
    )


def subset_files(directory: Path = SUBSET_DIR) -> tuple[dict[str, str], PromotionReport]:
    """Every generated file of the subset, by name, exactly as it must be committed."""
    promoted, report, truth = build_subset(directory)
    files = {
        f"{scenario.scenario_id}.yaml": yaml.safe_dump(
            _ordered(scenario), sort_keys=False, allow_unicode=True
        )
        for scenario in promoted
    }
    files[GROUND_TRUTH] = json.dumps(_ordered(truth), indent=2) + "\n"
    files[PROMOTION_REPORT] = json.dumps(_ordered(report), indent=2) + "\n"
    return files, report


def subset_drift(directory: Path = SUBSET_DIR) -> list[str]:
    """Committed files that disagree with what the records promote. Empty when in step."""
    files, _ = subset_files(directory)
    drift = [
        name
        for name, text in sorted(files.items())
        if not (directory / name).exists() or (directory / name).read_text(encoding="utf-8") != text
    ]
    drift.extend(path.name for path in scenario_paths(directory) if path.name not in files)
    return drift


def write_subset(directory: Path = SUBSET_DIR) -> PromotionReport:
    """Materialize the promoted scenarios, their labels, and the promotion counts."""
    files, report = subset_files(directory)
    for stale in scenario_paths(directory):
        stale.unlink()
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    return report


def committed_subset(directory: Path = SUBSET_DIR) -> list[Phase1Scenario]:
    return [load_scenario(path) for path in scenario_paths(directory)]


# --- running ------------------------------------------------------------------------------------


async def run_subset(
    root: Path,
    scenarios: Sequence[Phase1Scenario],
    *,
    model: Provider | None = None,
    seed: int = 42,
) -> list[RunSummary]:
    """Each promoted scenario as one paired run on the benchmark lane, offline.

    ``model`` defaults to the scripted stand-in. The manifest is the agent lane's offline
    manifest, which authorizes no model endpoint at all. ``root`` is sealed as one verified
    suite bundle, the way ``agent-demo`` seals the authored corpus, with its own ``suite.json``
    naming this lane, so it can never be read as part of the authored corpus's bundle.
    """
    key = Ed25519PrivateKey.generate()
    manifest = supportlab_agent_manifest(key, seed=seed)
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    verifier.verify(manifest)
    summaries: list[RunSummary] = []
    for scenario in scenarios:
        tokens = actor_credentials()
        control = actor_credentials()["customer-a"]
        directory = root / scenario.scenario_id
        runner = build_supportlab_runner(
            directory,
            manifest,
            verifier,
            actor_tokens=tokens,
            control=control,
            fixture=InProcessSupportlab(tokens, control),
            lane=BENCHMARK_LANE,
            model_provider=model if model is not None else ScriptedAgentModel(),
        )
        # Through the Inspect bridge like every other lane, which seals each scenario bundle.
        summaries.append(
            await evaluate_runner(
                runner,
                scenario,
                manifest,
                run_id=scenario.scenario_id,
                output_dir=directory,
                model_fixture=MODEL_FIXTURE,
            )
        )
    reports(root, summaries)
    (root / "authorization-public.pem").write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    write_json(
        root / "suite.json",
        {
            "schema_version": "1.4.0",
            "lane": BENCHMARK_LANE.name,
            "subset": SUBSET_DIR.name,
            "model_provider": "offline-scripted",
            "stand_in": type(model).__name__ if model is not None else "ScriptedAgentModel",
            "scenarios": [scenario.scenario_id for scenario in scenarios],
        },
    )
    inventory(root, complete=True)
    verify_bundle(root)
    return summaries


# --- reporting ----------------------------------------------------------------------------------


class BenchmarkMetrics(StrictModel):
    """The subset's numbers, reported beside -- never inside -- the authored corpus's.

    ``origin_counts`` and ``possibly_contaminated`` are derived from the scenarios themselves, so
    an imported case cannot be counted as authored or lose its contamination label.
    """

    schema_version: str = "1.0.0"
    subset: str
    stand_in: str
    attempted: int = Field(ge=0)
    promoted: int = Field(ge=0)
    not_promoted: int = Field(ge=0)
    origin_counts: dict[str, int]
    possibly_contaminated: tuple[str, ...]
    statuses: dict[str, str]
    corpus: dict[str, Any]
    utility_under_attack: dict[str, str | None]
    defense_credited: tuple[str, ...]
    #: The stand-in the ground-truth labels were written against. Under any other stand-in a
    #: defended-replay finding in ``corpus`` is an uncredited defense, not an oracle error.
    labels_authored_against: str = "scripted"
    note: str


def benchmark_metrics(
    *,
    subset: str,
    stand_in: str,
    report: PromotionReport,
    truth: GroundTruth,
    scenarios: Sequence[Phase1Scenario],
    summaries: Sequence[RunSummary],
) -> BenchmarkMetrics:
    by_id = {scenario.scenario_id: scenario for scenario in scenarios}
    if {summary.scenario_id for summary in summaries} - by_id.keys():
        raise ValueError("a run names a scenario outside the subset")
    origins: dict[str, int] = {"authored": 0, "imported": 0}
    for scenario in scenarios:
        if scenario.origin is None or scenario.public_exposure is None:
            raise ValueError(f"{scenario.scenario_id}: a benchmark case must state its origin")
        origins[scenario.origin] += 1
    return BenchmarkMetrics(
        subset=subset,
        stand_in=stand_in,
        attempted=report.attempted,
        promoted=report.promoted,
        not_promoted=report.not_promoted,
        origin_counts=origins,
        possibly_contaminated=tuple(sorted(s.scenario_id for s in scenarios if s.public_exposure)),
        statuses={summary.scenario_id: summary.status for summary in summaries},
        corpus=corpus_metrics(truth, summaries),
        utility_under_attack={
            summary.scenario_id: (
                summary.baseline.utility_under_attack.verdict
                if summary.baseline is not None
                and summary.baseline.utility_under_attack is not None
                else None
            )
            for summary in summaries
        },
        defense_credited=tuple(
            sorted(summary.scenario_id for summary in summaries if summary.mitigation_effective)
        ),
        note=(
            "Benchmark subset, reported separately from the 48 authored scenarios. Authored "
            "here in AgentDojo's task structure; no upstream case text. Deterministic stand-in "
            "only: a measurement of the harness and the fixture's defenses, not of any model."
        ),
    )
