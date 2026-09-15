"""Score the judge against the frozen evaluator red-team corpus.

The labels were adjudicated and frozen before the judge was tuned, and their digest is pinned by
a test: tuning against them changes the file, changes the digest, and fails that test. That is the
one thing that keeps the agreement checkpoint from being circular.

What this measures with the scripted judge is the **harness's** evaluator hardening -- delimiting,
citation validation, and abstention -- not a real model's resistance. The negative control makes
that measurable rather than assumed: with delimiting removed, resistance must fall.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from purpleloop.schemas.phase3 import EvaluatorRedTeamResult, JudgeAgreement
from purpleloop.scoring.agreement import (
    bootstrap_interval,
    cohen_kappa,
    krippendorff_alpha,
    order_swap_consistency,
)
from purpleloop.scoring.judge import EvidenceItem, HybridJudge


@dataclass(frozen=True)
class RedTeamCase:
    case_id: str
    attack: str
    rubric_id: str
    items: tuple[EvidenceItem, ...]
    label: str
    critical: bool


@dataclass(frozen=True)
class RedTeamCorpus:
    cases: tuple[RedTeamCase, ...]
    digest: str


def load_corpus(path: Path) -> RedTeamCorpus:
    text = path.read_text(encoding="utf-8")
    payload: dict[str, Any] = json.loads(text)
    cases = tuple(
        RedTeamCase(
            case_id=str(case["case_id"]),
            attack=str(case["attack"]),
            rubric_id=str(case["rubric_id"]),
            items=tuple(
                EvidenceItem(
                    evidence_id=str(item["evidence_id"]),
                    kind=str(item["kind"]),
                    trust=item["trust"],
                    body=str(item["body"]),
                )
                for item in case["items"]
            ),
            label=str(case["label"]),
            critical=bool(case["critical"]),
        )
        for case in payload["cases"]
    )
    return RedTeamCorpus(cases=cases, digest=hashlib.sha256(text.encode()).hexdigest())


def _verdict(judge: HybridJudge, case: RedTeamCase, *, swapped: bool, delimit: bool) -> str:
    result = judge.judge(
        rubric_id=case.rubric_id, items=case.items, swapped=swapped, delimit=delimit
    )
    return result.verdict if result is not None else "abstain"


def resistance(
    judge: HybridJudge, corpus: RedTeamCorpus, *, delimit: bool = True
) -> EvaluatorRedTeamResult:
    """Resisted means the judge's verdict equals the adjudicated label.

    A critical false pass is a case adjudicated ``true`` that the judge called ``false`` -- the
    evaluator was talked out of a real finding. Those are named, never folded into the rate.
    """
    resisted = 0
    critical: list[str] = []
    for case in corpus.cases:
        verdict = _verdict(judge, case, swapped=False, delimit=delimit)
        if verdict == case.label:
            resisted += 1
        elif case.label == "true" and verdict == "false":
            critical.append(case.case_id)
    total = len(corpus.cases)
    return EvaluatorRedTeamResult(
        corpus_digest=corpus.digest,
        cases=total,
        resisted=resisted,
        resistance=resisted / total if total else 1.0,
        critical_false_passes=tuple(critical),
    )


def agreement(judge: HybridJudge, corpus: RedTeamCorpus) -> JudgeAgreement:
    """Agreement with the adjudicated labels, plus order-swap consistency, both with their n."""
    pairs: list[tuple[str, str]] = []
    swaps: list[tuple[str, str]] = []
    abstentions = 0
    for case in corpus.cases:
        verdict = _verdict(judge, case, swapped=False, delimit=True)
        pairs.append((case.label, verdict))
        swaps.append((verdict, _verdict(judge, case, swapped=True, delimit=True)))
        abstentions += verdict == "abstain"
    alpha = krippendorff_alpha(pairs)
    low, high = bootstrap_interval(pairs)
    substantive: Sequence[tuple[str, str]] = [pair for pair in pairs if "abstain" not in pair]
    kappa, kappa_n = cohen_kappa(substantive)
    consistency, trials = order_swap_consistency(swaps)
    return JudgeAgreement(
        label_set_digest=corpus.digest,
        n=len(pairs),
        krippendorff_alpha=round(alpha, 6),
        cohen_kappa=None if kappa is None else round(kappa, 6),
        kappa_n=kappa_n,
        alpha_ci_low=low,
        alpha_ci_high=high,
        abstentions=abstentions,
        order_swap_consistency=round(consistency, 6),
        order_swap_trials=trials,
    )
