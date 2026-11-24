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


#: The adjudicated corpus as frozen in Phase 3. ``tests/phase3/test_judge.py`` pins the same value;
#: it is repeated here so a networked judge run refuses a corpus that is not the frozen one,
#: rather than reporting agreement against labels nobody adjudicated.
FROZEN_CORPUS_DIGEST = "9bcf0a2f6b84cf9bfcdecbb78c1ec4616fd012693f6d8573c5d65d8a513f697b"


class CorpusDigestMismatch(ValueError):
    reason_code = "EVALUATOR_CORPUS_CHANGED"


def require_frozen(corpus: RedTeamCorpus) -> RedTeamCorpus:
    if corpus.digest != FROZEN_CORPUS_DIGEST:
        raise CorpusDigestMismatch(
            f"evaluator red-team corpus digest is {corpus.digest}, not the frozen "
            f"{FROZEN_CORPUS_DIGEST}; agreement is only reported against the adjudicated labels"
        )
    return corpus


def _verdict(judge: HybridJudge, case: RedTeamCase, *, swapped: bool, delimit: bool) -> str:
    result = judge.judge(
        rubric_id=case.rubric_id, items=case.items, swapped=swapped, delimit=delimit
    )
    return result.verdict if result is not None else "abstain"


def resistance_from(corpus: RedTeamCorpus, verdicts: Sequence[str]) -> EvaluatorRedTeamResult:
    """Resistance from one verdict per case, in corpus order."""
    resisted = 0
    critical: list[str] = []
    for case, verdict in zip(corpus.cases, verdicts, strict=True):
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


def resistance(
    judge: HybridJudge, corpus: RedTeamCorpus, *, delimit: bool = True
) -> EvaluatorRedTeamResult:
    """Resisted means the judge's verdict equals the adjudicated label.

    A critical false pass is a case adjudicated ``true`` that the judge called ``false`` -- the
    evaluator was talked out of a real finding. Those are named, never folded into the rate.
    """
    verdicts = [_verdict(judge, case, swapped=False, delimit=delimit) for case in corpus.cases]
    return resistance_from(corpus, verdicts)


def agreement_from(
    labels: Sequence[str], verdicts: Sequence[str], swapped: Sequence[str], *, digest: str
) -> JudgeAgreement:
    """Agreement and order-swap consistency from aligned labels and verdicts, with their n."""
    pairs: list[tuple[str, str]] = list(zip(labels, verdicts, strict=True))
    swaps: list[tuple[str, str]] = list(zip(verdicts, swapped, strict=True))
    abstentions = sum(verdict == "abstain" for verdict in verdicts)
    alpha = krippendorff_alpha(pairs)
    low, high = bootstrap_interval(pairs)
    substantive: Sequence[tuple[str, str]] = [pair for pair in pairs if "abstain" not in pair]
    kappa, kappa_n = cohen_kappa(substantive)
    consistency, trials = order_swap_consistency(swaps)
    return JudgeAgreement(
        label_set_digest=digest,
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


def agreement(judge: HybridJudge, corpus: RedTeamCorpus) -> JudgeAgreement:
    """Agreement with the adjudicated labels, plus order-swap consistency, both with their n."""
    verdicts: list[str] = []
    swapped: list[str] = []
    for case in corpus.cases:
        verdicts.append(_verdict(judge, case, swapped=False, delimit=True))
        swapped.append(_verdict(judge, case, swapped=True, delimit=True))
    return agreement_from(
        [case.label for case in corpus.cases], verdicts, swapped, digest=corpus.digest
    )


@dataclass(frozen=True)
class Trial:
    """One pass over the corpus: delimited, order-swapped, and (optionally) undelimited."""

    verdicts: tuple[str, ...]
    swapped: tuple[str, ...]
    undelimited: tuple[str, ...] | None


def run_trial(judge: HybridJudge, corpus: RedTeamCorpus, *, negative_control: bool) -> Trial:
    """Three judge calls per case at most, and the delimited one is shared by both metrics.

    ``resistance`` and ``agreement`` each make the same delimited, unswapped call; for a real
    model that is a duplicate paid call, so a trial makes it once and derives both from it.
    For a deterministic judge the figures are identical to calling the two functions.
    """
    verdicts: list[str] = []
    swapped: list[str] = []
    undelimited: list[str] = []
    for case in corpus.cases:
        verdicts.append(_verdict(judge, case, swapped=False, delimit=True))
        swapped.append(_verdict(judge, case, swapped=True, delimit=True))
        if negative_control:
            undelimited.append(_verdict(judge, case, swapped=False, delimit=False))
    return Trial(
        verdicts=tuple(verdicts),
        swapped=tuple(swapped),
        undelimited=tuple(undelimited) if negative_control else None,
    )


def trial_agreement(corpus: RedTeamCorpus, trial: Trial) -> JudgeAgreement:
    return agreement_from(
        [case.label for case in corpus.cases], trial.verdicts, trial.swapped, digest=corpus.digest
    )


def pooled_agreement(corpus: RedTeamCorpus, trials: Sequence[Trial]) -> JudgeAgreement:
    """Agreement over every (case, trial) unit. Its n counts case-trials, not independent cases.

    Repeated trials of the same 24 cases are not 24 x k independent items, so the bootstrap
    interval over the pooled units is narrower than the evidence supports; the per-trial figures
    are the ones to quote, and this one is reported beside them, labelled.
    """
    labels = [case.label for _ in trials for case in corpus.cases]
    verdicts = [verdict for trial in trials for verdict in trial.verdicts]
    swapped = [verdict for trial in trials for verdict in trial.swapped]
    return agreement_from(labels, verdicts, swapped, digest=corpus.digest)
