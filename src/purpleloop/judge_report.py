"""``judge-report`` against a real pinned judge: the frozen 24-case corpus, n trials, order swaps.

The scripted ``judge-report`` measures the harness's evaluator hardening. This one measures a
model, so it reports what Phase 3 reported -- resistance, its negative control, Krippendorff's
alpha with its bootstrap interval and n, kappa with its own n, order-swap consistency -- per trial,
plus a pooled figure that says plainly its n counts case-trials rather than independent cases.

The corpus is refused unless its digest is the frozen one: agreement against labels nobody
adjudicated would be a number about nothing. The judge's endpoint is a signed model asset in an
ephemeral manifest written beside the report, checked before every call, and its tokens and cost
are charged against one signed budget for the whole report. Every result remains advisory: the
report exits zero when it completes, whatever the judge said, because no judge output may move a
gate (ADR 0009/0010). Critical false passes are still named, never averaged in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.adapters.model_provider import ModelClient, OpenAICompatibleProvider
from purpleloop.adapters.networked_judge import (
    JUDGE_PIN_ID,
    JUDGE_SYSTEM_PROMPT_HASH,
    ModelPlaneGuard,
    NetworkedJudgeModel,
)
from purpleloop.control.budgets import BudgetLedger
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.model_config import JUDGE_ENV, ModelSettings, build_pin, with_seed
from purpleloop.reporting.bundle import write_json
from purpleloop.runtime.supportlab import KEY_ID, supportlab_agent_manifest
from purpleloop.schemas.phase3 import ModelPin
from purpleloop.scoring.evaluator_redteam import (
    RedTeamCorpus,
    Trial,
    pooled_agreement,
    require_frozen,
    resistance_from,
    run_trial,
    trial_agreement,
)
from purpleloop.scoring.judge import HybridJudge

JUDGE_CREDENTIAL_ENV = "PURPLELOOP_JUDGE_API_KEY"
DEFAULT_JUDGE_TOKEN_BUDGET = 2_000_000
DEFAULT_JUDGE_TIMEOUT_SECONDS = 120.0


class JudgeUnavailable(RuntimeError):
    """Same reason code as the agent lane's skip: a hosted judge without a credential."""

    reason_code = "STOCHASTIC_LANE_UNAVAILABLE"


@dataclass(frozen=True)
class JudgeRunConfig:
    endpoint: str
    profile: str
    settings: ModelSettings
    trials: int = 1
    negative_control: bool = True
    timeout_seconds: float = DEFAULT_JUDGE_TIMEOUT_SECONDS
    token_budget: int = DEFAULT_JUDGE_TOKEN_BUDGET
    cost_microusd_budget: int = 1_000_000


def judge_pin(config: JudgeRunConfig) -> ModelPin:
    return build_pin(
        pin_id=JUDGE_PIN_ID,
        profile=config.profile,
        system_prompt_hash=JUDGE_SYSTEM_PROMPT_HASH,
        settings=config.settings,
        names=JUDGE_ENV,
    )


def trial_pin(pin: ModelPin, trial: int) -> ModelPin:
    """Trial *t* runs under seed ``seed + t``, so repeated trials can differ under sampling."""
    if pin.decoding.seed is None or trial == 0:
        return pin
    return with_seed(pin, pin.decoding.seed + trial)


def _trial_payload(
    corpus: RedTeamCorpus, index: int, pin: ModelPin, trial: Trial
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "trial": index,
        "seed": pin.decoding.seed,
        "hardened": resistance_from(corpus, trial.verdicts).model_dump(mode="json"),
        "agreement": trial_agreement(corpus, trial).model_dump(mode="json"),
        "verdicts": list(trial.verdicts),
        "swapped_verdicts": list(trial.swapped),
    }
    if trial.undelimited is not None:
        payload["negative_control_without_delimiting"] = resistance_from(
            corpus, trial.undelimited
        ).model_dump(mode="json")
    return payload


def run_networked_judge_report(
    corpus: RedTeamCorpus, config: JudgeRunConfig, output_dir: Path
) -> dict[str, Any]:
    """Run the report and write it. Raises on refusal; on a mid-run failure, writes what ran.

    The payload is written before any exception propagates, so a run stopped by its budget or by
    the endpoint still leaves its completed trials, its call records, and the reason it stopped.
    """
    require_frozen(corpus)
    if config.trials < 1:
        raise ValueError("at least one trial is required")
    credential = os.environ.get(JUDGE_CREDENTIAL_ENV)
    if config.profile == "openai-compatible" and not credential:
        raise JudgeUnavailable(
            f"{JUDGE_CREDENTIAL_ENV} is not set; the networked judge is skipped, not downgraded"
        )
    base = judge_pin(config)
    provider = OpenAICompatibleProvider(
        base_url=config.endpoint,
        credential=credential,
        profile=config.profile,  # type: ignore[arg-type]
    )
    key = Ed25519PrivateKey.generate()
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    manifests_dir = output_dir / "manifests"
    manifests_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "authorization-public.pem").write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    ledger: BudgetLedger | None = None
    model: NetworkedJudgeModel | None = None
    trials: list[Trial] = []
    trial_payloads: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    manifest_digests: list[str] = []
    payload: dict[str, Any] = {
        "schema_version": "1.3.0",
        "provenance": "advisory",
        "note": (
            "Measured against a real pinned judge model. Advisory by construction: no figure here "
            "can move a gate. Per-trial agreement is the figure to quote; the pooled figure's n "
            "counts case-trials, which are not independent, so its interval is too narrow."
        ),
        "corpus_digest": corpus.digest,
        "corpus_digest_frozen": True,
        "judge_pin": base.model_dump(mode="json"),
        "trials_requested": config.trials,
        "negative_control": config.negative_control,
        "timeout_seconds": config.timeout_seconds,
    }
    error: Exception | None = None
    try:
        for index in range(config.trials):
            pin = trial_pin(base, index)
            manifest = supportlab_agent_manifest(
                key,
                model_endpoint=provider.endpoint,
                judge=True,
                judge_pin=pin,
                token_budget=config.token_budget,
                cost_microusd_budget=config.cost_microusd_budget,
            )
            verifier.verify(manifest)
            assert manifest.phase3 is not None
            write_json(manifests_dir / f"trial-{index}.json", manifest.model_dump(mode="json"))
            manifest_digests.append(manifest.manifest_digest())
            # One ledger for the whole report, so the signed cap bounds every trial together.
            ledger = ledger or BudgetLedger(manifest.budgets)
            client = ModelClient(
                pins=manifest.phase3.model_pins,
                providers={pin.provider: provider},
                budgets=ledger,
                timeout=config.timeout_seconds,
            )
            guard = ModelPlaneGuard(manifest, verifier)
            if model is None:
                model = NetworkedJudgeModel(client=client, pin_id=pin.pin_id, guard=guard)
            else:
                model.use(client=client, guard=guard)
            try:
                trial = run_trial_with(model, corpus, config)
            finally:
                records.extend(record.model_dump(mode="json") for record in client.records)
                decisions.extend(guard.decisions)
            trials.append(trial)
            trial_payloads.append(_trial_payload(corpus, index, pin, trial))
    except Exception as exc:  # noqa: BLE001 -- recorded in the report, then re-raised
        error = exc
    finally:
        if model is not None:
            model.close()
        payload["trials"] = trial_payloads
        payload["trials_completed"] = len(trials)
        if trials:
            first = trial_payloads[0]
            # The same top-level keys the scripted report writes, from the first trial.
            payload["hardened"] = first["hardened"]
            payload["agreement"] = first["agreement"]
            if "negative_control_without_delimiting" in first:
                payload["negative_control_without_delimiting"] = first[
                    "negative_control_without_delimiting"
                ]
            payload["pooled_agreement"] = pooled_agreement(corpus, trials).model_dump(mode="json")
        payload["model_calls"] = {
            "calls": len(records),
            "tokens": sum(int(r["input_tokens"]) + int(r["output_tokens"]) for r in records),
            "cost_microusd": sum(int(r["cost_microusd"]) for r in records),
            "records": records,
        }
        payload["authorization"] = {
            "permitted": sum(d["decision"] == "permit" for d in decisions),
            "denied": sum(d["decision"] != "permit" for d in decisions),
            "origins": sorted({d["origin"] for d in decisions}),
            "manifest_digests": manifest_digests,
        }
        payload["thinking"] = {
            "stripped": len(model.thinking) if model is not None else 0,
            "unparseable_replies": model.unparseable if model is not None else 0,
            "notes": list(model.thinking) if model is not None else [],
        }
        if error is not None:
            payload["stopped"] = {
                "reason_code": str(getattr(error, "reason_code", "") or type(error).__name__),
                "detail": str(error)[:2000],
            }
        write_json(output_dir / "evaluator-redteam.json", payload)
    if error is not None:
        raise error
    return payload


def run_trial_with(
    model: NetworkedJudgeModel, corpus: RedTeamCorpus, config: JudgeRunConfig
) -> Trial:
    return run_trial(
        HybridJudge(model, trials=config.trials), corpus, negative_control=config.negative_control
    )
