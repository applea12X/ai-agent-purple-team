"""Compute a pin's token calibration from a measured run, and check a run against it.

Both directions read the same thing: the ``MODEL_CALLED`` records in verified evidence. Nothing
here estimates; the calibration is a mean over calls that actually happened, and the check
reports the delta between that held-fixed expectation and a later run's actual use with the
existing ``token_accounting`` +/-10% machinery -- whether it passes or misses.

Inputs are refused rather than coerced: an unverifiable bundle, records from more than one pin
identity, or calls that reported no token usage each stop the computation with a reason, because
a calibration silently averaged over the wrong calls would be held fixed for the rest of the
project.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from purpleloop.reporting.bundle import BundleError, verify_bundle
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.model_calibration import PinCalibration
from purpleloop.schemas.phase3 import ModelCallRecord, ModelPin, TokenAccounting
from purpleloop.scoring.phase3 import estimate_is_a_bound, estimate_tokens, token_accounting


class CalibrationError(ValueError):
    reason_code = "MODEL_CALIBRATION_REFUSED"


@dataclass(frozen=True)
class MeasuredCalls:
    """The model calls read from a set of verified bundles."""

    records: tuple[ModelCallRecord, ...]
    bundles: tuple[Path, ...]
    evidence_digests: tuple[str, ...]
    pins: tuple[ModelPin, ...]


def bundle_directories(root: Path) -> tuple[Path, ...]:
    """Every run bundle under ``root`` (a single bundle, a suite, or a directory of runs)."""
    if (root / "evidence.jsonl").is_file():
        return (root,)
    return tuple(sorted(path.parent for path in root.rglob("evidence.jsonl")))


def read_calls(root: Path, *, pin_id: str | None = None) -> MeasuredCalls:
    """Read and verify every bundle under ``root``, and collect its model call records."""
    directories = bundle_directories(root)
    if not directories:
        raise CalibrationError(f"no run bundle found under {root}")
    records: list[ModelCallRecord] = []
    digests: list[str] = []
    pins: dict[str, ModelPin] = {}
    for directory in directories:
        try:
            # A partial inventory is still a verified one: every file listed is checked.
            verify_bundle(directory, allow_partial=True)
        except (BundleError, OSError, ValueError) as exc:
            raise CalibrationError(f"{directory.name}: bundle does not verify: {exc}") from exc
        evidence = (directory / "evidence.jsonl").read_bytes()
        digests.append(hashlib.sha256(evidence).hexdigest())
        manifest = AuthorizationManifest.model_validate_json(
            (directory / "manifest.json").read_text(encoding="utf-8")
        )
        if manifest.phase3 is not None:
            for pin in manifest.phase3.model_pins:
                pins.setdefault(pin.pin_id, pin)
        for line in evidence.decode("utf-8").splitlines():
            event = json.loads(line)
            if event.get("kind") != "model" or event.get("reason_code") != "MODEL_CALLED":
                continue
            record = ModelCallRecord.model_validate(event["data"]["call"])
            if pin_id is None or record.pin_id == pin_id:
                records.append(record)
    return MeasuredCalls(
        records=tuple(records),
        bundles=directories,
        evidence_digests=tuple(sorted(digests)),
        pins=tuple(pins[key] for key in sorted(pins)),
    )


def _identity(record: ModelCallRecord) -> tuple[str, str, str | None, str]:
    return (record.provider, record.model_id, record.model_version, record.system_prompt_hash)


def _mean_half_up(values: Sequence[int]) -> int:
    return (2 * sum(values) + len(values)) // (2 * len(values))


def compute_calibration(measured: MeasuredCalls, *, min_calls: int = 1) -> PinCalibration:
    """The mean per-call tokens over ``measured``, with its n, ranges, and sources."""
    records = measured.records
    if len(records) < max(min_calls, 1):
        raise CalibrationError(
            f"{len(records)} model call(s) measured; at least {max(min_calls, 1)} required"
        )
    identities = sorted({_identity(record) for record in records}, key=str)
    if len(identities) != 1:
        raise CalibrationError(
            f"records come from {len(identities)} pin identities; calibrate one pin at a time "
            "(use --pin-id)"
        )
    inputs = [record.input_tokens for record in records]
    outputs = [record.output_tokens for record in records]
    if not any(inputs) or not any(outputs):
        # A provider that reports no usage would calibrate to zero, which the estimator reads
        # as "uncalibrated" -- better to refuse loudly than to commit a meaningless file.
        raise CalibrationError("the measured calls reported no token usage")
    provider, model_id, model_version, prompt_hash = identities[0]
    decodings = sorted(
        {record.decoding for record in records}, key=lambda decoding: decoding.model_dump_json()
    )
    return PinCalibration(
        provider=provider,  # type: ignore[arg-type]
        model_id=model_id,
        model_version=model_version,
        system_prompt_hash=prompt_hash,
        expected_input_tokens_per_call=_mean_half_up(inputs),
        expected_output_tokens_per_call=_mean_half_up(outputs),
        calls=len(records),
        input_tokens_min=min(inputs),
        input_tokens_max=max(inputs),
        output_tokens_min=min(outputs),
        output_tokens_max=max(outputs),
        decodings=tuple(decodings),
        bundles=len(measured.bundles),
        evidence_digests=measured.evidence_digests,
    )


@dataclass(frozen=True)
class CalibrationCheck:
    accounting: TokenAccounting
    calls: int
    estimate_is_bound: bool
    pin: ModelPin


def check_against(measured: MeasuredCalls, calibration: PinCalibration) -> CalibrationCheck:
    """A later run's actual tokens and cost against the held-fixed expectation.

    The price is the one the run's signed manifest carried for that pin, so the cost estimate
    uses exactly the figures the cap was enforced with.
    """
    records = [
        record
        for record in measured.records
        if _identity(record)
        == (
            calibration.provider,
            calibration.model_id,
            calibration.model_version,
            calibration.system_prompt_hash,
        )
    ]
    if not records:
        raise CalibrationError("no measured call matches the calibration's pin identity")
    signed = {pin.pin_id: pin for pin in measured.pins}
    pin_ids = sorted({record.pin_id for record in records})
    try:
        base = signed[pin_ids[0]]
    except KeyError as exc:
        raise CalibrationError(f"pin {pin_ids[0]} is not in the run's signed manifest") from exc
    pin = base.model_copy(
        update={
            "expected_input_tokens_per_call": calibration.expected_input_tokens_per_call,
            "expected_output_tokens_per_call": calibration.expected_output_tokens_per_call,
        }
    )
    estimated_tokens, estimated_cost = estimate_tokens(pin, model_calls=len(records))
    actual_tokens = sum(record.input_tokens + record.output_tokens for record in records)
    actual_cost = sum(record.cost_microusd for record in records)
    return CalibrationCheck(
        accounting=token_accounting(
            estimated_tokens=estimated_tokens,
            actual_tokens=actual_tokens,
            estimated_cost=estimated_cost,
            actual_cost=actual_cost,
        ),
        calls=len(records),
        estimate_is_bound=estimate_is_a_bound(pin),
        pin=pin,
    )
