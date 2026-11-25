"""Precision on adjudicated findings: the 5.0.8 checkpoint figure, from signed records only.

A record is counted only if every check passes; otherwise it is listed as refused with a reason
code and contributes nothing:

- ``MALFORMED_RECORD`` -- not a valid ``AdjudicationRecord`` document;
- ``UNKNOWN_SIGNING_KEY`` / ``INVALID_SIGNATURE`` -- unsigned, tampered, or signed by a key the
  caller did not name as a trusted reviewer key (``verify_adjudication``);
- ``UNKNOWN_BUNDLE`` -- labels a bundle that was not supplied, so its finding cannot be checked;
- ``UNKNOWN_FINDING`` -- names no accepted finding of that bundle;
- ``CITATION_NOT_IN_FINDING`` -- cites evidence the finding does not carry;
- ``REVIEWER_KEY_NOT_SEPARATE`` -- the reviewer key id, or the trusted key's material, is a key
  that signs or attests under that bundle.

Per finding, the latest record from each reviewer key counts. If counted reviewers disagree
between true- and false-positive the finding is *disputed*: reported, and kept out of the
precision figure rather than resolved by vote. ``cannot-tell`` is reported and kept out of the
denominator. Precision is ``tp / (tp + fp)`` over findings, with a 95% Wilson interval.

The **method** is ``census`` only when every distinct accepted finding class in the supplied
bundles has a counted label; otherwise it is ``sample``, with the coverage stated. This is the
whole difference between "precision on the corpus" and "precision on what someone looked at".

The report is not a verdict and not a gate input: :class:`PrecisionReport` is a plain model,
not ``Scored``, and the gates refuse it by type.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from purpleloop.control.phase5_signing import SignedDocumentError, verify_adjudication
from purpleloop.review.sources import ReviewSource
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase5 import AdjudicationRecord
from purpleloop.scoring.phase3 import wilson_interval

THRESHOLD = 0.95


class RefusedRecord(StrictModel):
    path: str
    reason_code: str
    detail: str


class PrecisionReport(StrictModel):
    """The precision figure and everything needed to read it. Human-derived; never binding."""

    schema_version: Literal["1.0.0"] = "1.0.0"
    method: Literal["census", "sample"]
    bundles: tuple[str, ...]
    findings_in_population: int
    classes_in_population: int
    findings_labelled: int
    classes_covered: int
    uncovered_classes: tuple[str, ...]
    true_positives: int
    false_positives: int
    cannot_tell: int
    disputed: int
    n: int
    precision: float | None
    wilson_low: float | None
    wilson_high: float | None
    threshold: float = THRESHOLD
    point_meets_threshold: bool
    wilson_low_meets_threshold: bool
    records_counted: int
    records_refused: tuple[RefusedRecord, ...]
    reviewer_key_ids: tuple[str, ...]
    blinded_records: int
    unblinded_records: int


def _raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def precision_report(
    records: Iterable[tuple[Path, AdjudicationRecord | None, str | None]],
    sources: Iterable[ReviewSource],
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> PrecisionReport:
    by_digest: dict[str, ReviewSource] = {}
    for source in sources:
        if not source.verified:
            raise ValueError(f"source does not verify: {source.path}: {source.verification}")
        by_digest.setdefault(source.bundle_digest, source)
    population = {
        (digest, finding.key): finding.finding_class
        for digest, source in by_digest.items()
        for finding in source.findings
    }
    classes = set(population.values())

    refused: list[RefusedRecord] = []
    counted: list[AdjudicationRecord] = []

    def refuse(path: Path, code: str, detail: str) -> None:
        refused.append(RefusedRecord(path=str(path), reason_code=code, detail=detail))

    for path, record, problem in records:
        if record is None:
            refuse(path, "MALFORMED_RECORD", problem or "not an adjudication record")
            continue
        try:
            verify_adjudication(record, trusted_keys)
        except SignedDocumentError as exc:
            refuse(path, exc.reason_code, str(exc))
            continue
        labelled = by_digest.get(record.bundle_digest)
        if labelled is None:
            refuse(path, "UNKNOWN_BUNDLE", "the labelled bundle was not supplied")
            continue
        try:
            finding = labelled.finding(record.finding_id)
        except ValueError:
            refuse(path, "UNKNOWN_FINDING", f"{record.finding_id!r} is not an accepted finding")
            continue
        if any(ref not in finding.evidence_ids for ref in record.cited_evidence_ids):
            refuse(path, "CITATION_NOT_IN_FINDING", "cites evidence the finding does not carry")
            continue
        if (
            record.reviewer_key_id in labelled.harness_key_ids
            or _raw(trusted_keys[record.reviewer_key_id]) in labelled.harness_public_keys
        ):
            refuse(path, "REVIEWER_KEY_NOT_SEPARATE", "a harness key cannot adjudicate")
            continue
        counted.append(record)

    latest: dict[tuple[str, str, str], AdjudicationRecord] = {}
    for record in counted:
        slot = (record.bundle_digest, record.finding_id, record.reviewer_key_id)
        if slot not in latest or record.recorded_at >= latest[slot].recorded_at:
            latest[slot] = record
    labels: dict[tuple[str, str], set[str]] = {}
    for (digest, finding_id, _), record in latest.items():
        labels.setdefault((digest, finding_id), set()).add(record.label)

    tp = fp = cannot = disputed = 0
    for verdicts in labels.values():
        definite = verdicts - {"cannot-tell"}
        if definite == {"true-positive"}:
            tp += 1
        elif definite == {"false-positive"}:
            fp += 1
        elif not definite:
            cannot += 1
        else:
            disputed += 1
    covered = {population[slot] for slot in labels}
    n = tp + fp
    precision = round(tp / n, 6) if n else None
    low, high = wilson_interval(tp, n) if n else (None, None)
    return PrecisionReport(
        method="census" if classes and covered == classes else "sample",
        bundles=tuple(sorted(by_digest)),
        findings_in_population=len(population),
        classes_in_population=len(classes),
        findings_labelled=len(labels),
        classes_covered=len(covered),
        uncovered_classes=tuple(sorted(classes - covered)),
        true_positives=tp,
        false_positives=fp,
        cannot_tell=cannot,
        disputed=disputed,
        n=n,
        precision=precision,
        wilson_low=low,
        wilson_high=high,
        point_meets_threshold=precision is not None and precision >= THRESHOLD,
        wilson_low_meets_threshold=low is not None and low >= THRESHOLD,
        records_counted=len(latest),
        records_refused=tuple(refused),
        reviewer_key_ids=tuple(sorted({record.reviewer_key_id for record in latest.values()})),
        blinded_records=sum(record.blinded for record in latest.values()),
        unblinded_records=sum(not record.blinded for record in latest.values()),
    )
