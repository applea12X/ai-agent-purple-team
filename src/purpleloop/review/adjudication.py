"""The one write path: a signed :class:`AdjudicationRecord`, stored beside its bundle.

Both ``purpleloop adjudicate`` and the review UI call :func:`write_adjudication`. It refuses, in
order, with a reason code:

- ``SOURCE_NOT_VERIFIED`` / ``SOURCE_NOT_ADJUDICABLE`` -- the evidence did not verify, or the
  source cannot name its findings unambiguously;
- ``UNKNOWN_FINDING`` -- the finding is not an accepted finding of this source;
- ``CITATION_NOT_IN_FINDING`` -- a cited evidence id is not one of the finding's own;
- ``REVIEWER_KEY_NOT_SEPARATE`` -- the reviewer key id, or the key itself, is one the harness
  signs or attests with under this bundle (a harness key labelling its own output is not
  human review);
- ``RECORDS_INSIDE_BUNDLE`` -- the records directory is inside a bundle (it would also break
  ``verify-bundle``, whose inventory must equal the directory).

Records are written with exclusive create, so a record is never overwritten. The file name
carries the record digest, so two labels of one finding sit side by side; which counts is the
precision report's rule, not the file system's.

**Blinding** is tracked by :class:`BlindingState`: a finding is blinded until its oracle verdict
has been shown to this reviewer -- by an explicit unblind, or because the reviewer already
labelled it (in this session, or in an earlier one whose records are in the records directory).
``blinded`` in a record is that state at the moment the label was chosen, set by this code, not
by the caller's say-so, except for the labels-file mode, where the tool cannot observe what the
reviewer saw and the file must state it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from pydantic import ValidationError

from purpleloop.control.phase5_signing import sign_record, verify_adjudication
from purpleloop.review.sources import ReviewFinding, ReviewSource
from purpleloop.schemas.phase5 import AdjudicationLabel, AdjudicationRecord

RECORDS_SUFFIX = ".adjudications"
LABELS: tuple[AdjudicationLabel, ...] = ("true-positive", "false-positive", "cannot-tell")


class AdjudicationError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True)
class ReviewerKey:
    key_id: str
    private_key: Ed25519PrivateKey

    @property
    def raw_public(self) -> bytes:
        return self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def load_reviewer_key(path: Path, key_id: str) -> ReviewerKey:
    loaded = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise AdjudicationError("INVALID_REVIEWER_KEY", "the reviewer key must be Ed25519")
    return ReviewerKey(key_id=key_id, private_key=loaded)


def generate_reviewer_key(private_path: Path, public_path: Path) -> None:
    """Write a new Ed25519 reviewer key pair; the private key file is created mode 0600."""
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_bytes)
    public_path.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )


def default_records_dir(source: ReviewSource) -> Path:
    """``<bundle>.adjudications/`` next to the bundle directory or the export file."""
    return source.path.parent / f"{source.path.name}{RECORDS_SUFFIX}"


def _inside_a_bundle(directory: Path) -> Path | None:
    resolved = directory.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / "inventory.json").is_file():
            return candidate
    return None


def check_records_dir(records_dir: Path, source: ReviewSource) -> Path:
    resolved = records_dir.resolve()
    if source.path.is_dir() and resolved.is_relative_to(source.path.resolve()):
        raise AdjudicationError(
            "RECORDS_INSIDE_BUNDLE", "adjudication records are stored beside a bundle, never in it"
        )
    enclosing = _inside_a_bundle(records_dir)
    if enclosing is not None:
        raise AdjudicationError(
            "RECORDS_INSIDE_BUNDLE", f"the records directory is inside the bundle {enclosing}"
        )
    return resolved


def separation_violations(key: ReviewerKey, source: ReviewSource) -> tuple[str, ...]:
    violations: list[str] = []
    if key.key_id in source.harness_key_ids:
        violations.append(f"key id {key.key_id!r} signs or attests under this bundle")
    if key.raw_public in source.harness_public_keys:
        violations.append("the key is this bundle's authorization or attestation key")
    return tuple(violations)


def require_adjudicable(source: ReviewSource) -> None:
    if not source.verified:
        raise AdjudicationError("SOURCE_NOT_VERIFIED", source.verification)
    if source.adjudication_blocked is not None:
        raise AdjudicationError("SOURCE_NOT_ADJUDICABLE", source.adjudication_blocked)


def write_adjudication(  # noqa: PLR0913 -- every field of the record is an explicit input
    source: ReviewSource,
    finding_key: str,
    *,
    label: str,
    rationale: str,
    cited_evidence_ids: tuple[str, ...],
    blinded: bool,
    key: ReviewerKey,
    records_dir: Path,
    now: datetime | None = None,
) -> tuple[AdjudicationRecord, Path]:
    """Sign one label and write it beside the bundle. Returns the record and where it went."""
    require_adjudicable(source)
    try:
        finding = source.finding(finding_key)
    except ValueError as exc:
        raise AdjudicationError("UNKNOWN_FINDING", str(exc)) from None
    if label not in LABELS:
        raise AdjudicationError("INVALID_LABEL", f"label must be one of {', '.join(LABELS)}")
    stray = [ref for ref in cited_evidence_ids if ref not in finding.evidence_ids]
    if stray:
        raise AdjudicationError(
            "CITATION_NOT_IN_FINDING",
            f"{len(stray)} cited id(s) are not evidence of this finding",
        )
    violations = separation_violations(key, source)
    if violations:
        raise AdjudicationError("REVIEWER_KEY_NOT_SEPARATE", "; ".join(violations))
    directory = check_records_dir(records_dir, source)
    try:
        unsigned = AdjudicationRecord(
            signature="",
            finding_id=finding.key,
            bundle_digest=source.bundle_digest,
            label=label,  # checked against LABELS above
            rationale=rationale,
            cited_evidence_ids=tuple(dict.fromkeys(cited_evidence_ids)),
            blinded=blinded,
            reviewer_key_id=key.key_id,
            recorded_at=(now or datetime.now(UTC)).astimezone(UTC),
        )
    except ValidationError as exc:
        first = exc.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        raise AdjudicationError(
            "INVALID_RECORD", f"{location or 'record'}: {first.get('msg', 'invalid')}"
        ) from None
    record = sign_record(unsigned, key.private_key)
    verify_adjudication(
        record, {key.key_id: key.private_key.public_key()}, bundle_digest=source.bundle_digest
    )
    directory.mkdir(parents=True, exist_ok=True)
    stem = finding.key.replace(":", "__")
    target = directory / f"{stem}.{record.record_digest()[:16]}.json"
    with target.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(record.model_dump(mode="json"), sort_keys=True, indent=2) + "\n")
    return record, target


def read_records(directory: Path) -> list[tuple[Path, AdjudicationRecord | None, str | None]]:
    """Every ``*.json`` under ``directory``: parsed, or ``None`` with why it did not parse."""
    results: list[tuple[Path, AdjudicationRecord | None, str | None]] = []
    paths = sorted(directory.rglob("*.json")) if directory.is_dir() else [directory]
    for path in paths:
        try:
            results.append((path, AdjudicationRecord.model_validate_json(path.read_bytes()), None))
        except (OSError, ValidationError) as exc:
            results.append((path, None, str(exc).splitlines()[0]))
    return results


@dataclass
class BlindingState:
    """Which findings' oracle verdicts this reviewer has already seen."""

    unblinded: set[str] = field(default_factory=set)
    labelled: set[str] = field(default_factory=set)

    def is_blinded(self, finding: ReviewFinding) -> bool:
        return finding.key not in self.unblinded and finding.key not in self.labelled

    def unblind(self, finding: ReviewFinding) -> None:
        self.unblinded.add(finding.key)

    def record(self, finding: ReviewFinding) -> None:
        self.labelled.add(finding.key)

    @classmethod
    def from_records(cls, records_dir: Path, source: ReviewSource, key_id: str) -> BlindingState:
        """A returning reviewer has seen the verdicts of what they already labelled."""
        state = cls()
        if records_dir.is_dir():
            for _, record, _ in read_records(records_dir):
                if (
                    record is not None
                    and record.bundle_digest == source.bundle_digest
                    and record.reviewer_key_id == key_id
                ):
                    state.labelled.add(record.finding_id)
        return state
