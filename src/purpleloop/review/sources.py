"""Read-only review sources: a run bundle, a suite bundle, or an audit export.

Loading verifies first. A bundle goes through :func:`reporting.bundle.verify_bundle`; an audit
export is checked for self-consistency (each embedded document against the SHA-256 recorded for
it, the manifest signature against the embedded key, the run's findings against the embedded
summary). A source that fails is still loaded for viewing where it parses, with
``verified=False`` and the reason, and :mod:`.adjudication` refuses to label it: a label on
evidence that does not verify is a label on nothing.

Nothing here opens a file for writing. ``bundle_digest`` is the SHA-256 of the bundle's
``inventory.json`` -- the attestation subject (ADR 0012) and the audit export's
``bundle_inventory_sha256`` -- so a finding has the same identity whether it is reviewed from the
bundle or from its export.

**Finding identity.** A record names a finding by ``finding_id`` within ``bundle_digest``. In a
suite run with repetitions the same scenario's finding id appears once per repetition, so there a
finding is named ``<run>:<finding_id>``. An audit export does not carry run directory names, so
an export with a repeated finding id is refused for adjudication; review it from the bundle.

**Finding class.** The census unit of the 5.0.8 checkpoint is the finding's ``scenario_id``:
each scenario has one seeded oracle, so a class is "this oracle firing on this scenario".

**What blinding hides.** :data:`VERDICT_KINDS` names the ledger event kinds that carry a verdict
(oracle, detector, judge). Those events, the oracle results in the summary, the run status and
reason, and the finding's own verdict-derived fields (:data:`VERDICT_FIELDS`) are the oracle's
verdict. Everything else -- the scenario, the oracle *specification*, the snapshots it read, and
the cited evidence events -- is what the reviewer judges from.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from purpleloop.reporting.attestation import ATTESTATION_FILE, ATTESTATION_KEY_FILE
from purpleloop.reporting.bundle import verify_bundle
from purpleloop.runtime.ledger import EvidenceLedger, LedgerError
from purpleloop.schemas.authorization import AuthorizationManifest

SourceKind = Literal["run-bundle", "suite-bundle", "audit-export", "ledger"]

#: Ledger event kinds whose content is a verdict. Hidden while a finding is blinded.
VERDICT_KINDS = frozenset({"oracle", "detector", "judge"})

#: Finding fields derived from the oracle's verdict. Hidden while a finding is blinded.
VERDICT_FIELDS = (
    "status",
    "observed_impact",
    "confidence",
    "severity",
    "severity_rationale",
    "reproducible",
    "reproducibility_basis",
    "provenance",
)

#: Summary fields that are, or reveal, the oracle's verdict.
SUMMARY_VERDICT_FIELDS = ("status", "reason", "baseline", "replay", "findings", "oracle_hash")


class SourceError(ValueError):
    pass


@dataclass(frozen=True)
class ReviewFinding:
    """One accepted finding, with what may be shown blinded and what may not."""

    key: str
    finding_id: str
    finding_class: str
    run_index: int
    evidence_ids: tuple[str, ...]
    #: Fields a reviewer may see before labelling (no verdict-derived field).
    shown: Mapping[str, Any]
    #: The oracle's verdict for this finding: the hidden finding fields and the oracle results.
    verdict: Mapping[str, Any]


@dataclass(frozen=True)
class ReviewRun:
    index: int
    name: str
    scenario_id: str
    summary: Mapping[str, Any]
    scenario: Mapping[str, Any] | None
    #: The full verified ledger for a bundle run; the decision records only, for an export.
    events: tuple[Mapping[str, Any], ...]
    events_complete: bool
    snapshots: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def event_by_id(self, evidence_id: str) -> int | None:
        for position, event in enumerate(self.events):
            if event.get("event_hash") == evidence_id:
                return position
        return None

    def decisions(self) -> list[Mapping[str, Any]]:
        decision_kinds = {"admission", "policy", "budget", "defense", "termination"}
        return [event for event in self.events if event.get("kind") in decision_kinds]


@dataclass(frozen=True)
class ReviewSource:
    path: Path
    kind: SourceKind
    bundle_digest: str
    verified: bool
    verification: str
    runs: tuple[ReviewRun, ...]
    #: Key ids that sign or attest under this source's manifests and attestation.
    harness_key_ids: frozenset[str]
    #: Raw Ed25519 public key bytes of those keys, where the source ships them.
    harness_public_keys: frozenset[bytes]
    findings: tuple[ReviewFinding, ...]
    #: Why findings cannot be adjudicated even though the source verified, if they cannot.
    adjudication_blocked: str | None = None

    def finding(self, key: str) -> ReviewFinding:
        for finding in self.findings:
            if finding.key == key:
                return finding
        raise SourceError(f"no accepted finding {key!r} in this source")

    @property
    def adjudicable(self) -> bool:
        return self.verified and self.adjudication_blocked is None

    def classes(self) -> frozenset[str]:
        return frozenset(finding.finding_class for finding in self.findings)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json_bytes(payload: Any) -> bytes:
    """The exact bytes ``reporting.bundle.write_json`` produces, to recheck embedded digests."""
    return (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def raw_public_key(pem: bytes) -> bytes | None:
    try:
        key = load_pem_public_key(pem)
    except ValueError:
        return None
    if not isinstance(key, Ed25519PublicKey):
        return None
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _manifest_key_ids(manifest: Mapping[str, Any]) -> set[str]:
    ids = {str(manifest["key_id"])} if "key_id" in manifest else set()
    phase4 = manifest.get("phase4") or {}
    ids.update(str(value) for value in phase4.get("attestation_key_ids", ()))
    return ids


def _findings(
    runs: tuple[ReviewRun, ...], *, qualify_duplicates: bool
) -> tuple[tuple[ReviewFinding, ...], str | None]:
    counts: dict[str, int] = {}
    for run in runs:
        for raw in run.summary.get("findings", ()):
            counts[str(raw.get("finding_id"))] = counts.get(str(raw.get("finding_id")), 0) + 1
    blocked = None
    if any(count > 1 for count in counts.values()) and not qualify_duplicates:
        blocked = (
            "this audit export repeats a finding id across runs and does not carry run names; "
            "adjudicate repetitions from the bundle"
        )
    findings: list[ReviewFinding] = []
    for run in runs:
        for raw in run.summary.get("findings", ()):
            finding_id = str(raw.get("finding_id"))
            key = finding_id if counts[finding_id] == 1 else f"{run.name}:{finding_id}"
            verdict: dict[str, Any] = {name: raw[name] for name in VERDICT_FIELDS if name in raw}
            for leg in ("baseline", "replay"):
                leg_result = run.summary.get(leg) or {}
                for oracle in ("security", "utility", "utility_under_attack"):
                    if leg_result.get(oracle) is not None:
                        verdict[f"{leg}.{oracle}"] = leg_result[oracle]
            findings.append(
                ReviewFinding(
                    key=key,
                    finding_id=finding_id,
                    finding_class=str(raw.get("scenario_id", run.scenario_id)),
                    run_index=run.index,
                    evidence_ids=tuple(str(ref) for ref in raw.get("evidence_ids", ())),
                    shown={k: v for k, v in raw.items() if k not in VERDICT_FIELDS},
                    verdict=verdict,
                )
            )
    return tuple(findings), blocked


def _bundle_run(directory: Path, index: int, name: str) -> ReviewRun:
    summary = _read_json(directory / "summary.json")
    scenario_path = directory / "scenario.json"
    events = EvidenceLedger(directory / "evidence.jsonl").verify()
    snapshots = {
        path.stem: _read_json(path) for path in sorted((directory / "snapshots").glob("*.json"))
    }
    return ReviewRun(
        index=index,
        name=name,
        scenario_id=str(summary.get("scenario_id", name)),
        summary=summary,
        scenario=_read_json(scenario_path) if scenario_path.exists() else None,
        events=tuple(event.model_dump(mode="json") for event in events),
        events_complete=True,
        snapshots=snapshots,
    )


def load_bundle(directory: Path) -> ReviewSource:
    inventory_path = directory / "inventory.json"
    if not inventory_path.is_file():
        raise SourceError(f"not a bundle: {directory} has no inventory.json")
    digest = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    try:
        verify_bundle(directory)
        verified, verification = True, "verify-bundle passed"
    except (OSError, ValueError, KeyError, InvalidSignature) as exc:
        verified, verification = False, f"verify-bundle FAILED: {exc}"
    inventory = _read_json(inventory_path)
    is_suite = "suite.json" in inventory.get("artifacts", {})
    names: list[str] = ["run"]
    if is_suite:
        try:
            suite = _read_json(directory / "suite.json")
            names = [str(name) for name in suite.get("scenarios", [])]
        except (OSError, ValueError) as exc:
            names, verification = [], verification + f"; suite.json unreadable: {exc}"

    runs: list[ReviewRun] = []
    for index, name in enumerate(names):
        run_dir = directory / name if is_suite else directory
        try:
            runs.append(_bundle_run(run_dir, index, name))
        except (OSError, ValueError, KeyError, LedgerError) as exc:
            if verified:  # pragma: no cover - verify_bundle already parsed every run
                raise
            verification += f"; run {name!r} could not be loaded: {exc}"
    key_ids: set[str] = set()
    public_keys: set[bytes] = set()
    for manifest_path in sorted(directory.rglob("manifest.json")):
        try:
            key_ids.update(_manifest_key_ids(_read_json(manifest_path)))
        except (OSError, ValueError):
            continue
    for pem_name in ("authorization-public.pem", ATTESTATION_KEY_FILE):
        for pem_path in sorted(directory.rglob(pem_name)):
            raw = raw_public_key(pem_path.read_bytes())
            if raw is not None:
                public_keys.add(raw)
    for attestation_path in sorted(directory.rglob(ATTESTATION_FILE)):
        try:
            key_ids.add(str(_read_json(attestation_path)["key_id"]))
        except (OSError, ValueError, KeyError):
            continue
    findings, blocked = _findings(tuple(runs), qualify_duplicates=True)
    return ReviewSource(
        path=directory,
        kind="suite-bundle" if is_suite else "run-bundle",
        bundle_digest=digest,
        verified=verified,
        verification=verification,
        runs=tuple(runs),
        harness_key_ids=frozenset(key_ids),
        harness_public_keys=frozenset(public_keys),
        findings=findings,
        adjudication_blocked=blocked,
    )


def _check_export_run(run: Mapping[str, Any]) -> str | None:
    for name in ("summary", "manifest"):
        embedded = run.get(name) or {}
        actual = hashlib.sha256(_write_json_bytes(embedded.get("content"))).hexdigest()
        if actual != embedded.get("sha256"):
            return f"embedded {name} does not match its recorded SHA-256"
    manifest = AuthorizationManifest.model_validate(run["manifest"]["content"])
    key = load_pem_public_key(str(run["authorization_public_key_pem"]).encode())
    if not isinstance(key, Ed25519PublicKey):
        return "embedded authorization key is not Ed25519"
    try:
        key.verify(base64.b64decode(manifest.signature, validate=True), manifest.signed_bytes())
    except (InvalidSignature, ValueError):
        return "embedded manifest signature does not verify"
    if run.get("findings") != run["summary"]["content"].get("findings", []):
        return "export findings differ from the embedded summary"
    return None


def load_audit_export(path: Path) -> ReviewSource:
    export = _read_json(path)
    if not isinstance(export, dict) or "runs" not in export:
        raise SourceError(f"not an audit export: {path}")
    digest = str(export.get("bundle_inventory_sha256", ""))
    problems: list[str] = []
    runs: list[ReviewRun] = []
    key_ids: set[str] = set()
    public_keys: set[bytes] = set()
    for index, raw_run in enumerate(export["runs"]):
        try:
            problem = _check_export_run(raw_run)
        except (KeyError, TypeError, ValueError) as exc:
            problem = f"malformed run record: {exc}"
        if problem:
            problems.append(f"run {index}: {problem}")
        summary = (raw_run.get("summary") or {}).get("content") or {}
        manifest = (raw_run.get("manifest") or {}).get("content") or {}
        key_ids.update(_manifest_key_ids(manifest))
        raw_key = raw_public_key(str(raw_run.get("authorization_public_key_pem", "")).encode())
        if raw_key is not None:
            public_keys.add(raw_key)
        runs.append(
            ReviewRun(
                index=index,
                name=f"run-{index}",
                scenario_id=str(raw_run.get("scenario_id", "")),
                summary=summary,
                scenario=None,
                events=tuple(raw_run.get("decisions", ())),
                events_complete=False,
            )
        )
    attestation = export.get("attestation") or {}
    if attestation.get("content", {}).get("key_id"):
        key_ids.add(str(attestation["content"]["key_id"]))
    if len(digest) != 64:
        problems.append("export names no bundle inventory digest")
    findings, blocked = _findings(tuple(runs), qualify_duplicates=False)
    return ReviewSource(
        path=path,
        kind="audit-export",
        bundle_digest=digest,
        verified=not problems,
        verification=(
            "audit export is self-consistent (embedded digests and manifest signature); the "
            "bundle itself was not available to verify"
            if not problems
            else "audit export FAILED: " + "; ".join(problems)
        ),
        runs=tuple(runs),
        harness_key_ids=frozenset(key_ids),
        harness_public_keys=frozenset(public_keys),
        findings=findings,
        adjudication_blocked=blocked,
    )


def load_ledger_run(directory: Path) -> ReviewSource:
    """A directory with a ledger but no sealed inventory, e.g. a run refused at admission.

    Viewable (its hash chain is verified first) and never adjudicable: there is no sealed bundle
    for a record to name, and a refused run has no accepted finding to label.
    """
    ledger = directory / "evidence.jsonl"
    try:
        events = EvidenceLedger(ledger).verify()
        verification = "not a sealed bundle; the ledger's hash chain verified"
        runs: tuple[ReviewRun, ...] = (
            ReviewRun(
                index=0,
                name="run",
                scenario_id=str(events[0].scenario_id or "") if events else "",
                summary={},
                scenario=None,
                events=tuple(event.model_dump(mode="json") for event in events),
                events_complete=True,
            ),
        )
    except (OSError, LedgerError) as exc:
        verification, runs = f"not a sealed bundle; the ledger FAILED to verify: {exc}", ()
    return ReviewSource(
        path=directory,
        kind="ledger",
        bundle_digest=hashlib.sha256(ledger.read_bytes()).hexdigest(),
        verified=False,
        verification=verification,
        runs=runs,
        harness_key_ids=frozenset(),
        harness_public_keys=frozenset(),
        findings=(),
        adjudication_blocked="a ledger without a sealed inventory cannot be adjudicated",
    )


def load_source(path: Path) -> ReviewSource:
    """Load a bundle directory or an audit-export file, verifying it first."""
    if path.is_dir():
        if not (path / "inventory.json").exists() and (path / "evidence.jsonl").is_file():
            return load_ledger_run(path)
        return load_bundle(path)
    if path.is_file():
        try:
            return load_audit_export(path)
        except json.JSONDecodeError as exc:
            raise SourceError(f"not an audit export: {path}: {exc}") from None
    raise SourceError(f"no such bundle or audit export: {path}")
