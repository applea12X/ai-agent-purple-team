"""Audit export: one self-contained, redacted, verifiable file per bundle.

The export embeds everything a reviewer needs to reconstruct what was attempted, what was
decided and why, and what evidence proves it -- without a repository checkout: the signed
manifest and its public key, every run's status and findings, every admission/policy/budget
decision with its reason code, and the attestation when one exists. Content comes from the
bundle's already-redacted artifacts, so nothing here re-derives or un-redacts.

Verification travels with the export: the manifest signature can be checked against the
embedded key, and each embedded document carries the digest recorded for it in the bundle
inventory, so a tampered export disagrees with itself.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from purpleloop.reporting.attestation import ATTESTATION_FILE
from purpleloop.reporting.bundle import write_json
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.event import EventKind

#: The decision record extracted per run: everything that admitted, permitted, denied, charged,
#: or terminated -- the events a reviewer reads to answer "what was decided and why".
DECISION_KINDS = frozenset(
    {
        EventKind.ADMISSION,
        EventKind.POLICY,
        EventKind.BUDGET,
        EventKind.DEFENSE,
        EventKind.TERMINATION,
    }
)

HOW_TO_VERIFY = (
    "Each embedded document lists the SHA-256 recorded for it in the bundle inventory; recompute "
    "and compare. The manifest signature verifies against the embedded authorization public key "
    "over the manifest's canonical bytes excluding the signature field. When an attestation is "
    "embedded, its subject_digest is the SHA-256 of the bundle's inventory.json, and its "
    "signature verifies against the embedded attestation public key. `purpleloop verify-bundle "
    "<bundle> --attestation` performs every check against the original bundle."
)


class AuditExportError(ValueError):
    pass


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _embedded(path: Path) -> dict[str, Any]:
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "content": _load(path),
    }


def _run_record(directory: Path) -> dict[str, Any]:
    summary = _load(directory / "summary.json")
    events = EvidenceLedger(directory / "evidence.jsonl").verify()
    decisions = [
        {
            "sequence": event.sequence,
            "stage": event.stage,
            "kind": event.kind.value,
            "decision": event.decision,
            "reason_code": event.reason_code,
            "action_digest": event.action_digest,
        }
        for event in events
        if event.kind in DECISION_KINDS
    ]
    return {
        "scenario_id": summary.get("scenario_id"),
        "status": summary.get("status"),
        "reason": summary.get("reason"),
        "teardown_complete": summary.get("teardown_complete"),
        "evidence_integrity_incident": summary.get("evidence_integrity_incident"),
        "findings": summary.get("findings", []),
        "budget_used": summary.get("budget_used"),
        "decisions": decisions,
        "events": len(events),
        "evidence_sha256": hashlib.sha256((directory / "evidence.jsonl").read_bytes()).hexdigest(),
        "summary": _embedded(directory / "summary.json"),
        "manifest": _embedded(directory / "manifest.json"),
        # Per run because a suite may span engagements: each run's manifest verifies against
        # the key that was shipped beside it.
        "authorization_public_key_pem": (directory / "authorization-public.pem").read_text(
            encoding="utf-8"
        ),
    }


def export_audit(directory: Path, out_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Write the audit export for one bundle (run or suite) and return it."""
    inventory_path = directory / "inventory.json"
    if not inventory_path.exists():
        raise AuditExportError("not a bundle: inventory.json is missing")
    inventory = _load(inventory_path)
    artifacts = inventory.get("artifacts", {})
    if "suite.json" in artifacts:
        suite = _load(directory / "suite.json")
        runs = [_run_record(directory / name) for name in suite.get("scenarios", [])]
    else:
        runs = [_run_record(directory)]
    export: dict[str, Any] = {
        "schema_version": "1.4.0",
        "generated_at": (now or datetime.now(UTC)).isoformat(),
        "bundle_inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        "bundle_complete": bool(inventory.get("complete")),
        "attestation": (
            _embedded(directory / ATTESTATION_FILE)
            if (directory / ATTESTATION_FILE).exists()
            else None
        ),
        "runs": runs,
        "how_to_verify": HOW_TO_VERIFY,
    }
    write_json(out_path, export)
    return export
