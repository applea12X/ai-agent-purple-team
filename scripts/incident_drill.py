"""Materialize a runbook incident into a *copy* of a real bundle, for the incident drill.

``purpleloop gates --inject`` proves a gate blocks on a violating input, but the violation lives
only in memory: there is no bundle afterwards for the runbook's own commands (``audit-export``,
``verify-ledger``) to examine. This script writes the same violations into a copied bundle the way
a harness defect would leave them -- appended through ``EvidenceLedger`` so the hash chain and
anchor stay valid, and re-inventoried -- so the drill can follow ``docs/incident-runbook.md`` with
real commands (``docs/phase5/drill-acceptance.md``). It refuses to touch anything under
``docs/samples`` or a bundle that is not a copy the caller made for the drill.

    uv run python scripts/incident_drill.py scope-bypass  <copied suite or run bundle>
    uv run python scripts/incident_drill.py cross-run-bypass <copied suite bundle>
    uv run python scripts/incident_drill.py budget-breach <copied suite or run bundle>
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from purpleloop.reporting.bundle import inventory
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.replay import replay_fingerprint
from purpleloop.schemas.event import EventKind, EvidenceEvent

FORGED_DIGEST = "f" * 64
DRILL_MARK = ".incident-drill"


def _first_run(bundle: Path) -> Path:
    ledgers = sorted(bundle.rglob("evidence.jsonl"))
    if not ledgers:
        raise SystemExit("no evidence.jsonl under the bundle")
    return ledgers[0].parent


def _reseal(bundle: Path, run: Path) -> None:
    """Rewrite the inventories a real run would have written after the defect."""
    inventory(run, complete=True)
    if run != bundle and (bundle / "inventory.json").is_file():
        inventory(bundle, complete=True)


def _borrowed_digest(bundle: Path, run: Path) -> str:
    """A digest another run of the suite permitted and executed, which ``run`` never saw."""
    own = {e.action_digest for e in EvidenceLedger(run / "evidence.jsonl").verify()}
    for path in sorted(bundle.rglob("evidence.jsonl")):
        if path.parent == run:
            continue
        for event in EvidenceLedger(path).verify():
            if (
                event.kind == EventKind.RESULT
                and event.decision == "permit"
                and event.action_digest
                and event.action_digest not in own
            ):
                return event.action_digest
    raise SystemExit("no digest executed elsewhere but not in the target run")


def scope_bypass(bundle: Path, *, cross_run: bool = False) -> str:
    """A RESULT permit for an action digest no POLICY event in its run ever permitted.

    ``cross_run`` borrows a digest that a *different* run of the same suite did permit, appended
    to the last run: within its own ledger it is still an execution without a permit.
    """
    ledgers = sorted(bundle.rglob("evidence.jsonl"))
    run = ledgers[-1].parent if cross_run else _first_run(bundle)
    digest = _borrowed_digest(bundle, run) if cross_run else FORGED_DIGEST
    ledger = EvidenceLedger(run / "evidence.jsonl")
    last = ledger.verify()[-1]
    event = ledger.append(
        EvidenceEvent(
            run_id=last.run_id,
            trace_id="incident-drill",
            sequence=0,
            timestamp=datetime.now(UTC),
            actor="incident-drill",
            kind=EventKind.RESULT,
            manifest_digest=last.manifest_digest,
            policy_digest=last.policy_digest,
            action_digest=digest,
            decision="permit",
            reason_code="COMPLETED",
        )
    )
    # A genuine bypass is in the ledger when the summary is written, so its replay hash covers it.
    # Without this step verify-bundle reports "normalized event hash mismatch": an event appended
    # after sealing is an integrity incident (runbook section 1), not a bypass.
    summary_path = run / "summary.json"
    if summary_path.is_file():  # a denied-at-admission run has no summary to bind
        summary = json.loads(summary_path.read_text())
        summary["event_replay_hash"] = replay_fingerprint(ledger.verify())
        summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    _reseal(bundle, run)
    return f"appended RESULT permit seq={event.sequence} digest={digest[:12]}... in {run}"


def budget_breach(bundle: Path) -> str:
    """A run summary charging more requests than the signed manifest allows."""
    run = _first_run(bundle)
    manifest = json.loads((run / "manifest.json").read_text())
    summary_path = run / "summary.json"
    summary = json.loads(summary_path.read_text())
    limit = int(manifest["budgets"]["requests"])
    summary["budget_used"]["requests"] = limit + 1
    summary_path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    _reseal(bundle, run)
    return f"set budget_used.requests={limit + 1} over the signed limit {limit} in {run}"


def main(argv: list[str]) -> int:
    modes = {
        "scope-bypass": scope_bypass,
        "cross-run-bypass": lambda bundle: scope_bypass(bundle, cross_run=True),
        "budget-breach": budget_breach,
    }
    if len(argv) != 2 or argv[0] not in modes:
        print(__doc__)
        return 2
    bundle = Path(argv[1]).resolve()
    if ROOT in (bundle, *bundle.parents):
        print("refusing: drill bundles must be copies outside the repository")
        return 2
    # Marked before resealing, so the mark is inventoried and the bundle says what was done to it.
    (bundle / DRILL_MARK).write_text(f"{argv[0]} materialized for the incident drill\n")
    print(modes[argv[0]](bundle))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
