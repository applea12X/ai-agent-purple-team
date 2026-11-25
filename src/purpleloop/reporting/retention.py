"""Resolve the signed retention rules over a real artifact tree, as a dry run.

``docs/retention-policy.md`` says retention classes are signed data (``Phase4Grants.retention``)
and that deletion is only ever by class and age. Until loose end 4.12 nothing resolved those rules
against an actual tree, so nobody could say which file would go when. This module does exactly
that and nothing more: it never deletes, moves, or rewrites a file.

For every file under the root it decides:

* **kind**: ``raw-ledgers`` (``evidence.jsonl`` and its anchor), ``attestations``
  (``attestation*``), ``browser-artifacts`` (anything under ``browser/``), ``model-transcripts``
  (Inspect logs under ``inspect/``), and ``bundles`` for everything else in a bundle;
* **created**: the first ledger event's timestamp of the run the file belongs to, because a file
  copy resets its mtime and a copied bundle must not look new. A file in no run falls back to its
  mtime, and the plan says so;
* **holds**, which beat any age (the policy's "regardless of duration" rules): an attested bundle
  is held by its attestation (repo life); a run with an evidence-integrity incident is held; and a
  run that reported findings is held, because no finding-closure record exists, so every finding is
  treated as open.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from purpleloop.schemas.phase4 import Phase4Grants, RetentionKind

LEDGER_NAMES = frozenset({"evidence.jsonl", "evidence.jsonl.anchor"})


def classify(relative: Path) -> RetentionKind:
    if relative.name in LEDGER_NAMES:
        return "raw-ledgers"
    if relative.name.startswith("attestation"):
        return "attestations"
    if "browser" in relative.parts[:-1]:
        return "browser-artifacts"
    if "inspect" in relative.parts[:-1]:
        return "model-transcripts"
    return "bundles"


def run_directory(path: Path, root: Path) -> Path | None:
    """The nearest directory at or above ``path`` (within ``root``) holding a run ledger."""
    for candidate in (path.parent, *path.parent.parents):
        if (candidate / "evidence.jsonl").is_file():
            return candidate
        if candidate == root:
            break
    return None


def run_created(run: Path) -> datetime | None:
    with (run / "evidence.jsonl").open(encoding="utf-8") as handle:
        first = handle.readline()
    if not first.strip():
        return None
    return datetime.fromisoformat(str(json.loads(first)["timestamp"]).replace("Z", "+00:00"))


def run_holds(run: Path) -> list[str]:
    holds: list[str] = []
    if (run / "attestation.json").is_file():
        holds.append("attested: held for the life of its attestation (repo life)")
    summary_path = run / "summary.json"
    summary: dict[str, Any] = (
        json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else {}
    )
    if (run / "integrity-incident.json").is_file() or summary.get("evidence_integrity_incident"):
        holds.append("evidence-integrity incident: held until the incident is resolved")
    if summary.get("findings"):
        holds.append(
            f"{len(summary['findings'])} finding(s): no closure record exists, so held as open"
        )
    return holds


def suite_inheritance(
    directory: Path, cache: dict[Path, tuple[datetime | None, list[str]]]
) -> tuple[datetime | None, list[str]]:
    """A suite-level file is as old as its oldest run and held by every hold under it.

    The suite's ``inventory.json``, reports, and ``suite.json`` describe the runs beneath them, and
    ``verify-bundle`` on the suite needs them. Ageing them by mtime let them fall due while every
    run they cover was still held (found resolving a real smoke suite, the drill record).
    """
    for run in sorted(p.parent for p in directory.rglob("evidence.jsonl")):
        if run not in cache:
            cache[run] = (run_created(run), run_holds(run))
    covered = [cache[run] for run in cache if directory in (run, *run.parents)]
    times = [created for created, _ in covered if created is not None]
    held = sorted({hold.split(":")[0] for _, run_holds_ in covered for hold in run_holds_})
    return (min(times) if times else None), [f"covers a held run ({reason})" for reason in held]


def retention_plan(root: Path, grants: Phase4Grants, *, as_of: datetime) -> dict[str, Any]:
    """Every file under ``root`` with its kind, rule, deletion date, and any hold."""
    entries: list[dict[str, Any]] = []
    cache: dict[Path, tuple[datetime | None, list[str]]] = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root)
        kind = classify(relative)
        rule = grants.retention_for(kind)
        run = run_directory(path, root)
        if run is not None and run not in cache:
            cache[run] = (run_created(run), run_holds(run))
        basis = "ledger"
        if run is not None:
            created, holds = cache[run]
        else:
            created, holds = suite_inheritance(path.parent, cache)
            basis = "suite"
        if created is None:
            created = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            basis = "mtime"
        if rule is None:
            # A kind with no signed rule is never deleted: absence of a rule is not permission.
            delete_after, reason = None, "no signed rule for this kind: kept"
        elif rule.days == 0:
            delete_after, reason = None, "repo life"
        else:
            delete_after, reason = created + timedelta(days=rule.days), f"{rule.days} days"
        due = delete_after is not None and as_of >= delete_after and not holds
        entries.append(
            {
                "path": relative.as_posix(),
                "kind": kind,
                "bytes": path.stat().st_size,
                "created": created.isoformat(timespec="seconds"),
                "created_basis": basis,
                "rule": reason,
                "delete_after": delete_after.isoformat(timespec="seconds")
                if delete_after
                else None,
                "holds": holds,
                "due": due,
            }
        )
    by_kind: dict[str, dict[str, int]] = {}
    for entry in entries:
        bucket = by_kind.setdefault(entry["kind"], Counter())
        bucket["files"] += 1
        bucket["bytes"] += entry["bytes"]
        bucket["due"] += int(entry["due"])
        bucket["held"] += int(bool(entry["holds"]) and entry["delete_after"] is not None)
    return {
        "schema": "purpleloop.retention-plan/1",
        "root": root.as_posix(),
        "as_of": as_of.isoformat(timespec="seconds"),
        "dry_run": True,
        "files": len(entries),
        "due": sum(1 for entry in entries if entry["due"]),
        "by_kind": {kind: dict(counts) for kind, counts in sorted(by_kind.items())},
        "entries": entries,
    }
