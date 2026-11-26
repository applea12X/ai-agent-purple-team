"""Retention resolution (loose end 4.12): signed rules resolved over a real bundle tree, dry run.

The policy's rules are tested against the committed sample bundles copied into a temporary tree,
so the files, the ledger timestamps, and the attestations are real. Nothing here may delete.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.reporting.retention import classify, retention_plan
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.nightly import (
    NIGHTLY_MANIFEST,
    NIGHTLY_PUBLIC_KEY,
    RETENTION_RULES,
    read_nightly_scope,
    verified_manifest,
)
from purpleloop.schemas.phase4 import RETENTION_KINDS, Phase4Grants

SAMPLES = ROOT / "docs" / "samples"


def _grants() -> Phase4Grants:
    signed = verified_manifest(NIGHTLY_MANIFEST, NIGHTLY_PUBLIC_KEY)
    assert signed.phase4 is not None
    return signed.phase4


def _unattested_run(tmp_path: Path, *, findings: bool) -> Path:
    """The passing sample, unsealed: attestation removed, findings optionally cleared."""
    run = tmp_path / "suite" / "run"
    shutil.copytree(SAMPLES / "passing-run", run)
    for name in ("attestation.json", "attestation-public.pem"):
        (run / name).unlink()
    summary = json.loads((run / "summary.json").read_text())
    if not findings:
        summary["findings"] = []
    (run / "summary.json").write_text(json.dumps(summary))
    browser = run / "browser" / "01-attack"
    browser.mkdir(parents=True)
    (browser / "trace.zip").write_bytes(b"PK")
    return run


def test_the_signed_rules_cover_every_kind_as_the_policy_states() -> None:
    grants = _grants()
    assert {rule.artifact_kind for rule in grants.retention} == set(RETENTION_KINDS)
    days = {rule.artifact_kind: rule.days for rule in grants.retention}
    assert days == {
        "raw-ledgers": 0,
        "attestations": 0,
        "bundles": 90,
        "browser-artifacts": 90,
        "model-transcripts": 30,
    }
    assert tuple(grants.retention) == RETENTION_RULES
    assert read_nightly_scope().manifest_digest  # the same signed document carries both


def test_files_are_classified_by_kind() -> None:
    assert classify(Path("run/evidence.jsonl")) == "raw-ledgers"
    assert classify(Path("run/evidence.jsonl.anchor")) == "raw-ledgers"
    assert classify(Path("run/attestation.json")) == "attestations"
    assert classify(Path("run/browser/01-x/trace.zip")) == "browser-artifacts"
    assert classify(Path("run/inspect/log.json")) == "model-transcripts"
    assert classify(Path("run/summary.json")) == "bundles"
    assert classify(Path("browser.json")) == "bundles"  # a name, not a directory


def test_age_comes_from_the_ledger_so_a_copied_bundle_does_not_look_new(tmp_path: Path) -> None:
    run = _unattested_run(tmp_path, findings=False)
    first = json.loads((run / "evidence.jsonl").read_text().splitlines()[0])
    created = datetime.fromisoformat(first["timestamp"].replace("Z", "+00:00"))
    plan = retention_plan(tmp_path, _grants(), as_of=created + timedelta(days=31))
    entries = {entry["path"]: entry for entry in plan["entries"]}
    ledger = entries["suite/run/evidence.jsonl"]
    assert ledger["created_basis"] == "ledger"
    assert ledger["delete_after"] is None and not ledger["due"]
    transcripts = [e for e in plan["entries"] if e["kind"] == "model-transcripts"]
    assert transcripts and all(e["due"] for e in transcripts)  # 30 days, past
    browser = entries["suite/run/browser/01-attack/trace.zip"]
    assert not browser["due"]  # 90 days, not yet
    later = retention_plan(tmp_path, _grants(), as_of=created + timedelta(days=91))
    due = {e["path"] for e in later["entries"] if e["due"]}
    assert "suite/run/browser/01-attack/trace.zip" in due
    assert "suite/run/summary.json" in due  # a per-run CI bundle, 90 days
    assert "suite/run/evidence.jsonl" not in due
    assert "suite/run/evidence.jsonl.anchor" not in due


def test_holds_beat_age(tmp_path: Path) -> None:
    attested = tmp_path / "attested"
    shutil.copytree(SAMPLES / "passing-run", attested)
    _unattested_run(tmp_path, findings=True)
    far = datetime(2100, 1, 1, tzinfo=UTC)
    plan = retention_plan(tmp_path, _grants(), as_of=far)
    assert plan["due"] == 0
    for entry in plan["entries"]:
        if entry["path"].startswith("attested/"):
            assert any(hold.startswith("attested") for hold in entry["holds"])
        else:
            assert any("finding" in hold for hold in entry["holds"])


def test_an_incident_bundle_is_held(tmp_path: Path) -> None:
    run = _unattested_run(tmp_path, findings=False)
    (run / "integrity-incident.json").write_text("{}")
    plan = retention_plan(tmp_path, _grants(), as_of=datetime(2100, 1, 1, tzinfo=UTC))
    assert plan["due"] == 0
    assert all(any("incident" in h for h in e["holds"]) for e in plan["entries"])


def test_the_command_is_a_dry_run_that_deletes_nothing(tmp_path: Path) -> None:
    run = _unattested_run(tmp_path, findings=False)
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    output = tmp_path.parent / f"{tmp_path.name}-plan.json"
    result = CliRunner().invoke(
        app, ["retention-plan", str(tmp_path), "--as-of", "2100-01-01", "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert "nothing deleted" in result.output
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before
    plan = json.loads(output.read_text())
    assert plan["dry_run"] is True and plan["due"] > 0
    assert (run / "evidence.jsonl").is_file()
    unsigned = tmp_path.parent / f"{tmp_path.name}-bad.pem"
    unsigned.write_text("not a key")
    refused = CliRunner().invoke(
        app, ["retention-plan", str(tmp_path), "--public-key", str(unsigned)]
    )
    assert refused.exit_code != 0


def test_suite_level_files_inherit_the_age_and_holds_of_the_runs_they_cover(
    tmp_path: Path,
) -> None:
    run = _unattested_run(tmp_path, findings=True)
    suite_file = run.parent / "suite.json"
    suite_file.write_text("{}")
    plan = retention_plan(tmp_path, _grants(), as_of=datetime(2100, 1, 1, tzinfo=UTC))
    entry = next(e for e in plan["entries"] if e["path"] == "suite/suite.json")
    run_entry = next(e for e in plan["entries"] if e["path"] == "suite/run/summary.json")
    assert entry["created_basis"] == "suite"
    assert entry["created"] == run_entry["created"]  # not the fresh mtime of the copy
    assert entry["holds"] == ["covers a held run (1 finding(s))"]
    assert not entry["due"]
