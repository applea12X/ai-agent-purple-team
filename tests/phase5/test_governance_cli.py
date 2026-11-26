"""The governance CLI sequence (WP5.1): keygen -> shadow-run -> approve -> approval-check.

Run exactly as a person would, against the committed baseline. Keys live in ``tmp_path`` only.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.control.phase5_signing import verify_record_signature
from purpleloop.runtime import governance
from purpleloop.runtime.shadow import verify_shadow_bundle
from purpleloop.schemas.phase5 import RiskApproval

SCENARIO = "agent-tool-misuse"


def invoke(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(app, [str(arg) for arg in args])
    return result.exit_code, result.output


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private, public = tmp_path / "keys" / "approver.pem", tmp_path / "keys" / "approver.pub.pem"
    code, output = invoke("approver-keygen", private, public)
    assert code == 0, output
    assert private.stat().st_mode & 0o777 == 0o600
    return private, public


def shadow(tmp_path: Path, *extra: str) -> Path:
    bundle = tmp_path / "shadow"
    code, output = invoke("shadow-run", bundle, "--scenario", SCENARIO, *extra)
    assert code == 0, output
    assert "adapter dispatches 0 (report adapter_calls 0)" in output
    return bundle


def approve(bundle: Path, keys: tuple[Path, Path], out: Path, *extra: str) -> tuple[int, str]:
    return invoke(
        "approve",
        bundle,
        "--approver-key",
        keys[0],
        "--approver-key-id",
        "approver-cli",
        "--approver",
        "a test approver",
        "--rationale",
        "cli test",
        "--out",
        out,
        *extra,
    )


def check(
    bundle: Path, keys: tuple[Path, Path], approval: Path | None, *extra: str
) -> tuple[int, str]:
    options = ["--approval", approval] if approval is not None else []
    return invoke(
        "approval-check",
        bundle,
        *options,
        "--approver-public-key",
        keys[1],
        "--approver-key-id",
        "approver-cli",
        *extra,
    )


@pytest.mark.parametrize(
    ("flags", "delta"),
    [
        (("--proposal-source", "model-driven"), "proposal-source-change"),
        (("--action-class", "code-exec"), "new-action-class"),
    ],
)
def test_the_sequence_produces_an_approval_admission_accepts(
    tmp_path: Path, keys: tuple[Path, Path], flags: tuple[str, ...], delta: str
) -> None:
    bundle = shadow(tmp_path, *flags)
    report = verify_shadow_bundle(bundle)
    out = tmp_path / "approval.json"
    code, output = approve(bundle, keys, out, "--ttl-hours", "1")
    assert code == 0 and f"APPROVED ['{delta}']" in output, output
    approval = RiskApproval.model_validate(json.loads(out.read_text()))
    assert approval.shadow_report_digest == report.report_digest()
    verify_record_signature(approval, {"approver-cli": governance.load_public_key(keys[1])})
    code, output = check(bundle, keys, out)
    assert code == 0 and f"ADMITTED CAPABILITY_INCREASE_APPROVED delta=['{delta}']" in output
    later = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    code, output = check(bundle, keys, out, "--at", later)
    assert code == 1 and "REFUSED APPROVAL_EXPIRED" in output
    code, output = check(bundle, keys, None)
    assert code == 1 and "REFUSED CAPABILITY_INCREASE_UNAPPROVED" in output


def test_a_manifest_with_no_increase_has_nothing_to_approve(
    tmp_path: Path, keys: tuple[Path, Path]
) -> None:
    bundle = shadow(tmp_path, "--no-attacker")
    code, output = approve(bundle, keys, tmp_path / "approval.json")
    assert code == 1 and "REFUSED NO_CAPABILITY_INCREASE" in output
    code, output = check(bundle, keys, None)
    assert code == 0 and "ADMITTED NO_CAPABILITY_INCREASE" in output


def test_an_untrusted_approver_key_is_refused(tmp_path: Path, keys: tuple[Path, Path]) -> None:
    bundle = shadow(tmp_path, "--proposal-source", "model-driven")
    out = tmp_path / "approval.json"
    assert approve(bundle, keys, out)[0] == 0
    other = (tmp_path / "other.pem", tmp_path / "other.pub.pem")
    assert invoke("approver-keygen", *other)[0] == 0
    code, output = check(bundle, other, out)
    assert code == 1 and "REFUSED INVALID_SIGNATURE" in output


def test_bad_inputs_are_refused_without_a_traceback(
    tmp_path: Path, keys: tuple[Path, Path]
) -> None:
    code, output = invoke("shadow-run", tmp_path / "s", "--proposal-source", "magic")
    assert code == 2 and "INVALID" in output
    code, output = invoke("shadow-run", tmp_path / "s", "--scenario", "no-such-scenario")
    assert code == 1 and "INVALID" in output
    code, output = approve(tmp_path / "missing", keys, tmp_path / "a.json")
    assert code == 1 and "INVALID" in output
    code, output = check(tmp_path / "missing", keys, None)
    assert code == 1 and "INVALID" in output


def test_the_committed_baseline_checks_and_a_fresh_one_can_be_signed(tmp_path: Path) -> None:
    code, output = invoke("capability-baseline", "--check")
    assert code == 0 and "matches the v1 lane manifests" in output, output
    target, key = tmp_path / "baseline.json", tmp_path / "baseline.pem"
    code, output = invoke("capability-baseline", "--output", target, "--public-key-output", key)
    assert code == 0 and "ephemeral" in output
    code, output = invoke(
        "capability-baseline", "--check", "--output", target, "--public-key-output", key
    )
    assert code == 0, output
    # A key that did not sign it is refused.
    other_key = tmp_path / "other.pem"
    invoke(
        "capability-baseline", "--output", tmp_path / "b2.json", "--public-key-output", other_key
    )
    code, output = invoke(
        "capability-baseline", "--check", "--output", target, "--public-key-output", other_key
    )
    assert code == 1 and "INVALID" in output
