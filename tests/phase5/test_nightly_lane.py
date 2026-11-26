"""The nightly lane (loose ends 4.23-4.25): signed scope, a browser workflow, and the issue.

Everything here is offline. The scheduled job itself cannot run in this repository's test suite,
so the parts it is made of are tested one by one: the scope comes only from signed data, the
browser workflow really runs, every outcome is classified, a quiet night files nothing, a
non-pass night files or updates exactly one issue through ``gh``, and the workflow wires those
commands together with ``issues: write`` on the nightly job alone.
"""

from __future__ import annotations

import json
import stat
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.control.manifest import ManifestError, load_manifest
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.nightly import (
    ISSUE_TITLE,
    NIGHTLY_MANIFEST,
    NIGHTLY_PUBLIC_KEY,
    ScopedScenario,
    build_nightly_manifest,
    file_or_update_issue,
    outcome_from_stderr,
    public_pem,
    read_nightly_scope,
    render_issue_body,
    run_night,
)
from purpleloop.runtime.supportlab import supportlab_agent_manifest
from purpleloop.schemas.phase1 import load_scenario
from purpleloop.schemas.phase4 import NightlyScope, StochasticRunOutcome

WORKFLOW = ROOT / ".github" / "workflows" / "phase5.yml"


def _signed(tmp_path: Path, scope: NightlyScope, **kwargs: Any) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    manifest = build_nightly_manifest(key, scope, **kwargs)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json())
    key_path = tmp_path / "authorization-public.pem"
    key_path.write_bytes(public_pem(key))
    return manifest_path, key_path


# --- the signed scope -------------------------------------------------------------------------


def test_the_committed_scope_verifies_and_names_a_browser_workflow_and_agent_scenarios() -> None:
    plan = read_nightly_scope()
    assert plan.repetitions >= 5
    agent, supportlab = plan.lane("agent"), plan.lane("supportlab")
    assert agent, "the nightly must still run the agent lane"
    surfaces = {load_scenario(item.path).surface for item in supportlab}
    # A shared workflow: the same attack on the API and the browser surface.
    assert {"api", "browser"} <= surfaces
    assert plan.valid_until - load_manifest(NIGHTLY_MANIFEST).issued_at >= timedelta(days=300)


def test_an_edited_scope_fails_verification(tmp_path: Path) -> None:
    raw = json.loads(NIGHTLY_MANIFEST.read_text())
    raw["phase4"]["nightly_scope"]["repetitions"] = 50
    edited = tmp_path / "manifest.json"
    edited.write_text(json.dumps(raw))
    with pytest.raises(ManifestError) as caught:
        read_nightly_scope(edited, NIGHTLY_PUBLIC_KEY)
    assert caught.value.reason_code == "INVALID_SIGNATURE"


def test_a_scope_signed_by_another_key_is_refused(tmp_path: Path) -> None:
    other = tmp_path / "other.pem"
    other.write_bytes(public_pem(Ed25519PrivateKey.generate()))
    with pytest.raises(ManifestError) as caught:
        read_nightly_scope(NIGHTLY_MANIFEST, other)
    assert caught.value.reason_code == "INVALID_SIGNATURE"


def test_an_expired_scope_is_refused() -> None:
    plan = read_nightly_scope()
    later = plan.valid_until + timedelta(seconds=1)
    with pytest.raises(ManifestError) as caught:
        read_nightly_scope(now=later)
    assert caught.value.reason_code == "EXPIRED_MANIFEST"


async def test_an_expired_scope_runs_nothing_and_files(tmp_path: Path) -> None:
    plan = read_nightly_scope()
    ran: list[str] = []

    async def browser(item: ScopedScenario, output: Path) -> StochasticRunOutcome:
        ran.append(item.scenario_id)
        raise AssertionError("nothing runs without a verified scope")

    report = await run_night(
        tmp_path,
        endpoint=None,
        browser_executor=browser,
        now=plan.valid_until + timedelta(days=1),
    )
    assert ran == []
    assert report["needs_issue"] is True
    assert report["outcomes"][0]["reason_code"] == "EXPIRED_MANIFEST"


def test_a_manifest_without_a_nightly_scope_is_refused(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    older = supportlab_agent_manifest(key)  # Manifest 1.3: no phase4, no scope
    path = tmp_path / "manifest.json"
    path.write_text(older.model_dump_json())
    pem = tmp_path / "key.pem"
    pem.write_bytes(public_pem(key))
    # Signed under the agent lane's key id; trust exactly that key.
    with pytest.raises(ValueError, match="no nightly_scope"):
        read_nightly_scope(path, pem)


def test_a_signed_scope_naming_an_unknown_scenario_is_refused(tmp_path: Path) -> None:
    manifest, key = _signed(
        tmp_path, NightlyScope(scenario_ids=frozenset({"no-such-scenario"}), repetitions=5)
    )
    with pytest.raises(ValueError, match="unknown scenario"):
        read_nightly_scope(manifest, key)


def test_the_scope_command_writes_github_outputs(tmp_path: Path) -> None:
    outputs = tmp_path / "github-output"
    result = CliRunner().invoke(app, ["nightly-scope", "--github-output", str(outputs)])
    assert result.exit_code == 0, result.output
    lines = dict(line.split("=", 1) for line in outputs.read_text().splitlines())
    plan = read_nightly_scope()
    assert lines["repetitions"] == str(plan.repetitions)
    assert lines["manifest_digest"] == plan.manifest_digest
    assert set(lines["agent_scenarios"].split()) == {i.scenario_id for i in plan.lane("agent")}
    edited = tmp_path / "edited.json"
    raw = json.loads(NIGHTLY_MANIFEST.read_text())
    raw["phase4"]["nightly_scope"]["scenario_ids"].append("agent-goal-hijack")
    edited.write_text(json.dumps(raw))
    refused = CliRunner().invoke(app, ["nightly-scope", "--manifest", str(edited)])
    assert refused.exit_code == 1
    assert "INVALID_SIGNATURE" in refused.output


def test_the_sign_command_round_trips_through_the_reader(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "nightly-scope-sign",
            "--scenario",
            "bola-ticket-ui",
            "--scenario",
            "agent-goal-hijack",
            "--repetitions",
            "7",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ephemeral key, discarded" in result.output
    assert not any(path.suffix == ".key" or "private" in path.name for path in tmp_path.iterdir())
    plan = read_nightly_scope(tmp_path / "manifest.json", tmp_path / "authorization-public.pem")
    assert plan.repetitions == 7
    assert {item.scenario_id for item in plan.scenarios} == {"bola-ticket-ui", "agent-goal-hijack"}
    bad = CliRunner().invoke(
        app, ["nightly-scope-sign", "--scenario", "nope", "--output-dir", str(tmp_path / "x")]
    )
    assert bad.exit_code == 1


# --- running the night ------------------------------------------------------------------------


async def test_a_night_without_an_endpoint_runs_the_browser_workflow_and_records_the_skip(
    tmp_path: Path,
) -> None:
    from purpleloop.runtime.nightly import run_browser_workflow

    async def in_process(item: ScopedScenario, output: Path) -> StochasticRunOutcome:
        return await run_browser_workflow(item, output, served=False)

    def no_agent(*args: Any) -> StochasticRunOutcome:
        raise AssertionError("no endpoint: the agent lane must not run")

    report = await run_night(
        tmp_path, endpoint=None, agent_executor=no_agent, browser_executor=in_process
    )
    by_id = {item["scenario_id"]: item for item in report["outcomes"]}
    plan = read_nightly_scope()
    assert set(by_id) == {item.scenario_id for item in plan.scenarios}
    for item in plan.lane("supportlab"):
        assert by_id[item.scenario_id]["outcome"] == "pass"
        assert (tmp_path / item.scenario_id / "summary.json").is_file()
    for item in plan.lane("agent"):
        assert by_id[item.scenario_id]["outcome"] == "skip-no-credential"
    assert report["needs_issue"] is False
    assert json.loads((tmp_path / "nightly.json").read_text()) == report


async def test_the_agent_lane_gets_the_signed_repetitions_and_a_non_pass_needs_an_issue(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, int, str]] = []

    def agent(
        item: ScopedScenario, output: Path, repetitions: int, endpoint: str, profile: str
    ) -> StochasticRunOutcome:
        calls.append((item.scenario_id, repetitions, endpoint))
        return StochasticRunOutcome(
            outcome="endpoint-error",
            reason_code="MODEL_PROVIDER_UNAVAILABLE",
            scenario_id=item.scenario_id,
        )

    async def browser(item: ScopedScenario, output: Path) -> StochasticRunOutcome:
        return StochasticRunOutcome(
            outcome="pass", reason_code="PAIRED_EVALUATION", scenario_id=item.scenario_id
        )

    report = await run_night(
        tmp_path,
        endpoint="http://127.0.0.1:11434",
        agent_executor=agent,
        browser_executor=browser,
    )
    plan = read_nightly_scope()
    assert calls == [
        (item.scenario_id, plan.repetitions, "http://127.0.0.1:11434")
        for item in plan.lane("agent")
    ]
    assert report["needs_issue"] is True


def test_the_agent_outcome_is_read_from_agent_run_output() -> None:
    line = StochasticRunOutcome(outcome="budget-stop", reason_code="BUDGET_EXCEEDED")
    parsed = outcome_from_stderr(f"noise\nOUTCOME {line.model_dump_json()}\nmore", "s")
    assert parsed.outcome == "budget-stop"
    missing = outcome_from_stderr("Traceback: boom", "s")
    assert (missing.outcome, missing.reason_code) == ("fail", "NO_OUTCOME_RECORDED")


def test_the_lane_command_exits_by_outcome(tmp_path: Path) -> None:
    ok = CliRunner().invoke(
        app,
        ["nightly-lane", "--output-dir", str(tmp_path / "ok"), "--browser-fixture", "in-process"],
        env={"PURPLELOOP_MODEL_ENDPOINT": ""},
    )
    assert ok.exit_code == 0, ok.output
    assert "skip-no-credential" in ok.output
    edited = tmp_path / "edited.json"
    raw = json.loads(NIGHTLY_MANIFEST.read_text())
    raw["phase4"]["nightly_scope"]["repetitions"] = 6
    edited.write_text(json.dumps(raw))
    bad = CliRunner().invoke(
        app,
        ["nightly-lane", "--output-dir", str(tmp_path / "bad"), "--manifest", str(edited)],
        env={"PURPLELOOP_MODEL_ENDPOINT": ""},
    )
    assert bad.exit_code == 1
    assert "INVALID_SIGNATURE" in bad.output


# --- the tracking issue -----------------------------------------------------------------------

FAILED_NIGHT: dict[str, Any] = {
    "scope": {"manifest_digest": "ab" * 32, "repetitions": 5, "valid_until": "2027-11-25"},
    "outcomes": [
        {"scenario_id": "bola-ticket-ui", "lane": "supportlab", "outcome": "pass",
         "reason_code": "PAIRED_EVALUATION", "detail": ""},
        {"scenario_id": "agent-indirect-ticket", "lane": "agent", "outcome": "fail",
         "reason_code": "EXECUTION_FAILED", "detail": "ValueError: 403 | ```x```"},
        {"scenario_id": "agent-goal-hijack", "lane": "agent", "outcome": "skip-no-credential",
         "reason_code": "STOCHASTIC_LANE_UNAVAILABLE", "detail": "unset"},
    ],
    "needs_issue": True,
}  # fmt: skip


def test_the_issue_body_names_the_run_the_scope_and_only_the_non_pass_outcomes() -> None:
    body = render_issue_body(FAILED_NIGHT, run_url="https://example.invalid/run/1")
    assert "https://example.invalid/run/1" in body
    assert "abababababababab" in body and "5 repetitions" in body
    assert "`fail` **(non-pass)**" in body
    assert "`pass` **(non-pass)**" not in body
    assert "`skip-no-credential` **(non-pass)**" not in body
    assert "ValueError: 403" in body and "```x```" not in body  # no fence break-out
    assert "unset" not in body  # a skip's detail is not triage material
    empty = render_issue_body(None, run_url="u")
    assert "before it recorded any classified outcome" in empty


def _fake_gh(tmp_path: Path, existing: list[dict[str, Any]]) -> tuple[Path, Path]:
    log = tmp_path / "gh-calls.jsonl"
    script = tmp_path / "gh"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if sys.argv[1:3] == ['issue', 'list']:\n"
        f"    print(json.dumps({existing!r}))\n"
        "elif sys.argv[1:3] == ['issue', 'create']:\n"
        "    print('https://github.invalid/o/r/issues/9')\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script, log


def _calls(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_a_non_pass_night_opens_an_issue_when_none_is_open(tmp_path: Path) -> None:
    gh, log = _fake_gh(tmp_path, [{"number": 3, "title": "Nightly something else"}])
    (tmp_path / "nightly.json").write_text(json.dumps(FAILED_NIGHT))
    result = CliRunner().invoke(
        app, ["nightly-issue", "--output-dir", str(tmp_path), "--run-url", "u", "--gh", str(gh)]
    )
    assert result.exit_code == 0, result.output
    calls = _calls(log)
    assert calls[0][:2] == ["issue", "list"]
    assert calls[1][:4] == ["issue", "create", "--title", ISSUE_TITLE]
    assert "EXECUTION_FAILED" in (tmp_path / "issue-body.md").read_text()
    assert "ISSUE created" in result.output


def test_a_non_pass_night_comments_on_the_open_tracking_issue(tmp_path: Path) -> None:
    gh, log = _fake_gh(
        tmp_path, [{"number": 12, "title": ISSUE_TITLE}, {"number": 7, "title": ISSUE_TITLE}]
    )
    (tmp_path / "nightly.json").write_text(json.dumps(FAILED_NIGHT))
    result = CliRunner().invoke(
        app, ["nightly-issue", "--output-dir", str(tmp_path), "--gh", str(gh)]
    )
    assert result.exit_code == 0, result.output
    assert _calls(log)[1][:3] == ["issue", "comment", "7"]
    assert not any(call[:2] == ["issue", "create"] for call in _calls(log))


def test_a_quiet_night_files_nothing_and_a_missing_report_files(tmp_path: Path) -> None:
    gh, log = _fake_gh(tmp_path, [])
    quiet = {**FAILED_NIGHT, "outcomes": FAILED_NIGHT["outcomes"][::2], "needs_issue": False}
    (tmp_path / "nightly.json").write_text(json.dumps(quiet))
    result = CliRunner().invoke(
        app, ["nightly-issue", "--output-dir", str(tmp_path), "--gh", str(gh)]
    )
    assert result.exit_code == 0 and "no issue" in result.output
    assert _calls(log) == []
    (tmp_path / "nightly.json").unlink()
    filed = CliRunner().invoke(
        app, ["nightly-issue", "--output-dir", str(tmp_path), "--gh", str(gh)]
    )
    assert filed.exit_code == 0, filed.output
    assert [call[:2] for call in _calls(log)] == [["issue", "list"], ["issue", "create"]]


def test_issue_filing_uses_only_gh_arguments_and_never_a_token(tmp_path: Path) -> None:
    seen: list[Sequence[str]] = []

    def run(args: Sequence[str]) -> str:
        seen.append(args)
        return "[]" if args[1] == "list" else "https://github.invalid/o/r/issues/1"

    action, reference = file_or_update_issue("body", run=run, body_path=tmp_path / "b.md")
    assert (action, reference) == ("created", "https://github.invalid/o/r/issues/1")
    assert not any("token" in part.lower() for args in seen for part in args)


# --- the workflow -----------------------------------------------------------------------------


def test_the_nightly_job_is_scheduled_reads_signed_scope_and_alone_writes_issues() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    triggers = workflow[True]  # YAML 1.1 reads the key "on" as a boolean
    assert "schedule" in triggers and "workflow_dispatch" in triggers
    assert workflow["permissions"] == {"contents": "read"}
    jobs = workflow["jobs"]
    nightly = jobs["nightly"]
    assert "schedule" in nightly["if"] and "workflow_dispatch" in nightly["if"]
    assert nightly["permissions"] == {"contents": "read", "issues": "write"}
    for name, job in jobs.items():
        if name != "nightly":
            assert "issues" not in job.get("permissions", {}), name
    script = "\n".join(str(step.get("run", "")) for step in nightly["steps"])
    for command in ("nightly-scope", "nightly-lane", "nightly-issue", "playwright install"):
        assert command in script
    # The scope is signed data: no scenario path or repetition count is written in the job.
    assert "scenarios/" not in script and "--repetitions" not in script
    issue_step = next(step for step in nightly["steps"] if "nightly-issue" in step.get("run", ""))
    assert issue_step["if"] == "${{ !cancelled() }}"
    assert issue_step["env"]["GH_TOKEN"] == "${{ github.token }}"  # noqa: S105 -- an Actions expression


def test_phase4_nightly_is_left_as_it_was() -> None:
    phase4 = (ROOT / ".github" / "workflows" / "phase4.yml").read_text()
    assert "scenarios/agent/agent-indirect-ticket.yaml" in phase4
    assert "nightly-lane" not in phase4 and "issues: write" not in phase4
