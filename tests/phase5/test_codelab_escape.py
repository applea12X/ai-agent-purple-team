"""WP5.5.4 -- the escape suite's data and its containment decision, without a container.

The decision is a pure function of recorded observations, so it is tested against constructed
escapes: every check must be able to fail. A check that could not fail would make "0 escapes"
a number nobody measured.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from purpleloop.runtime import codelab
from purpleloop.runtime.codelab_escape import (
    CHECKS,
    REQUIRED_CATEGORIES,
    EscapeAttempt,
    Observation,
    evaluate_attempt,
    load_suite,
    parse_report,
)

SUITE = load_suite(codelab.ESCAPE_SUITE)
ZERO = "0000000000000000"
SECRET = "CODELAB-OUTSIDE-test"  # noqa: S105 -- a synthetic canary, not a credential


def contained_observation() -> Observation:
    """A run in which every check holds -- the shape a real contained attempt records."""
    return Observation(
        status="completed",
        reason_code="COMPLETED",
        value={"timed_out": True, "exit_code": -9, "swept_processes": 3, "stdout": ""},
        elapsed_seconds=3.2,
        report={
            "public-ip": "BLOCKED OSError",
            "interfaces_up": ["lo"],
            "routes": [],
            "/etc/x": "BLOCKED OSError",
            "bytes_written": 15_000_000,
            "large_file": "BLOCKED OSError",
            "fill": "BLOCKED OSError",
            "/proc/1/environ": "BLOCKED PermissionError",
            "ipc_listing": ["broker.sock"],
            "environment": ["HOME", "LANG", "PATH"],
            "allocate_1GiB": "BLOCKED MemoryError",
            "setuid": "BLOCKED PermissionError",
            "CapEff": ZERO,
            "CapPrm": ZERO,
            "NoNewPrivs": "1",
            "Seccomp": "2",
            "ptrace_attach_supervisor": "BLOCKED errno 1",
        },
        listener_connections=0,
        container_diff=(),
        container_diff_baseline=(),
        network_mode="none",
        ipc_listing=("broker.sock",),
        processes_after=1,
        pids_peak=64,
        oom_killed=False,
        rejected_before=0,
        rejected_after=1,
        probe_ok=True,
        secrets=(SECRET,),
    )


def every_check() -> EscapeAttempt:
    return EscapeAttempt(
        attempt_id="all-checks",
        category="network-egress",
        description="every check at once",
        code="pass",
        checks=tuple(CHECKS),
    )


def test_the_suite_attempts_every_required_class_with_known_checks() -> None:
    assert REQUIRED_CATEGORIES <= {attempt.category for attempt in SUITE.attempts}
    assert len(SUITE.attempts) == 10
    assert all(len(attempt.code) <= 2000 for attempt in SUITE.attempts)
    # Every class is decided by at least one observation taken outside the snippet.
    outside = {
        "listener-untouched",
        "network-mode-none",
        "container-layer-unchanged",
        "ipc-volume-unchanged",
        "broker-refused-forgery",
        "pids-bounded",
        "no-leftover-process",
        "not-oom-killed",
        "sandbox-alive",
        "timed-out",
        "processes-swept",
    }
    for category in REQUIRED_CATEGORIES:
        checks = {c for a in SUITE.attempts if a.category == category for c in a.checks}
        assert checks & outside, category


def test_a_clean_observation_is_contained() -> None:
    outcome = evaluate_attempt(every_check(), contained_observation())
    assert outcome.contained, {k: v for k, v in outcome.checks.items() if not v}


BREACHES: dict[str, dict[str, Any]] = {
    "no-network-success": {"report": {"public-ip": "CONNECTED"}},
    "listener-untouched": {"listener_connections": 1},
    "loopback-only": {"report": {"interfaces_up": ["lo", "eth0"], "routes": []}},
    "network-mode-none": {"network_mode": "bridge"},
    "no-write-success": {"report": {"/etc/x": "WROTE"}},
    "container-layer-unchanged": {"container_diff": ("A /etc/x",)},
    "ipc-volume-unchanged": {"ipc_listing": ("broker.sock", "codelab-escape")},
    "tmpfs-bounded": {
        "report": {"bytes_written": 64 << 20, "large_file": "WROTE", "fill": "WROTE"}
    },
    "no-outside-secret": {"value": {"stdout": f"leaked {SECRET}"}},
    "broker-refused-forgery": {"rejected_after": 0},
    "timed-out": {"value": {"timed_out": False}},
    "pids-bounded": {"pids_peak": 65},
    "no-leftover-process": {"processes_after": 2},
    "processes-swept": {"value": {"swept_processes": 0}},
    "allocation-refused": {"report": {"allocate_1GiB": "ALLOCATED"}},
    "not-oom-killed": {"oom_killed": True},
    "no-privilege": {"report": {"setuid": "ESCALATED"}},
    "sandbox-alive": {"probe_ok": False},
}


def test_every_check_has_a_constructed_breach() -> None:
    assert set(BREACHES) == set(CHECKS)


@pytest.mark.parametrize("check", sorted(BREACHES))
def test_each_check_fails_on_its_breach(check: str) -> None:
    base = contained_observation()
    change = dict(BREACHES[check])
    if "report" in change:
        change["report"] = {**(base.report or {}), **change["report"]}
    if "value" in change:
        change["value"] = {**base.value, **change["value"]}
    breached = dataclasses.replace(base, **change)
    attempt = every_check().model_copy(update={"checks": (check,)})
    outcome = evaluate_attempt(attempt, breached)
    assert not outcome.contained and outcome.checks == {check: False}


def test_an_unevaluable_check_and_a_kernel_refusal_are_not_containment() -> None:
    missing = dataclasses.replace(contained_observation(), report=None)
    assert not evaluate_attempt(every_check(), missing).contained
    refused = dataclasses.replace(contained_observation(), status="denied")
    assert not evaluate_attempt(every_check(), refused).contained
    no_secrets = dataclasses.replace(contained_observation(), secrets=())
    attempt = every_check().model_copy(update={"checks": ("no-outside-secret",)})
    assert not evaluate_attempt(attempt, no_secrets).contained


def test_the_loader_refuses_unknown_checks_and_missing_classes(tmp_path: Any) -> None:
    raw = SUITE.model_dump(mode="json")
    raw["attempts"][0]["checks"] = ["trust-me"]
    bad = tmp_path / "bad.json"
    import json

    bad.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="unknown escape checks"):
        load_suite(bad)
    raw = SUITE.model_dump(mode="json")
    raw["attempts"] = [a for a in raw["attempts"] if a["category"] != "fork-bomb"]
    bad.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="does not attempt"):
        load_suite(bad)


def test_a_redacted_leak_is_still_a_leak() -> None:
    """Results come back from the kernel redacted, so a leaked secret shows up as the marker."""
    leaked = dataclasses.replace(contained_observation(), value={"stdout": "[REDACTED]"})
    attempt = every_check().model_copy(update={"checks": ("no-outside-secret",)})
    assert not evaluate_attempt(attempt, leaked).contained


def test_parse_report_reads_the_last_json_line_only() -> None:
    assert parse_report('noise\n{"a": 1}\n') == {"a": 1}
    assert parse_report("no json here") is None
