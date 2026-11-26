"""WP5.5 against the real sandbox container (``compose.codelab.yaml``).

Gated like every container lane: ``PURPLELOOP_CONTAINER_TESTS=1``. These are the tests the
containment claims rest on -- the in-process lane's stub never runs a snippet, so it cannot
support any of them.

- the escape suite: every attempt contained, zero breaches, under the recorded runtime;
- the stub calibration: every snippet the stub simulates gives the same exit code, output, and
  files in the real sandbox;
- the corpus on the container agrees with the in-process lane on every status and oracle hash.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.runtime import codelab
from purpleloop.runtime.codelab_escape import calibrate_stub, load_suite, run_escape_suite

pytestmark = pytest.mark.skipif(
    os.environ.get("PURPLELOOP_CONTAINER_TESTS") != "1",
    reason="codelab container lane: needs Docker (PURPLELOOP_CONTAINER_TESTS=1)",
)


def test_every_escape_attempt_is_contained(tmp_path: Path) -> None:
    report = asyncio.run(run_escape_suite(tmp_path, load_suite(codelab.ESCAPE_SUITE)))
    assert report.breaches == (), [a for a in report.attempts if not a.contained]
    assert report.contained == len(report.attempts) == 10
    security = report.container_security
    assert security["NetworkMode"] == "none" and security["IpcMode"] == "none"
    assert security["ReadonlyRootfs"] is True and security["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in security["SecurityOpt"]
    # Docker's default seccomp profile is in force when none is overridden.
    assert not any("seccomp" in option for option in security["SecurityOpt"])
    assert security["PidsLimit"] == 64 and security["Memory"] == 256 << 20
    assert report.runtime in {"runc", "runsc"}


def test_the_stub_is_a_recording_of_the_real_sandbox(tmp_path: Path) -> None:
    result = asyncio.run(calibrate_stub(tmp_path))
    assert result["snippets"] >= 10
    assert result["mismatches"] == []


def test_the_container_corpus_agrees_with_the_in_process_lane(tmp_path: Path) -> None:
    async def both() -> tuple[list[object], list[object]]:
        key = Ed25519PrivateKey.generate()
        approval = await codelab.approve(tmp_path / "gov", key)
        corpus = codelab.load_corpus()
        local = [
            await codelab.run_scenario(
                tmp_path / "local" / s.scenario_id, s, approval, inspect=False
            )
            for s in corpus
        ]
        fixture = codelab.ComposeCodelab(
            codelab.actor_credentials(), "c" * 48, project="purpleloop-codelab-agree", keep=True
        )
        try:
            remote = [
                await codelab.run_scenario(
                    tmp_path / "remote" / s.scenario_id, s, approval, fixture=fixture, inspect=False
                )
                for s in corpus
            ]
        finally:
            await fixture.down()
        return local, remote

    local, remote = asyncio.run(both())
    for here, there in zip(local, remote, strict=True):
        assert here.status == there.status == "passed", (here.scenario_id, there.reason)  # type: ignore[attr-defined]
        assert here.oracle_hash == there.oracle_hash, here.scenario_id  # type: ignore[attr-defined]
