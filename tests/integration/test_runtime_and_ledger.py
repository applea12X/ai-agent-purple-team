from __future__ import annotations

import asyncio
from typing import Any

import pytest

from purpleloop.adapters import MockReadAdapter
from purpleloop.control import DefaultDenyPolicy, KillSwitch
from purpleloop.runtime import LedgerError, compare_replays
from purpleloop.schemas import (
    ActionRequest,
    ActionTarget,
    AuthorizationManifest,
    TargetObservation,
)


@pytest.mark.asyncio
async def test_completed_read_is_redacted_and_evidenced(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    runtime, adapter, ledger = runtime_factory(manifest=manifest)
    result = await runtime.run(manifest, action, run_id="run-1", trace_id="trace-1")
    assert result.status == "completed"
    assert adapter.invocations == 1
    assert result.result is not None
    rendered = result.model_dump_json()
    assert "CANARY-SECRET" not in rendered
    assert "CREDENTIAL-SECRET" not in rendered
    assert "[REDACTED]" in rendered
    events = ledger.verify()
    assert len(events) == 3


@pytest.mark.asyncio
async def test_denied_action_never_reaches_adapter(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    denied_action = action.model_copy(update={"operation": "admin.read"})
    runtime, adapter, ledger = runtime_factory(manifest=manifest)
    result = await runtime.run(
        manifest, denied_action, run_id="run-denied", trace_id="trace-denied"
    )
    assert result.status == "denied"
    assert adapter.invocations == 0
    assert ledger.verify()[-1].reason_code == "OPERATION_NOT_ALLOWED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        ActionTarget(
            url="http://evil.local:8080/records/record-1",
            tenant_id="tenant-a",
            resource_id="record-1",
        ),
        ActionTarget(
            url="http://fixture.local:8080/records/record-1",
            tenant_id="tenant-b",
            resource_id="record-1",
        ),
    ],
)
async def test_scope_mutation_never_reaches_adapter(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    target: ActionTarget,
    runtime_factory: Any,
) -> None:
    runtime, adapter, _ = runtime_factory(manifest=manifest)
    result = await runtime.run(
        manifest,
        action.model_copy(update={"target": target}),
        run_id="run-scope",
        trace_id="trace-scope",
    )
    assert result.status == "denied"
    assert adapter.invocations == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "observation",
    [
        TargetObservation(
            url="http://evil.local:8080/records/record-1",
            resolved_addresses=("127.0.0.1",),
            hop_index=0,
        ),
        TargetObservation(
            url="http://fixture.local:8080/records/record-1",
            resolved_addresses=("127.0.0.2",),
            hop_index=0,
        ),
        TargetObservation(
            url="http://fixture.local:8080/records/record-2",
            resolved_addresses=("127.0.0.1",),
            hop_index=1,
        ),
    ],
)
async def test_trusted_target_mutation_never_performs_io(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    observation: TargetObservation,
    runtime_factory: Any,
) -> None:
    observations = (
        (
            TargetObservation(
                url=action.target.url,
                resolved_addresses=("127.0.0.1",),
                hop_index=0,
            ),
            observation,
        )
        if observation.hop_index == 1
        else (observation,)
    )
    adapter = MockReadAdapter(observations=observations)
    runtime, _, _ = runtime_factory(manifest=manifest, adapter=adapter)
    result = await runtime.run(
        manifest, action, run_id="run-observed-scope", trace_id="trace-observed-scope"
    )
    assert result.status == "denied"
    assert adapter.invocations == 0


@pytest.mark.asyncio
async def test_unavailable_policy_never_reaches_adapter(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    runtime, adapter, _ = runtime_factory(
        manifest=manifest, policy=DefaultDenyPolicy(available=False)
    )
    result = await runtime.run(manifest, action, run_id="run-policy", trace_id="trace-policy")
    assert result.reason_code == "POLICY_UNAVAILABLE"
    assert adapter.invocations == 0


@pytest.mark.asyncio
async def test_kill_switch_cancels_active_adapter(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    switch = KillSwitch()
    adapter = MockReadAdapter(delay_seconds=30)
    runtime, _, ledger = runtime_factory(manifest=manifest, adapter=adapter, kill_switch=switch)
    task = asyncio.create_task(
        runtime.run(manifest, action, run_id="run-kill", trace_id="trace-kill")
    )
    await asyncio.sleep(0.01)
    await switch.terminate()
    result = await asyncio.wait_for(task, timeout=1)
    assert result.status == "cancelled"
    assert ledger.verify()[-1].reason_code == "CANCELLED"


@pytest.mark.asyncio
async def test_offline_replay_fingerprint_matches(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    first, _, first_ledger = runtime_factory(manifest=manifest)
    second, _, second_ledger = runtime_factory(manifest=manifest)
    first_result = await first.run(manifest, action, run_id="run-replay", trace_id="trace-replay")
    second_result = await second.run(manifest, action, run_id="run-replay", trace_id="trace-replay")
    assert compare_replays(
        first_ledger.verify(),
        second_ledger.verify(),
        first_score_hash=first_result.score_hash,
        second_score_hash=second_result.score_hash,
    )


@pytest.mark.asyncio
async def test_meaningful_fixture_change_changes_replay_and_score_hashes(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    first_adapter = MockReadAdapter({"record-1": {"id": "record-1", "value": "one"}})
    second_adapter = MockReadAdapter({"record-1": {"id": "record-1", "value": "two"}})
    first, _, first_ledger = runtime_factory(manifest=manifest, adapter=first_adapter)
    second, _, second_ledger = runtime_factory(manifest=manifest, adapter=second_adapter)
    first_result = await first.run(
        manifest, action, run_id="first-change", trace_id="first-change-trace"
    )
    second_result = await second.run(
        manifest, action, run_id="second-change", trace_id="second-change-trace"
    )
    assert first_result.score_hash != second_result.score_hash
    assert not compare_replays(first_ledger.verify(), second_ledger.verify())


@pytest.mark.asyncio
async def test_ledger_detects_modification_and_truncation(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    runtime, _, ledger = runtime_factory(manifest=manifest)
    await runtime.run(manifest, action, run_id="run-ledger", trace_id="trace-ledger")
    original = ledger.path.read_text(encoding="utf-8")
    lines = original.splitlines()
    ledger.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        ledger.verify()
    ledger.path.write_text(original.replace("COMPLETED", "ALTERED"), encoding="utf-8")
    with pytest.raises(LedgerError):
        ledger.verify()
