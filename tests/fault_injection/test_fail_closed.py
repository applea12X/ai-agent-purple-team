from __future__ import annotations

from typing import Any

import pytest

from purpleloop.runtime import LedgerError
from purpleloop.schemas import ActionRequest, AuthorizationManifest


@pytest.mark.asyncio
async def test_partial_ledger_write_is_detected(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    runtime, _, ledger = runtime_factory(manifest=manifest)
    await runtime.run(manifest, action, run_id="run-partial", trace_id="trace-partial")
    with ledger.path.open("a", encoding="utf-8") as stream:
        stream.write('{"partial":')
    with pytest.raises(LedgerError):
        ledger.verify()


@pytest.mark.asyncio
async def test_invalid_signature_never_invokes_adapter(
    manifest: AuthorizationManifest,
    action: ActionRequest,
    runtime_factory: Any,
) -> None:
    tampered = manifest.model_copy(update={"owner": "attacker"})
    runtime, adapter, ledger = runtime_factory(manifest=manifest)
    result = await runtime.run(tampered, action, run_id="run-signature", trace_id="trace-signature")
    assert result.reason_code == "INVALID_SIGNATURE"
    assert adapter.invocations == 0
    assert ledger.verify()[-1].reason_code == "INVALID_SIGNATURE"
