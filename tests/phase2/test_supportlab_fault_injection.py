from __future__ import annotations

import asyncio
from typing import Any

import pytest

from purpleloop.schemas.phase1 import Stage


async def test_browser_emergency_stop_kills_the_driver(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    """A cancelled browser flow tears the driver down; it is an out-of-process child."""
    from purpleloop.adapters.browser import BrowserAdapter

    scenario = next(s for s in supportlab_scenarios if s.scenario_id == "bola-ticket-ui")
    runner, fixture, directory = make_supportlab_runner()
    browser = runner.runtime.adapter._adapters[("browser", "ui.ticket.view")]
    assert isinstance(browser, BrowserAdapter)
    shutdowns: list[int] = []
    original_shutdown = browser.driver.shutdown

    async def counting_shutdown() -> None:
        shutdowns.append(1)
        await original_shutdown()

    browser.driver.shutdown = counting_shutdown  # type: ignore[method-assign]

    async def cancel_during_attack(stage: Stage) -> None:
        if stage == Stage.REPLAY:
            raise asyncio.CancelledError

    runner.stage_hook = cancel_during_attack
    with pytest.raises(asyncio.CancelledError):
        await runner.run(scenario, supportlab_signed, run_id="kill", output_dir=directory)
    assert fixture.closed


async def test_snapshot_mismatch_fails_closed(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = next(s for s in supportlab_scenarios if s.scenario_id == "bola-ticket")
    runner, fixture, directory = make_supportlab_runner()

    async def corrupt_after_seed(stage: Stage) -> None:
        if stage == Stage.SEED:
            # Tamper with the seeded database so the first leg's snapshot hash cannot match.
            fixture.state.database.execute(
                "UPDATE orgs SET name = ? WHERE id = ?", ("tampered", "org-a")
            )
            fixture.state.database.commit()

    runner.stage_hook = corrupt_after_seed
    result = await runner.run(scenario, supportlab_signed, run_id="mismatch", output_dir=directory)
    assert result.status == "error"
    assert fixture.closed and result.teardown_complete


async def test_database_unavailable_tears_down(
    make_supportlab_runner: Any, supportlab_scenarios: Any, supportlab_signed: Any
) -> None:
    scenario = next(s for s in supportlab_scenarios if s.scenario_id == "bola-ticket")
    runner, fixture, directory = make_supportlab_runner()

    async def drop_database(stage: Stage) -> None:
        if stage == Stage.SEED:
            fixture.state.database.teardown()

    runner.stage_hook = drop_database
    result = await runner.run(scenario, supportlab_signed, run_id="db-down", output_dir=directory)
    assert result.status == "error" and fixture.closed
