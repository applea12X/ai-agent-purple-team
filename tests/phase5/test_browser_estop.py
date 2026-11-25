"""Browser-lane emergency-stop latency (loose end 2.4): the record and the method behind it.

The Phase 2 record stored ``{"measured": true}`` and no latency. These tests make that shape of
failure impossible to repeat quietly: the committed figures must be recomputable from the raw
per-trial samples they ship with, and the measurement itself must be shown to time the browser
teardown and to refuse credit for a browser that did not stop.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from pathlib import Path
from statistics import quantiles
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from purpleloop.adapters.browser import BrowserDriver, HtmlFormDriver
from purpleloop.cli import app
from purpleloop.runtime.browser_estop import CEILING_MS, SCHEMA, measure
from purpleloop.runtime.demo import ROOT

EVIDENCE = ROOT / "docs" / "phase5" / "evidence"
DRIVERS = ("html-form", "playwright-chromium")


def _p99(samples: list[float]) -> float:
    return quantiles(samples, n=100, method="inclusive")[98]


@pytest.mark.parametrize("driver", DRIVERS)
def test_the_committed_figure_is_recomputable_from_its_own_samples(driver: str) -> None:
    record = json.loads((EVIDENCE / f"browser-estop-{driver}.json").read_text())
    assert record["schema"] == SCHEMA
    assert record["driver"] == driver
    # Phase 0's methodology: at least 1,000 trials, every counted one had activity in flight.
    assert record["trials_attempted"] >= 1000
    assert record["trials_counted"] == record["trials_attempted"]
    assert record["trials_not_started"] == 0
    assert record["trials_fully_stopped"] == record["trials_counted"]
    assert record["anomalies"] == []
    stops: list[float] = record["stop_ms"]
    returns: list[float] = record["run_return_ms"]
    assert len(stops) == len(returns) == record["trials_counted"]
    # A faked figure would have to fake a plausible sample too: real timings are positive, vary,
    # and the run returns only after the stop it contains.
    assert all(value > 0 for value in stops)
    assert len(set(stops)) > len(stops) // 2
    assert all(run >= stop for stop, run in zip(stops, returns, strict=True))
    assert record["stop_p99_ms"] == round(_p99(stops), 4)
    assert record["stop_max_ms"] == round(max(stops), 4)
    assert record["run_return_p99_ms"] == round(_p99(returns), 4)
    assert record["within_ceiling"] is (_p99(stops) <= CEILING_MS)
    assert record["within_ceiling"] is True
    if driver == "playwright-chromium":
        # Each trial saw real browser processes before the kill, and none survived it.
        assert record["browser_processes_seen"] >= record["trials_counted"]
        assert record["driver_version"]["playwright"] == "1.58.0"
        assert record["driver_version"]["chromium"] != "not-started"


async def test_live_trials_stop_the_browser_while_a_page_is_in_flight() -> None:
    record = await measure(20)
    assert record["trials_counted"] == 20
    assert record["trials_fully_stopped"] == 20
    assert record["stop_p99_ms"] < CEILING_MS


class SlowShutdownDriver(HtmlFormDriver):
    """A driver whose teardown takes a known 80 ms, as a browser process exit would."""

    async def shutdown(self) -> None:
        await asyncio.sleep(0.08)
        await super().shutdown()


class ImmortalDriver(HtmlFormDriver):
    """A driver that survives its own shutdown: a browser the stop failed to kill."""

    async def shutdown(self) -> None:
        return None


async def test_the_timed_window_includes_the_browser_teardown() -> None:
    def factory(transports: Mapping[int, httpx.ASGITransport] | None) -> BrowserDriver:
        assert transports is not None
        return SlowShutdownDriver(transports)

    record = await measure(5, driver_factory=factory)
    assert record["trials_fully_stopped"] == 5
    # If the stop were timed before the adapter's finally path ran, these would be ~10 ms.
    assert min(record["stop_ms"]) >= 80.0


async def test_a_browser_that_survives_the_stop_is_never_counted_as_stopped() -> None:
    def factory(transports: Mapping[int, httpx.ASGITransport] | None) -> BrowserDriver:
        assert transports is not None
        return ImmortalDriver(transports)

    record = await measure(3, driver_factory=factory)
    assert record["trials_counted"] == 3
    assert record["trials_fully_stopped"] == 0
    assert [trial["driver_alive_after_stop"] for trial in record["anomalies"]] == [True] * 3


async def test_a_trial_whose_browser_never_started_is_not_counted() -> None:
    class BrokenDriver(HtmlFormDriver):
        async def open(self, **kwargs: Any) -> Any:
            raise ValueError("browser failed to launch")

    def factory(transports: Mapping[int, httpx.ASGITransport] | None) -> BrowserDriver:
        assert transports is not None
        return BrokenDriver(transports)

    record = await measure(2, driver_factory=factory)
    assert record["trials_counted"] == 0
    assert record["trials_not_started"] == 2
    assert "stop_p99_ms" not in record
    assert all(trial["failure"] for trial in record["anomalies"])


def test_the_cli_writes_the_record_and_refuses_too_few_trials(tmp_path: Path) -> None:
    output = tmp_path / "estop.json"
    result = CliRunner().invoke(app, ["browser-estop", str(output), "--trials", "3"])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["trials_fully_stopped"] == 3
    assert CliRunner().invoke(app, ["browser-estop", str(output), "--trials", "1"]).exit_code == 2
    refused = CliRunner().invoke(app, ["browser-estop", str(output), "--driver", "firefox"])
    assert refused.exit_code == 2


@pytest.mark.skipif(
    os.environ.get("PURPLELOOP_CONTAINER_TESTS") != "1",
    reason="browser lane: needs Playwright's Chromium (PURPLELOOP_CONTAINER_TESTS=1)",
)
async def test_live_playwright_trials_kill_every_chromium_process() -> None:  # pragma: no cover
    record = await measure(3, driver_name="playwright-chromium")
    assert record["trials_fully_stopped"] == 3
    assert record["browser_processes_seen"] >= 3
    assert record["stop_p99_ms"] < CEILING_MS
