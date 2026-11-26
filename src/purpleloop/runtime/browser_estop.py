"""Browser-lane emergency-stop latency, measured the way Phase 0 measured the kill switch.

Phase 0 measured cooperative in-process cancellation: 1,000 independent trials, each waiting until
adapter activity had started, then timing ``KillSwitch.terminate()`` to the stop. The browser lane
needs its own figure because the browser can be an out-of-process child (Chromium under
Playwright), and the Phase 2 record held none (``docs/phase5/loose-ends.md`` row 2.4).

Each trial here is a whole supportlab run of ``bola-ticket-ui`` on a fresh fixture, fresh kernel,
and fresh browser driver. The fixture's data app holds the first ``/ui/`` page request open, so at
the moment of the kill the browser adapter is mid-navigation: a request is in flight inside the
driver. Pre-start trials are not counted, as in Phase 0; a trial whose page request never arrived
is recorded as a failure instead.

What a trial times, from the ``perf_counter()`` taken immediately before ``terminate()``:

* ``stop``: ``terminate()`` has returned. It cancels every kernel task and awaits them, and the
  browser adapter's ``finally`` path awaits the session close and the driver shutdown, so this is
  the point at which the browser is down. The trial then checks that it really is: the driver
  reports not alive and, for Playwright, every browser process seen before the kill has exited.
* ``run_return``: the runner has finished its own teardown and evidence write and re-raised the
  cancellation. Reported beside ``stop``; it is not the emergency-stop figure.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import platform
import subprocess
import tempfile
import time
from asyncio import FIRST_COMPLETED
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from datetime import UTC, datetime
from pathlib import Path
from statistics import quantiles
from typing import Any, Literal, cast

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.adapters.browser import BrowserDriver, HtmlFormDriver
from purpleloop.control import phase2_tools
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    ServedSupportlab,
    actor_credentials,
    build_supportlab_runner,
    supportlab_manifest,
)
from purpleloop.schemas.phase1 import RunSummary, load_scenario

SCHEMA = "purpleloop.browser-emergency-stop/1"
CEILING_MS = 2000.0
SCENARIO = ROOT / "scenarios" / "supportlab" / "bola-ticket-ui.yaml"
CONTROL = "SUPPORTLAB-CONTROL-SECRET"
START_TIMEOUT = 15.0
DriverName = Literal["html-form", "playwright-chromium"]
Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
#: Builds the trial's driver; the in-process driver is handed the held data transport.
DriverFactory = Callable[[Mapping[int, httpx.ASGITransport] | None], BrowserDriver]


class StallFirstPage:
    """ASGI wrapper that holds the first browser page request open until released.

    API calls share the data app, so only ``/ui/`` paths, which only the browser requests, are
    held. ``started`` is set when the held request reaches the fixture: browser activity is then
    in flight. The hold ends on ``release`` or after 30 seconds, whichever is first.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.held = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and str(scope["path"]).startswith("/ui/") and not self.held:
            self.held = True
            self.started.set()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.release.wait(), timeout=30)
        await self.app(scope, receive, send)


def descendant_pids(root: int) -> set[int]:  # pragma: no cover - browser lane
    """Every live descendant process of ``root``, from one ``ps`` listing."""
    with subprocess.Popen(  # noqa: S603 -- fixed argv, no shell
        ["/bin/ps", "-A", "-o", "pid=,ppid="], stdout=subprocess.PIPE, text=True
    ) as lister:
        listing, _ = lister.communicate()
        own = lister.pid  # the listing process itself is not part of the browser
    children: dict[int, list[int]] = {}
    for line in listing.splitlines():
        pid, ppid = (int(part) for part in line.split())
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    frontier = [root]
    while frontier:
        for child in children.get(frontier.pop(), []):
            if child not in found and child != own:
                found.add(child)
                frontier.append(child)
    return found


def pid_alive(pid: int) -> bool:  # pragma: no cover - browser lane
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def one_trial(
    index: int,
    *,
    driver_name: DriverName,
    work: Path,
    key: Ed25519PrivateKey,
    driver_factory: DriverFactory | None = None,
) -> dict[str, Any]:
    """Run one kill-during-browser-activity trial and return its raw record."""
    manifest = supportlab_manifest(key, seed=42)
    verifier = ManifestVerifier({KEY_ID: key.public_key()})
    scenario = load_scenario(SCENARIO)
    tokens = actor_credentials()
    directory = work / f"trial-{index:04d}"
    fixture: InProcessSupportlab | ServedSupportlab
    driver: BrowserDriver
    if driver_name == "html-form":
        in_process = InProcessSupportlab(tokens, CONTROL)
        assert in_process.transports is not None
        data = in_process.transports[phase2_tools.DATA_PORT]
        stall = StallFirstPage(data.app)
        in_process.transports[phase2_tools.DATA_PORT] = httpx.ASGITransport(app=stall)
        transports = {phase2_tools.DATA_PORT: in_process.transports[phase2_tools.DATA_PORT]}
        driver = driver_factory(transports) if driver_factory else HtmlFormDriver(transports)
        fixture = in_process
    else:  # pragma: no cover - browser lane
        from purpleloop.adapters.browser import PlaywrightDriver

        served = ServedSupportlab(tokens, CONTROL)
        server = served._servers[0]
        stall = StallFirstPage(cast(ASGIApp, server.config.app))
        server.config.app = stall
        await served.start()
        driver = driver_factory(None) if driver_factory else PlaywrightDriver()
        fixture = served
    runner = build_supportlab_runner(
        directory,
        manifest,
        verifier,
        actor_tokens=tokens,
        control=CONTROL,
        fixture=fixture,
        browser_driver=driver,
    )
    switch = runner.runtime.kill_switch
    task = asyncio.create_task(
        runner.run(scenario, manifest, run_id=f"estop-{index}", output_dir=directory)
    )
    record: dict[str, Any] = {"trial": index, "started": False}
    # Wait for the held request, or for the run to end without one (a pre-start failure).
    arrival = asyncio.create_task(stall.started.wait())
    await asyncio.wait({arrival, task}, timeout=START_TIMEOUT, return_when=FIRST_COMPLETED)
    arrival.cancel()
    if not stall.started.is_set():
        record["failure"] = "browser page request never reached the fixture"
        stall.release.set()
        await switch.terminate()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
        return record
    record["started"] = True
    before = (
        descendant_pids(os.getpid()) if driver_name == "playwright-chromium" else set()
    )  # the browser is fully up: it has already sent the held request
    began = time.perf_counter()
    await switch.terminate()
    stopped = time.perf_counter()
    # Checked immediately, before anything else is awaited, so a late exit is not credited.
    record["driver_alive_after_stop"] = driver.alive
    record["processes_before"] = len(before)
    record["processes_alive_after_stop"] = sum(1 for pid in before if pid_alive(pid))
    stall.release.set()
    cancelled = False
    try:
        await task
    except asyncio.CancelledError:
        cancelled = True
    returned = time.perf_counter()
    summary = RunSummary.model_validate_json((directory / "summary.json").read_text())
    record.update(
        stop_ms=round((stopped - began) * 1000, 4),
        run_return_ms=round((returned - began) * 1000, 4),
        run_cancelled=cancelled,
        summary_reason=summary.reason,
        fixture_closed=bool(fixture.closed),
    )
    return record


def p99(samples: list[float]) -> float:
    """Phase 0's estimator: the 99th of 100 inclusive quantiles."""
    return quantiles(samples, n=100, method="inclusive")[98]


def fully_stopped(trial: dict[str, Any]) -> bool:
    """The browser is down, every browser process has exited, and the run stopped as cancelled."""
    return bool(
        trial["started"]
        and not trial["driver_alive_after_stop"]
        and trial["processes_alive_after_stop"] == 0
        and trial["run_cancelled"]
        and str(trial["summary_reason"]).startswith("CANCELLED")
        and trial["fixture_closed"]
    )


def summarize(
    trials: list[dict[str, Any]], *, driver_name: DriverName, version: dict[str, str]
) -> dict[str, Any]:
    """Aggregate raw trial records.

    The per-trial latencies are kept in trial order, so every figure here can be recomputed from
    the record itself; any trial that did not start or did not fully stop is kept whole.
    """
    counted = [trial for trial in trials if trial["started"]]
    stops = [float(trial["stop_ms"]) for trial in counted]
    returns = [float(trial["run_return_ms"]) for trial in counted]
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "driver": driver_name,
        "driver_version": version,
        "scenario": SCENARIO.name,
        "trials_attempted": len(trials),
        "trials_counted": len(counted),
        "trials_not_started": len(trials) - len(counted),
        "trials_fully_stopped": sum(1 for trial in counted if fully_stopped(trial)),
        "browser_processes_seen": sum(int(trial["processes_before"]) for trial in counted),
        "ceiling_ms": CEILING_MS,
    }
    if len(stops) >= 2:
        result.update(
            stop_p50_ms=round(quantiles(stops, n=2, method="inclusive")[0], 4),
            stop_p99_ms=round(p99(stops), 4),
            stop_max_ms=round(max(stops), 4),
            run_return_p99_ms=round(p99(returns), 4),
            within_ceiling=p99(stops) <= CEILING_MS,
        )
    result.update(
        stop_ms=stops,
        run_return_ms=returns,
        anomalies=[trial for trial in trials if not fully_stopped(trial)],
    )
    return result


async def measure(
    trials: int,
    *,
    driver_name: DriverName = "html-form",
    work: Path | None = None,
    driver_factory: DriverFactory | None = None,
) -> dict[str, Any]:
    """Run ``trials`` independent trials and return the summary with every raw trial in it."""
    started_at = datetime.now(UTC)
    clock = time.monotonic()
    key = Ed25519PrivateKey.generate()
    records: list[dict[str, Any]] = []
    version: dict[str, str] = {}
    if driver_name == "playwright-chromium":  # pragma: no cover - browser lane
        from purpleloop.adapters.browser import PlaywrightDriver

        # The Chromium version is only readable while a browser is up, so one is started briefly,
        # outside every timed trial.
        probe = PlaywrightDriver()
        await probe.start()
        version = probe.version()
        await probe.shutdown()
    with tempfile.TemporaryDirectory(prefix="purpleloop-estop-") as scratch:
        root = work or Path(scratch)
        for index in range(trials):
            records.append(
                await one_trial(
                    index,
                    driver_name=driver_name,
                    work=root,
                    key=key,
                    driver_factory=driver_factory,
                )
            )
    if not version:
        version = HtmlFormDriver({}).version() if driver_name == "html-form" else {}
    summary = summarize(records, driver_name=driver_name, version=version)
    summary.update(
        method=(
            "Each trial: a fresh supportlab run of bola-ticket-ui, fresh kernel and driver; the "
            "fixture holds the first /ui/ page request open; once it arrives, time "
            "KillSwitch.terminate() from just before the call to its return (stop), and to the "
            "runner re-raising the cancellation (run_return). Pre-start trials are not counted."
        ),
        machine={
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        started_at=started_at.isoformat(timespec="seconds"),
        wall_seconds=round(time.monotonic() - clock, 2),
    )
    return summary
