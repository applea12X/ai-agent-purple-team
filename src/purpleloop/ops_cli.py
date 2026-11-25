"""Operational commands closing Phase 0-4 loose ends (docs/phase5/loose-ends.md).

* ``browser-estop`` measures the browser lane's emergency-stop latency (row 2.4).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from purpleloop.reporting.bundle import write_json


def register(app: typer.Typer) -> None:
    @app.command("browser-estop")
    def browser_estop(
        output: Path,
        trials: int = 1000,
        driver: Annotated[
            str, typer.Option(help="html-form (in process) or playwright-chromium")
        ] = "html-form",
    ) -> None:
        """Measure kill-switch-to-stop latency while browser adapter activity is in flight."""
        from purpleloop.runtime.browser_estop import measure

        if driver not in {"html-form", "playwright-chromium"}:
            typer.echo("INVALID: --driver is html-form or playwright-chromium", err=True)
            raise typer.Exit(2)
        if trials < 2:
            typer.echo("INVALID: --trials must be at least 2 for a p99", err=True)
            raise typer.Exit(2)
        record = asyncio.run(measure(trials, driver_name=driver))  # type: ignore[arg-type]
        output.parent.mkdir(parents=True, exist_ok=True)
        write_json(output, record)
        typer.echo(
            json.dumps(
                {
                    key: record.get(key)
                    for key in (
                        "driver",
                        "trials_counted",
                        "trials_fully_stopped",
                        "stop_p99_ms",
                        "stop_max_ms",
                        "within_ceiling",
                    )
                }
            )
        )
        if record["trials_fully_stopped"] != record["trials_attempted"] or not record.get(
            "within_ceiling"
        ):
            raise typer.Exit(1)
