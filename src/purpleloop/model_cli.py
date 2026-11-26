"""Model-plane CLI: calibrate a pin, check a run against its calibration, check containment.

All three read verified bundles and nothing else; none calls a model. ``calibrate-pin`` writes
the committed reference document a pin's pre-run estimate is built from (WP5.0.3);
``calibration-check`` reports a later run's tokens and cost against it with the +/-10% machinery;
``containment-check`` holds the compromised-model property over any run's evidence, which is how
it is applied to a real model's intent distribution (WP5.0.6).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from purpleloop.control.model_config import (
    calibration_dir,
    calibration_filename,
    load_calibration,
)
from purpleloop.reporting.bundle import write_json
from purpleloop.scoring.calibration import (
    CalibrationError,
    check_against,
    compute_calibration,
    read_calls,
)
from purpleloop.scoring.containment import check_tree


def register(app: typer.Typer) -> None:
    @app.command("calibrate-pin")
    def calibrate_pin(
        source: Annotated[Path, typer.Argument(help="A bundle, a suite, or a directory of runs")],
        output: Annotated[
            Path | None,
            typer.Option(help="Where to write; default baselines/model-calibration/<pin>.json"),
        ] = None,
        pin_id: Annotated[
            str | None, typer.Option(help="Only calls under this pin id")
        ] = "networked",
        min_calls: int = 1,
    ) -> None:
        """Compute a pin's per-call token expectations from a measured run's model calls."""
        try:
            calibration = compute_calibration(
                read_calls(source, pin_id=pin_id or None), min_calls=min_calls
            )
        except (CalibrationError, OSError, ValueError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        target = output or calibration_dir() / calibration_filename(
            calibration.provider, calibration.model_id, calibration.model_version
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        write_json(target, calibration.model_dump(mode="json"))
        typer.echo(
            f"calibrated {calibration.provider}/{calibration.model_id}@"
            f"{calibration.model_version or 'unversioned'}: "
            f"input={calibration.expected_input_tokens_per_call} "
            f"[{calibration.input_tokens_min},{calibration.input_tokens_max}] "
            f"output={calibration.expected_output_tokens_per_call} "
            f"[{calibration.output_tokens_min},{calibration.output_tokens_max}] "
            f"n={calibration.calls} bundles={calibration.bundles} -> {target}"
        )

    @app.command("calibration-check")
    def calibration_check(
        source: Annotated[Path, typer.Argument(help="A bundle, a suite, or a directory of runs")],
        calibration: Annotated[Path, typer.Option(help="The committed calibration file")],
        output: Path | None = None,
        pin_id: str | None = "networked",
    ) -> None:
        """A run's actual tokens and cost against a held-fixed calibration, with the delta."""
        try:
            held = load_calibration(calibration)
            result = check_against(read_calls(source, pin_id=pin_id or None), held)
        except (CalibrationError, OSError, ValueError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        accounting = result.accounting
        payload = {
            "schema_version": "1.5.0",
            "calibration": held.model_dump(mode="json"),
            "calls": result.calls,
            "estimate_is_bound": result.estimate_is_bound,
            "price_input_microusd_per_1k": result.pin.price_input_microusd_per_1k,
            "price_output_microusd_per_1k": result.pin.price_output_microusd_per_1k,
            "accounting": accounting.model_dump(mode="json"),
        }
        if output is not None:
            write_json(output, payload)
        typer.echo(
            f"calls={result.calls} tokens estimated={accounting.estimated_tokens} "
            f"actual={accounting.actual_tokens} delta={accounting.delta_percent['tokens']:+.2f}% "
            f"within={accounting.within_tolerance['tokens']} "
            f"cost estimated={accounting.estimated_cost_microusd} "
            f"actual={accounting.actual_cost_microusd} "
            f"delta={accounting.delta_percent['cost_microusd']:+.2f}% "
            f"within={accounting.within_tolerance['cost_microusd']}"
        )

    @app.command("containment-check")
    def containment_check(
        source: Annotated[Path, typer.Argument(help="A bundle, a suite, or a directory of runs")],
        output: Path | None = None,
    ) -> None:
        """Hold the compromised-model property over every bundle's evidence (WP5.0.6)."""
        try:
            report = check_tree(source)
        except (OSError, ValueError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        payload = report.to_json()
        if output is not None:
            write_json(output, payload)
        totals = payload["totals"]
        typer.echo(
            f"bundles={payload['bundles']} model_calls={totals['model_calls']} "
            f"proposed={totals['proposed_intents']} compiled={totals['compiled_intents']} "
            f"rejected={totals['rejected_intents']} refused={totals['refused_intents']} "
            f"failed={totals['failed_intents']} "
            f"invented={len(payload['invented_operations'])} "
            f"violations={len(payload['violations'])}"
        )
        for violation in payload["violations"][:50]:
            typer.echo(f"VIOLATION {violation}", err=True)
        if not payload["holds"]:
            raise typer.Exit(1)
