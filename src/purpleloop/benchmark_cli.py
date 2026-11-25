"""WP5.6 CLI: promote the benchmark subset and run it, reported apart from the authored corpus.

Offline only. Neither command reads a model credential or opens a model endpoint; the stand-ins
are the deterministic scripted models.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer

from purpleloop.runtime.benchmark import (
    STAND_INS,
    SUBSET_DIR,
    benchmark_metrics,
    build_subset,
    committed_subset,
    run_subset,
    subset_drift,
    write_subset,
)


def register(app: typer.Typer) -> None:
    @app.command("benchmark-promote")
    def benchmark_promote(
        write: bool = typer.Option(False, "--write", help="Rewrite the committed subset files"),
    ) -> None:
        """Promote the subset from its hand-authored records; check (default) or rewrite."""
        if write:
            report = write_subset()
        else:
            drift = subset_drift()
            if drift:
                typer.echo(f"FAILED: committed subset differs from its records: {drift}", err=True)
                raise typer.Exit(1)
            _, report, _ = build_subset()
        typer.echo(
            f"attempted={report.attempted} promoted={report.promoted} "
            f"not_promoted={report.not_promoted}"
        )
        for outcome in report.outcomes:
            if not outcome.promoted:
                typer.echo(f"not promoted: {outcome.scenario_id}: {outcome.reason}")

    @app.command("benchmark-run")
    def benchmark_run(
        output_dir: Path = Path("artifacts/benchmark"),
        stand_in: str = typer.Option("all", help="scripted, delimitation-blind, or all"),
        seed: int = 42,
    ) -> None:
        """Run the promoted subset offline and write its metrics, separate from the 48."""
        names = sorted(STAND_INS) if stand_in == "all" else [stand_in]
        if any(name not in STAND_INS for name in names):
            typer.echo(f"FAILED: unknown stand-in {stand_in}", err=True)
            raise typer.Exit(1)
        if subset_drift():
            typer.echo("FAILED: committed subset differs from its records", err=True)
            raise typer.Exit(1)
        occupied = [
            name
            for name in names
            if (output_dir / name).exists() and any((output_dir / name).iterdir())
        ]
        if occupied:
            # A sealed bundle's inventory must match its directory, so a run never writes over
            # an earlier one.
            typer.echo(f"FAILED: output directory not empty for {occupied}", err=True)
            raise typer.Exit(1)
        scenarios = committed_subset()
        _, report, truth = build_subset()
        failed = False
        for name in names:
            try:
                summaries = asyncio.run(
                    run_subset(output_dir / name, scenarios, model=STAND_INS[name](), seed=seed)
                )
            except (OSError, ValueError, RuntimeError) as exc:
                typer.echo(f"FAILED: {name}: {exc}", err=True)
                raise typer.Exit(1) from None
            metrics = benchmark_metrics(
                subset=SUBSET_DIR.name,
                stand_in=name,
                report=report,
                truth=truth,
                scenarios=scenarios,
                summaries=summaries,
            )
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / f"metrics-{name}.json").write_text(
                json.dumps(metrics.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
            )
            corpus = metrics.corpus
            typer.echo(
                f"{name}: promoted={metrics.promoted}/{metrics.attempted} "
                f"authored={metrics.origin_counts['authored']} "
                f"imported={metrics.origin_counts['imported']} "
                f"possibly_contaminated={len(metrics.possibly_contaminated)} "
                f"recall={corpus['seeded_recall']:.3f} "
                # Against the labels, a defended-replay finding counts as a false positive. Under
                # a non-cooperating stand-in it is an uncredited defense, so it is printed as
                # what it observably is rather than under the label's name.
                f"replay_findings={corpus['false_positives']}/{corpus['negative_control_runs']} "
                f"defense_credited={len(metrics.defense_credited)}/{len(summaries)}"
            )
            # The scripted stand-in is what the labels were authored against, so a miss there
            # fails the command. The delimitation-blind run is a measurement of which defenses
            # survive a non-cooperating model; an uncredited defense there is a result.
            if name == "scripted" and any(s.status != "passed" for s in summaries):
                failed = True
        if failed:
            raise typer.Exit(1)
