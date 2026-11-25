"""Phase 5 CLI: contract inspection now; shadow runs, approvals, the matrix, and review later.

Registered into the main ``purpleloop`` app the same way ``phase4_cli`` is. Each Phase 5 work
package appends its own commands inside :func:`register` (WP5.1 ``shadow-run``/``approve``/
``approval-check``, WP5.0.8 ``adjudicate``, WP5.4 ``review``), so this module starts with only
the command that reports which contract versions the installed code speaks.
"""

from __future__ import annotations

import json

import typer

from purpleloop import telemetry_cli
from purpleloop.review import cli as review_cli
from purpleloop.schemas.phase5 import CONTRACT_VERSIONS


def register(app: typer.Typer) -> None:
    telemetry_cli.register(app)  # WP5.3 observe-suite, telemetry-*, analyze
    review_cli.register(app)  # WP5.0.8 adjudicate/precision-report, WP5.4 review

    @app.command("phase5-contracts")
    def phase5_contracts(as_json: bool = typer.Option(False, "--json")) -> None:
        """Print every Phase 5 contract and the version this code implements."""
        if as_json:
            typer.echo(json.dumps(dict(CONTRACT_VERSIONS), sort_keys=True))
            return
        for name, version in CONTRACT_VERSIONS:
            typer.echo(f"{name} {version}")

    # WP5.6: ``benchmark-promote`` and ``benchmark-run``.
    from purpleloop.benchmark_cli import register as register_benchmark

    register_benchmark(app)
