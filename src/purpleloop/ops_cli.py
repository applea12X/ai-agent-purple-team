"""Operational commands closing Phase 0-4 loose ends (docs/phase5/loose-ends.md).

* ``browser-estop`` measures the browser lane's emergency-stop latency (row 2.4).
* ``retention-plan`` resolves the signed retention rules over a real artifact tree (row 4.12);
  ``locate-ledger-break`` and ``locate-action`` are the two lookups the incident drill found the
  runbook needed and no command provided (row 4.12).
* ``nightly-scope``, ``nightly-scope-sign``, ``nightly-lane``, and ``nightly-issue`` are the
  nightly lane's scope reader, scope signer, runner, and tracking-issue filer (rows 4.23-4.25).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from purpleloop.control.manifest import ManifestError
from purpleloop.reporting.bundle import write_json
from purpleloop.runtime.nightly import (
    NIGHTLY_DIR,
    NIGHTLY_MANIFEST,
    NIGHTLY_PUBLIC_KEY,
    REPORT_NAME,
    ScopedScenario,
    build_nightly_manifest,
    file_or_update_issue,
    gh_runner,
    public_pem,
    read_nightly_scope,
    render_issue_body,
    resolve_scenario,
    verified_manifest,
)
from purpleloop.schemas.phase4 import NightlyScope, StochasticRunOutcome


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

    @app.command("nightly-scope")
    def nightly_scope(
        manifest: Path = NIGHTLY_MANIFEST,
        public_key: Path = NIGHTLY_PUBLIC_KEY,
        github_output: Annotated[
            Path | None, typer.Option(help="Append scope outputs here ($GITHUB_OUTPUT)")
        ] = None,
    ) -> None:
        """Verify the signed nightly manifest and print its scope. Exit 1 if there is none."""
        try:
            plan = read_nightly_scope(manifest, public_key)
        except (ManifestError, ValueError, OSError) as exc:
            reason = str(getattr(exc, "reason_code", "") or "NIGHTLY_SCOPE_INVALID")
            typer.echo(f"INVALID: {reason}: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(json.dumps(plan.as_json(), sort_keys=True))
        if github_output is not None:
            with github_output.open("a", encoding="utf-8") as handle:
                handle.write(f"repetitions={plan.repetitions}\n")
                handle.write(f"manifest_digest={plan.manifest_digest}\n")
                for lane in ("agent", "supportlab"):
                    ids = " ".join(item.scenario_id for item in plan.lane(lane))
                    handle.write(f"{lane}_scenarios={ids}\n")

    @app.command("nightly-scope-sign")
    def nightly_scope_sign(
        scenario: Annotated[list[str], typer.Option(help="Scenario id in scope (repeatable)")],
        repetitions: int = 5,
        rotation: str = "",
        valid_days: int = 365,
        output_dir: Path = NIGHTLY_DIR,
        key_path: Annotated[
            Path | None, typer.Option(help="Ed25519 private key PEM; omitted, an ephemeral key")
        ] = None,
    ) -> None:
        """Sign a nightly scope. Without --key-path the private key is generated and discarded."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        try:
            scope = NightlyScope(
                scenario_ids=frozenset(scenario), repetitions=repetitions, rotation=rotation
            )
            for item in sorted(scope.scenario_ids):
                resolve_scenario(item)
            if key_path is None:
                key = Ed25519PrivateKey.generate()
            else:
                loaded = load_pem_private_key(key_path.read_bytes(), password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("the signing key is not Ed25519")
                key = loaded
            signed = build_nightly_manifest(key, scope, valid_days=valid_days)
        except (ValueError, OSError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(output_dir / "manifest.json", signed.model_dump(mode="json"))
        (output_dir / "authorization-public.pem").write_bytes(public_pem(key))
        typer.echo(
            f"SIGNED {signed.manifest_digest()} valid_until={signed.valid_until.isoformat()}"
            + (" (ephemeral key, discarded)" if key_path is None else "")
        )

    @app.command("nightly-lane")
    def nightly_lane(
        output_dir: Path = Path("artifacts/nightly"),
        manifest: Path = NIGHTLY_MANIFEST,
        public_key: Path = NIGHTLY_PUBLIC_KEY,
        endpoint: Annotated[str | None, typer.Option(envvar="PURPLELOOP_MODEL_ENDPOINT")] = None,
        profile: Annotated[
            str, typer.Option(envvar="PURPLELOOP_MODEL_PROFILE")
        ] = "openai-compatible",
        browser_fixture: Annotated[
            str, typer.Option(help="served (real Chromium) or in-process")
        ] = "served",
    ) -> None:
        """Run the signed nightly scope; write nightly.json. Exit 1 on any non-pass outcome."""
        from purpleloop.runtime.nightly import run_browser_workflow, run_night

        served = browser_fixture == "served"

        async def browser(item: ScopedScenario, output: Path) -> StochasticRunOutcome:
            return await run_browser_workflow(item, output, served=served)

        report = asyncio.run(
            run_night(
                output_dir,
                manifest_path=manifest,
                public_key_path=public_key,
                endpoint=endpoint or None,
                profile=profile,
                browser_executor=browser,
            )
        )
        for item in report["outcomes"]:
            typer.echo(
                f"{item.get('scenario_id') or 'scope'} [{item.get('lane') or '-'}]: "
                f"{item['outcome']} {item['reason_code']}"
            )
        if report["needs_issue"]:
            raise typer.Exit(1)

    @app.command("nightly-issue")
    def nightly_issue(
        output_dir: Path = Path("artifacts/nightly"),
        run_url: Annotated[str, typer.Option(help="The workflow run's URL")] = "",
        gh: Annotated[str, typer.Option(help="The gh executable")] = "gh",
        dry_run: bool = False,
    ) -> None:
        """File or update the nightly tracking issue when the night was not a pass."""
        report_path = output_dir / REPORT_NAME
        report = json.loads(report_path.read_text()) if report_path.is_file() else None
        if report is not None and not report["needs_issue"]:
            typer.echo("no issue: every outcome is pass or a recorded skip-no-credential")
            return
        body = render_issue_body(report, run_url=run_url or "(run URL not given)")
        if dry_run:
            typer.echo(body)
            return
        output_dir.mkdir(parents=True, exist_ok=True)
        action, reference = file_or_update_issue(
            body, run=gh_runner(gh), body_path=output_dir / "issue-body.md"
        )
        typer.echo(f"ISSUE {action} {reference}")

    @app.command("retention-plan")
    def retention_plan_command(
        root: Path,
        manifest: Path = NIGHTLY_MANIFEST,
        public_key: Path = NIGHTLY_PUBLIC_KEY,
        as_of: Annotated[
            str | None, typer.Option(help="ISO date to resolve at (default: now, UTC)")
        ] = None,
        output: Path | None = None,
    ) -> None:
        """Dry run: which artifacts the signed retention rules would delete, and when."""
        from datetime import UTC, datetime

        from purpleloop.reporting.retention import retention_plan

        try:
            signed = verified_manifest(manifest, public_key)
            if signed.phase4 is None:
                raise ValueError("the signed manifest carries no retention rules (1.4+)")
            moment = (
                datetime.fromisoformat(as_of).replace(tzinfo=UTC) if as_of else datetime.now(UTC)
            )
            plan = retention_plan(root, signed.phase4, as_of=moment)
        except (ManifestError, ValueError, OSError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        if output is not None:
            write_json(output, plan)
        typer.echo(
            f"DRY RUN as_of={plan['as_of']} files={plan['files']} due={plan['due']} "
            "(nothing deleted)"
        )
        for kind, counts in plan["by_kind"].items():
            typer.echo(
                f"  {kind}: files={counts.get('files', 0)} bytes={counts.get('bytes', 0)} "
                f"due={counts.get('due', 0)} held={counts.get('held', 0)}"
            )

    @app.command("locate-ledger-break")
    def locate_ledger_break(ledger: Path) -> None:
        """Name the first event at which a ledger's hash chain stops verifying."""
        from purpleloop.reporting.incident_tools import first_ledger_break

        result = first_ledger_break(ledger)
        typer.echo(json.dumps(result, sort_keys=True))
        if not result["valid"]:
            raise typer.Exit(1)

    @app.command("locate-action")
    def locate_action_command(run: Path, digest: str) -> None:
        """Where an action digest came from in a run bundle, and every event naming it."""
        from purpleloop.reporting.incident_tools import locate_action

        try:
            result = locate_action(run, digest)
        except (OSError, ValueError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
