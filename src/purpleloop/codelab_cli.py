"""WP5.5 CLI: the codelab lane end to end, and its containment-escape suite.

``codelab-run`` is the WP5.1 approval path's end-to-end use, in the order a person would take it:
shadow the requested manifest over the corpus, sign an approval of the exact delta with an
**ephemeral** approver key (generated here, never written), prove the unapproved manifest is
refused at admission, then run the corpus under the approved manifest and write per-lane metrics.
``codelab-escape`` runs the escape suite against the real sandbox container (Docker required).
No command here calls a model.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path

import typer


def register(app: typer.Typer) -> None:
    @app.command("codelab-run")
    def codelab_run(
        output_dir: Path = Path("artifacts/codelab"),
        stand_in: str = typer.Option("scripted", help="scripted or delimitation-blind"),
        compose: bool = typer.Option(False, help="Run snippets in the sandbox container"),
        replay: int = typer.Option(3, help="Replay trials per scenario (in process); 0 skips"),
    ) -> None:
        """Shadow, approve (ephemeral key), refuse-without, then run the codelab corpus."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from purpleloop.adapters.codelab import STAND_INS
        from purpleloop.reporting.bundle import write_json
        from purpleloop.runtime import codelab, governance

        if stand_in not in STAND_INS:
            typer.echo(f"FAILED: unknown stand-in {stand_in}", err=True)
            raise typer.Exit(2)
        if output_dir.exists() and any(output_dir.iterdir()):
            typer.echo(f"FAILED: output directory not empty: {output_dir}", err=True)
            raise typer.Exit(1)

        async def flow() -> dict[str, object]:
            key = Ed25519PrivateKey.generate()
            approval = await codelab.approve(output_dir / "governance", key)
            write_json(
                output_dir / "governance" / "approval.json",
                approval.approval.model_dump(mode="json", exclude_none=True),
            )
            corpus = codelab.load_corpus()
            # Without the approval: the requested manifest, the same baseline, no approvals.
            unapproved = codelab.InProcessCodelab(
                codelab.actor_credentials(), secrets.token_hex(24)
            )
            refused = await codelab.run_scenario(
                output_dir / "refused" / corpus[0].scenario_id,
                corpus[0],
                approval,
                fixture=unapproved,
                manifest=approval.requested,
                admission=governance.committed_admission(),
                inspect=False,
            )
            refused_jobs = unapproved.state.jobs
            fixture = None
            if compose:  # pragma: no cover - container lane
                fixture = codelab.ComposeCodelab(
                    codelab.actor_credentials(),
                    secrets.token_hex(24),
                    project="purpleloop-codelab-run",
                    keep=True,
                )
            summaries = []
            jobs: int | None = 0 if fixture is None else None
            try:
                for scenario in corpus:
                    local = (
                        codelab.InProcessCodelab(codelab.actor_credentials(), secrets.token_hex(24))
                        if fixture is None
                        else None
                    )
                    summaries.append(
                        await codelab.run_scenario(
                            output_dir / "corpus" / scenario.scenario_id,
                            scenario,
                            approval,
                            fixture=fixture or local,
                            model=STAND_INS[stand_in](),
                        )
                    )
                    if local is not None and jobs is not None:
                        jobs += local.state.jobs
                runtime = await fixture.sandbox_runtime() if fixture is not None else "stub"
            finally:
                if fixture is not None:  # pragma: no cover - container lane
                    await fixture.down()
            from purpleloop.reporting.bundle import inventory, reports, verify_bundle

            root = output_dir / "corpus"
            reports(root, summaries)
            (root / "authorization-public.pem").write_bytes(
                approval.verifier.public_key_bytes(approval.approved.key_id)
            )
            write_json(
                root / "suite.json",
                {
                    "schema_version": "1.4.0",
                    "lane": "codelab",
                    "stand_in": stand_in,
                    "sandbox": runtime,
                    "approval_digest": approval.approval.approval_digest(),
                    "scenarios": [scenario.scenario_id for scenario in corpus],
                },
            )
            inventory(root, complete=True)
            verify_bundle(root)
            replay_record = (
                await codelab.replay_trials(output_dir / "replay", approval, trials=replay)
                if replay
                else None
            )
            metrics = codelab.codelab_metrics(
                scenarios=corpus,
                summaries=summaries,
                stand_in=stand_in,
                sandbox=runtime,
                sandbox_jobs=jobs,
                approval=approval,
                replay=replay_record,
            )
            write_json(output_dir / "metrics.json", metrics.model_dump(mode="json"))
            return {
                "shadow_suppressed": approval.report.suppressed_executions,
                "shadow_adapter_calls": approval.report.adapter_calls,
                "delta": sorted(d.value for d in approval.approval.capability_delta),
                "refused": (refused.status, refused.reason, refused_jobs),
                "metrics": metrics,
            }

        try:
            result = asyncio.run(flow())
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        metrics = result["metrics"]
        assert isinstance(metrics, codelab.CodelabMetrics)
        corpus_numbers = metrics.corpus
        typer.echo(
            f"shadow: suppressed {result['shadow_suppressed']}, "
            f"adapter calls {result['shadow_adapter_calls']}"
        )
        typer.echo(f"approved delta {result['delta']} (approver key ephemeral)")
        typer.echo(f"without the approval: {result['refused']}")
        typer.echo(
            f"{stand_in} on {metrics.sandbox}: "
            f"passed={sum(s == 'passed' for s in metrics.statuses.values())}/{metrics.scenarios} "
            f"recall={corpus_numbers['seeded_recall']:.3f} "
            f"fp_rate={corpus_numbers['false_positive_rate']:.3f} "
            f"defense_credited={len(metrics.defense_credited)}/{metrics.scenarios}"
        )
        if metrics.replay is not None:
            typer.echo(
                f"replay {metrics.replay.matched}/{metrics.replay.trials} "
                f"(rate {metrics.replay.rate:.3f})"
            )
        typer.echo(f"Verified codelab bundle: {(output_dir / 'corpus').resolve()}")
        refused_status = result["refused"]
        assert isinstance(refused_status, tuple)
        # The refused run's teardown is refused too (admission runs on every action, the control
        # plane included), so its reason carries "; cleanup: ..." after the admission code; the
        # fixture is still disposed host-side. The admission code is what must match.
        if (
            str(refused_status[1]).split(";")[0] != "CAPABILITY_INCREASE_UNAPPROVED"
            or refused_status[2]
        ):
            typer.echo("FAILED: the unapproved codelab manifest was not refused", err=True)
            raise typer.Exit(1)
        if stand_in == "scripted" and any(s != "passed" for s in metrics.statuses.values()):
            raise typer.Exit(1)

    @app.command("codelab-escape")
    def codelab_escape(
        output_dir: Path = Path("artifacts/codelab-escape"),
        runtime: str | None = typer.Option(None, help="Sandbox OCI runtime (default runc)"),
    ) -> None:  # pragma: no cover - container lane
        """Run the containment-escape suite against the real sandbox container."""
        from purpleloop.runtime import codelab
        from purpleloop.runtime.codelab_escape import load_suite, run_escape_suite

        try:
            report = asyncio.run(
                run_escape_suite(output_dir, load_suite(codelab.ESCAPE_SUITE), runtime=runtime)
            )
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"runtime {report.runtime} (requested {report.runtime_requested})")
        for attempt in report.attempts:
            failed = [name for name, ok in attempt.checks.items() if not ok]
            marker = "contained" if attempt.contained else "BREACH   "
            typer.echo(f"{marker} {attempt.attempt_id} ({attempt.category}) {failed or ''}")
        typer.echo(f"contained {report.contained}/{len(report.attempts)}")
        typer.echo(json.dumps({"report": str((output_dir / "escape-report.json").resolve())}))
        if report.breaches:
            typer.echo(f"INVARIANT BREACH: {list(report.breaches)}", err=True)
            raise typer.Exit(1)
