"""Evaluation-matrix CLI (WP5.2): sign a spec, run it, and re-read a finished matrix.

``matrix-sign`` turns an unsigned draft into a signed :class:`EvaluationMatrix` and, when the spec
has a real-pin row, a manifest 1.5 whose ``matrix_scope`` authorizes exactly that spec.

``matrix-run`` verifies the signature (and the authorization, for a spec that can spend), writes
the pre-flight decision before anything else, and refuses -- exit 1, no model call -- when the
estimate is over a cap. ``--dry-run`` stops after the pre-flight either way. A real pin is reached
only through ``--endpoint``; there is no fallback from a real row to a stand-in.

``matrix-report`` re-verifies a finished matrix bundle, recomputes every cell, contrast, and
classification from the recorded trials, and refuses if any stored output disagrees.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from purpleloop.adapters.model_provider import OpenAICompatibleProvider, Provider
from purpleloop.control.manifest import ManifestError, ManifestVerifier, load_manifest
from purpleloop.control.phase5_signing import SignedDocumentError, sign_record, verify_matrix_spec
from purpleloop.reporting.bundle import BundleError, verify_bundle
from purpleloop.reporting.matrix_report import render_page, write_matrix
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.matrix import (
    MatrixPreflight,
    MatrixResults,
    MatrixRun,
    analyse,
    authorization_manifest,
    preflight,
    run_matrix,
)
from purpleloop.schemas.phase1 import Phase1Scenario, load_scenario, scenario_paths
from purpleloop.schemas.phase5 import EvaluationMatrix
from purpleloop.scoring.matrix import MatrixTrial

SCENARIOS = ROOT / "scenarios" / "agent"
CREDENTIAL_ENV = "PURPLELOOP_MODEL_API_KEY"


def agent_corpus() -> dict[str, Phase1Scenario]:
    return {path.stem: load_scenario(path) for path in scenario_paths(SCENARIOS)}


def _public_key(path: Path) -> Ed25519PublicKey:
    key = load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("the matrix signing key must be Ed25519")
    return key


def _private_key(path: Path) -> Ed25519PrivateKey:
    key = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the matrix signing key must be Ed25519")
    return key


def load_spec(path: Path) -> EvaluationMatrix:
    return EvaluationMatrix.model_validate_json(path.read_text(encoding="utf-8"))


def companion(spec_path: Path, suffix: str) -> Path:
    """``x.json`` -> ``x.<suffix>``: where the public key and the authorization live."""
    return spec_path.with_name(spec_path.stem + suffix)


def headline(results: MatrixResults) -> list[str]:
    lines = []
    for item in results.defenses:
        lines.append(
            f"DEFENSE {item.defense_column} scenarios={item.scenarios} "
            f"model-independent={item.model_independent} model-dependent={item.model_dependent} "
            f"ineffective={item.ineffective} unclassified={item.unclassified} "
            + " ".join(f"{kind}={count}" for kind, count in sorted(item.enforcement.items()))
        )
    rejected = sum(bool(item.reject) for item in results.contrasts)
    lines.append(
        f"CONTRASTS registered={len(results.contrasts)} rejected_at_alpha={rejected} "
        f"exploratory={len(results.exploratory)} cells={len(results.cells)} "
        f"not_applicable={len(results.not_applicable)}"
    )
    return lines


def _providers(spec: EvaluationMatrix, endpoint: str | None) -> dict[str, Provider]:
    providers: dict[str, Provider] = {}
    for row in spec.rows:
        if row.kind != "real-pin":
            continue
        if endpoint is None:
            raise ValueError(f"row {row.row_id} is a real pin and needs --endpoint")
        credential = os.environ.get(CREDENTIAL_ENV)
        providers[row.row_id] = OpenAICompatibleProvider(
            base_url=endpoint, credential=credential, profile=row.pin.provider
        )
    return providers


def register(app: typer.Typer) -> None:
    @app.command("matrix-sign")
    def matrix_sign(
        draft: Path,
        out: Annotated[Path, typer.Option(help="Where to write the signed spec")],
        key: Annotated[Path | None, typer.Option(help="Ed25519 private key PEM")] = None,
        generate_key: Annotated[
            Path | None, typer.Option(help="Generate a key and write its private PEM here")
        ] = None,
        key_id: str = "matrix-signing-key",
        endpoint: Annotated[
            str, typer.Option(help="Model origin the real pins may reach (authorization only)")
        ] = "http://127.0.0.1:11434",
        valid_hours: Annotated[
            int, typer.Option(help="How long the spend authorization stays valid")
        ] = 336,
    ) -> None:
        """Sign a draft matrix spec; for a spec that can spend, also sign its authorization."""
        if (key is None) == (generate_key is None):
            typer.echo("FAILED: pass exactly one of --key and --generate-key", err=True)
            raise typer.Exit(1)
        if generate_key is not None:
            private = Ed25519PrivateKey.generate()
            generate_key.parent.mkdir(parents=True, exist_ok=True)
            generate_key.write_bytes(
                private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            generate_key.chmod(0o600)
        else:
            assert key is not None
            private = _private_key(key)
        raw: dict[str, Any] = json.loads(draft.read_text(encoding="utf-8"))
        raw.update(
            key_id=key_id,
            issued_at=datetime.now(UTC).isoformat(),
            signature="",
        )
        try:
            spec = sign_record(EvaluationMatrix.model_validate(raw), private)
        except ValueError as exc:
            typer.echo(f"FAILED: invalid matrix draft: {exc}", err=True)
            raise typer.Exit(1) from None
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(spec.model_dump(mode="json", exclude_none=True), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        companion(out, ".pub.pem").write_bytes(
            private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        typer.echo(f"SIGNED {spec.matrix_id} digest={spec.matrix_digest()}")
        if any(row.kind == "real-pin" for row in spec.rows):
            manifest = authorization_manifest(
                spec,
                private,
                key_id=key_id,
                endpoint=endpoint,
                valid_for=timedelta(hours=valid_hours),
            )
            path = companion(out, ".authorization.json")
            path.write_text(
                json.dumps(
                    manifest.model_dump(mode="json", exclude_none=True), indent=2, sort_keys=True
                )
                + "\n",
                encoding="utf-8",
            )
            typer.echo(
                f"AUTHORIZED matrix_scope={spec.matrix_digest()} until={manifest.valid_until}"
            )

    @app.command("matrix-run")
    def matrix_run(
        spec_path: Path,
        output_dir: Path = Path("artifacts/matrix"),
        public_key: Annotated[
            Path | None, typer.Option(help="Spec signing key (default: <spec>.pub.pem)")
        ] = None,
        authorization: Annotated[
            Path | None,
            typer.Option(help="Manifest 1.5 authorizing the spec (default: beside the spec)"),
        ] = None,
        endpoint: Annotated[
            str | None,
            typer.Option(envvar="PURPLELOOP_MODEL_ENDPOINT", help="Base URL for real-pin rows"),
        ] = None,
        dry_run: Annotated[bool, typer.Option(help="Stop after the pre-flight")] = False,
    ) -> None:
        """Verify a signed matrix spec, pre-flight it, and run it (or refuse before any call)."""
        try:
            spec = load_spec(spec_path)
            key = _public_key(public_key or companion(spec_path, ".pub.pem"))
            verify_matrix_spec(spec, {spec.key_id: key})
            real = any(row.kind == "real-pin" for row in spec.rows)
            if real:
                manifest = load_manifest(
                    authorization or companion(spec_path, ".authorization.json")
                )
                ManifestVerifier({manifest.key_id: key}).verify(manifest)
                verify_matrix_spec(spec, {spec.key_id: key}, manifest=manifest)
                providers = None if dry_run else _providers(spec, endpoint)
                if providers:
                    assert manifest.phase3 is not None
                    origins = {provider.endpoint for provider in providers.values()}
                    if not origins <= manifest.phase3.model_assets:
                        raise SignedDocumentError(
                            "MATRIX_NOT_AUTHORIZED",
                            "the endpoint's origin is not the one the authorization signs",
                        )
            else:
                providers = None
            corpus = agent_corpus()
        except (OSError, ValueError, ManifestError) as exc:
            reason = str(getattr(exc, "reason_code", "") or type(exc).__name__)
            typer.echo(f"FAILED: {reason}: {exc}", err=True)
            raise typer.Exit(1) from None
        root = output_dir / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        root.mkdir(parents=True, exist_ok=True)
        decision = preflight(spec, corpus)
        (root / "preflight.json").write_text(
            decision.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        typer.echo(
            f"PREFLIGHT {decision.decision} trials={decision.trials} "
            f"cost_microusd={decision.cost_microusd}/{decision.cost_cap_microusd} "
            f"wall_seconds={decision.wall_seconds:.0f}/{decision.wall_time_cap_seconds}"
        )
        for estimate in decision.rows:
            typer.echo(
                f"  ROW {estimate.row_id} trials={estimate.trials} calls={estimate.model_calls} "
                f"wall_seconds={estimate.wall_seconds:.0f} cost_microusd={estimate.cost_microusd}"
            )
        for line in decision.detail:
            typer.echo(f"  {line}")
        typer.echo(f"Pre-flight record: {(root / 'preflight.json').resolve()}")
        if decision.decision == "refused":
            typer.echo(f"REFUSED: {', '.join(decision.reasons)}; no model was called", err=True)
            raise typer.Exit(1)
        if dry_run:
            return
        run_key = Ed25519PrivateKey.generate()
        try:
            run = asyncio.run(
                run_matrix(spec, corpus, root, run_key, providers=providers, progress=typer.echo)
            )
            results = analyse(spec, corpus, run.trials)
            write_matrix(
                root,
                spec,
                decision,
                run,
                results,
                run_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            )
        except (OSError, ValueError, RuntimeError) as exc:
            typer.echo(f"FAILED: {exc}; partial evidence: {root.resolve()}", err=True)
            raise typer.Exit(1) from None
        for line in headline(results):
            typer.echo(line)
        excluded = sum(trial.status == "excluded" for trial in run.trials)
        typer.echo(
            f"MATRIX trials={len(run.trials)} excluded={excluded} not_run={len(run.not_run)} "
            f"elapsed_seconds={run.elapsed_seconds:.1f} cost_microusd={run.cost_microusd}"
        )
        typer.echo(f"Verified matrix: {(root / 'matrix.html').resolve()}")

    @app.command("matrix-report")
    def matrix_report(
        matrix_dir: Path,
        html_out: Annotated[Path | None, typer.Option("--html", help="Re-render here")] = None,
    ) -> None:
        """Verify a finished matrix and recompute every output from its trial records."""
        try:
            verify_bundle(matrix_dir)
            spec = load_spec(matrix_dir / "spec.json")
            decision = MatrixPreflight.model_validate_json(
                (matrix_dir / "preflight.json").read_text()
            )
            trials = [
                MatrixTrial.model_validate(item)
                for item in json.loads((matrix_dir / "trials.json").read_text())
            ]
            results = analyse(spec, agent_corpus(), trials)
            stored = MatrixResults.model_validate_json((matrix_dir / "results.json").read_text())
            if stored != results:
                raise BundleError("stored matrix results do not follow from the recorded trials")
        except (OSError, ValueError) as exc:
            typer.echo(f"FAILED: {type(exc).__name__}: {exc}", err=True)
            raise typer.Exit(1) from None
        if html_out is not None:
            suite = json.loads((matrix_dir / "suite.json").read_text())
            run = MatrixRun(
                trials=trials,
                bundles=list(suite["scenarios"]),
                not_run=list(suite["not_run"]),
                cost_microusd=int(suite["cost_microusd"]),
                elapsed_seconds=float(suite["elapsed_seconds"]),
            )
            html_out.write_text(render_page(spec, decision, results, run), encoding="utf-8")
        typer.echo(f"VERIFIED matrix {spec.matrix_id} digest={spec.matrix_digest()}")
        for line in headline(results):
            typer.echo(line)
