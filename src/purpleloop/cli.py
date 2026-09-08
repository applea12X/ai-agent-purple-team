from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from purpleloop.adapters import MockReadAdapter, OfflineModelStore, OfflineResponseMissing
from purpleloop.control import (
    BudgetLedger,
    DefaultDenyPolicy,
    InMemoryCredentialBroker,
    KillSwitch,
    ManifestError,
    ManifestVerifier,
    Redactor,
    load_manifest,
)
from purpleloop.runtime import EvidenceLedger, LedgerError, SafetyRuntime
from purpleloop.schemas import ActionRequest

app = typer.Typer(no_args_is_help=True, help="PurpleLoop Phase 0 safety-kernel CLI")


def _verifier(key_id: str, public_key: Path) -> ManifestVerifier:
    key = load_pem_public_key(public_key.read_bytes())
    return ManifestVerifier({key_id: key})  # type: ignore[dict-item]


@app.command("validate-manifest")
def validate_manifest(
    manifest_path: Path,
    public_key: Path,
    key_id: str = typer.Option(...),
) -> None:
    try:
        manifest = load_manifest(manifest_path)
        _verifier(key_id, public_key).verify(manifest)
    except (ManifestError, OSError, ValueError) as exc:
        typer.echo(f"DENIED: {getattr(exc, 'reason_code', 'INVALID_KEY')}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"VALID {manifest.manifest_digest()}")


@app.command("check-action")
def check_action(
    manifest_path: Path,
    action_path: Path,
    public_key: Path,
    key_id: str = typer.Option(...),
) -> None:
    try:
        manifest = load_manifest(manifest_path)
        _verifier(key_id, public_key).verify(manifest)
        action = ActionRequest.model_validate_json(action_path.read_text(encoding="utf-8"))
        decision = DefaultDenyPolicy().evaluate(manifest, action)
    except (ManifestError, OSError, ValueError) as exc:
        typer.echo(f"DENY {getattr(exc, 'reason_code', 'INVALID_INPUT')}")
        raise typer.Exit(1) from None
    typer.echo(f"{decision.effect.upper()} {decision.reason_code}")
    if not decision.permitted:
        raise typer.Exit(1)


@app.command("run-mock")
def run_mock(
    manifest_path: Path,
    action_path: Path,
    public_key: Path,
    ledger_path: Path,
    key_id: str = typer.Option(...),
) -> None:
    manifest = load_manifest(manifest_path)
    action = ActionRequest.model_validate_json(action_path.read_text(encoding="utf-8"))
    runtime = SafetyRuntime(
        verifier=_verifier(key_id, public_key),
        policy=DefaultDenyPolicy(),
        budgets=BudgetLedger(manifest.budgets),
        kill_switch=KillSwitch(),
        credential_broker=InMemoryCredentialBroker(
            {handle: "SYNTHETIC-CREDENTIAL" for handle in manifest.credential_handles}
        ),
        redactor=Redactor((*manifest.synthetic_secrets, "SYNTHETIC-CREDENTIAL")),
        adapter=MockReadAdapter(),
        ledger=EvidenceLedger(ledger_path),
    )
    result = asyncio.run(runtime.run(manifest, action, run_id="cli-run", trace_id="cli-trace"))
    typer.echo(json.dumps(result.model_dump(mode="json"), sort_keys=True))
    if result.status != "completed":
        raise typer.Exit(1)


@app.command("verify-ledger")
def verify_ledger(ledger_path: Path) -> None:
    try:
        events = EvidenceLedger(ledger_path).verify()
    except LedgerError as exc:
        typer.echo(f"INVALID {exc.reason_code}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"VALID events={len(events)}")


@app.command("offline-complete")
def offline_complete(
    fixture_path: Path,
    request_path: Path,
    model: str = typer.Option(...),
    profile: str = typer.Option(...),
) -> None:
    """Return an exact offline response; never falls back to a network model."""
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        response = OfflineModelStore(fixture_path).complete(
            model=model,
            profile=profile,
            request=request,
        )
    except (OSError, ValueError, KeyError, OfflineResponseMissing) as exc:
        typer.echo(
            f"DENIED: {getattr(exc, 'reason_code', 'INVALID_OFFLINE_FIXTURE')}",
            err=True,
        )
        raise typer.Exit(1) from None
    typer.echo(response.model_dump_json())


from purpleloop.phase1_cli import register  # noqa: E402
from purpleloop.supportlab_cli import register as register_supportlab  # noqa: E402

register(app)
register_supportlab(app)

if __name__ == "__main__":
    app()
