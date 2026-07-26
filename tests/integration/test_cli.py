from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.schemas import ActionRequest, AuthorizationManifest


def _write_inputs(
    tmp_path: Path,
    manifest: AuthorizationManifest,
    action: ActionRequest,
    private_key: Ed25519PrivateKey,
) -> tuple[Path, Path, Path]:
    manifest_path = tmp_path / "manifest.json"
    action_path = tmp_path / "action.json"
    key_path = tmp_path / "public.pem"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    action_path.write_text(action.model_dump_json(), encoding="utf-8")
    key_path.write_bytes(
        private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return manifest_path, action_path, key_path


def test_cli_success_paths(
    tmp_path: Path,
    manifest: AuthorizationManifest,
    action: ActionRequest,
    private_key: Ed25519PrivateKey,
) -> None:
    manifest_path, action_path, key_path = _write_inputs(tmp_path, manifest, action, private_key)
    runner = CliRunner()
    common = [str(manifest_path), str(key_path), "--key-id", "test-key"]
    validated = runner.invoke(app, ["validate-manifest", *common])
    assert validated.exit_code == 0
    checked = runner.invoke(
        app,
        [
            "check-action",
            str(manifest_path),
            str(action_path),
            str(key_path),
            "--key-id",
            "test-key",
        ],
    )
    assert checked.exit_code == 0
    ledger_path = tmp_path / "cli-ledger.jsonl"
    executed = runner.invoke(
        app,
        [
            "run-mock",
            str(manifest_path),
            str(action_path),
            str(key_path),
            str(ledger_path),
            "--key-id",
            "test-key",
        ],
    )
    assert executed.exit_code == 0, (executed.output, executed.exception)
    verified = runner.invoke(app, ["verify-ledger", str(ledger_path)])
    assert verified.exit_code == 0


def test_cli_rejects_tampered_manifest(
    tmp_path: Path,
    manifest: AuthorizationManifest,
    action: ActionRequest,
    private_key: Ed25519PrivateKey,
) -> None:
    tampered = manifest.model_copy(update={"owner": "attacker"})
    manifest_path, _, key_path = _write_inputs(tmp_path, tampered, action, private_key)
    result = CliRunner().invoke(
        app,
        [
            "validate-manifest",
            str(manifest_path),
            str(key_path),
            "--key-id",
            "test-key",
        ],
    )
    assert result.exit_code == 1
    assert "INVALID_SIGNATURE" in result.output


def test_cli_denial_and_invalid_ledger_paths(
    tmp_path: Path,
    manifest: AuthorizationManifest,
    action: ActionRequest,
    private_key: Ed25519PrivateKey,
) -> None:
    denied = action.model_copy(update={"operation": "admin.read"})
    manifest_path, action_path, key_path = _write_inputs(tmp_path, manifest, denied, private_key)
    runner = CliRunner()
    checked = runner.invoke(
        app,
        [
            "check-action",
            str(manifest_path),
            str(action_path),
            str(key_path),
            "--key-id",
            "test-key",
        ],
    )
    assert checked.exit_code == 1
    assert "OPERATION_NOT_ALLOWED" in checked.output
    ledger_path = tmp_path / "denied-ledger.jsonl"
    executed = runner.invoke(
        app,
        [
            "run-mock",
            str(manifest_path),
            str(action_path),
            str(key_path),
            str(ledger_path),
            "--key-id",
            "test-key",
        ],
    )
    assert executed.exit_code == 1
    ledger_path.write_text('{"partial":', encoding="utf-8")
    invalid = runner.invoke(app, ["verify-ledger", str(ledger_path)])
    assert invalid.exit_code == 1
    assert "LEDGER_INVALID" in invalid.output


def test_cli_offline_model_is_exact_and_fail_closed(tmp_path: Path) -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "model_responses" / "phase0.json"
    request = tmp_path / "request.json"
    request.write_text(
        '{"messages":[{"role":"user","content":"phase0"}]}',
        encoding="utf-8",
    )
    runner = CliRunner()
    common = [
        "offline-complete",
        str(fixture),
        str(request),
        "--model",
        "offline-model",
        "--profile",
        "deterministic",
    ]
    completed = runner.invoke(app, common)
    assert completed.exit_code == 0
    assert "Synthetic offline response." in completed.output
    request.write_text('{"messages":[]}', encoding="utf-8")
    missing = runner.invoke(app, common)
    assert missing.exit_code == 1
    assert "OFFLINE_RESPONSE_MISSING" in missing.output
