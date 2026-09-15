"""The committed reviewer samples carry no secret material.

``.gitguardian.yaml`` excludes ``docs/samples/`` because its digests, signatures, and public keys
trip generic entropy detectors on every regeneration. That exclusion removes scanner coverage from
files holding real run evidence, which is where a redaction regression would expose a credential,
so this test replaces the coverage with checks that understand what a leak here looks like:

- a credential-bearing field holding anything but ``[REDACTED]`` or a broker handle;
- a standalone 48-hex value, the shape of the per-run tokens ``secrets.token_hex(24)`` issues;
- a fixture canary, or the synthetic credential values the harness brokers;
- a bearer header carrying a token, or any private-key block.

The checker is tested against planted leaks, so it cannot pass by checking nothing.
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any

from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.supportlab import ALL_CANARIES

SAMPLES = ROOT / "docs" / "samples"

CREDENTIAL_KEY = re.compile(
    r"(authorization|bearer|token|credential|secret|password|api[_-]?key)", re.IGNORECASE
)
#: A broker handle: a short canonical identifier with no long random run inside it.
HANDLE = re.compile(r"^[a-z][a-z0-9.-]{0,63}$")
LONG_HEX = re.compile(r"[0-9a-f]{16,}")
TOKEN_SHAPED = re.compile(r"(?<![0-9a-f])[0-9a-f]{48}(?![0-9a-f])")
BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
#: Credential values the harness brokers in-process; they must never reach an artifact.
BROKERED_VALUES = ("SYNTHETIC-CREDENTIAL", "SUPPORTLAB-CONTROL-SECRET")


def _credential_field_problems(value: Any, path: str) -> list[str]:
    problems: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            # An inventory maps file names to file digests; a name containing "authorization"
            # is not a credential field.
            if key == "artifacts" and isinstance(item, dict):
                continue
            if CREDENTIAL_KEY.search(str(key)) and isinstance(item, str):
                safe = item == "[REDACTED]" or (
                    HANDLE.fullmatch(item) and not LONG_HEX.search(item)
                )
                if not safe:
                    problems.append(f"{child}: credential field holds a raw value")
            problems.extend(_credential_field_problems(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            problems.extend(_credential_field_problems(item, f"{path}[{index}]"))
    return problems


def scan(root: Path) -> list[str]:
    """Every secret-shaped problem under ``root``, as ``file: reason`` strings."""
    problems: list[str] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        if PRIVATE_KEY.search(text):
            problems.append(f"{relative}: private key block")
        if path.suffix == ".pem" and "BEGIN PUBLIC KEY" not in text:
            problems.append(f"{relative}: PEM file is not a public key")
        if BEARER.search(text):
            problems.append(f"{relative}: bearer header with a token")
        if TOKEN_SHAPED.search(text):
            problems.append(f"{relative}: token-shaped 48-hex value")
        for canary in (*ALL_CANARIES, *BROKERED_VALUES):
            if canary in text:
                problems.append(f"{relative}: contains a canary or brokered credential value")
        documents: list[Any] = []
        if path.suffix == ".jsonl":
            documents = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif path.suffix == ".json":
            documents = [json.loads(text)]
        for document in documents:
            problems.extend(f"{relative}: {p}" for p in _credential_field_problems(document, ""))
    return problems


def test_committed_samples_carry_no_secret_material() -> None:
    assert SAMPLES.is_dir(), "the reviewer samples are missing"
    assert any(SAMPLES.rglob("evidence.jsonl")), "no evidence ledger to scan"
    problems = scan(SAMPLES)
    assert not problems, problems


def test_samples_show_redaction_actually_happened() -> None:
    """A scan of files that never held a credential proves nothing; these did, and were redacted."""
    ledger = (SAMPLES / "passing-run" / "evidence.jsonl").read_text()
    assert "[REDACTED]" in ledger


def test_the_scanner_catches_planted_leaks(tmp_path: Path) -> None:
    token = secrets.token_hex(24)
    (tmp_path / "evidence.jsonl").write_text(
        json.dumps({"data": {"credential": token}})
        + "\n"
        + json.dumps({"data": {"note": ALL_CANARIES[0]}})
        + "\n"
    )
    (tmp_path / "headers.json").write_text(
        json.dumps({"request": {"authorization": f"Bearer {secrets.token_urlsafe(24)}"}})
    )
    (tmp_path / "key.pem").write_text(
        "-----BEGIN PRIVATE KEY-----\nMC4CAQ\n-----END PRIVATE KEY-----\n"
    )
    problems = "\n".join(scan(tmp_path))
    assert "credential field holds a raw value" in problems
    assert "token-shaped 48-hex value" in problems
    assert "canary or brokered credential" in problems
    assert "bearer header" in problems
    assert "private key block" in problems
    assert "PEM file is not a public key" in problems


def test_the_scanner_passes_public_by_design_values(tmp_path: Path) -> None:
    """Digests, signatures, handles, and redaction markers are not findings."""
    (tmp_path / "inventory.json").write_text(
        json.dumps({"artifacts": {"authorization-public.pem": "a" * 64}})
    )
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "credential_handles": ["supportlab-agent-a"],
                "model_credential_handle": "supportlab-model",
                "signature": "zaqcz1rSfat+egJBus72tEkmZg==",
                "event_hash": "b" * 64,
                "authorization": "[REDACTED]",
            }
        )
    )
    (tmp_path / "public.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----\n"
    )
    assert scan(tmp_path) == []
