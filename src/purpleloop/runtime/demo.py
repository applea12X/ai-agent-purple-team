from __future__ import annotations

import asyncio
import os
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.adapters.base import Adapter
from purpleloop.adapters.offline_model import OfflineModelStore
from purpleloop.adapters.phase1 import AdapterRegistry, ChatAdapter, HttpAdapter, ToolAdapter
from purpleloop.control.budgets import BudgetLedger
from purpleloop.control.credentials import InMemoryCredentialBroker
from purpleloop.control.kill_switch import KillSwitch
from purpleloop.control.manifest import ManifestVerifier, sign_manifest
from purpleloop.control.phase1_tools import CONTROL_DEFINITIONS, DATA_DEFINITIONS, PHASE1_TOOLS
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.control.redaction import Redactor
from purpleloop.fixture.app import CANARY
from purpleloop.runtime.fixture import InProcessFixture
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.runtime import SafetyRuntime
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)

ROOT = Path(__file__).resolve().parents[3]
MODEL_FIXTURE = ROOT / "scenarios" / "phase1" / "model-responses.json"


def demo_manifest(key: Ed25519PrivateKey, *, now: datetime | None = None) -> AuthorizationManifest:
    current = now or datetime.now(UTC)
    operations = frozenset(d.operation for d in DATA_DEFINITIONS)
    control_operations = frozenset(d.operation for d in CONTROL_DEFINITIONS)
    manifest = AuthorizationManifest(
        schema_version="1.1.0",
        engagement_id="phase1-local-demo",
        owner="fixture-owner",
        approvers=("local-demo-operator",),
        key_id="demo-key",
        issued_at=current - timedelta(seconds=1),
        valid_from=current - timedelta(seconds=1),
        valid_until=current + timedelta(hours=2),
        phase1=Phase1Grants(
            defense_profiles=frozenset(
                {"tenant-ownership", "property-allowlist", "verified-approval", "capability-guard"}
            )
        ),
        assets=(
            AssetScope(
                asset_id="fixture-data",
                scheme="http",
                host="127.0.0.1",
                port=18080,
                tenant_ids=frozenset({"tenant-a", "tenant-b"}),
                resource_ids=frozenset(),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
            AssetScope(
                asset_id="fixture-control",
                scheme="http",
                host="127.0.0.1",
                port=18081,
                path_prefix="/control",
                tenant_ids=frozenset({"harness"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
        allowed_adapters=frozenset({"http", "tool", "chat", "control"}),
        allowed_operations=operations | control_operations,
        allowed_methods=frozenset({"GET", "POST", "PATCH"}),
        allowed_side_effects=frozenset({SideEffectClass.READ, SideEffectClass.WRITE}),
        credential_handles=frozenset({"fixture-customer", "fixture-control"}),
        credential_scopes={"fixture-customer": operations, "fixture-control": control_operations},
        egress_hosts=frozenset({"127.0.0.1"}),
        budgets=BudgetLimits(
            requests=100, writes=32, records=100, tokens=16384, concurrency=1, wall_time_seconds=60
        ),
        signature="",
    )
    return sign_manifest(manifest, key)


class ComposeFixture:
    def __init__(self, customer: str, control: str) -> None:
        self.environment = {
            **os.environ,
            "PURPLELOOP_CUSTOMER_CREDENTIAL": customer,
            "PURPLELOOP_CONTROL_CREDENTIAL": control,
        }
        self.closed = False

    async def command(self, *args: str) -> None:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.phase1.yaml"),
            "-p",
            "purpleloop-phase1",
            *args,
            cwd=ROOT,
            env=self.environment,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode:
            raise RuntimeError(f"Compose command failed: {stderr.decode()[:1000]}")

    async def start(self) -> None:
        try:
            await self.command("up", "--build", "--wait", "--wait-timeout", "30")
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        await self.command("down", "--volumes", "--timeout", "0")
        self.closed = True


def build_runner(
    output_dir: Path,
    manifest: AuthorizationManifest,
    verifier: ManifestVerifier,
    *,
    customer: str,
    control: str,
    fixture: InProcessFixture | ComposeFixture,
    **runner_options: Any,
) -> PurpleTeamRunner:
    transport = fixture.transports if isinstance(fixture, InProcessFixture) else None
    http, tool = HttpAdapter(transports=transport), ToolAdapter(transports=transport)
    chat = ChatAdapter(OfflineModelStore(MODEL_FIXTURE))
    adapters: dict[str, Adapter] = {"http": http, "tool": tool, "control": http, "chat": chat}
    registry = AdapterRegistry(
        tuple(
            (d.adapter, d.operation, adapters[d.adapter])
            for d in (*DATA_DEFINITIONS, *CONTROL_DEFINITIONS)
        )
    )
    runtime = SafetyRuntime(
        verifier=verifier,
        policy=DefaultDenyPolicy(PHASE1_TOOLS),
        budgets=BudgetLedger(manifest.budgets),
        kill_switch=KillSwitch(),
        credential_broker=InMemoryCredentialBroker(
            {"fixture-customer": customer, "fixture-control": control}
        ),
        redactor=Redactor((customer, control, CANARY, *manifest.synthetic_secrets)),
        adapter=registry,
        ledger=EvidenceLedger(output_dir / "evidence.jsonl"),
    )
    return PurpleTeamRunner(runtime, close=fixture.close, **runner_options)


def credentials() -> tuple[str, str]:
    return secrets.token_hex(24), secrets.token_hex(24)
