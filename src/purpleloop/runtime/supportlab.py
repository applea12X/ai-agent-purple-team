"""Assemble a supportlab lane run: signed manifest, adapters, fixture, and browser driver.

This mirrors ``runtime/demo.py`` for Phase 1 but binds the supportlab lane, resolves resource
ownership from the deterministic seed at signing time, and can pair the HTTP/tool adapters with
either the in-process HTML form driver or a Playwright browser.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.adapters.base import Adapter
from purpleloop.adapters.browser import BrowserAdapter, BrowserDriver, HtmlFormDriver
from purpleloop.adapters.offline_model import OfflineModelStore
from purpleloop.adapters.phase1 import AdapterRegistry, ChatAdapter, HttpAdapter, ToolAdapter
from purpleloop.control import phase2_tools
from purpleloop.control.budgets import BudgetLedger
from purpleloop.control.credentials import InMemoryCredentialBroker
from purpleloop.control.kill_switch import KillSwitch
from purpleloop.control.lanes import SUPPORTLAB_LANE
from purpleloop.control.manifest import ManifestVerifier, sign_manifest
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.control.redaction import Redactor
from purpleloop.fixture.supportlab import seed as seeding
from purpleloop.fixture.supportlab.app import SupportlabState, create_apps, in_process_upstream
from purpleloop.fixture.supportlab.database import SqliteDatabase
from purpleloop.fixture.supportlab.seed import CANARIES
from purpleloop.fixture.supportlab.upstream import INTERNAL_METADATA_CANARY
from purpleloop.runtime.demo import ROOT
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
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants

MODEL_FIXTURE = ROOT / "scenarios" / "supportlab" / "model-responses.json"
KEY_ID = "supportlab-demo-key"
DEFENSE_PROFILES = frozenset(phase2_tools.DEFENSES)
ALL_CANARIES = (*CANARIES, INTERNAL_METADATA_CANARY)


def supportlab_manifest(
    key: Ed25519PrivateKey, *, seed: int = 42, now: datetime | None = None
) -> AuthorizationManifest:
    current = now or datetime.now(UTC)
    ownership = tuple(
        OwnershipScope(tenant_id=org, resource_ids=resources)
        for org, resources in sorted(seeding.ownership(seed).items())
    )
    manifest = AuthorizationManifest(
        schema_version="1.2.0",
        engagement_id="supportlab-local-demo",
        owner="fixture-owner",
        approvers=("local-demo-operator",),
        key_id=KEY_ID,
        issued_at=current - timedelta(seconds=1),
        valid_from=current - timedelta(seconds=1),
        valid_until=current + timedelta(hours=2),
        phase1=Phase1Grants(defense_profiles=DEFENSE_PROFILES),
        phase2=Phase2Grants(
            ownership_seed=seed,
            ownership=ownership,
            database_credential_handle=phase2_tools.DATABASE_HANDLE,
            containment_prefix=phase2_tools.CONTAINMENT_PREFIX,
            browser_assets=frozenset({phase2_tools.DATA_ASSET}),
            subresource_origins=frozenset(),
            max_browser_contexts=32,
        ),
        assets=(
            AssetScope(
                asset_id=phase2_tools.DATA_ASSET,
                scheme="http",
                host="127.0.0.1",
                port=phase2_tools.DATA_PORT,
                tenant_ids=frozenset({"org-a", "org-b"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
            AssetScope(
                asset_id=phase2_tools.CONTROL_ASSET,
                scheme="http",
                host="127.0.0.1",
                port=phase2_tools.CONTROL_PORT,
                path_prefix="/control",
                tenant_ids=frozenset({"harness"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
        allowed_adapters=frozenset({"http", "tool", "chat", "browser", "control"}),
        allowed_operations=phase2_tools.DATA_OPERATIONS | phase2_tools.CONTROL_OPERATIONS,
        allowed_methods=frozenset({"GET", "POST", "PATCH"}),
        allowed_side_effects=frozenset({SideEffectClass.READ, SideEffectClass.WRITE}),
        credential_handles=frozenset(phase2_tools.ATTACK_HANDLES | {phase2_tools.CONTROL_HANDLE}),
        credential_scopes={
            **{handle: phase2_tools.DATA_OPERATIONS for handle in phase2_tools.ATTACK_HANDLES},
            phase2_tools.CONTROL_HANDLE: phase2_tools.CONTROL_OPERATIONS,
        },
        egress_hosts=frozenset({"127.0.0.1"}),
        budgets=BudgetLimits(
            requests=400,
            writes=64,
            records=400,
            tokens=16384,
            concurrency=1,
            wall_time_seconds=120,
        ),
        signature="",
    )
    return sign_manifest(manifest, key)


class InProcessSupportlab:
    """In-process supportlab: SQLite database, ASGI transports, ASGI upstream."""

    def __init__(self, actor_tokens: dict[str, str], control: str) -> None:
        self.state = SupportlabState(
            SqliteDatabase(),
            actor_tokens=actor_tokens,
            control_token=control,
            upstream=in_process_upstream(),
        )
        data_app, control_app = create_apps(self.state)
        self.transports = {
            phase2_tools.DATA_PORT: httpx.ASGITransport(app=data_app),
            phase2_tools.CONTROL_PORT: httpx.ASGITransport(app=control_app),
        }
        self.closed = False

    async def close(self) -> None:
        self.state.dispose()
        self.closed = True


class ServedSupportlab:  # pragma: no cover - served host browser lane
    """In-process supportlab served over real loopback sockets, for the Playwright driver.

    A real browser cannot speak to an ASGI transport, so the data and control apps are bound to
    the signed loopback ports through uvicorn. The database is still in-process SQLite and the
    upstream is still in-process, so the run stays offline and needs no Docker.
    """

    def __init__(self, actor_tokens: dict[str, str], control: str) -> None:
        self.state = SupportlabState(
            SqliteDatabase(),
            actor_tokens=actor_tokens,
            control_token=control,
            upstream=in_process_upstream(),
        )
        data_app, control_app = create_apps(self.state)
        self._servers = [
            uvicorn.Server(
                uvicorn.Config(
                    app, host="127.0.0.1", port=port, access_log=False, log_level="warning"
                )
            )
            for app, port in (
                (data_app, phase2_tools.DATA_PORT),
                (control_app, phase2_tools.CONTROL_PORT),
            )
        ]
        self._tasks: list[asyncio.Task[None]] = []
        self.transports = None
        self.closed = False

    async def start(self) -> None:
        self._tasks = [asyncio.create_task(server.serve()) for server in self._servers]
        for _ in range(200):
            if all(server.started for server in self._servers):
                return
            await asyncio.sleep(0.02)
        raise RuntimeError("supportlab servers did not start")

    async def close(self) -> None:
        for server in self._servers:
            server.should_exit = True
        for task in self._tasks:
            try:
                await asyncio.wait_for(task, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                task.cancel()
        self.state.dispose()
        self.closed = True


def actor_credentials() -> dict[str, str]:
    return {actor: secrets.token_hex(24) for actor in phase2_tools.ACTORS}


def build_supportlab_runner(
    output_dir: Path,
    manifest: AuthorizationManifest,
    verifier: ManifestVerifier,
    *,
    actor_tokens: dict[str, str],
    control: str,
    fixture: InProcessSupportlab | ServedSupportlab | ComposeSupportlab,
    browser_driver: BrowserDriver | None = None,
    **runner_options: Any,
) -> PurpleTeamRunner:
    transports = fixture.transports
    http = HttpAdapter(transports=transports, tools=SUPPORTLAB_LANE.tools)
    tool = ToolAdapter(transports=transports, tools=SUPPORTLAB_LANE.tools)
    chat = ChatAdapter(OfflineModelStore(MODEL_FIXTURE))
    if browser_driver is not None:
        driver: BrowserDriver = browser_driver
    elif transports is not None:
        driver = HtmlFormDriver({phase2_tools.DATA_PORT: transports[phase2_tools.DATA_PORT]})
    else:  # pragma: no cover - container/browser lane
        # A container-backed fixture has real loopback ports, so the browser lane drives Chromium.
        from purpleloop.adapters.browser import PlaywrightDriver

        driver = PlaywrightDriver()
    browser = BrowserAdapter(
        driver,
        artifact_root=output_dir / "browser",
        tools=SUPPORTLAB_LANE.tools,
        secrets=(control, *actor_tokens.values(), *ALL_CANARIES),
    )
    adapters: dict[str, Adapter] = {
        "http": http,
        "tool": tool,
        "control": http,
        "chat": chat,
        "browser": browser,
    }
    registry = AdapterRegistry(
        tuple(
            (definition.adapter, definition.operation, adapters[definition.adapter])
            for definition in (
                *phase2_tools.API_DEFINITIONS,
                *phase2_tools.BROWSER_DEFINITIONS,
                *phase2_tools.CONTROL_DEFINITIONS,
            )
        ),
        tools=SUPPORTLAB_LANE.tools,
    )
    broker = InMemoryCredentialBroker(
        {
            phase2_tools.ACTORS[actor].credential_handle: token
            for actor, token in actor_tokens.items()
        }
        | {phase2_tools.CONTROL_HANDLE: control}
    )
    runtime = SafetyRuntime(
        verifier=verifier,
        policy=DefaultDenyPolicy(SUPPORTLAB_LANE.tools),
        budgets=BudgetLedger(manifest.budgets),
        kill_switch=KillSwitch(),
        credential_broker=broker,
        redactor=Redactor(
            (control, *actor_tokens.values(), *ALL_CANARIES, *manifest.synthetic_secrets)
        ),
        adapter=registry,
        ledger=EvidenceLedger(output_dir / "evidence.jsonl"),
    )
    return PurpleTeamRunner(
        runtime, close=fixture.close, lane=SUPPORTLAB_LANE, browser=browser, **runner_options
    )


class ComposeSupportlab:  # pragma: no cover - container lane
    """Container-lane supportlab over ``compose.phase2.yaml`` with Postgres and the upstream."""

    def __init__(
        self, actor_tokens: dict[str, str], control: str, database: str, *, project: str
    ) -> None:
        self.project = project
        self.environment = {
            **os.environ,
            "SUPPORTLAB_ACTOR_CREDENTIALS": json.dumps(actor_tokens),
            "SUPPORTLAB_CONTROL_CREDENTIAL": control,
            "SUPPORTLAB_DATABASE_PASSWORD": database,
        }
        self.transports = None
        self.closed = False

    async def command(self, *args: str) -> None:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "compose",
            "-f",
            str(ROOT / "compose.phase2.yaml"),
            "-p",
            self.project,
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
            await self.command("up", "--build", "--wait", "--wait-timeout", "60")
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        await self.command("down", "--volumes", "--timeout", "0")
        self.closed = True
