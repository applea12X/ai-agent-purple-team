"""Shared fixtures for the Phase 5 tests.

Contract builders: ``tests`` is not a package and earlier suites are not edited, so these are
fixtures rather than imports from the Phase 4 tests; the manifest construction mirrors
``tests/phase4/test_phase4_contracts.py::manifest_14``.

Model-plane fixtures: stub transports, never a real model. Every networked path here is driven
through ``httpx.MockTransport``. Nothing in this directory opens a socket to a model, and the
environment is scrubbed of every model-plane variable first, so a developer's shell (which may
well point at a local Ollama) cannot leak into a test.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop import agent_cli
from purpleloop.adapters.model_provider import OpenAICompatibleProvider
from purpleloop.schemas.action import BudgetRequest, SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, Phase3Grants
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import ActionClass, Phase5Grants, ShadowReport

DIGEST = "a" * 64
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def _manifest_fields() -> dict[str, Any]:
    return {
        "schema_version": "1.5.0",
        "engagement_id": "phase5-lane",
        "owner": "fixture-owner",
        "approvers": ("operator",),
        "key_id": "manifest-key",
        "issued_at": NOW - timedelta(hours=1),
        "valid_from": NOW - timedelta(hours=1),
        "valid_until": NOW + timedelta(hours=1),
        "phase1": Phase1Grants(defense_profiles=frozenset({"object-ownership"})),
        "phase2": Phase2Grants(
            ownership_seed=42,
            ownership=(OwnershipScope(tenant_id="org-a", resource_ids=frozenset({"ticket-a1"})),),
            database_credential_handle="supportlab-database",
            containment_prefix="purpleloop-agent",
        ),
        "phase3": Phase3Grants(
            model_credential_handle="model-api",
            model_pins=(
                ModelPin(
                    pin_id="offline",
                    provider="offline",
                    model_id="scripted",
                    decoding=DecodingParameters(seed=7),
                    system_prompt_hash=DIGEST,
                ),
            ),
            token_budget=1000,
            cost_microusd_budget=1000,
        ),
        "phase4": Phase4Grants(
            attestation_key_ids=frozenset({"ci-key"}),
            retention=(RetentionRule(artifact_kind="raw-ledgers", days=0, rationale="kept"),),
        ),
        "phase5": Phase5Grants(action_classes=frozenset({ActionClass.READ})),
        "assets": (
            AssetScope(
                asset_id="supportlab-data",
                scheme="http",
                host="127.0.0.1",
                port=28080,
                tenant_ids=frozenset({"org-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
            AssetScope(
                asset_id="otel-collector",
                scheme="http",
                host="127.0.0.1",
                port=24318,
                tenant_ids=frozenset({"org-a"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
        "allowed_adapters": frozenset({"http"}),
        "allowed_operations": frozenset({"ticket.read"}),
        "allowed_side_effects": frozenset({SideEffectClass.READ}),
        "credential_handles": frozenset({"customer"}),
        "credential_scopes": {"customer": frozenset({"ticket.read"})},
        "budgets": BudgetLimits(requests=10, records=10),
        "signature": "",
    }


@pytest.fixture
def make_manifest() -> Callable[..., AuthorizationManifest]:
    """A manifest 1.5 builder; keyword overrides replace top-level fields."""

    def make(**overrides: Any) -> AuthorizationManifest:
        fields = _manifest_fields()
        fields.update(overrides)
        return AuthorizationManifest.model_validate(fields)

    return make


@pytest.fixture
def make_shadow_report() -> Callable[..., ShadowReport]:
    def make(**overrides: Any) -> ShadowReport:
        fields: dict[str, Any] = {
            "run_id": "shadow-run-1",
            "engagement_id": "phase5-lane",
            "manifest_digest": DIGEST,
            "action_classes_reached": frozenset({ActionClass.READ, ActionClass.CODE_EXEC}),
            "operations_proposed": {"snippet.run": 3, "ticket.read": 1},
            "denials_by_reason": {"OPERATION_NOT_ALLOWED": 2},
            "would_be_budget": BudgetRequest(requests=4, records=4),
            "proposals_total": 4,
            "proposals_rejected": 1,
            "proposal_rejection_rate": 0.25,
            "suppressed_executions": 2,
            "unreachable_steps": 1,
            "created_at": NOW - timedelta(minutes=30),
        }
        fields.update(overrides)
        return ShadowReport.model_validate(fields)

    return make


@pytest.fixture
def approver_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def now() -> datetime:
    """The instant every Phase 5 contract test treats as the present."""
    return NOW


PREFIXES = ("PURPLELOOP_MODEL", "PURPLELOOP_JUDGE")


@pytest.fixture(autouse=True)
def scrubbed_model_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[None]:
    for name in list(os.environ):
        if name.startswith(PREFIXES):
            monkeypatch.delenv(name, raising=False)
    # An empty calibration directory, so a committed calibration never changes a test's pin.
    monkeypatch.setenv(
        "PURPLELOOP_MODEL_CALIBRATION_DIR", str(tmp_path_factory.mktemp("calibration"))
    )
    yield


@dataclass
class StubModel:
    """A scripted OpenAI-compatible endpoint. Records every request body it is sent."""

    content: str | Callable[[dict[str, Any]], str] = '{"message": "Answered.", "tool_intents": []}'
    prompt_tokens: int = 100
    completion_tokens: int = 20
    status: int = 200
    requests: list[dict[str, Any]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def respond(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        self.urls.append(str(request.url))
        text = self.content(body) if callable(self.content) else self.content
        return httpx.Response(
            self.status,
            json={
                "choices": [{"message": {"content": text}}],
                "usage": {
                    "prompt_tokens": self.prompt_tokens,
                    "completion_tokens": self.completion_tokens,
                },
            },
        )

    def provider_class(self) -> type[OpenAICompatibleProvider]:
        stub = self

        class Stubbed(OpenAICompatibleProvider):
            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs, transport=httpx.MockTransport(stub.respond))

        return Stubbed


@pytest.fixture
def stub_model(monkeypatch: pytest.MonkeyPatch) -> StubModel:
    """Route every provider the agent CLI builds to a stub endpoint."""
    stub = StubModel()
    monkeypatch.setattr(agent_cli, "OpenAICompatibleProvider", stub.provider_class())
    return stub


@pytest.fixture
def stub_judge(monkeypatch: pytest.MonkeyPatch) -> StubModel:
    """Route the networked judge-report's provider to a stub endpoint."""
    from purpleloop import judge_report

    stub = StubModel()
    monkeypatch.setattr(judge_report, "OpenAICompatibleProvider", stub.provider_class())
    return stub


@pytest.fixture
def read_events() -> Callable[[Path], list[dict[str, Any]]]:
    def read(bundle: Path) -> list[dict[str, Any]]:
        lines = (bundle / "evidence.jsonl").read_text().splitlines()
        return [json.loads(line) for line in lines]

    return read


# --- WP5.0.8 / WP5.4 review fixtures --------------------------------------------------------
#
# Real offline bundles, generated once per session from the agent corpus (no model, no Ollama),
# plus suites built from them. Tests copy them before use, so no test can alter another's input.

REVIEW_SCENARIOS = ("agent-indirect-html", "agent-indirect-markdown")


def _seal_suite(root: Path, members: dict[str, Path]) -> Path:
    import shutil

    from purpleloop.reporting.bundle import inventory, verify_bundle, write_json

    root.mkdir()
    for name, source in members.items():
        shutil.copytree(source, root / name)
    write_json(root / "suite.json", {"schema_version": "1.3.0", "scenarios": list(members)})
    inventory(root, complete=True)
    verify_bundle(root)
    return root


@pytest.fixture(scope="session")
def review_bundles(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    import asyncio

    from purpleloop.reporting.bundle import verify_bundle
    from purpleloop.runtime.demo import ROOT

    root = tmp_path_factory.mktemp("review-bundles")
    bundles: dict[str, Path] = {}
    for scenario_id in REVIEW_SCENARIOS:
        directory = root / scenario_id
        asyncio.run(
            agent_cli.run_offline_scenario(
                ROOT / "scenarios" / "agent" / f"{scenario_id}.yaml", directory
            )
        )
        verify_bundle(directory)
        bundles[scenario_id] = directory
    bundles["suite"] = _seal_suite(
        root / "suite", {name: bundles[name] for name in REVIEW_SCENARIOS}
    )
    first = bundles[REVIEW_SCENARIOS[0]]
    bundles["repeated"] = _seal_suite(
        root / "repeated", {f"{REVIEW_SCENARIOS[0]}-rep-{index}": first for index in range(2)}
    )
    return bundles


@pytest.fixture
def review_copy(tmp_path: Path, review_bundles: dict[str, Path]) -> Callable[[str], Path]:
    """A private copy of one review bundle, under ``tmp_path/bundles``."""
    import shutil

    def copy(name: str) -> Path:
        target = tmp_path / "bundles" / name
        shutil.copytree(review_bundles[name], target)
        return target

    return copy


@pytest.fixture
def reviewer_key_file(tmp_path: Path) -> tuple[Path, Path]:
    """A fresh reviewer key pair, outside any bundle: (private PEM, public PEM)."""
    from purpleloop.review.adjudication import generate_reviewer_key

    keys = tmp_path / "keys"
    keys.mkdir()
    generate_reviewer_key(keys / "reviewer.pem", keys / "reviewer-public.pem")
    return keys / "reviewer.pem", keys / "reviewer-public.pem"


# --- WP5.1 governance: shadow runs, the approved baseline, risk approvals ----------------------
#
# Every key here is generated in memory for one test and never written anywhere. The baseline is
# signed fresh per test from the v1 lane manifests, exactly as the committed one was, so a test
# can also sign a deliberately wrong one.

APPROVER_KEY_ID = "approver-ephemeral"


class Counts(dict[str, int]):
    def __missing__(self, key: str) -> int:
        return 0


class CountingTransport(httpx.AsyncBaseTransport):
    """Counts every request that reaches the in-process fixture. A shadow run leaves it at 0."""

    def __init__(self, inner: httpx.AsyncBaseTransport, counts: Counts) -> None:
        self.inner, self.counts = inner, counts

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.counts["fixture-requests"] += 1
        return await self.inner.handle_async_request(request)


class CountingModel:
    """Wraps the scripted target model; counts every completion. A shadow run leaves it at 0."""

    def __init__(self, counts: Counts) -> None:
        from purpleloop.adapters.scripted_model import ScriptedAgentModel

        self.inner, self.counts = ScriptedAgentModel(), counts
        self.profile = self.inner.profile

    @property
    def endpoint(self) -> str | None:
        return None

    async def complete(self, **kwargs: Any) -> tuple[str, int, int]:
        self.counts["model-calls"] += 1
        return await self.inner.complete(**kwargs)


def agent_scenarios() -> list[Any]:
    from purpleloop.schemas.phase1 import load_scenario, scenario_paths

    return [load_scenario(path) for path in scenario_paths(agent_cli.SCENARIOS)]


@dataclass
class Governance:
    """Builders for the WP5.1 tests: manifests, shadow runs, approvals, execute runs."""

    manifest_key: Ed25519PrivateKey
    approver_key: Ed25519PrivateKey
    baseline: Any
    baseline_keys: dict[str, Any]
    counts: Counts = field(default_factory=Counts)
    approver_key_id: str = APPROVER_KEY_ID

    def manifest(self, **kwargs: Any) -> AuthorizationManifest:
        from purpleloop.runtime.governance import agent_manifest_15

        return agent_manifest_15(self.manifest_key, **kwargs)

    def sign(self, manifest: AuthorizationManifest) -> AuthorizationManifest:
        from purpleloop.control.manifest import sign_manifest

        return sign_manifest(
            AuthorizationManifest.model_validate(manifest.model_dump()), self.manifest_key
        )

    def verifier(self) -> Any:
        from purpleloop.control.manifest import ManifestVerifier
        from purpleloop.runtime.supportlab import KEY_ID

        return ManifestVerifier({KEY_ID: self.manifest_key.public_key()})

    def admission(self, approvals: Any = (), reports: Any = (), approver_keys: Any = None) -> Any:
        from purpleloop.control.approvals import ApprovalAdmission

        return ApprovalAdmission.of(
            self.baseline,
            self.baseline_keys,
            approver_keys=(
                approver_keys
                if approver_keys is not None
                else {self.approver_key_id: self.approver_key.public_key()}
            ),
            approvals=approvals,
            shadow_reports=reports,
        )

    def agent_runner(
        self, manifest: AuthorizationManifest, directory: Path, admission: Any, **options: Any
    ) -> Any:
        from purpleloop.runtime.supportlab import (
            InProcessSupportlab,
            actor_credentials,
            build_agent_runner,
        )

        tokens = actor_credentials()
        control = actor_credentials()["customer-a"]
        fixture = InProcessSupportlab(tokens, control)
        fixture.transports = {
            port: CountingTransport(transport, self.counts)  # type: ignore[misc]
            for port, transport in fixture.transports.items()
        }
        return build_agent_runner(
            directory,
            manifest,
            self.verifier(),
            actor_tokens=tokens,
            control=control,
            fixture=fixture,
            admission=admission,
            model_provider=CountingModel(self.counts),
            **options,
        )

    def runtime_factory(self, manifest: AuthorizationManifest, admission: Any) -> Any:
        return lambda directory: self.agent_runner(manifest, directory, admission).runtime

    def attacker(self, source: str = "bounded-search", **overrides: Any) -> Any:
        from purpleloop.control.attacker import BoundedAttacker, ModelDrivenAttacker
        from purpleloop.control.phase3_tools import INTENT_OPERATIONS
        from purpleloop.runtime.governance import ATTACKER_PIN

        common: dict[str, Any] = {
            "max_proposals": 8,
            "max_depth": 3,
            "operations": sorted(INTENT_OPERATIONS),
            "own_tenant": "org-a",
            "other_tenants": ("org-b",),
            "resource_id": "admin-a",
        }
        common.update(overrides)
        if source == "model-driven":
            from purpleloop.adapters.scripted_attacker import ScriptedAttackerModel

            model = common.pop("model", None) or ScriptedAttackerModel()
            pin = common.pop("pin", ATTACKER_PIN)
            return ModelDrivenAttacker(
                model, pin, objective="change another tenant's records", **common
            )
        return BoundedAttacker(**common)

    def twin(self, requested: AuthorizationManifest) -> AuthorizationManifest:
        from purpleloop.control.approvals import shadow_twin

        return self.sign(shadow_twin(requested))

    def shadow(
        self,
        requested: AuthorizationManifest,
        out: Path,
        *,
        scenarios: list[Any] | None = None,
        attacker: Callable[[], Any] | None = None,
        admission: Any = None,
    ) -> tuple[Any, Any, AuthorizationManifest]:
        import asyncio

        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        from purpleloop.control.lanes import AGENT_LANE
        from purpleloop.runtime.shadow import ShadowRunner

        twin = self.twin(requested)
        runner = ShadowRunner(
            self.runtime_factory(twin, admission or self.admission()),
            lane=AGENT_LANE,
            attacker_factory=attacker,
        )
        report = asyncio.run(
            runner.run(
                scenarios or agent_scenarios()[:2],
                twin,
                run_id="shadow-test",
                output_dir=out,
                public_key_pem=self.manifest_key.public_key().public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                ),
                requested=requested,
            )
        )
        return report, runner, twin

    def approve(self, requested: AuthorizationManifest, report: Any, **overrides: Any) -> Any:
        from purpleloop.control.approvals import grant_approval

        options: dict[str, Any] = {
            "approver_key_id": self.approver_key_id,
            "approver": "a test approver holding an ephemeral key",
            "rationale": "test approval",
            "approval_id": "approval-test",
        }
        key = overrides.pop("key", self.approver_key)
        baseline = overrides.pop("baseline", self.baseline)
        options.update(overrides)
        return grant_approval(requested, report, baseline, key, **options)

    def approved(self, requested: AuthorizationManifest, *approvals: Any) -> AuthorizationManifest:
        from purpleloop.control.approvals import with_approvals

        return self.sign(with_approvals(requested, approvals))


@pytest.fixture
def counting_transport() -> type[CountingTransport]:
    return CountingTransport


@pytest.fixture
def governance() -> Governance:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from purpleloop.runtime.governance import sign_v1_baseline

    baseline, pem = sign_v1_baseline()
    return Governance(
        manifest_key=Ed25519PrivateKey.generate(),
        approver_key=Ed25519PrivateKey.generate(),
        baseline=baseline,
        baseline_keys={baseline.key_id: load_pem_public_key(pem)},
    )
