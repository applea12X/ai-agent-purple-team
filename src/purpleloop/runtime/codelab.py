"""Assemble a codelab lane run: manifest 1.5, its risk approval, adapters, fixture, and sandbox.

WP5.5, ADR 0015. The codelab lane admits only manifest 1.5, so every run passes capability
admission (ADR 0014) against the committed v1 baseline. Its delta is a new action class
(``code-exec``), new operations, and a new target fixture, so no run is admitted until that exact
delta is approved -- the first real use of the WP5.1 approval path, and its end-to-end test:

1. :func:`codelab_manifest` builds the requested manifest (``execute``);
2. its shadow twin runs over the corpus through :class:`~purpleloop.runtime.shadow.ShadowRunner`,
   which dispatches nothing -- no snippet reaches any sandbox in shadow;
3. :func:`approve` signs a ``RiskApproval`` of the exact delta on that shadow report, with an
   approver key that is *ephemeral* unless one is passed in, and returns the manifest naming it
   plus the admission that accepts it.

The in-process fixture uses the stub sandbox (``fixture/codelab/sandbox.py``) and never runs a
snippet. :class:`ComposeCodelab` brings up ``compose.codelab.yaml``, where snippets run in the
sandbox container.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import Field, model_validator

from purpleloop.adapters.base import Adapter
from purpleloop.adapters.codelab import (
    SYSTEM_PROMPT_HASH,
    CodelabAgentAdapter,
    CodelabScriptedModel,
)
from purpleloop.adapters.model_provider import ModelClient, Provider
from purpleloop.adapters.phase1 import AdapterRegistry, HttpAdapter, ToolAdapter
from purpleloop.control import phase5_tools as tools
from purpleloop.control.approvals import (
    ApprovalAdmission,
    grant_approval,
    shadow_twin,
    with_approvals,
)
from purpleloop.control.budgets import BudgetLedger
from purpleloop.control.credentials import InMemoryCredentialBroker
from purpleloop.control.kill_switch import KillSwitch
from purpleloop.control.lanes import CODELAB_LANE
from purpleloop.control.manifest import ManifestVerifier, sign_manifest
from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.control.redaction import Redactor
from purpleloop.fixture.codelab.app import CodelabState, create_apps
from purpleloop.fixture.codelab.sandbox import Sandbox
from purpleloop.fixture.codelab.seed import DATASETS, canary_for
from purpleloop.reporting.bundle import inventory, reports, verify_bundle, write_json
from purpleloop.runtime import governance
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.inspect_bridge import evaluate_runner
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.runner import PurpleTeamRunner
from purpleloop.runtime.runtime import SafetyRuntime
from purpleloop.runtime.shadow import ShadowRunner
from purpleloop.runtime.supportlab import MODEL_FIXTURE
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.authorization import (
    AssetScope,
    AuthorizationManifest,
    BudgetLimits,
    Phase1Grants,
)
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase1 import (
    Phase1Scenario,
    RunSummary,
    load_ground_truth,
    load_scenario,
    scenario_paths,
)
from purpleloop.schemas.phase2 import OwnershipScope, Phase2Grants
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, Phase3Grants
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import ActionClass, Phase5Grants, RiskApproval, RunMode, ShadowReport
from purpleloop.scoring.phase1 import corpus_metrics
from purpleloop.scoring.phase4 import risk_class_metrics

SCENARIOS = ROOT / "scenarios" / "codelab"
GROUND_TRUTH = SCENARIOS / "ground-truth.json"
ESCAPE_SUITE = SCENARIOS / "escape-suite.json"
COMPOSE_FILE = ROOT / "compose.codelab.yaml"
KEY_ID = "codelab-demo-key"
OFFLINE_PIN = "codelab-scripted"
APPROVER_KEY_ID = "codelab-approver-ephemeral"
ENGAGEMENT = "codelab-local-demo"


def codelab_manifest(
    key: Ed25519PrivateKey,
    *,
    seed: int = 42,
    now: datetime | None = None,
    run_mode: RunMode = "execute",
    risk_approvals: Sequence[str] = (),
    action_classes: Sequence[ActionClass] = (
        ActionClass.READ,
        ActionClass.WRITE,
        ActionClass.CODE_EXEC,
    ),
) -> AuthorizationManifest:
    """Manifest 1.5 for the codelab lane, signed. Offline: no model endpoint is authorized."""
    current = now or datetime.now(UTC)
    pin = ModelPin(
        pin_id=OFFLINE_PIN,
        provider="offline",
        model_id="codelab-scripted",
        model_version="scripted-v1",
        decoding=DecodingParameters(seed=seed),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
    )
    manifest = AuthorizationManifest(
        schema_version="1.5.0",
        engagement_id=ENGAGEMENT,
        owner="fixture-owner",
        approvers=("local-demo-operator",),
        key_id=KEY_ID,
        issued_at=current - timedelta(seconds=1),
        valid_from=current - timedelta(seconds=1),
        valid_until=current + timedelta(hours=2),
        phase1=Phase1Grants(defense_profiles=frozenset(tools.CODELAB_DEFENSES)),
        phase2=Phase2Grants(
            ownership_seed=seed,
            ownership=(OwnershipScope(tenant_id=tools.TENANT, resource_ids=frozenset(DATASETS)),),
            database_credential_handle=tools.STORE_HANDLE,
            containment_prefix=tools.CONTAINMENT_PREFIX,
            max_browser_contexts=0,
        ),
        phase3=Phase3Grants(
            model_credential_handle="codelab-model",
            model_pins=(pin,),
            token_budget=200_000,
            cost_microusd_budget=0,
            max_agent_steps=8,
            max_tool_intents_per_turn=4,
            max_attacker_proposals=0,
            max_attacker_depth=0,
        ),
        phase4=Phase4Grants(
            attestation_key_ids=frozenset({governance.ATTESTATION_KEY_ID}),
            retention=(
                RetentionRule(
                    artifact_kind="raw-ledgers", days=7, rationale="synthetic fixture evidence"
                ),
            ),
        ),
        phase5=Phase5Grants(
            action_classes=frozenset(action_classes),
            run_mode=run_mode,
            risk_approvals=frozenset(risk_approvals),
        ),
        assets=(
            AssetScope(
                asset_id=tools.DATA_ASSET,
                scheme="http",
                host="127.0.0.1",
                port=tools.DATA_PORT,
                tenant_ids=frozenset({tools.TENANT}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
            AssetScope(
                asset_id=tools.CONTROL_ASSET,
                scheme="http",
                host="127.0.0.1",
                port=tools.CONTROL_PORT,
                path_prefix="/control",
                tenant_ids=frozenset({"harness"}),
                allowed_resolved_addresses=frozenset({IPv4Address("127.0.0.1")}),
            ),
        ),
        allowed_adapters=frozenset({"agent", "tool", "control"}),
        allowed_operations=tools.DATA_OPERATIONS | tools.CONTROL_OPERATIONS,
        allowed_methods=frozenset({"GET", "POST"}),
        allowed_side_effects=frozenset({SideEffectClass.READ, SideEffectClass.WRITE}),
        credential_handles=frozenset(tools.ATTACK_HANDLES | {tools.CONTROL_HANDLE}),
        credential_scopes={
            **{handle: tools.DATA_OPERATIONS for handle in tools.ATTACK_HANDLES},
            tools.CONTROL_HANDLE: tools.CONTROL_OPERATIONS,
        },
        egress_hosts=frozenset({"127.0.0.1"}),
        budgets=BudgetLimits(
            requests=600,
            writes=64,
            records=600,
            tokens=200_000,
            concurrency=1,
            wall_time_seconds=120,
        ),
        signature="",
    )
    return sign_manifest(manifest, key)


# --- fixtures -----------------------------------------------------------------------------------


def actor_credentials() -> dict[str, str]:
    return {actor: secrets.token_hex(24) for actor in tools.ACTORS}


class InProcessCodelab:
    """In-process codelab over ASGI transports, with the stub sandbox. Runs no snippet."""

    def __init__(
        self, actor_tokens: dict[str, str], control: str, *, sandbox: Sandbox | None = None
    ) -> None:
        self.state = CodelabState(actor_tokens=actor_tokens, control_token=control, sandbox=sandbox)
        data_app, control_app = create_apps(self.state)
        self.transports: dict[int, httpx.ASGITransport] | None = {
            tools.DATA_PORT: httpx.ASGITransport(app=data_app),
            tools.CONTROL_PORT: httpx.ASGITransport(app=control_app),
        }
        self.closed = False

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        await self.state.sandbox.close()
        self.state.dispose()
        self.closed = True


class ComposeCodelab:  # pragma: no cover - container lane (tests/phase5/test_codelab_container.py)
    """The container lane over ``compose.codelab.yaml``: fixture, relay, and sandbox container.

    ``runtime`` selects the sandbox container's OCI runtime (``runc`` by default; ``runsc`` where
    gVisor is installed). :meth:`sandbox_runtime` reads back what Docker actually used.
    """

    def __init__(
        self,
        actor_tokens: dict[str, str],
        control: str,
        *,
        project: str,
        runtime: str | None = None,
        outside_canary: str | None = None,
        keep: bool = False,
    ) -> None:
        self.project = project
        self.keep = keep
        self.outside_canary = outside_canary or "CODELAB-OUTSIDE-" + secrets.token_hex(12)
        self.requested_runtime = runtime or os.environ.get("CODELAB_SANDBOX_RUNTIME", "runc")
        self.environment = {
            **os.environ,
            "CODELAB_ACTOR_CREDENTIALS": json.dumps(actor_tokens),
            "CODELAB_CONTROL_CREDENTIAL": control,
            "CODELAB_SANDBOX_TOKEN": secrets.token_hex(32),
            "CODELAB_OUTSIDE_CANARY": self.outside_canary,
            "CODELAB_SANDBOX_RUNTIME": self.requested_runtime,
        }
        self.transports = None
        self.closed = False
        self.started = False

    async def compose(self, *args: str) -> str:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "-p",
            self.project,
            *args,
            cwd=ROOT,
            env=self.environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode:
            raise RuntimeError(f"Compose command failed: {stderr.decode()[:1000]}")
        return stdout.decode()

    async def container_id(self, service: str) -> str:
        return (await self.compose("ps", "-q", service)).strip()

    async def sandbox_runtime(self) -> str:
        container = await self.container_id("codelab-sandbox")
        return (await docker("inspect", "--format", "{{.HostConfig.Runtime}}", container)).strip()

    async def close(self) -> None:
        """A run's teardown. With ``keep`` the deployment outlives the run (a suite shares one
        deployment; each run still provisions, seeds, and resets it); :meth:`down` removes it."""
        if not self.keep:
            await self.down()
        self.closed = True

    async def down(self) -> None:
        await self.compose("down", "--volumes", "--timeout", "0")

    async def start(self) -> None:
        if self.started:
            return
        try:
            await self.compose("up", "--build", "--wait", "--wait-timeout", "120")
        except BaseException:
            await self.down()
            raise
        self.started = True


async def docker(*args: str) -> str:  # pragma: no cover - container lane
    process = await asyncio.create_subprocess_exec(
        "docker",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {stderr.decode()[:500]}")
    return stdout.decode()


Fixture = InProcessCodelab | ComposeCodelab


# --- runner -------------------------------------------------------------------------------------


def build_codelab_runner(
    output_dir: Path,
    manifest: AuthorizationManifest,
    verifier: ManifestVerifier,
    *,
    actor_tokens: dict[str, str],
    control: str,
    fixture: Fixture,
    admission: ApprovalAdmission | None,
    model_provider: Provider | None = None,
    seed: int = 42,
    **runner_options: Any,
) -> PurpleTeamRunner:
    transports = fixture.transports
    lane = CODELAB_LANE
    # A snippet run waits on the sandbox's wall-time kill, so the tool timeout sits above it.
    http = HttpAdapter(transports=transports, tools=lane.tools)
    tool = ToolAdapter(transports=transports, tools=lane.tools, timeout=20.0)
    budgets = BudgetLedger(manifest.budgets)
    assert manifest.phase3 is not None
    provider = model_provider or CodelabScriptedModel()
    model = ModelClient(
        pins=manifest.phase3.model_pins, providers={provider.profile: provider}, budgets=budgets
    )
    agent = CodelabAgentAdapter(
        model,
        pin_id=OFFLINE_PIN,
        tools=lane.tools,
        transports=transports,
        max_intents=manifest.phase3.max_tool_intents_per_turn,
        timeout=30.0,
    )
    adapters: dict[str, Adapter] = {"agent": agent, "tool": tool, "control": http}
    registry = AdapterRegistry(
        tuple(
            (definition.adapter, definition.operation, adapters[definition.adapter])
            for definition in (*tools.DATA_DEFINITIONS, *tools.CONTROL_DEFINITIONS)
        ),
        tools=lane.tools,
    )
    broker = InMemoryCredentialBroker(
        {tools.ACTORS[actor].credential_handle: token for actor, token in actor_tokens.items()}
        | {tools.CONTROL_HANDLE: control}
    )
    secrets_to_redact = (control, *actor_tokens.values(), canary_for(seed))
    if isinstance(fixture, ComposeCodelab):  # pragma: no cover - container lane
        secrets_to_redact = (
            *secrets_to_redact,
            fixture.outside_canary,
            fixture.environment["CODELAB_SANDBOX_TOKEN"],
        )
    runtime = SafetyRuntime(
        verifier=verifier,
        policy=DefaultDenyPolicy(lane.tools),
        budgets=budgets,
        kill_switch=KillSwitch(),
        credential_broker=broker,
        redactor=Redactor(secrets_to_redact),
        adapter=registry,
        ledger=EvidenceLedger(output_dir / "evidence.jsonl"),
        admission=admission,
    )
    return PurpleTeamRunner(runtime, close=fixture.close, lane=lane, **runner_options)


# --- governance: shadow, approve, admit ---------------------------------------------------------


@dataclass(frozen=True)
class CodelabApproval:
    """Everything the approval path produced, and what an admitted run needs."""

    requested: AuthorizationManifest
    approved: AuthorizationManifest
    approval: RiskApproval
    report: ShadowReport
    admission: ApprovalAdmission
    verifier: ManifestVerifier
    approver_key_provenance: str


def load_corpus(directory: Path = SCENARIOS) -> list[Phase1Scenario]:
    return [load_scenario(path) for path in scenario_paths(directory)]


async def shadow_codelab(
    output_dir: Path,
    requested: AuthorizationManifest,
    key: Ed25519PrivateKey,
    scenarios: Sequence[Phase1Scenario],
    *,
    run_id: str = "codelab-shadow",
) -> tuple[ShadowReport, ShadowRunner]:
    """Run the requested manifest's shadow twin over ``scenarios``. Dispatches nothing."""
    twin = sign_manifest(shadow_twin(requested), key)
    verifier = ManifestVerifier({twin.key_id: key.public_key()})
    admission = governance.committed_admission()

    def runtime_factory(directory: Path) -> SafetyRuntime:
        tokens = actor_credentials()
        control = secrets.token_hex(24)
        return build_codelab_runner(
            directory,
            twin,
            verifier,
            actor_tokens=tokens,
            control=control,
            fixture=InProcessCodelab(tokens, control),
            admission=admission,
        ).runtime

    runner = ShadowRunner(runtime_factory, lane=CODELAB_LANE)
    report = await runner.run(
        scenarios,
        twin,
        run_id=run_id,
        output_dir=output_dir,
        public_key_pem=key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ),
        requested=requested,
    )
    return report, runner


async def approve(
    work_dir: Path,
    key: Ed25519PrivateKey,
    *,
    scenarios: Sequence[Phase1Scenario] | None = None,
    approver_key: Ed25519PrivateKey | None = None,
    approver_key_id: str = APPROVER_KEY_ID,
    now: datetime | None = None,
    ttl: timedelta = timedelta(hours=4),
) -> CodelabApproval:
    """Shadow the codelab manifest, sign an approval of its exact delta, and admit it.

    With no ``approver_key`` an ephemeral one is generated here and never written anywhere; the
    result says so in ``approver_key_provenance``.
    """
    corpus = list(scenarios) if scenarios is not None else load_corpus()
    requested = codelab_manifest(key, now=now)
    report, _ = await shadow_codelab(work_dir / "shadow", requested, key, corpus)
    provenance = "provided" if approver_key is not None else "ephemeral"
    signer = approver_key or Ed25519PrivateKey.generate()
    baseline, _ = governance.committed_baseline()
    approval = grant_approval(
        requested,
        report,
        baseline,
        signer,
        approver_key_id=approver_key_id,
        approver=(
            "the project's single author, holding an ephemeral key generated for this run"
            if provenance == "ephemeral"
            else "the holder of the approver key passed to this run"
        ),
        rationale=(
            "codelab adds a code-execution tool on a new disposable fixture. Shadow run showed "
            "the kernel's decisions on every corpus action with zero dispatches; snippets run "
            "only inside the fixture's sandbox container (ADR 0015)."
        ),
        approval_id="codelab-code-exec",
        ttl=ttl,
        now=now,
    )
    approved = sign_manifest(with_approvals(requested, [approval]), key)
    admission = governance.committed_admission(
        approver_keys={approver_key_id: signer.public_key()},
        approvals=(approval,),
        shadow_reports=(report,),
    )
    return CodelabApproval(
        requested=requested,
        approved=approved,
        approval=approval,
        report=report,
        admission=admission,
        verifier=ManifestVerifier({KEY_ID: key.public_key()}),
        approver_key_provenance=provenance,
    )


# --- corpus run ---------------------------------------------------------------------------------


async def run_scenario(
    directory: Path,
    scenario: Phase1Scenario,
    approval: CodelabApproval,
    *,
    fixture: Fixture | None = None,
    model: Provider | None = None,
    manifest: AuthorizationManifest | None = None,
    admission: ApprovalAdmission | None = None,
    inspect: bool = True,
    run_id: str | None = None,
) -> RunSummary:
    """One paired codelab run, under the approved manifest unless another is given."""
    if fixture is None:
        tokens = actor_credentials()
        control = secrets.token_hex(24)
        fixture = InProcessCodelab(tokens, control)
    else:  # pragma: no cover - container lane passes its own credentials
        tokens, control = _fixture_credentials(fixture)
    signed = manifest or approval.approved
    runner = build_codelab_runner(
        directory,
        signed,
        approval.verifier,
        actor_tokens=tokens,
        control=control,
        fixture=fixture,
        admission=admission or approval.admission,
        model_provider=model,
    )
    await fixture.start()
    if not inspect:
        return await runner.run(
            scenario, signed, run_id=run_id or scenario.scenario_id, output_dir=directory
        )
    return await evaluate_runner(
        runner,
        scenario,
        signed,
        run_id=run_id or scenario.scenario_id,
        output_dir=directory,
        model_fixture=MODEL_FIXTURE,
    )


def _fixture_credentials(fixture: Fixture) -> tuple[dict[str, str], str]:  # pragma: no cover
    if isinstance(fixture, ComposeCodelab):
        environment = fixture.environment
        return (
            json.loads(environment["CODELAB_ACTOR_CREDENTIALS"]),
            environment["CODELAB_CONTROL_CREDENTIAL"],
        )
    state = fixture.state
    return {actor: token for token, actor in state.tokens.items()}, state.control_token


async def run_corpus(
    root: Path,
    approval: CodelabApproval,
    *,
    scenarios: Sequence[Phase1Scenario] | None = None,
    model: Provider | None = None,
    stand_in: str = "scripted",
    fixture_factory: Any = None,
) -> list[RunSummary]:
    """Every codelab scenario as one paired run, sealed into one verified suite bundle."""
    corpus = list(scenarios) if scenarios is not None else load_corpus()
    summaries = []
    for scenario in corpus:
        fixture = fixture_factory(scenario) if fixture_factory is not None else None
        summaries.append(
            await run_scenario(
                root / scenario.scenario_id, scenario, approval, fixture=fixture, model=model
            )
        )
    reports(root, summaries)
    (root / "authorization-public.pem").write_bytes(
        approval.verifier.public_key_bytes(approval.approved.key_id)
    )
    write_json(
        root / "suite.json",
        {
            "schema_version": "1.4.0",
            "lane": CODELAB_LANE.name,
            "model_provider": "offline-scripted",
            "stand_in": stand_in,
            "approval_digest": approval.approval.approval_digest(),
            "approver_key_provenance": approval.approver_key_provenance,
            "scenarios": [scenario.scenario_id for scenario in corpus],
        },
    )
    inventory(root, complete=True)
    verify_bundle(root)
    return summaries


# --- metrics ------------------------------------------------------------------------------------


class ReplayRecord(StrictModel):
    """Deterministic replay for the lane: identical normalized event and oracle hashes."""

    trials_per_scenario: int = Field(ge=2)
    trials: int = Field(ge=0)
    matched: int = Field(ge=0)
    rate: float = Field(ge=0, le=1)
    mismatched_scenarios: tuple[str, ...]

    @model_validator(mode="after")
    def consistent(self) -> ReplayRecord:
        if self.matched > self.trials or (
            self.trials and abs(self.rate - self.matched / self.trials) > 1e-12
        ):
            raise ValueError("replay rate must equal matched / trials")
        return self


class CodelabMetrics(StrictModel):
    """The codelab lane's numbers, reported per lane -- never folded into the authored 48."""

    schema_version: str = "1.0.0"
    lane: str = CODELAB_LANE.name
    stand_in: str
    sandbox: str
    scenarios: int
    statuses: dict[str, str]
    corpus: dict[str, Any]
    risk_classes: tuple[dict[str, Any], ...]
    defense_credited: tuple[str, ...]
    sandbox_jobs: int
    replay: ReplayRecord | None = None
    approval_digest: str
    approver_key_provenance: str
    note: str


def codelab_metrics(
    *,
    scenarios: Sequence[Phase1Scenario],
    summaries: Sequence[RunSummary],
    stand_in: str,
    sandbox: str,
    sandbox_jobs: int,
    approval: CodelabApproval,
    replay: ReplayRecord | None = None,
) -> CodelabMetrics:
    truth = load_ground_truth(GROUND_TRUTH)
    ids = {scenario.scenario_id for scenario in scenarios}
    if {summary.scenario_id for summary in summaries} - ids:
        raise ValueError("a run names a scenario outside the codelab corpus")
    if any(scenario.lane != CODELAB_LANE.name for scenario in scenarios):
        raise ValueError("codelab metrics accept codelab scenarios only")
    return CodelabMetrics(
        stand_in=stand_in,
        sandbox=sandbox,
        scenarios=len(summaries),
        statuses={summary.scenario_id: summary.status for summary in summaries},
        corpus=corpus_metrics(truth, summaries),
        risk_classes=tuple(
            item.model_dump(mode="json") for item in risk_class_metrics(scenarios, truth, summaries)
        ),
        defense_credited=tuple(
            sorted(summary.scenario_id for summary in summaries if summary.mitigation_effective)
        ),
        sandbox_jobs=sandbox_jobs,
        replay=replay,
        approval_digest=approval.approval.approval_digest(),
        approver_key_provenance=approval.approver_key_provenance,
        note=(
            "codelab lane, reported apart from the authored 48 and the benchmark subset. "
            "Deterministic stand-in model: a measurement of the harness, the fixture's "
            "defenses, and (on the container lane) the sandbox, not of any model."
        ),
    )


async def replay_trials(
    root: Path,
    approval: CodelabApproval,
    *,
    trials: int = 3,
    scenarios: Sequence[Phase1Scenario] | None = None,
) -> ReplayRecord:
    """Run each scenario ``trials`` times in process; every trial must hash identically."""
    corpus = list(scenarios) if scenarios is not None else load_corpus()
    matched = total = 0
    mismatched = []
    for scenario in corpus:
        fingerprints = set()
        for trial in range(trials):
            summary = await run_scenario(
                root / f"{scenario.scenario_id}-{trial}",
                scenario,
                approval,
                inspect=False,
                run_id=f"replay-{scenario.scenario_id}-{trial}",
            )
            fingerprints.add((summary.event_replay_hash, summary.oracle_hash, summary.status))
            total += 1
        if len(fingerprints) == 1 and None not in next(iter(fingerprints)):
            matched += trials
        else:
            mismatched.append(scenario.scenario_id)
    return ReplayRecord(
        trials_per_scenario=trials,
        trials=total,
        matched=matched,
        rate=matched / total if total else 0.0,
        mismatched_scenarios=tuple(mismatched),
    )
