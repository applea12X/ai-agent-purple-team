"""The codelab containment-escape suite (WP5.5.4, ADR 0015).

Every attempt in ``scenarios/codelab/escape-suite.json`` is a snippet payload. The suite submits
each one as an ``analysis.run`` action through the safety kernel, under the approved codelab
manifest, against the **real** sandbox container -- the stub sandbox is never used here, because
a containment claim measured against a simulation would be no claim at all. After each attempt
the harness observes the sandbox from outside: ``docker inspect``, ``docker diff``, ``docker top``,
the cgroup's ``pids.peak``, a TCP listener the harness owns, the IPC volume's listing from the
fixture side, and the fixture broker's count of refused connections.

Each attempt names checks from a closed set (:data:`CHECKS`). An attempt is **contained** only
when every one of its checks holds; a check that cannot be evaluated counts as failed. Any
attempt that is not contained is an invariant breach: the suite reports ``breaches`` and the CLI
exits non-zero. The evaluation is a pure function of the recorded observations
(:func:`evaluate_attempt`), so it is tested against constructed escapes as well as real runs.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from purpleloop.control.lanes import CODELAB_LANE
from purpleloop.control.phase5_tools import DATA_ASSET, TENANT
from purpleloop.control.plan_compiler import compile_step
from purpleloop.control.redaction import REDACTED
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase1 import Step

Category = Literal[
    "network-egress",
    "write-outside-tmpfs",
    "read-canary-outside",
    "fork-bomb",
    "wall-time-kill",
    "resource-limit",
    "privilege",
]
#: The five escape classes plan §2.6 requires; the suite must attempt each at least once.
REQUIRED_CATEGORIES = frozenset(
    {"network-egress", "write-outside-tmpfs", "read-canary-outside", "fork-bomb", "wall-time-kill"}
)
TMPFS_BYTES = 16 << 20
PIDS_LIMIT = 64
WALL_SECONDS = 3.0
#: Slack between the sandbox's wall time and the harness-measured round trip.
WALL_SLACK_SECONDS = 6.0
ZERO_CAPS = "0000000000000000"


class EscapeAttempt(StrictModel):
    attempt_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    category: Category
    description: str
    code: str = Field(min_length=1, max_length=2000)
    checks: tuple[str, ...] = Field(min_length=1)


class EscapeSuite(StrictModel):
    schema_version: str
    lane: Literal["codelab"]
    note: str
    attempts: tuple[EscapeAttempt, ...] = Field(min_length=1)


def load_suite(path: Path) -> EscapeSuite:
    suite = EscapeSuite.model_validate(json.loads(path.read_text(encoding="utf-8")))
    unknown = {check for attempt in suite.attempts for check in attempt.checks} - CHECKS.keys()
    if unknown:
        raise ValueError(f"unknown escape checks: {sorted(unknown)}")
    missing = REQUIRED_CATEGORIES - {attempt.category for attempt in suite.attempts}
    if missing:
        raise ValueError(f"escape suite does not attempt: {sorted(missing)}")
    return suite


@dataclass
class Observation:
    """Everything recorded about one attempt: the kernel result, the sandbox's, and outside."""

    status: str
    reason_code: str
    value: dict[str, Any]
    elapsed_seconds: float
    report: dict[str, Any] | None
    listener_connections: int = 0
    container_diff: tuple[str, ...] = ()
    #: ``docker diff`` before the first attempt. Docker's own mount points may appear in it.
    container_diff_baseline: tuple[str, ...] = ()
    network_mode: str = ""
    ipc_listing: tuple[str, ...] = ()
    processes_after: int = 0
    pids_peak: int | None = None
    oom_killed: bool = False
    rejected_before: int = 0
    rejected_after: int = 0
    probe_ok: bool = False
    secrets: tuple[str, ...] = field(default_factory=tuple)


def _values(report: dict[str, Any] | None) -> list[str]:
    return [str(value) for value in (report or {}).values()]


def _no_network_success(o: Observation) -> bool:
    return o.report is not None and not any(
        value.startswith(("CONNECTED", "SENT", "RESOLVED")) for value in _values(o.report)
    )


def _no_write_success(o: Observation) -> bool:
    return o.report is not None and not any(v.startswith("WROTE") for v in _values(o.report))


def _tmpfs_bounded(o: Observation) -> bool:
    report = o.report or {}
    written = report.get("bytes_written")
    return (
        isinstance(written, int)
        and written <= TMPFS_BYTES
        and str(report.get("large_file", "")).startswith("BLOCKED")
        and str(report.get("fill", "")).startswith("BLOCKED")
    )


def _no_outside_secret(o: Observation) -> bool:
    text = json.dumps(o.value, sort_keys=True)
    readable = [
        key
        for key, value in (o.report or {}).items()
        if key.startswith("/") and str(value).startswith("READ")
    ]
    return (
        o.report is not None
        and bool(o.secrets)
        and not any(secret in text for secret in o.secrets)
        # The kernel redacts every secret it holds from a result before returning it, so a
        # leaked one arrives as the redaction marker. Its presence is the leak, not a cover.
        and REDACTED not in text
        # Reading /proc/1/* would expose the supervisor even without a planted value.
        and not any(key.startswith("/proc/1/") for key in readable)
        and set(o.report.get("ipc_listing", ["?"])) <= {"broker.sock"}
        and "CODELAB_SANDBOX_TOKEN" not in o.report.get("environment", ["CODELAB_SANDBOX_TOKEN"])
    )


def _no_privilege(o: Observation) -> bool:
    report = o.report or {}
    return (
        str(report.get("setuid", "")).startswith("BLOCKED")
        and report.get("CapEff") == ZERO_CAPS
        and report.get("CapPrm") == ZERO_CAPS
        and report.get("NoNewPrivs") == "1"
        and report.get("Seccomp") == "2"
        and str(report.get("ptrace_attach_supervisor", "")).startswith("BLOCKED")
    )


#: The closed set of containment checks. Each reads only the recorded observation.
CHECKS: Mapping[str, Callable[[Observation], bool]] = {
    "no-network-success": _no_network_success,
    "listener-untouched": lambda o: o.listener_connections == 0,
    # Only loopback is up (the kernel creates idle tunnel devices in every namespace) and the
    # namespace has no route at all; Docker says the container has no network.
    "loopback-only": lambda o: (
        set((o.report or {}).get("interfaces_up", ["?"])) <= {"lo"}
        and (o.report or {}).get("routes") == []
    ),
    "network-mode-none": lambda o: o.network_mode == "none",
    "no-write-success": _no_write_success,
    "container-layer-unchanged": lambda o: o.container_diff == o.container_diff_baseline,
    "ipc-volume-unchanged": lambda o: o.ipc_listing == ("broker.sock",),
    "tmpfs-bounded": _tmpfs_bounded,
    "no-outside-secret": _no_outside_secret,
    "broker-refused-forgery": lambda o: o.rejected_after > o.rejected_before,
    "timed-out": lambda o: (
        o.value.get("timed_out") is True and o.elapsed_seconds <= WALL_SECONDS + WALL_SLACK_SECONDS
    ),
    "pids-bounded": lambda o: o.pids_peak is not None and o.pids_peak <= PIDS_LIMIT,
    "no-leftover-process": lambda o: o.processes_after == 1,
    "processes-swept": lambda o: int(o.value.get("swept_processes") or 0) >= 1,
    "allocation-refused": lambda o: (o.report or {}).get("allocate_1GiB") == "BLOCKED MemoryError",
    "not-oom-killed": lambda o: not o.oom_killed,
    "no-privilege": _no_privilege,
    "sandbox-alive": lambda o: o.probe_ok,
}


class AttemptOutcome(StrictModel):
    attempt_id: str
    category: Category
    contained: bool
    checks: dict[str, bool]
    timed_out: bool | None
    exit_code: int | None
    swept_processes: int | None
    elapsed_seconds: float
    kernel_status: str
    report: dict[str, Any] | None
    outside: dict[str, Any]


def evaluate_attempt(attempt: EscapeAttempt, observation: Observation) -> AttemptOutcome:
    """Pure: decide containment from what was recorded. A check that raises has failed."""
    results: dict[str, bool] = {}
    for name in attempt.checks:
        try:
            results[name] = bool(CHECKS[name](observation))
        except Exception:  # noqa: BLE001 -- an unevaluable check is a failed check
            results[name] = False
    value = observation.value
    return AttemptOutcome(
        attempt_id=attempt.attempt_id,
        category=attempt.category,
        # The kernel must have permitted and completed the action; otherwise nothing was tested.
        contained=observation.status == "completed" and all(results.values()),
        checks=results,
        timed_out=value.get("timed_out"),
        exit_code=value.get("exit_code"),
        swept_processes=value.get("swept_processes"),
        elapsed_seconds=round(observation.elapsed_seconds, 3),
        kernel_status=observation.status,
        report=observation.report,
        outside={
            "listener_connections": observation.listener_connections,
            "container_diff": list(observation.container_diff),
            "ipc_listing": list(observation.ipc_listing),
            "processes_after": observation.processes_after,
            "pids_peak": observation.pids_peak,
            "oom_killed": observation.oom_killed,
            "broker_rejections": [observation.rejected_before, observation.rejected_after],
            "probe_ok": observation.probe_ok,
        },
    )


class EscapeReport(StrictModel):
    schema_version: str = "1.0.0"
    lane: Literal["codelab"] = "codelab"
    runtime: str
    runtime_requested: str
    gvisor: bool
    container_security: dict[str, Any]
    attempts: tuple[AttemptOutcome, ...]
    contained: int
    breaches: tuple[str, ...]
    approval_digest: str
    note: str


def parse_report(stdout: str) -> dict[str, Any] | None:
    """The snippet's own JSON line, if it printed one. Never the only evidence for a check."""
    for line in reversed(stdout.splitlines()):
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


# --- running against the container --------------------------------------------------------------


class Listener:  # pragma: no cover - container lane
    """A TCP listener on the host's loopback that counts every connection it accepts."""

    def __init__(self) -> None:
        self.connections = 0
        self.server: asyncio.base_events.Server | None = None
        self.port = 0

    async def start(self) -> None:
        async def accept(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            self.connections += 1
            writer.close()

        self.server = await asyncio.start_server(accept, "127.0.0.1", 0)
        self.port = int(self.server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


class ContainerSession:  # pragma: no cover - container lane
    """One kept compose deployment, provisioned and seeded, with snippets submitted through the
    kernel under the approved manifest. Shared by the escape suite and the stub calibration."""

    def __init__(self, output_dir: Path, *, runtime: str | None = None) -> None:
        from purpleloop.runtime import codelab

        self.codelab = codelab
        self.output_dir = output_dir
        self.tokens = codelab.actor_credentials()
        self.control = secrets.token_hex(24)
        self.fixture = codelab.ComposeCodelab(
            self.tokens,
            self.control,
            project="purpleloop-codelab-escape",
            runtime=runtime,
            keep=True,
        )
        self.counter = 0

    async def start(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from purpleloop.runtime.fixture import FixtureController

        codelab = self.codelab
        key = Ed25519PrivateKey.generate()
        self.approval = await codelab.approve(self.output_dir / "governance", key)
        await self.fixture.start()
        self.sandbox = await self.fixture.container_id("codelab-sandbox")
        self.fixture_container = await self.fixture.container_id("codelab-fixture")
        self.runtime_name = await self.fixture.sandbox_runtime()
        directory = self.output_dir / "session"
        directory.mkdir(parents=True, exist_ok=True)
        runner = codelab.build_codelab_runner(
            directory,
            self.approval.approved,
            self.approval.verifier,
            actor_tokens=self.tokens,
            control=self.control,
            fixture=self.fixture,
            admission=self.approval.admission,
        )
        self.runtime = runner.runtime
        self.carrier = codelab.load_corpus()[0].model_copy(update={"scenario_id": "codelab-escape"})
        self.controller = FixtureController(
            self.runtime,
            self.approval.approved,
            "codelab-escape",
            tools=CODELAB_LANE.tools,
            control_asset_id=CODELAB_LANE.control_asset_id,
            credential_handle=CODELAB_LANE.control_credential_handle,
        )
        await self.controller.call("provision")
        await self.controller.call("seed", {"seed": 42, "scenario_id": "codelab-escape"})

    async def submit(
        self, code: str, *, dataset: str = "sales"
    ) -> tuple[str, str, dict[str, Any], float]:
        self.counter += 1
        step = Step(
            node_id=f"escape-{self.counter}",
            adapter="tool",
            operation="analysis.run",
            asset_id=DATA_ASSET,
            target_tenant=TENANT,
            arguments={"dataset": dataset, "code": code},
        )
        action = compile_step(step, self.carrier, self.approval.approved, lane=CODELAB_LANE)
        started = time.monotonic()
        result = await self.runtime.run(
            self.approval.approved,
            action,
            run_id="codelab-escape",
            trace_id=f"escape-{self.counter}",
        )
        elapsed = time.monotonic() - started
        value = dict((result.result.data.get("value") or {}) if result.result else {})
        return result.status, result.reason_code, value, elapsed

    async def rejected(self) -> int:
        snapshot = await self.controller.call("snapshot")
        return int(snapshot.get("sandbox_rejected_connections", 0))

    async def security(self) -> dict[str, Any]:
        inspect = json.loads(await self.codelab.docker("inspect", self.sandbox))[0]["HostConfig"]
        keys = (
            "Runtime NetworkMode IpcMode ReadonlyRootfs CapDrop CapAdd SecurityOpt Privileged "
            "PidsLimit Memory MemorySwap NanoCpus Tmpfs"
        ).split()
        return {key: inspect.get(key) for key in keys} | {
            "Mounts": [
                {k: m.get(k) for k in ("Type", "Target", "ReadOnly")}
                for m in inspect.get("Mounts") or []
            ]
        }

    async def layer_changes(self) -> tuple[str, ...]:
        """``docker diff`` of the sandbox: changes to its container layer."""
        text = await self.codelab.docker("diff", self.sandbox)
        return tuple(line for line in text.splitlines() if line)

    async def close(self) -> None:
        try:
            await self.controller.call("teardown")
        finally:
            await self.fixture.down()


async def run_escape_suite(  # pragma: no cover - container lane
    output_dir: Path, suite: EscapeSuite, *, runtime: str | None = None
) -> EscapeReport:
    session = ContainerSession(output_dir, runtime=runtime)
    listener = Listener()
    await listener.start()
    await session.start()
    codelab = session.codelab
    try:
        security = await session.security()
        baseline_layer = await session.layer_changes()
        security["DiffBeforeAttempts"] = list(baseline_layer)
        held = (
            session.fixture.outside_canary,
            session.fixture.environment["CODELAB_SANDBOX_TOKEN"],
            session.control,
            *session.tokens.values(),
        )
        outcomes = []
        for attempt in suite.attempts:
            before = await session.rejected()
            code = attempt.code.replace("LISTENER_PORT", str(listener.port))
            status, reason, value, elapsed = await session.submit(code)
            layer = await session.layer_changes()
            ipc = (
                await codelab.docker("exec", session.fixture_container, "ls", "-A", "/ipc")
            ).split()
            top = (await codelab.docker("top", session.sandbox, "-o", "pid")).splitlines()[1:]
            peak = (
                await codelab.docker("exec", session.sandbox, "cat", "/sys/fs/cgroup/pids.peak")
            ).strip()
            state = json.loads(await codelab.docker("inspect", session.sandbox))[0]["State"]
            probe = await session.submit('print("alive")')
            observation = Observation(
                status=status,
                reason_code=reason,
                value=value,
                elapsed_seconds=elapsed,
                report=parse_report(str(value.get("stdout", ""))),
                listener_connections=listener.connections,
                container_diff=layer,
                container_diff_baseline=baseline_layer,
                network_mode=str(security["NetworkMode"]),
                ipc_listing=tuple(sorted(ipc)),
                processes_after=len([line for line in top if line.strip()]),
                pids_peak=int(peak) if peak.isdigit() else None,
                oom_killed=bool(state.get("OOMKilled")),
                rejected_before=before,
                rejected_after=await session.rejected(),
                probe_ok=probe[0] == "completed" and probe[2].get("stdout") == "alive",
                secrets=held,
            )
            outcomes.append(evaluate_attempt(attempt, observation))
    finally:
        await listener.close()
        await session.close()
    report = EscapeReport(
        runtime=session.runtime_name,
        runtime_requested=session.fixture.requested_runtime,
        gvisor=session.runtime_name == "runsc",
        container_security=security,
        attempts=tuple(outcomes),
        contained=sum(o.contained for o in outcomes),
        breaches=tuple(o.attempt_id for o in outcomes if not o.contained),
        approval_digest=session.approval.approval.approval_digest(),
        note=(
            "Measured against the real sandbox container. gVisor was used only if runtime is "
            "runsc; otherwise this is hardened runc. A breach is release-blocking."
        ),
    )
    (output_dir / "escape-report.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return report


def simulation_dataset(code: str) -> str:
    """The dataset a simulated snippet reads, so calibration materializes the same job files."""
    return next(
        (name for name in ("vendor-feed", "vendor-chain", "vendor-relay") if name in code),
        "sales",
    )


async def calibrate_stub(output_dir: Path) -> dict[str, Any]:  # pragma: no cover - container
    """Run every snippet the stub simulates in the real sandbox; report any disagreement.

    The stub answers the in-process lane from ``seed.SIMULATIONS``. This is what makes that
    table a recording rather than a guess: the same snippet, the same job files, the real
    container, and the fields the oracles read (exit code, output, files created).
    """
    from purpleloop.fixture.codelab.sandbox import SandboxJob, StubSandbox
    from purpleloop.fixture.codelab.seed import SIMULATIONS, job_files

    session = ContainerSession(output_dir)
    await session.start()
    stub = StubSandbox()
    mismatches = []
    try:
        for index, code in enumerate(SIMULATIONS):
            dataset = simulation_dataset(code)
            expected = await stub.run(
                SandboxJob(job_id=f"job-{index}", code=code, files=job_files(dataset, 42))
            )
            _, _, value, _ = await session.submit(code, dataset=dataset)
            observed = (
                value.get("exit_code"),
                value.get("stdout"),
                tuple(value.get("files_created") or ()),
            )
            # The kernel returns results redacted (the planted canary among its secrets), so the
            # stub's answer is compared after the same redaction.
            wanted = (
                expected.exit_code,
                session.runtime.redactor.redact(expected.stdout),
                expected.files_created,
            )
            if observed != wanted:
                mismatches.append({"index": index, "stub": wanted, "container": observed})
    finally:
        await session.close()
    return {"runtime": session.runtime_name, "snippets": len(SIMULATIONS), "mismatches": mismatches}
