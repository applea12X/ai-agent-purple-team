"""The codelab sandbox interface, its deterministic stub, and the broker to the real container.

Where code runs (ADR 0015). A snippet runs in the **sandbox container** (``targets/codelab/
sandbox/``): ``network_mode: none``, read-only root, a size-capped tmpfs, every capability
dropped, ``no-new-privileges``, Docker's default seccomp profile, pids/memory/CPU limits, and a
wall-time kill enforced by a supervisor inside it. The fixture's application process never runs
a snippet, and neither does the harness. The fixture reaches the sandbox through
:class:`BrokerSandbox`: a Unix socket the fixture listens on, in a volume the sandbox mounts
**read-only**, so the sandbox's only writable path is its tmpfs. The supervisor authenticates
with a per-deployment token a snippet cannot read (the supervisor is non-dumpable and starts each
snippet with an empty environment); any other connection is refused and counted.

:class:`StubSandbox` is the in-process lane's stand-in. It enforces the same interface and never
interprets code: it looks the exact snippet up in ``seed.SIMULATIONS`` and replays the recorded
effect, computed from the job's own files, or answers "not simulated". Containment is never
claimed from the stub; the escape suite runs against the container only.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import Literal, Protocol

from pydantic import Field

from purpleloop.fixture.codelab.seed import SIMULATIONS
from purpleloop.schemas.common import StrictModel

#: The longest a snippet may run, enforced inside the sandbox; the broker adds a margin on top.
DEFAULT_WALL_SECONDS = 3.0
MAX_WALL_SECONDS = 10.0
#: How much of each output stream the sandbox returns. Recorded output is bounded, not complete.
OUTPUT_CAP = 16384
#: Exit code the stub returns for a snippet it has no recorded effect for.
NOT_SIMULATED = 127


class SandboxJob(StrictModel):
    job_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    code: str = Field(min_length=1, max_length=2000)
    #: Relative path -> content. The dataset and the planted canary; written into the job's tmpfs.
    files: dict[str, str]
    wall_seconds: float = Field(default=DEFAULT_WALL_SECONDS, gt=0, le=MAX_WALL_SECONDS)


class SandboxResult(StrictModel):
    """What the sandbox observed. ``files_created`` is listed by the supervisor after the snippet
    and every process it started are dead, so a snippet cannot write the listing itself."""

    job_id: str
    exit_code: int
    timed_out: bool = False
    stdout: str = Field(default="", max_length=OUTPUT_CAP)
    stderr: str = Field(default="", max_length=OUTPUT_CAP)
    files_created: tuple[str, ...] = ()
    #: Processes the supervisor had to kill after the snippet's own process ended or was killed.
    swept_processes: int = Field(default=0, ge=0)
    #: Set by the broker, never by the sandbox: the sandbox did not answer, so nothing is known.
    error: str | None = None


class Sandbox(Protocol):
    #: ``stub`` for the in-process lane; for the container, the runtime the supervisor reported.
    runtime: str

    async def run(self, job: SandboxJob) -> SandboxResult: ...

    async def close(self) -> None: ...


class StubSandbox:
    """Deterministic stand-in with the sandbox's interface. Replays recorded effects only."""

    runtime = "stub"

    def __init__(self) -> None:
        self.jobs = 0

    async def run(self, job: SandboxJob) -> SandboxResult:
        self.jobs += 1
        simulate = SIMULATIONS.get(job.code)
        if simulate is None:
            return SandboxResult(
                job_id=job.job_id,
                exit_code=NOT_SIMULATED,
                stderr="stub sandbox: this snippet has no recorded effect; nothing was run\n",
            )
        effect = simulate(job.files)
        return SandboxResult(
            job_id=job.job_id,
            exit_code=effect.exit_code,
            stdout=effect.stdout,
            files_created=effect.files_created,
        )

    async def close(self) -> None:
        return None


SupervisorState = Literal["waiting", "connected", "lost"]


class BrokerSandbox:  # pragma: no cover - container lane (tests/phase5/test_codelab_container.py)
    """The fixture's side of the sandbox channel: a Unix socket server in the shared volume.

    One authenticated supervisor connection at a time carries one job at a time, newline-framed
    JSON. A connection that does not open with the token is closed and counted in
    :attr:`rejected_connections` -- a snippet that finds the socket can reach this and nothing else.
    """

    def __init__(self, path: str, token: str, *, connect_timeout: float = 20.0) -> None:
        self.path = path
        self.token = token
        self.connect_timeout = connect_timeout
        self.runtime = "unknown"
        self.rejected_connections = 0
        self._server: asyncio.base_events.Server | None = None
        self._supervisor: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._connected = asyncio.Event()
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        import contextlib
        import os

        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)
        self._server = await asyncio.start_unix_server(self._accept, path=self.path, limit=1 << 20)
        # The sandbox runs as another uid and must be able to connect; it cannot write the
        # directory (the volume is read-only on its side), so it cannot replace the socket.
        os.chmod(self.path, 0o666)  # noqa: S103 -- a socket, connect-only for the sandbox uid

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with asyncio.timeout(2):
                line = await reader.readline()
            hello = json.loads(line or b"{}")
            token = hello.get("token") if isinstance(hello, dict) else None
            if (
                not isinstance(token, str)
                or not secrets.compare_digest(token, self.token)
                or hello.get("role") != "supervisor"
            ):
                raise PermissionError("unauthenticated broker connection")
        except (TimeoutError, ValueError, PermissionError, OSError):
            self.rejected_connections += 1
            writer.close()
            return
        if self._supervisor is not None:
            self._supervisor[1].close()
        self.runtime = str(hello.get("runtime", "unknown"))[:32]
        self._supervisor = (reader, writer)
        self._connected.set()

    async def run(self, job: SandboxJob) -> SandboxResult:
        async with self._lock:
            try:
                async with asyncio.timeout(self.connect_timeout):
                    await self._connected.wait()
            except TimeoutError:
                return SandboxResult(job_id=job.job_id, exit_code=-1, error="sandbox unavailable")
            assert self._supervisor is not None
            reader, writer = self._supervisor
            try:
                writer.write(job.model_dump_json().encode() + b"\n")
                await writer.drain()
                async with asyncio.timeout(job.wall_seconds + 8):
                    line = await reader.readline()
                if not line:
                    raise ConnectionError("supervisor closed the channel")
                result = SandboxResult.model_validate_json(line)
            except (TimeoutError, ConnectionError, OSError, ValueError) as exc:
                self._supervisor = None
                self._connected.clear()
                writer.close()
                return SandboxResult(
                    job_id=job.job_id, exit_code=-1, error=f"sandbox channel failed: {exc!s}"[:200]
                )
            if result.job_id != job.job_id:
                return SandboxResult(job_id=job.job_id, exit_code=-1, error="job id mismatch")
            return result

    async def close(self) -> None:
        if self._supervisor is not None:
            self._supervisor[1].close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


__all__ = [
    "BrokerSandbox",
    "Sandbox",
    "SandboxJob",
    "SandboxResult",
    "StubSandbox",
]
