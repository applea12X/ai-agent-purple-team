"""codelab sandbox supervisor: the only process in the sandbox container that is not a snippet.

Standard library only, and deliberately outside the ``purpleloop`` package: the harness cannot
import it, so the harness cannot run it (ADR 0015). It runs as PID 1 of a container with no
network, a read-only root, one size-capped tmpfs (``/scratch``), every capability dropped,
``no-new-privileges``, Docker's default seccomp profile, and pids/memory/CPU limits.

Per job it:

1. writes the job's files (the dataset and the planted canary) into a fresh directory on the
   tmpfs, plus empty stdout/stderr capture files;
2. starts ``python -I -S -B -c <snippet>`` in a new session, with an empty environment, closed
   descriptors, and per-process rlimits (CPU, address space, file size, open files, no core);
3. waits at most the job's wall time, then kills the snippet's process group;
4. kills every other process left in the container (anything a snippet forked, including into
   its own session) and reaps it -- PID 1 inherits orphans;
5. lists the files the snippet left behind, *after* nothing it started is alive, and returns
   that listing, the exit status, and the first bytes of each output stream.

The channel to the fixture is a Unix socket the *fixture* listens on, in a volume mounted
read-only here. The supervisor authenticates with a per-deployment token. It drops its own
dumpable flag first, so a snippet running as the same uid cannot read the token from
``/proc/1/environ`` or ``/proc/1/mem``; snippets are exec'd with an empty environment, so they
never inherit it.
"""

from __future__ import annotations

import ctypes
import json
import os
import resource
import shutil
import signal
import socket
import subprocess  # noqa: S404 -- this process exists to start snippets inside the sandbox
import sys
import time
from pathlib import Path

BROKER = "/ipc/broker.sock"
SCRATCH = Path("/scratch")
PYTHON = "/usr/local/bin/python3"
OUTPUT_CAP = 16384
MAX_WALL = 10.0
PR_SET_DUMPABLE = 4
#: The runtime this container was started under, as the launcher requested it. Reported, not
#: trusted: the harness reads the real one from ``docker inspect``.
RUNTIME = os.environ.get("CODELAB_SANDBOX_RUNTIME", "runc")[:32]


def non_dumpable() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE) failed")


def limits(wall: float) -> None:
    """Applied in the child between fork and exec."""
    cpu = int(wall) + 1
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def others() -> list[int]:
    me = os.getpid()
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit() and int(entry) != me:
            found.append(int(entry))
    return found


def reap() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def sweep() -> int:
    """Kill and reap every process but this one. Returns how many were killed."""
    killed = 0
    for _ in range(400):
        pids = others()
        if not pids:
            break
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except ProcessLookupError:
                pass
        reap()
        time.sleep(0.005)
    reap()
    return killed


def listing(root: Path) -> set[str]:
    found = set()
    for path in root.rglob("*"):
        if path.is_file() or path.is_symlink():
            found.add(path.relative_to(root).as_posix())
    return found


def capture(directory: Path, name: str) -> int:
    """A capture file created by the supervisor, never through a path a snippet could swap."""
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    return os.open(directory / name, flags, 0o600)


def head(descriptor: int) -> str:
    """The first bytes written to a capture descriptor, read back through the same descriptor."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    return os.read(descriptor, OUTPUT_CAP).decode("utf-8", "replace")[: OUTPUT_CAP // 2]


def run_job(job: dict, counter: int) -> dict:
    job_id = str(job.get("job_id", "job"))[:64]
    wall = min(float(job.get("wall_seconds", 3.0)), MAX_WALL)
    directory = SCRATCH / f"job-{counter}"
    if directory.exists():
        shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(mode=0o700)
    for name, content in dict(job.get("files", {})).items():
        target = (directory / name).resolve()
        if not target.is_relative_to(directory.resolve()):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(content), encoding="utf-8")
    before = {".stdout", ".stderr", *listing(directory)}
    out, err = capture(directory, ".stdout"), capture(directory, ".stderr")
    timed_out = False
    process = subprocess.Popen(  # noqa: S603 -- the snippet, inside the sandbox, by design
        [PYTHON, "-I", "-S", "-B", "-c", str(job.get("code", ""))],
        cwd=directory,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(directory), "LANG": "C.UTF-8"},
        stdin=subprocess.DEVNULL,
        stdout=out,
        stderr=err,
        close_fds=True,
        start_new_session=True,
        preexec_fn=lambda: limits(wall),
    )
    try:
        process.wait(timeout=wall)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    swept = sweep()
    exit_code = process.returncode
    files = sorted(listing(directory) - before)[:64]
    stdout, stderr = head(out), head(err)
    os.close(out)
    os.close(err)
    result = {
        "job_id": job_id,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "files_created": files,
        "swept_processes": swept,
    }
    shutil.rmtree(directory, ignore_errors=True)
    return result


def connect(token: str) -> socket.socket:
    while True:
        try:
            channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            channel.connect(BROKER)
            hello = {"role": "supervisor", "token": token, "runtime": RUNTIME}
            channel.sendall(json.dumps(hello).encode() + b"\n")
            return channel
        except OSError:
            channel.close()
            time.sleep(0.2)


def main() -> None:
    token = os.environ.pop("CODELAB_SANDBOX_TOKEN", "")
    if not token:
        sys.exit("no sandbox token")
    non_dumpable()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    counter = 0
    while True:
        channel = connect(token)
        stream = channel.makefile("rwb")
        try:
            for line in stream:
                counter += 1
                try:
                    job = json.loads(line)
                    result = run_job(job if isinstance(job, dict) else {}, counter)
                except (ValueError, OSError) as exc:
                    sweep()
                    result = {"job_id": "job", "exit_code": -1, "stderr": f"supervisor: {exc}"}
                stream.write(json.dumps(result).encode() + b"\n")
                stream.flush()
        except OSError:
            pass
        finally:
            channel.close()


if __name__ == "__main__":
    main()
