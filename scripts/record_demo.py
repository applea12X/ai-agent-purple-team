"""Record real commands in a pseudo-terminal as an asciicast v2 file (standard library only).

asciinema is not a project dependency, so this is a minimal recorder for the same format
(https://docs.asciinema.org/manual/asciicast/v2/): a JSON header line, then one
``[seconds, "o", text]`` event per chunk of terminal output, in order. The file plays in
asciinema-player or with ``asciinema play``.

Each command runs to completion in its own pseudo-terminal, so programs see a real TTY and
render as they would for a person. The recording is not edited. The recorder adds only two
kinds of line of its own, both marked so they cannot be mistaken for program output: a
``$ <command>`` line before each command (there is no interactive shell to echo it) and a
``# exit <code>`` line after it. Everything between them is the command's own pty output,
byte for byte, timed as it arrived.

    uv run python scripts/record_demo.py docs/demo/phase-demo.cast \\
        "uv run purpleloop smoke-demo --output-dir artifacts/demo/smoke" \\
        "uv run purpleloop holdout-check"
"""

from __future__ import annotations

import argparse
import codecs
import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path
from typing import IO

PROMPT = "\x1b[1;35m$\x1b[0m "
NOTE = "\x1b[2m# {}\x1b[0m\r\n"


class Recorder:
    def __init__(self, sink: IO[str], *, width: int, height: int) -> None:
        self.sink = sink
        self.width = width
        self.height = height
        self.start = time.monotonic()

    def emit(self, text: str) -> None:
        if text:
            elapsed = round(time.monotonic() - self.start, 6)
            self.sink.write(json.dumps([elapsed, "o", text], ensure_ascii=False) + "\n")

    def run(self, command: str, env: dict[str, str]) -> int:
        """Run one shell command on a fresh pty, recording its output; return its exit code."""
        self.emit(PROMPT + command + "\r\n")
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", self.height, self.width, 0, 0))
        process = subprocess.Popen(  # noqa: S602 -- the recorder's whole job is to run a command line
            command,
            shell=True,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(slave)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            ready, _, _ = select.select([master], [], [], 0.1)
            if master in ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError:  # EIO: the slave side closed
                    chunk = b""
                if not chunk:
                    break
                self.emit(decoder.decode(chunk))
            elif process.poll() is not None:
                # Drain anything still buffered, then stop.
                ready, _, _ = select.select([master], [], [], 0)
                if not ready:
                    break
        self.emit(decoder.decode(b"", final=True))
        os.close(master)
        code = process.wait()
        self.emit(NOTE.format(f"exit {code}"))
        return code


def record(
    output: Path,
    commands: list[str],
    *,
    title: str,
    width: int = 100,
    height: int = 30,
    idle_time_limit: float = 2.0,
) -> list[int]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "LANG", "LC_ALL", "UV_CACHE_DIR", "VIRTUAL_ENV", "TMPDIR"}
    }
    env.update({"TERM": "xterm-256color", "COLUMNS": str(width), "LINES": str(height)})
    header = {
        "version": 2,
        "width": width,
        "height": height,
        "timestamp": int(time.time()),
        "idle_time_limit": idle_time_limit,
        "title": title,
        "env": {"TERM": env["TERM"], "SHELL": "/bin/sh"},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as sink:
        sink.write(json.dumps(header) + "\n")
        recorder = Recorder(sink, width=width, height=height)
        return [recorder.run(command, env) for command in commands]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("commands", nargs="+")
    parser.add_argument("--title", default="PurpleLoop demo")
    parser.add_argument("--width", type=int, default=100)
    parser.add_argument("--height", type=int, default=30)
    args = parser.parse_args(argv)
    codes = record(
        args.output, args.commands, title=args.title, width=args.width, height=args.height
    )
    for command, code in zip(args.commands, codes, strict=True):
        print(f"exit {code}: {command}", file=sys.stderr)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
