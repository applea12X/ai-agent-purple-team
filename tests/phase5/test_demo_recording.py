"""WP5.0.11 / WP4.5.3 -- the recorded demo is a valid asciicast v2 of real, fail-closed runs."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

from purpleloop.runtime.demo import ROOT

CAST = ROOT / "docs" / "demo" / "phase-demo.cast"
RECORDER = ROOT / "scripts" / "record_demo.py"
MAX_BYTES = 2 * 1024 * 1024


def parse_cast(path: Path) -> tuple[dict[str, Any], list[tuple[float, str]]]:
    """Parse an asciicast v2 file strictly: header object, then [time, "o", text] events."""
    lines = path.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    assert isinstance(header, dict) and header["version"] == 2
    assert isinstance(header["width"], int) and header["width"] > 0
    assert isinstance(header["height"], int) and header["height"] > 0
    events: list[tuple[float, str]] = []
    previous = 0.0
    for line in lines[1:]:
        event = json.loads(line)
        assert isinstance(event, list) and len(event) == 3, line
        elapsed, kind, text = event
        assert isinstance(elapsed, int | float) and elapsed >= previous, line
        assert kind == "o" and isinstance(text, str), line
        previous = float(elapsed)
        events.append((previous, text))
    assert events, "a cast with no output records nothing"
    return header, events


def output_of(events: list[tuple[float, str]]) -> str:
    return "".join(text for _, text in events)


def segments(text: str) -> dict[str, tuple[str, int]]:
    """Command line -> (its output, its exit code), split on the recorder's own markers."""
    pattern = re.compile(
        r"\x1b\[1;35m\$\x1b\[0m (?P<cmd>[^\r\n]*)\r\n(?P<out>.*?)\x1b\[2m# exit (?P<code>-?\d+)",
        re.DOTALL,
    )
    return {m["cmd"]: (m["out"], int(m["code"])) for m in pattern.finditer(text)}


def load_recorder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("record_demo", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_cast_is_valid_asciicast_v2_and_small() -> None:
    assert CAST.stat().st_size < MAX_BYTES
    header, events = parse_cast(CAST)
    assert header["title"].startswith("PurpleLoop")
    assert events[-1][0] > 1.0, "a real run takes measurable time"


def test_the_cast_records_the_one_command_demo_passing() -> None:
    runs = segments(output_of(parse_cast(CAST)[1]))
    smoke = next(cmd for cmd in runs if "purpleloop smoke-demo" in cmd)
    out, code = runs[smoke]
    assert code == 0
    assert len(re.findall(r"^(?:phase1|supportlab|agent)/[a-z0-9-]+: passed\r$", out, re.M)) == 14
    assert "Verified smoke bundle:" in out
    assert re.search(r"wall time [0-9.]+s against the stated 600s target", out)


def test_the_cast_records_fail_closed_cases_with_their_reason_codes() -> None:
    runs = segments(output_of(parse_cast(CAST)[1]))
    admission = next(cmd for cmd in runs if "check-action docs/samples/denied-run" in cmd)
    out, code = runs[admission]
    assert code == 1 and "DENY EXPIRED_MANIFEST" in out
    holdout = next(cmd for cmd in runs if "purpleloop holdout-check" in cmd)
    out, code = runs[holdout]
    assert code == 0 and "17/17 mutations denied" in out
    assert "OUT_OF_SCOPE" in out and "RESOURCE_OWNERSHIP_MISMATCH" in out
    judge = next(cmd for cmd in runs if "purpleloop judge-report" in cmd)
    out, code = runs[judge]
    assert code == 0 and re.search(r"resistance=1\.000 .* n=24", out)


def test_the_cast_leaks_no_home_directory() -> None:
    text = output_of(parse_cast(CAST)[1])
    assert "/Users/" not in text and "/home/" not in text


def test_the_recorder_writes_a_valid_cast_of_a_real_pty_run(tmp_path: Path) -> None:
    recorder = load_recorder()
    cast = tmp_path / "t.cast"
    codes = recorder.record(cast, ["printf 'hi\\n'; test -t 1 && echo tty", "exit 3"], title="t")
    assert codes == [0, 3]
    runs = segments(output_of(parse_cast(cast)[1]))
    assert runs["printf 'hi\\n'; test -t 1 && echo tty"] == ("hi\r\ntty\r\n", 0)
    assert runs["exit 3"] == ("", 3)
