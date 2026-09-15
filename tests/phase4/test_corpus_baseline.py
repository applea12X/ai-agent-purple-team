"""The committed corpus baseline agrees with what the current code produces.

The risk-class regression gate compares against ``baselines/corpus-baseline.json``. If that
file drifted from the code -- a scenario relabelled, a class renamed, a count changed without a
reviewed baseline bump -- the gate would be comparing against fiction. This runs the real
``corpus-baseline`` command over the whole agent corpus and requires the per-class metrics to
match the committed file exactly, the same standing check the schema-drift baseline gets.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase4 import RiskClassBaseline

COMMITTED = ROOT / "baselines" / "corpus-baseline.json"


def test_corpus_baseline_command_reproduces_the_committed_baseline(tmp_path: Path) -> None:
    out = tmp_path / "corpus-current.json"
    result = CliRunner().invoke(app, ["corpus-baseline", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert "failed=none" in result.output

    current = RiskClassBaseline.model_validate_json(out.read_text())
    committed = RiskClassBaseline.model_validate_json(COMMITTED.read_text())
    assert current.corpus == committed.corpus
    assert current.classes == committed.classes, (
        "per-class metrics differ from the committed baseline; if the change is intended, "
        "re-run `purpleloop corpus-baseline` and commit the diff with the change that caused it"
    )
    assert sum(entry.scenarios for entry in current.classes) == 25
    # The committed file is what the gate reads, so it must round-trip cleanly too.
    assert json.loads(COMMITTED.read_text())["schema_version"] == "1.4.0"
