"""Loose-ends audit: the documents that index the project point at things that exist.

Phase 1 carried "PRD §5 lists paths that do not exist" as debt, and the audit found `docs/prd.md`
still listing only the Phase 0-2 records. These tests make that class of drift fail instead of
waiting for the next audit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from purpleloop.runtime.demo import ROOT

INDEX_DOCUMENTS = (
    "README.md",
    "docs/prd.md",
    "docs/architecture.md",
    "docs/threat-model.md",
    "docs/phase5/loose-ends.md",
    "docs/phase5/wp5.0.10-acceptance.md",
    "docs/phase5/wp5.0.11-acceptance.md",
)
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def relative_links(document: Path) -> list[str]:
    return [
        target
        for target in LINK.findall(document.read_text(encoding="utf-8"))
        if not re.match(r"^[a-z]+:", target)
    ]


@pytest.mark.parametrize("name", INDEX_DOCUMENTS)
def test_every_relative_link_resolves(name: str) -> None:
    document = ROOT / name
    missing = [t for t in relative_links(document) if not (document.parent / t).exists()]
    assert not missing, f"{name}: {missing}"


def test_prd_section_5_names_only_paths_that_exist() -> None:
    text = (ROOT / "planning" / "PRD.md").read_text(encoding="utf-8")
    section = text.split("## 5. Proposed repository structure", 1)[1].split("\n## ", 1)[0]
    paths = re.findall(r"^- `([^`]+)`:", section, re.MULTILINE)
    assert len(paths) >= 15
    missing = [path for path in paths if not (ROOT / path).exists()]
    assert not missing, missing


def test_the_index_lists_every_acceptance_record() -> None:
    index = (ROOT / "docs" / "prd.md").read_text(encoding="utf-8")
    for record in sorted((ROOT / "docs").glob("phase*-acceptance.md")):
        assert f"({record.name})" in index, record.name


def test_the_link_check_can_fail(tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    document.write_text("see [x](missing.md) and [y](https://example.org/a)\n")
    assert relative_links(document) == ["missing.md"]
