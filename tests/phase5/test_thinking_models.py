"""Thinking models: a leading ``<think>`` block is reasoning, not an answer.

``deepseek-r1`` served through Ollama's OpenAI-compatible API can put its reasoning inline at the
head of ``content``. Parsed as-is, every reply is unparseable and every intent is lost, so a run
would read "the model did nothing" when the model said something. The parser now strips exactly a
leading block and records that it did -- by size and digest, never the text -- and a reply without
one parses byte for byte as before, which a property test holds over arbitrary text.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from purpleloop.adapters.agent import AgentAdapter
from purpleloop.adapters.model_provider import split_thinking, thinking_note
from purpleloop.cli import app
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.common import digest_data

runner = CliRunner()
SCENARIO = ROOT / "scenarios" / "agent" / "agent-indirect-ticket.yaml"
Events = Callable[[Path], list[dict[str, Any]]]
REPLY = json.dumps({"message": "Invoices are monthly.", "tool_intents": []})


def test_a_reply_without_thinking_is_returned_unchanged() -> None:
    for text in (REPLY, "", "  plain text  ", 'x <think>later</think> {"message": "m"}'):
        assert split_thinking(text) == (text, None)


def test_a_leading_block_is_stripped_with_its_surrounding_whitespace() -> None:
    visible, thinking = split_thinking(f"\n  <think>\nweigh it up\n</think>\n\n{REPLY}")
    assert visible == REPLY and thinking == "\nweigh it up\n"


def test_only_the_first_leading_block_is_reasoning() -> None:
    """A second block is content: stripping it would let a model hide text from the parser."""
    visible, thinking = split_thinking("<think>a</think><think>b</think>rest")
    assert thinking == "a" and visible == "<think>b</think>rest"


def test_an_unterminated_block_leaves_no_answer() -> None:
    visible, thinking = split_thinking('<think>still going {"message": "half"}')
    assert visible == "" and thinking == ' still going {"message": "half"}'.lstrip()
    _, intents, rejected = AgentAdapter.parse_intents(visible, 4)
    assert intents == () and rejected == ("<unparseable>",)


def test_the_note_records_size_and_digest_never_the_text() -> None:
    note = thinking_note("secret reasoning", REPLY)
    assert note == {
        "stripped": True,
        "chars": 16,
        "digest": digest_data("secret reasoning"),
        "answer_remaining": True,
    }
    assert thinking_note("x", "  ")["answer_remaining"] is False


@given(st.text(max_size=400))
def test_any_reply_that_does_not_open_with_thinking_parses_exactly_as_before(text: str) -> None:
    if text.lstrip().startswith("<think>"):
        return
    visible, thinking = split_thinking(text)
    assert thinking is None and visible == text
    assert AgentAdapter.parse_intents(visible, 4) == AgentAdapter.parse_intents(text, 4)


@given(
    st.text(alphabet=st.characters(blacklist_characters="<"), max_size=200),
    st.sampled_from(
        [
            REPLY,
            json.dumps(
                {
                    "message": "m",
                    "tool_intents": [{"operation": "shell.exec", "arguments": {}}],
                }
            ),
        ]
    ),
)
def test_a_thinking_reply_parses_as_its_answer_would_alone(reasoning: str, answer: str) -> None:
    visible, thinking = split_thinking(f"<think>{reasoning}</think>{answer}")
    assert thinking == reasoning
    assert AgentAdapter.parse_intents(visible, 4) == AgentAdapter.parse_intents(answer, 4)


def run_with(tmp_path: Path, stub_model: Any, content: str, name: str) -> Path:
    stub_model.content = content
    out = tmp_path / name
    result = runner.invoke(
        app,
        [
            "agent-run",
            str(SCENARIO),
            str(out),
            "--endpoint",
            "http://127.0.0.1:11434/v1",
            "--profile",
            "ollama",
        ],
    )
    assert "FAILED" not in result.output, result.output
    return out / SCENARIO.stem


def agent_results(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        event["data"]["data"]
        for event in events
        if event["kind"] == "result"
        and isinstance(event.get("data", {}).get("data"), dict)
        and "model_pin_id" in event["data"]["data"]
    ]


def test_a_thinking_model_run_records_the_answer_and_a_stripping_note(
    tmp_path: Path, stub_model: Any, read_events: Events
) -> None:
    plain = agent_results(read_events(run_with(tmp_path, stub_model, REPLY, "plain")))
    thought = agent_results(
        read_events(
            run_with(tmp_path, stub_model, f"<think>The ticket says to email.</think>{REPLY}", "t")
        )
    )
    assert plain and thought and len(plain) == len(thought)
    for without, with_ in zip(plain, thought, strict=True):
        assert with_["message"] == without["message"] == "Invoices are monthly."
        assert with_["tool_intents"] == without["tool_intents"]
        assert with_["rejected_intents"] == without["rejected_intents"]
        assert "thinking" not in without
        assert with_["thinking"]["stripped"] is True
        assert with_["thinking"]["digest"] == digest_data("The ticket says to email.")
    bundle_text = (tmp_path / "t" / SCENARIO.stem / "evidence.jsonl").read_text()
    assert "The ticket says to email." not in bundle_text
