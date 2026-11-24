"""Shared fixtures for the Phase 5 model-plane tests: stub transports, never a real model.

Every networked path here is driven through ``httpx.MockTransport``. Nothing in this directory
opens a socket to a model, and the environment is scrubbed of every model-plane variable first,
so a developer's shell (which may well point at a local Ollama) cannot leak into a test.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from purpleloop import agent_cli
from purpleloop.adapters.model_provider import OpenAICompatibleProvider

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
