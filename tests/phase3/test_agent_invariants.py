"""Structural invariants of the agent lane, and fault injection across its lifecycle.

Two of these are source-level checks. They exist because the corresponding claims are made in
module docstrings, and a docstring that asserts a test which does not exist is worse than no
docstring: the next reader stops checking.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path
from typing import Any

import pytest

from purpleloop.adapters import agent as agent_module
from purpleloop.adapters import model_provider
from purpleloop.schemas.phase1 import Stage

AGENT_SOURCE = Path(inspect.getfile(agent_module)).read_text(encoding="utf-8")
PROVIDER_SOURCE = Path(inspect.getfile(model_provider)).read_text(encoding="utf-8")


# --- structural invariants ----------------------------------------------------------------------


def test_the_agent_module_never_dispatches_to_another_adapter() -> None:
    """The assistant parses intents; it never invokes a tool.

    The agent adapter is allowed exactly one outbound call of its own -- the retrieval context on
    the signed data asset -- and the model call through its client. Anything that looks like tool
    dispatch, adapter selection, or a tool path would move authority out of ``SafetyRuntime``.
    """
    forbidden_names = {
        "AdapterRegistry",
        "compile_step",
        "compile_plan",
        "ToolAdapter",
        "HttpAdapter",
        "BrowserAdapter",
        "SafetyRuntime",
    }
    tree = ast.parse(AGENT_SOURCE)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
    assert not (imported & forbidden_names), sorted(imported & forbidden_names)

    # No tool path is reachable from this module: the only path it names is the context endpoint,
    # and that comes from the signed asset via the compiled action, not from a literal here.
    for literal in ("/api/agent/email", "/api/agent/memory", "/api/agent/crm", "/api/exports"):
        assert literal not in AGENT_SOURCE, literal


def test_the_agent_adapter_opens_exactly_one_http_client() -> None:
    """One outbound client, aimed at the compiled action's own target — not a composed URL."""
    tree = ast.parse(AGENT_SOURCE)
    clients = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "AsyncClient"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "httpx"
    ]
    assert len(clients) == 1, "the agent adapter opens more than one HTTP client"
    # Its destination is the compiled action's target, never a string built in this module.
    assert "action.target.url" in AGENT_SOURCE
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "://" not in node.value, f"agent module names a URL: {node.value!r}"


def test_the_networked_provider_has_no_path_to_the_offline_store() -> None:
    """A silent downgrade would report a network result as a deterministic one."""
    tree = ast.parse(PROVIDER_SOURCE)
    networked = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "OpenAICompatibleProvider"
    )
    body = ast.dump(networked)
    for name in ("OfflineModelStore", "OfflineProvider", "ScriptedAgentModel"):
        assert name not in body, name
    # And no except-clause anywhere in the module falls back to another provider.
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            handler = ast.dump(node)
            assert "OfflineProvider" not in handler and "store" not in handler.lower()


def test_the_model_plane_is_not_reachable_from_a_plan() -> None:
    """No registered adapter operation can aim an action at a model endpoint."""
    from purpleloop.control.phase2_tools import (
        API_DEFINITIONS,
        BROWSER_DEFINITIONS,
        CONTROL_DEFINITIONS,
    )
    from purpleloop.control.phase3_tools import AGENT_DEFINITIONS

    for definition in (
        *API_DEFINITIONS,
        *BROWSER_DEFINITIONS,
        *AGENT_DEFINITIONS,
        *CONTROL_DEFINITIONS,
    ):
        # Every registered operation is a path on a signed asset. None can name an origin, so no
        # compiled action can be aimed at a model endpoint.
        assert definition.path_template.startswith("/"), definition.operation
        assert "://" not in definition.path_template, definition.operation


# --- fault injection across the agent lifecycle ---------------------------------------------------

STAGES = [
    Stage.PROVISION,
    Stage.SEED,
    Stage.CLEAN,
    Stage.ATTACK,
    Stage.SCORE,
    Stage.DETECT,
    Stage.DEFENSE,
    Stage.RESET,
    Stage.REPLAY_CLEAN,
    Stage.REPLAY,
    Stage.TEARDOWN,
]


@pytest.mark.parametrize("stage", STAGES, ids=[s.value for s in STAGES])
@pytest.mark.parametrize("mode", ["raise", "cancel"])
async def test_agent_lane_tears_down_from_every_stage(
    make_agent_runner: Any,
    agent_scenarios: Any,
    agent_manifest: Any,
    stage: Stage,
    mode: str,
) -> None:
    """Every stage, in both raising and cancelled form, tears down and retains evidence."""
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")
    runner, fixture, directory = make_agent_runner()

    async def fail(current: Stage) -> None:
        if current == stage:
            if mode == "cancel":
                raise asyncio.CancelledError
            raise RuntimeError("injected")

    runner.stage_hook = fail
    if mode == "cancel" and stage is Stage.TEARDOWN:
        # Cancellation *during* teardown is deliberately recorded rather than propagated: the
        # cleanup path is shielded so evidence is still flushed and the fixture still closed.
        summary = await runner.run(
            scenario, agent_manifest, run_id=f"fault-{stage.value}", output_dir=directory
        )
        assert summary.status == "error" and "cleanup" in summary.reason
    elif mode == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await runner.run(
                scenario, agent_manifest, run_id=f"fault-{stage.value}", output_dir=directory
            )
    else:
        summary = await runner.run(
            scenario, agent_manifest, run_id=f"fault-{stage.value}", output_dir=directory
        )
        assert summary.status == "error"
    # The teardown path always runs and always leaves something a reviewer can inspect.
    assert fixture.closed, f"{stage.value}/{mode}: fixture was not closed"
    assert (directory / "evidence.jsonl").exists(), f"{stage.value}/{mode}: no evidence retained"


async def test_a_model_failure_mid_leg_fails_the_run_closed(
    make_agent_runner: Any, agent_scenarios: Any, agent_manifest: Any
) -> None:
    """A provider that raises is a run error, not a silently empty agent turn."""
    from purpleloop.adapters.model_provider import ModelUnavailable
    from purpleloop.schemas.phase3 import ModelPin

    class _Broken:
        profile = "offline"
        endpoint = None

        async def complete(
            self, *, pin: ModelPin, system: str, prompt: str, deadline: float
        ) -> tuple[str, int, int]:
            raise ModelUnavailable("model endpoint returned 503")

    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")
    runner, fixture, directory = make_agent_runner(model_provider=_Broken())
    summary = await runner.run(scenario, agent_manifest, run_id="model-fail", output_dir=directory)
    assert summary.status == "error"
    assert fixture.closed and summary.teardown_complete
