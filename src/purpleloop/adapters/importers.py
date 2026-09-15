"""Normalize third-party attack cases into PurpleLoop scenarios.

PyRIT, garak, Promptfoo, and AgentDojo-style corpora each carry a payload and, at most, a loose
notion of success. None of them carries what this project requires of a corpus entry: a fixture
binding, a clean utility task, a deterministic oracle, a pre-approved defense, and a ground-truth
label.

So an imported case arrives **not runnable**, with its conversion issues recorded, exactly the way
``load_scenario`` already handles a 1.0 document. It is real, citable provenance -- and it is not
counted toward the corpus until somebody supplies the missing parts. Silently promoting an
imported payload to a scored scenario would put an unlabelled, un-oracled case into a metric, and
no imported framework owns this project's schema.

Everything an importer reads is untrusted data. Payload text is carried as data and never becomes
an instruction, a URL, a selector, or an operation.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from purpleloop.schemas.phase1 import Actor, Phase1Scenario

#: Why an imported case cannot be scored as it stands. Recorded on every import.
BASE_ISSUES: tuple[str, ...] = (
    "imported case supplies no fixture binding; clean and attack steps must be authored",
    "imported case supplies no deterministic security or utility oracle",
    "imported case is unlabelled; ground truth must be authored before it is scored",
)

SAFE_ID = re.compile(r"[^a-z0-9-]+")


def _identifier(source: str, raw: object, index: int) -> str:
    text = SAFE_ID.sub("-", str(raw).lower()).strip("-")
    return f"{source}-{text or index}"[:64].rstrip("-")


def _scenario(
    *,
    scenario_id: str,
    objective: str,
    attacker_objective: str,
    provenance: str,
    license_name: str,
    payload: str,
    extra_issues: tuple[str, ...] = (),
) -> Phase1Scenario:
    return Phase1Scenario(
        schema_version="1.3.0",
        scenario_id=scenario_id,
        scenario_version="1.0.0",
        fixture_seed=42,
        actor=Actor(
            schema_version="1.3.0",
            actor_id="agent-a",
            role="agent",
            tenant_id="org-a",
            credential_handle="supportlab-agent-a",
        ),
        legitimate_objective=objective[:500] or "imported case: objective not supplied",
        attacker_objective=attacker_objective[:500] or "imported case: objective not supplied",
        capabilities=frozenset({"agent.ask"}),
        clean_steps=(),
        attack_steps=(),
        # The payload is carried as recorded data on the scenario, never as a step.
        security_oracle=None,
        utility_oracle=None,
        expected_telemetry=(),
        defense_profile="retrieval-provenance-guard",
        taxonomy_mappings={},
        provenance=f"{provenance} | payload sha-bounded: {payload[:120]!r}",
        license=license_name,
        conversion_issues=(*BASE_ISSUES, *extra_issues),
    )


def from_pyrit(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """A PyRIT-shaped prompt entry: ``{"name", "value", "harm_categories", "source"}``."""
    return _scenario(
        scenario_id=_identifier("pyrit", case.get("name", index), index),
        objective="Imported PyRIT case; legitimate task not supplied",
        attacker_objective=str(case.get("name") or "unspecified PyRIT objective"),
        provenance=f"PyRIT import; upstream source: {case.get('source', 'unrecorded')}",
        license_name=str(case.get("license") or "unrecorded"),
        payload=str(case.get("value", "")),
        extra_issues=(
            ()
            if case.get("harm_categories")
            else ("imported case declares no harm category; risk class must be authored",)
        ),
    )


def from_garak(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """A garak-shaped probe entry: ``{"probe", "prompt", "detector", "goal"}``."""
    return _scenario(
        scenario_id=_identifier("garak", case.get("probe", index), index),
        objective="Imported garak case; legitimate task not supplied",
        attacker_objective=str(case.get("goal") or "unspecified garak goal"),
        provenance=f"garak import; probe: {case.get('probe', 'unrecorded')}",
        license_name=str(case.get("license") or "unrecorded"),
        payload=str(case.get("prompt", "")),
        extra_issues=(
            (
                "garak detector is a string matcher over model output, not a state oracle; "
                "a deterministic oracle must be authored",
            )
            if case.get("detector")
            else ()
        ),
    )


def from_promptfoo(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """A Promptfoo-shaped test entry: ``{"description", "vars", "assert"}``."""
    variables = case.get("vars") or {}
    payload = " ".join(str(value) for value in variables.values()) if variables else ""
    assertions = case.get("assert") or []
    llm_rubric = any(
        str(item.get("type", "")).startswith("llm-")
        for item in assertions
        if isinstance(item, dict)
    )
    return _scenario(
        scenario_id=_identifier("promptfoo", case.get("description", index), index),
        objective=str(case.get("description") or "Imported Promptfoo case"),
        attacker_objective=str(case.get("description") or "unspecified Promptfoo objective"),
        provenance="Promptfoo import",
        license_name=str(case.get("license") or "unrecorded"),
        payload=payload,
        extra_issues=(
            ("imported assertion is an LLM rubric, which is advisory here, not binding",)
            if llm_rubric
            else ()
        ),
    )


def from_agentdojo(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """An AgentDojo-shaped task pair: ``{"id", "user_task", "injection_task", "suite"}``.

    AgentDojo already separates the legitimate task from the attacker objective, which is the
    same split this project makes, so the conversion loses less here than elsewhere. It still
    supplies no supportlab binding and no state oracle.
    """
    return _scenario(
        scenario_id=_identifier("agentdojo", case.get("id", index), index),
        objective=str(case.get("user_task") or "Imported AgentDojo user task"),
        attacker_objective=str(case.get("injection_task") or "unspecified AgentDojo injection"),
        provenance=f"AgentDojo import; suite: {case.get('suite', 'unrecorded')}",
        license_name=str(case.get("license") or "unrecorded"),
        payload=str(case.get("injection_task", "")),
        extra_issues=(
            ()
            if case.get("user_task")
            else ("imported case supplies no legitimate task; utility cannot be measured",)
        ),
    )


IMPORTERS = {
    "pyrit": from_pyrit,
    "garak": from_garak,
    "promptfoo": from_promptfoo,
    "agentdojo": from_agentdojo,
}


def import_case(framework: str, case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    try:
        importer = IMPORTERS[framework]
    except KeyError as exc:
        raise ValueError(f"no importer for framework: {framework}") from exc
    return importer(case, index=index)
