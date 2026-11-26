"""Two lookups the incident runbook needs and no command provided (found by the drill).

``docs/incident-runbook.md`` section 1 says to *localize the first broken event*, but
``verify-ledger`` only answers valid or invalid. Section 2 says to *find the action digest's
compiled action in plan.json*, but ``plan.json`` holds actions, not digests, and two kinds of
executed action are not plan nodes at all: fixture control-plane calls and model intents compiled
during the run. These functions answer both questions from the artifacts alone, read-only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from purpleloop.schemas.action import ActionRequest
from purpleloop.schemas.event import EvidenceEvent


def first_ledger_break(path: Path) -> dict[str, Any]:
    """The first line at which the hash chain stops verifying, or ``{"valid": True, ...}``."""
    parent: str | None = None
    lines = path.read_text(encoding="utf-8").splitlines()
    count = 0
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = EvidenceEvent.model_validate_json(line)
        except ValidationError:
            return {"valid": False, "line": number, "reason": "line is not a valid event"}
        broken = {"valid": False, "line": number, "sequence": event.sequence}
        if event.sequence != count:
            return {**broken, "reason": f"sequence {event.sequence} where {count} was expected"}
        if event.parent_hash != parent:
            return {**broken, "reason": "parent hash does not match the previous event"}
        if event.event_hash != event.calculated_hash():
            return {**broken, "reason": "event content does not match its own hash"}
        parent, count = event.event_hash, count + 1
    anchor = path.with_suffix(f"{path.suffix}.anchor")
    if anchor.is_file() and anchor.read_text(encoding="ascii").strip() != (parent or ""):
        return {"valid": False, "line": None, "reason": "anchor does not name the last event"}
    return {"valid": True, "events": count}


def locate_action(run: Path, digest: str) -> dict[str, Any]:
    """Where an action digest came from in one run bundle, and every event that names it."""
    origins: list[str] = []
    plan_path = run / "plan.json"
    if plan_path.is_file():
        for node in json.loads(plan_path.read_text(encoding="utf-8")).get("nodes", []):
            if ActionRequest.model_validate(node["action"]).digest() == digest:
                origins.append(f"plan node {node['node_id']} (stage {node['stage']})")
    trail: list[dict[str, Any]] = []
    stages: set[str] = set()
    for line in (run / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = EvidenceEvent.model_validate_json(line)
        if event.reason_code == "TOOL_INTENT_COMPILED" and isinstance(event.data, dict):
            compiled = event.data.get("action")
            if isinstance(compiled, dict):
                if ActionRequest.model_validate(compiled).digest() == digest:
                    origins.append(f"model intent compiled at sequence {event.sequence}")
        if event.action_digest == digest:
            stage = str(event.stage) if event.stage else None
            if stage:
                stages.add(stage)
            trail.append(
                {
                    "sequence": event.sequence,
                    "stage": stage,
                    "kind": str(event.kind),
                    "decision": event.decision,
                    "reason_code": event.reason_code,
                }
            )
    if not origins:
        origins.append(
            "neither a plan node nor a compiled model intent"
            + (
                f"; ledger stages {sorted(stages)}"
                if stages
                else "; no staged ledger event names it"
            )
            + " (fixture control-plane calls are issued by the runner, not compiled from the plan)"
        )
    return {"digest": digest, "origins": origins, "events": trail}
