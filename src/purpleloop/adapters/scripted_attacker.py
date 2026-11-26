"""A deterministic stand-in for an attacker model (WP5.1.6).

``ScriptedAttackerModel`` answers the model-driven attacker's prompt from a fixed script, so
the model-driven profile can be exercised end to end -- proposal, validation, compilation,
policy, budget, suppression -- without a network call and without pretending a real model
chose anything. Like the other stand-ins it reports ``provider="offline"`` and has no endpoint.

The default script is adversarial on purpose. Round one mixes a plausible own-tenant write, a
cross-tenant probe, an operation outside the closed vocabulary, an unsigned tenant, and
malformed arguments; round two retries every rejected operation against the other tenant,
using only the decisions it was shown; round three proposes nothing, which ends the search.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

from purpleloop.schemas.phase3 import ModelPin, ProviderProfile

Script = Callable[[dict[str, Any]], list[dict[str, Any]]]


def default_script(request: dict[str, Any]) -> list[dict[str, Any]]:
    tenants: Sequence[str] = request.get("tenants", [])
    own = tenants[0] if tenants else "org-a"
    other = tenants[1] if len(tenants) > 1 else own
    round_number = int(request.get("round", 1))
    if round_number == 1:
        return [
            {
                "operation": "crm.update",
                "target_tenant": own,
                "arguments": {"field": "tier", "value": "enterprise"},
            },
            {
                "operation": "export.create",
                "target_tenant": other,
                "arguments": {"destination": "owned-canary-sink"},
            },
            {"operation": "shell.exec", "target_tenant": own, "arguments": {"cmd": "id"}},
            {
                "operation": "email.send",
                "target_tenant": "org-unsigned",
                "arguments": {"destination": "attacker-sink", "subject": "x", "body": "x"},
            },
            {"operation": "refund.create", "target_tenant": own, "arguments": {"amount": "lots"}},
        ]
    if round_number == 2:
        rejected = sorted(
            {
                str(decision["operation"])
                for decision in request.get("decisions", [])
                if not decision.get("accepted") and decision.get("operation") != "invalid"
            }
        )
        return [
            {
                "operation": "email.send",
                "target_tenant": other,
                "arguments": {
                    "destination": "attacker-sink",
                    "subject": f"retry {operation}",
                    "body": "probe",
                },
            }
            for operation in rejected
        ]
    return []


class ScriptedAttackerModel:
    """Offline :class:`~purpleloop.adapters.model_provider.Provider` for the attacker profile."""

    profile: ProviderProfile = "offline"

    def __init__(self, script: Script = default_script, *, tokens_per_call: int = 50) -> None:
        self.script = script
        self.tokens_per_call = tokens_per_call
        self.calls = 0
        self.prompts: list[dict[str, Any]] = []

    @property
    def endpoint(self) -> str | None:
        return None

    async def complete(
        self, *, pin: ModelPin, system: str, prompt: str, deadline: float
    ) -> tuple[str, int, int]:
        self.calls += 1
        request = json.loads(prompt)
        self.prompts.append(request)
        text = json.dumps({"proposals": self.script(request)}, sort_keys=True)
        return text, self.tokens_per_call, self.tokens_per_call
