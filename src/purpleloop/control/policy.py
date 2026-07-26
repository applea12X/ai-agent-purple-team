from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from purpleloop.control.targets import TargetError, match_scope
from purpleloop.control.tools import PHASE0_TOOLS, ToolDefinitionError, ToolRegistry
from purpleloop.schemas.action import ActionRequest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import digest_data


class PolicyEffect(StrEnum):
    PERMIT = "permit"
    DENY = "deny"


@dataclass(frozen=True)
class PolicyDecision:
    effect: PolicyEffect
    reason_code: str
    policy_digest: str

    @property
    def permitted(self) -> bool:
        return self.effect == PolicyEffect.PERMIT


class PolicyEngine(Protocol):
    def evaluate(
        self, manifest: AuthorizationManifest, action: ActionRequest
    ) -> PolicyDecision: ...


class DefaultDenyPolicy:
    VERSION = "phase0-v2"

    def __init__(
        self,
        tools: ToolRegistry = PHASE0_TOOLS,
        *,
        available: bool = True,
        stale: bool = False,
    ) -> None:
        self.tools = tools
        self.available = available
        self.stale = stale
        self.policy_digest = digest_data(
            {"name": "default-deny", "version": self.VERSION, "tools": tools.digest}
        )

    def evaluate(self, manifest: AuthorizationManifest, action: ActionRequest) -> PolicyDecision:
        if not self.available:
            return self._deny("POLICY_UNAVAILABLE")
        if self.stale:
            return self._deny("POLICY_STALE")
        if action.operation in manifest.denied_operations:
            return self._deny("EXPLICITLY_DENIED")
        if action.adapter not in manifest.allowed_adapters:
            return self._deny("ADAPTER_NOT_ALLOWED")
        if action.operation not in manifest.allowed_operations:
            return self._deny("OPERATION_NOT_ALLOWED")
        try:
            self.tools.require(action)
            match_scope(action.target, manifest.assets)
        except (TargetError, ToolDefinitionError) as exc:
            return self._deny(exc.reason_code)
        target = urlsplit(action.target.url)
        normalized_host = (target.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        for exclusion in manifest.exact_exclusions:
            if (
                (exclusion.host is None or exclusion.host == normalized_host)
                and (exclusion.tenant_id is None or exclusion.tenant_id == action.target.tenant_id)
                and (
                    exclusion.resource_id is None
                    or exclusion.resource_id == action.target.resource_id
                )
                and (exclusion.operation is None or exclusion.operation == action.operation)
                and (exclusion.path is None or exclusion.path == target.path)
            ):
                return self._deny("EXACT_EXCLUSION")
        if action.method not in manifest.allowed_methods:
            return self._deny("METHOD_NOT_ALLOWED")
        if action.side_effect not in manifest.allowed_side_effects:
            return self._deny("SIDE_EFFECT_NOT_ALLOWED")
        if (
            action.credential_handle is not None
            and action.credential_handle not in manifest.credential_handles
        ):
            return self._deny("CREDENTIAL_NOT_ALLOWED")
        if (
            action.credential_handle is not None
            and action.operation not in manifest.credential_scopes[action.credential_handle]
        ):
            return self._deny("CREDENTIAL_SCOPE_DENIED")
        host = urlsplit(action.target.url).hostname
        if host is None or host.rstrip(".").lower().encode("idna").decode("ascii") not in {
            item.rstrip(".").lower().encode("idna").decode("ascii")
            for item in manifest.egress_hosts
        }:
            return self._deny("EGRESS_NOT_ALLOWED")
        return PolicyDecision(PolicyEffect.PERMIT, "PERMITTED", self.policy_digest)

    def _deny(self, reason_code: str) -> PolicyDecision:
        return PolicyDecision(PolicyEffect.DENY, reason_code, self.policy_digest)
