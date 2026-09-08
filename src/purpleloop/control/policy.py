from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from purpleloop.control.targets import TargetError, match_scope
from purpleloop.control.tools import PHASE0_TOOLS, ToolDefinitionError, ToolRegistry
from purpleloop.schemas.action import ActionRequest, SideEffectClass
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
    # Bumped for the Phase 2 checks below; 1.0 and 1.1 manifests take exactly the earlier path.
    VERSION = "phase2-v3"

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
        if action.side_effect == SideEffectClass.DESTRUCTIVE:
            return self._deny("DESTRUCTIVE_FORBIDDEN")
        if action.operation == "fixture.defense" and (
            manifest.phase1 is None
            or (action.arguments or {}).get("profile") not in manifest.phase1.defense_profiles
        ):
            return self._deny("DEFENSE_NOT_AUTHORIZED")
        if action.operation in manifest.denied_operations:
            return self._deny("EXPLICITLY_DENIED")
        if action.adapter not in manifest.allowed_adapters:
            return self._deny("ADAPTER_NOT_ALLOWED")
        if action.operation not in manifest.allowed_operations:
            return self._deny("OPERATION_NOT_ALLOWED")
        if manifest.schema_version == "1.0.0":
            try:
                PHASE0_TOOLS.require(action)
                ActionRequest.model_validate(action.model_dump())
            except ValueError:
                return self._deny("TOOL_SCHEMA_MISMATCH")
            if action.arguments is not None or action.budget.writes:
                return self._deny("TOOL_SCHEMA_MISMATCH")
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
        if manifest.phase2 is not None:
            phase2_reason = self._evaluate_phase2(manifest, action)
            if phase2_reason is not None:
                return self._deny(phase2_reason)
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

    def _evaluate_phase2(
        self, manifest: AuthorizationManifest, action: ActionRequest
    ) -> str | None:
        """Manifest 1.2 checks. Ownership is resolved from signed data, never from the fixture."""
        grants = manifest.phase2
        assert grants is not None
        if action.credential_handle == grants.database_credential_handle:
            return "DATABASE_CREDENTIAL_FORBIDDEN"
        if action.target.resource_id is not None and action.adapter != "control":
            owner = grants.owner_of(action.target.resource_id)
            if owner is None:
                return "RESOURCE_NOT_SIGNED"
            if owner != action.target.tenant_id:
                return "RESOURCE_OWNERSHIP_MISMATCH"
        if action.adapter == "browser":
            try:
                asset = match_scope(action.target, manifest.assets)
            except TargetError as exc:
                return exc.reason_code
            if asset.asset_id not in grants.browser_assets:
                return "BROWSER_ASSET_NOT_ALLOWED"
        return None

    def _deny(self, reason_code: str) -> PolicyDecision:
        return PolicyDecision(PolicyEffect.DENY, reason_code, self.policy_digest)
