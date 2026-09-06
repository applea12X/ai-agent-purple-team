from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from pydantic import BaseModel

from purpleloop.control.targets import canonicalize_url
from purpleloop.schemas.action import ActionRequest, SideEffectClass
from purpleloop.schemas.common import digest_data


class ToolDefinitionError(ValueError):
    reason_code = "TOOL_SCHEMA_MISMATCH"


@dataclass(frozen=True)
class ToolDefinition:
    adapter: str
    operation: str
    method: str
    side_effect: SideEffectClass
    path_template: str
    resource_required: bool
    input_model: type[BaseModel] | None = None
    output_model: type[BaseModel] | None = None
    min_records: int = 1
    min_tokens: int = 0
    resource_tenants: Mapping[str, str] | None = None
    tenant_id: str | None = None
    credential_handle: str | None = None

    def expected_path(self, action: ActionRequest) -> str:
        if self.resource_required and action.target.resource_id is None:
            raise ToolDefinitionError("tool requires a resource id")
        return self.path_template.format(resource_id=action.target.resource_id or "")

    def validate(self, action: ActionRequest) -> None:
        if (
            action.adapter != self.adapter
            or action.operation != self.operation
            or action.method != self.method
            or action.side_effect != self.side_effect
        ):
            raise ToolDefinitionError("action claims do not match the trusted tool schema")
        target = canonicalize_url(action.target.url)
        if target.query or target.path != self.expected_path(action):
            raise ToolDefinitionError("target URL does not match the trusted tool schema")
        if self.input_model is not None:
            if self.resource_tenants is not None and (
                self.resource_tenants.get(action.target.resource_id or "")
                != action.target.tenant_id
            ):
                raise ToolDefinitionError("resource does not belong to the declared target tenant")
            if self.tenant_id is not None and action.target.tenant_id != self.tenant_id:
                raise ToolDefinitionError("operation target tenant mismatch")
            if not self.resource_required and action.target.resource_id is not None:
                raise ToolDefinitionError("operation does not address a resource")
            if (
                self.credential_handle is not None
                and action.credential_handle != self.credential_handle
            ):
                raise ToolDefinitionError("operation credential binding mismatch")
            try:
                self.input_model.model_validate(action.arguments or {})
            except ValueError as exc:
                raise ToolDefinitionError("invalid typed arguments") from exc
            if action.schema_version != "1.1.0" or action.credential_handle is None:
                raise ToolDefinitionError("Phase 1 operation requires version and credentials")
            if (
                action.budget.requests < 1
                or action.budget.records < self.min_records
                or action.budget.tokens < self.min_tokens
                or action.budget.writes < int(self.side_effect == SideEffectClass.WRITE)
            ):
                raise ToolDefinitionError("operation budget is understated")
        elif action.arguments is not None:
            raise ToolDefinitionError("legacy tools do not accept arguments")


class ToolRegistry:
    def __init__(self, definitions: tuple[ToolDefinition, ...]) -> None:
        self._definitions = MappingProxyType(
            {(item.adapter, item.operation): item for item in definitions}
        )
        if len(self._definitions) != len(definitions):
            raise ValueError("tool definitions must be unique")
        self.digest = digest_data(
            [
                {
                    "adapter": item.adapter,
                    "operation": item.operation,
                    "method": item.method,
                    "side_effect": item.side_effect,
                    "path_template": item.path_template,
                    "resource_required": item.resource_required,
                    **(
                        {
                            "input_schema": item.input_model.model_json_schema(),
                            "output_schema": item.output_model.model_json_schema()
                            if item.output_model
                            else None,
                            "min_records": item.min_records,
                            "min_tokens": item.min_tokens,
                            "resource_tenants": dict(item.resource_tenants)
                            if item.resource_tenants
                            else None,
                            "tenant_id": item.tenant_id,
                            "credential_handle": item.credential_handle,
                        }
                        if item.input_model
                        else {}
                    ),
                }
                for item in definitions
            ]
        )

    def require(self, action: ActionRequest) -> ToolDefinition:
        try:
            definition = self._definitions[(action.adapter, action.operation)]
        except KeyError as exc:
            raise ToolDefinitionError("tool is not registered") from exc
        definition.validate(action)
        return definition

    def lookup(self, adapter: str, operation: str) -> ToolDefinition:
        try:
            return self._definitions[(adapter, operation)]
        except KeyError as exc:
            raise ToolDefinitionError("tool is not registered") from exc


PHASE0_TOOLS = ToolRegistry(
    (
        ToolDefinition("mock_read", "health.read", "GET", SideEffectClass.READ, "/health", False),
        ToolDefinition(
            "mock_read",
            "record.read",
            "GET",
            SideEffectClass.READ,
            "/records/{resource_id}",
            True,
        ),
    )
)
