from __future__ import annotations

from dataclasses import dataclass

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


class ToolRegistry:
    def __init__(self, definitions: tuple[ToolDefinition, ...]) -> None:
        self._definitions = {(item.adapter, item.operation): item for item in definitions}
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
