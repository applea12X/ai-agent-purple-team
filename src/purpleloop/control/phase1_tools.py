from __future__ import annotations

from types import MappingProxyType
from typing import Literal

from pydantic import Field, JsonValue

from purpleloop.control.tools import ToolDefinition, ToolRegistry
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.common import StrictModel


class EmptyArgs(StrictModel):
    pass


class UpdateArgs(StrictModel):
    display_name: str | None = Field(default=None, max_length=80)
    tier: Literal["standard", "admin"] | None = None


class RefundArgs(StrictModel):
    amount: int = Field(strict=True, ge=1, le=100)
    approval_id: Literal["approved-1"] | None = None


class ExportArgs(StrictModel):
    destination: Literal["owned-canary-sink"]


class ChatArgs(StrictModel):
    prompt: str = Field(max_length=2000)
    retrieved: str = Field(default="", max_length=4000)


class SeedArgs(StrictModel):
    seed: int = Field(strict=True, ge=0, le=2**32 - 1)
    scenario_id: Literal[
        "bola", "mass-assignment", "refund", "direct-injection", "indirect-injection"
    ]
    capabilities: tuple[Literal["record.read", "record.update", "refund.create"], ...]


class DefenseArgs(StrictModel):
    profile: Literal[
        "tenant-ownership", "property-allowlist", "verified-approval", "capability-guard"
    ]


class OperationResult(StrictModel):
    outcome: Literal["ok", "denied"]
    value: dict[str, JsonValue]


class ToolIntent(StrictModel):
    operation: Literal["canary.export"]
    arguments: ExportArgs


class ChatResult(StrictModel):
    message: str
    tool_intents: tuple[ToolIntent, ...] = Field(default=(), max_length=1)
    input_tokens: int = Field(ge=0, le=2048)
    output_tokens: int = Field(ge=0, le=2048)


def definition(
    adapter: str,
    operation: str,
    path: str,
    args: type[StrictModel],
    *,
    write: bool = False,
    resource: bool = False,
    method: str | None = None,
) -> ToolDefinition:
    return ToolDefinition(
        adapter,
        operation,
        method or ("POST" if write else "GET"),
        SideEffectClass.WRITE if write else SideEffectClass.READ,
        path,
        resource,
        args,
        OperationResult,
        resource_tenants=MappingProxyType(
            {"record-a": "tenant-a", "record-b": "tenant-b", "ticket-injected": "tenant-a"}
        )
        if resource
        else None,
        tenant_id=None if resource else "harness" if adapter == "control" else "tenant-a",
        credential_handle="fixture-control" if adapter == "control" else "fixture-customer",
    )


DATA_DEFINITIONS = (
    definition("http", "record.read", "/records/{resource_id}", EmptyArgs, resource=True),
    definition(
        "tool",
        "record.update",
        "/records/{resource_id}",
        UpdateArgs,
        write=True,
        resource=True,
        method="PATCH",
    ),
    definition("tool", "refund.create", "/refunds", RefundArgs, write=True),
    definition("tool", "canary.export", "/exports", ExportArgs, write=True),
    ToolDefinition(
        "chat",
        "chat.complete",
        "POST",
        SideEffectClass.READ,
        "/chat",
        False,
        ChatArgs,
        ChatResult,
        min_tokens=4096,
        tenant_id="tenant-a",
        credential_handle="fixture-customer",
    ),
)
CONTROL_DEFINITIONS = tuple(
    definition("control", f"fixture.{op}", f"/control/{op}", args, write=write)
    for op, args, write in (
        ("provision", EmptyArgs, True),
        ("seed", SeedArgs, True),
        ("snapshot", EmptyArgs, False),
        ("telemetry", EmptyArgs, False),
        ("defense", DefenseArgs, True),
        ("reset", EmptyArgs, True),
        ("teardown", EmptyArgs, True),
    )
)
PHASE1_TOOLS = ToolRegistry((*DATA_DEFINITIONS, *CONTROL_DEFINITIONS))
