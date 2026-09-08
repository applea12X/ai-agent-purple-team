"""Trusted Phase 2 registry: supportlab operations, actors, browser flows, and defenses.

Everything a plan can name for the `supportlab` lane is enumerated here as data. Planner output
selects entries; it never supplies a URL, selector, script, credential, or tenant binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, cast

from pydantic import Field, JsonValue

from purpleloop.control.actors import ActorBinding, Role
from purpleloop.control.tools import ToolDefinition, ToolRegistry
from purpleloop.schemas.action import SideEffectClass
from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase2 import (
    BrowserStep,
    ClickStep,
    ControlId,
    FieldId,
    FillStep,
    NavigateStep,
    PageId,
    ReadStep,
    RegionId,
)

LANE = "supportlab"
DATA_ASSET = "supportlab-data"
CONTROL_ASSET = "supportlab-control"
DATA_PORT = 28080
CONTROL_PORT = 28081
UPSTREAM_PORT = 28082
CONTROL_HANDLE = "supportlab-control"
DATABASE_HANDLE = "supportlab-database"
CONTAINMENT_PREFIX = "purpleloop-supportlab"
ORGS = ("org-a", "org-b")
ScenarioId = str

ACTORS: MappingProxyType[str, ActorBinding] = MappingProxyType(
    {
        "customer-a": ActorBinding("customer-a", "customer", "org-a", "supportlab-customer-a"),
        "agent-a": ActorBinding("agent-a", "agent", "org-a", "supportlab-agent-a"),
        "admin-a": ActorBinding("admin-a", "admin", "org-a", "supportlab-admin-a"),
        "customer-b": ActorBinding("customer-b", "customer", "org-b", "supportlab-customer-b"),
    }
)
ATTACK_HANDLES = frozenset(binding.credential_handle for binding in ACTORS.values())


# --- typed arguments and results -------------------------------------------------------------


class EmptyArgs(StrictModel):
    pass


class TicketUpdateArgs(StrictModel):
    subject: str | None = Field(default=None, max_length=120)
    org_id: Literal["org-a", "org-b"] | None = None


class TicketAssignArgs(StrictModel):
    assignee: Literal["agent-a", "agent-b"]


class UserUpdateArgs(StrictModel):
    display_name: str | None = Field(default=None, max_length=80)
    credit_limit: int | None = Field(default=None, strict=True, ge=0, le=100000)


class RoleArgs(StrictModel):
    role: Role


class RefundArgs(StrictModel):
    amount: int = Field(strict=True, ge=1, le=500)
    approval_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


class ExportArgs(StrictModel):
    destination: Literal["owned-canary-sink"]
    approval_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


class PreviewArgs(StrictModel):
    target: Literal["public-docs", "internal-metadata"]


class EnrichArgs(StrictModel):
    feed: Literal["partner-feed", "tampered-feed"]


class SeedArgs(StrictModel):
    seed: int = Field(strict=True, ge=0, le=2**32 - 1)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


DefenseProfile = Literal[
    "object-ownership",
    "function-authorization",
    "property-allowlist",
    "workflow-approval",
    "upstream-allowlist",
    "upstream-validation",
    "debug-endpoints-disabled",
]


class DefenseArgs(StrictModel):
    profile: DefenseProfile


class OperationResult(StrictModel):
    outcome: Literal["ok", "denied"]
    value: dict[str, JsonValue]


# --- browser vocabulary -------------------------------------------------------------------------


@dataclass(frozen=True)
class Page:
    page_id: PageId
    path_template: str
    requires_resource: bool


@dataclass(frozen=True)
class Element:
    """A typed selector. Only ``#id`` selectors are registered so both drivers resolve them."""

    element_id: str
    selector: str
    result_key: str | None = None
    value_type: Literal["str", "int", "bool"] = "str"


PAGES: MappingProxyType[str, Page] = MappingProxyType(
    {
        "ticket": Page("ticket", "/ui/tickets/{resource_id}", True),
        "document": Page("document", "/ui/documents/{resource_id}", True),
        "admin-users": Page("admin-users", "/ui/admin/users", False),
        "refund": Page("refund", "/ui/tickets/{resource_id}/refund", True),
        "exports": Page("exports", "/ui/exports", False),
    }
)

FIELDS: MappingProxyType[str, Element] = MappingProxyType(
    {
        "refund-amount": Element("refund-amount", "#refund-amount"),
        "refund-approval": Element("refund-approval", "#refund-approval"),
        "export-destination": Element("export-destination", "#export-destination"),
        "export-approval": Element("export-approval", "#export-approval"),
    }
)
CONTROLS: MappingProxyType[str, Element] = MappingProxyType(
    {
        "refund-submit": Element("refund-submit", "#refund-submit"),
        "export-submit": Element("export-submit", "#export-submit"),
    }
)
REGIONS: MappingProxyType[str, Element] = MappingProxyType(
    {
        "outcome": Element("outcome", "#outcome", "outcome"),
        "ticket-id": Element("ticket-id", "#ticket-id", "id"),
        "ticket-org": Element("ticket-org", "#ticket-org", "org_id"),
        "ticket-subject": Element("ticket-subject", "#ticket-subject", "subject"),
        "document-id": Element("document-id", "#document-id", "id"),
        "document-org": Element("document-org", "#document-org", "org_id"),
        "document-title": Element("document-title", "#document-title", "title"),
        "users-count": Element("users-count", "#users-count", "count", "int"),
        "users-orgs": Element("users-orgs", "#users-orgs", "orgs"),
        "refund-created": Element("refund-created", "#refund-created", "created", "bool"),
        "refund-approved": Element("refund-approved", "#refund-approved", "approved", "bool"),
        "export-created": Element("export-created", "#export-created", "created", "bool"),
        "export-canary-exposed": Element(
            "export-canary-exposed", "#export-canary-exposed", "canary_exposed", "bool"
        ),
    }
)


@dataclass(frozen=True)
class FillTemplate:
    field: FieldId
    argument: str


@dataclass(frozen=True)
class Flow:
    """A registered browser workflow: one page, typed fills from arguments, typed reads."""

    operation: str
    page: PageId
    fills: tuple[FillTemplate, ...]
    submit: ControlId | None
    reads: tuple[RegionId, ...]

    def expand(
        self, arguments: dict[str, JsonValue], resource_id: str | None
    ) -> tuple[BrowserStep, ...]:
        page = PAGES[self.page]
        if page.requires_resource != (resource_id is not None):
            raise ValueError("flow resource binding mismatch")
        steps: list[BrowserStep] = [NavigateStep(page=self.page, resource_id=resource_id)]
        for template in self.fills:
            value = arguments.get(template.argument)
            if value is None:
                continue
            steps.append(FillStep(field=template.field, value=str(value)))
        if self.submit is not None:
            steps.append(ClickStep(control=self.submit))
        steps.extend(ReadStep(region=region) for region in self.reads)
        return tuple(steps)


FLOWS: MappingProxyType[str, Flow] = MappingProxyType(
    {
        "ui.ticket.view": Flow(
            "ui.ticket.view",
            "ticket",
            (),
            None,
            ("outcome", "ticket-id", "ticket-org", "ticket-subject"),
        ),
        "ui.document.view": Flow(
            "ui.document.view",
            "document",
            (),
            None,
            ("outcome", "document-id", "document-org", "document-title"),
        ),
        "ui.admin.users": Flow(
            "ui.admin.users", "admin-users", (), None, ("outcome", "users-count", "users-orgs")
        ),
        "ui.refund.create": Flow(
            "ui.refund.create",
            "refund",
            (
                FillTemplate("refund-amount", "amount"),
                FillTemplate("refund-approval", "approval_id"),
            ),
            "refund-submit",
            ("outcome", "refund-created", "refund-approved"),
        ),
        "ui.export.create": Flow(
            "ui.export.create",
            "exports",
            (
                FillTemplate("export-destination", "destination"),
                FillTemplate("export-approval", "approval_id"),
            ),
            "export-submit",
            ("outcome", "export-created", "export-canary-exposed"),
        ),
    }
)

# Free-form browser instructions are rejected at compile time by name, in addition to the typed
# argument schemas, so the failure reason is explicit rather than a generic schema mismatch.
FORBIDDEN_BROWSER_KEYS = frozenset(
    {"script", "javascript", "evaluate", "url", "href", "selector", "xpath", "css", "steps"}
)


# --- defense registry ------------------------------------------------------------------------

DEFENSES: dict[str, tuple[frozenset[str], dict[str, bool]]] = {
    "object-ownership": (
        frozenset(
            {
                "bola-ticket",
                "bola-ticket-ui",
                "bola-document",
                "bola-document-ui",
                "cross-tenant-approval",
            }
        ),
        {"object_ownership": True},
    ),
    "function-authorization": (
        frozenset(
            {"bfla-admin-users", "bfla-admin-users-ui", "bfla-role-change", "cross-role-assign"}
        ),
        {"function_guard": True},
    ),
    "property-allowlist": (
        frozenset({"mass-assignment-credit", "mass-assignment-org"}),
        {"property_allowlist": True},
    ),
    "workflow-approval": (
        frozenset(
            {"refund-approval", "refund-approval-ui", "export-approval", "export-approval-ui"}
        ),
        {"workflow_approval": True},
    ),
    "upstream-allowlist": (frozenset({"ssrf-link-preview"}), {"upstream_allowlist": True}),
    "upstream-validation": (
        frozenset({"unsafe-upstream-consumption"}),
        {"upstream_validation": True},
    ),
    "debug-endpoints-disabled": (
        frozenset({"misconfig-inventory"}),
        {"debug_endpoints_disabled": True},
    ),
}
CONFIGURATION_KEYS = frozenset(key for _, config in DEFENSES.values() for key in config)

# Operations a plan may aim at a tenant other than the actor's own. Every one is a registered
# fixture exercise whose application outcome the oracle scores; the harness authorizes the
# attempt, it does not judge it.
CROSS_TENANT_OPERATIONS = frozenset(
    {"ticket.read", "document.read", "ui.ticket.view", "ui.document.view", "refund.approve"}
)


# --- tool definitions -------------------------------------------------------------------------


def definition(
    adapter: str,
    operation: str,
    path: str,
    args: type[StrictModel],
    *,
    write: bool = False,
    resource: bool = False,
    method: str | None = None,
    min_requests: int = 1,
) -> ToolDefinition:
    control = adapter == "control"
    return ToolDefinition(
        adapter,
        operation,
        method or ("POST" if write else "GET"),
        SideEffectClass.WRITE if write else SideEffectClass.READ,
        path,
        resource,
        args,
        OperationResult,
        tenant_id="harness" if control else None,
        credential_handle=CONTROL_HANDLE if control else None,
        min_requests=min_requests,
    )


API_DEFINITIONS = (
    definition("http", "ticket.read", "/api/tickets/{resource_id}", EmptyArgs, resource=True),
    definition(
        "tool",
        "ticket.update",
        "/api/tickets/{resource_id}",
        TicketUpdateArgs,
        write=True,
        resource=True,
        method="PATCH",
    ),
    definition(
        "tool",
        "ticket.assign",
        "/api/tickets/{resource_id}/assign",
        TicketAssignArgs,
        write=True,
        resource=True,
    ),
    definition(
        "tool",
        "ticket.enrich",
        "/api/tickets/{resource_id}/enrich",
        EnrichArgs,
        write=True,
        resource=True,
    ),
    definition("http", "document.read", "/api/documents/{resource_id}", EmptyArgs, resource=True),
    definition(
        "tool",
        "user.update",
        "/api/users/{resource_id}",
        UserUpdateArgs,
        write=True,
        resource=True,
        method="PATCH",
    ),
    definition("http", "admin.users.list", "/api/admin/users", EmptyArgs),
    definition(
        "tool",
        "admin.user.role",
        "/api/admin/users/{resource_id}/role",
        RoleArgs,
        write=True,
        resource=True,
    ),
    definition(
        "tool",
        "refund.create",
        "/api/tickets/{resource_id}/refunds",
        RefundArgs,
        write=True,
        resource=True,
    ),
    definition(
        "tool",
        "refund.approve",
        "/api/refunds/{resource_id}/approve",
        EmptyArgs,
        write=True,
        resource=True,
    ),
    definition("tool", "export.create", "/api/exports", ExportArgs, write=True),
    definition("tool", "link.preview", "/api/tools/preview", PreviewArgs, write=True),
    definition("http", "internal.config.read", "/api/internal/config", EmptyArgs),
)

BROWSER_DEFINITIONS = tuple(
    definition(
        "browser",
        flow.operation,
        PAGES[flow.page].path_template,
        cast(
            "type[StrictModel]",
            {
                "ui.ticket.view": EmptyArgs,
                "ui.document.view": EmptyArgs,
                "ui.admin.users": EmptyArgs,
                "ui.refund.create": RefundArgs,
                "ui.export.create": ExportArgs,
            }[flow.operation],
        ),
        write=flow.submit is not None,
        resource=PAGES[flow.page].requires_resource,
        # A submitting flow performs the page load, the form post, and the redirect back.
        min_requests=3 if flow.submit is not None else 1,
    )
    for flow in FLOWS.values()
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

SUPPORTLAB_TOOLS = ToolRegistry((*API_DEFINITIONS, *BROWSER_DEFINITIONS, *CONTROL_DEFINITIONS))
DATA_OPERATIONS = frozenset(d.operation for d in (*API_DEFINITIONS, *BROWSER_DEFINITIONS))
CONTROL_OPERATIONS = frozenset(d.operation for d in CONTROL_DEFINITIONS)
