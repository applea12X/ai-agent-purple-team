"""Agent-lane tools, defenses, and intent vocabulary.

The agent lane is the supportlab lane plus an agent surface: the same fixture, the same signed
ownership, the same control plane, with retrieval, memory, and four narrow agent tools added.

Two rules from earlier phases carry through unchanged and are the reason this module is trusted
code rather than configuration. The set of operations an intent may name is closed and lives
here, not in model output; and every intent the assistant parses is compiled into a typed action
and executed by ``SafetyRuntime`` one at a time, exactly as a Phase 1 chat intent is.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, JsonValue

from purpleloop.control.phase2_tools import (
    ACTORS,
    API_DEFINITIONS,
    BROWSER_DEFINITIONS,
    CONTROL_DEFINITIONS,
    CROSS_TENANT_OPERATIONS,
    DEFENSES,
    OperationResult,
    definition,
)
from purpleloop.control.tools import ToolRegistry
from purpleloop.schemas.common import StrictModel

LANE = "supportlab-agent"

#: Destinations an agent tool may name. ``owned-canary-sink`` is a sink this project owns;
#: ``attacker-sink`` is the synthetic exfiltration destination the corpus points at. Both are
#: fixture-local strings -- neither resolves to anything, and no packet leaves the fixture.
Destination = Literal["owned-canary-sink", "attacker-sink", "org-mailbox"]

#: CRM fields an agent tool may write. A closed set, so schema injection has a boundary to cross.
CrmField = Literal["note", "tier", "role"]


class AgentContextArgs(StrictModel):
    """Ask the fixture for the retrieval context for one topic. Read-only."""

    topic: str = Field(max_length=64, pattern=r"^[a-z][a-z0-9-]{0,63}$")
    task: str = Field(max_length=500)


class EmailArgs(StrictModel):
    destination: Destination
    subject: str = Field(max_length=200)
    body: str = Field(max_length=4000)


class CrmArgs(StrictModel):
    field: CrmField
    value: str = Field(max_length=200)


class MemoryWriteArgs(StrictModel):
    topic: str = Field(max_length=64, pattern=r"^[a-z][a-z0-9-]{0,63}$")
    body: str = Field(max_length=1000)
    #: Where the content came from. The assistant reports it; the fixture decides what to do with
    #: it. A defended fixture refuses an untrusted-derived write; a vulnerable one does not.
    derived_from: Literal["trusted", "untrusted"] = "trusted"


class MemoryReadArgs(StrictModel):
    topic: str = Field(max_length=64, pattern=r"^[a-z][a-z0-9-]{0,63}$")


#: The closed operation set an assistant intent may name. Model output selects from this; it can
#: never introduce an operation, an adapter, or a target.
IntentOperation = Literal[
    "email.send",
    "crm.update",
    "memory.write",
    "refund.create",
    "export.create",
]

INTENT_OPERATIONS: frozenset[str] = frozenset(
    ("email.send", "crm.update", "memory.write", "refund.create", "export.create")
)


class AgentToolIntent(StrictModel):
    """One tool the assistant asked for. Arguments are typed before anything is compiled."""

    operation: IntentOperation
    resource_id: str | None = Field(default=None, max_length=128)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class RetrievedChunk(StrictModel):
    """A retrieved chunk with the provenance that follows it into evidence."""

    chunk_id: str
    source_kind: str
    source_id: str
    trust_level: Literal["trusted", "untrusted"]
    body: str = Field(max_length=4000)


class AgentResult(StrictModel):
    """What the agent adapter returns. Susceptibility and execution stay separate fields."""

    message: str = Field(max_length=4000)
    tool_intents: tuple[AgentToolIntent, ...] = ()
    retrieved: tuple[RetrievedChunk, ...] = ()
    untrusted_chunks: int = Field(default=0, ge=0)
    quarantined: bool = False
    model_pin_id: str
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)
    model_call: dict[str, JsonValue] = Field(default_factory=dict)


# --- tool definitions ---------------------------------------------------------------------------

AGENT_DEFINITIONS = (
    definition("agent", "agent.ask", "/api/agent/context", AgentContextArgs, method="POST"),
    definition("tool", "email.send", "/api/agent/email", EmailArgs, write=True),
    definition(
        "tool",
        "crm.update",
        "/api/agent/crm/{resource_id}",
        CrmArgs,
        write=True,
        resource=True,
    ),
    definition("tool", "memory.write", "/api/agent/memory", MemoryWriteArgs, write=True),
    definition("http", "memory.read", "/api/agent/memory/read", MemoryReadArgs, method="POST"),
)

AGENT_OPERATIONS = frozenset(d.operation for d in AGENT_DEFINITIONS)

#: Which adapter executes each intent operation, derived from the registry rather than restated.
INTENT_ADAPTERS: dict[str, str] = {
    d.operation: d.adapter
    for d in (*API_DEFINITIONS, *AGENT_DEFINITIONS)
    if d.operation in INTENT_OPERATIONS
}

SUPPORTLAB_AGENT_TOOLS = ToolRegistry(
    (*API_DEFINITIONS, *BROWSER_DEFINITIONS, *AGENT_DEFINITIONS, *CONTROL_DEFINITIONS)
)

DATA_OPERATIONS = frozenset(
    d.operation for d in (*API_DEFINITIONS, *BROWSER_DEFINITIONS, *AGENT_DEFINITIONS)
)

# --- defenses -----------------------------------------------------------------------------------

#: Agent-lane defense profiles. Each is a named configuration value the signed manifest must
#: pre-authorize, exactly like the Phase 2 seven. The harness never edits fixture source.
AGENT_DEFENSES: dict[str, tuple[frozenset[str], dict[str, bool]]] = {
    "retrieval-provenance-guard": (
        frozenset(
            {
                "agent-indirect-ticket",
                "agent-indirect-document",
                "agent-indirect-html",
                "agent-indirect-markdown",
                "agent-indirect-api-response",
                "agent-indirect-tool-description",
                "agent-indirect-log",
                "agent-indirect-inter-agent",
                "agent-rag-poisoning",
                "agent-encoded-injection",
                "agent-multilingual-injection",
                "agent-multiturn-injection",
                "agent-goal-hijack",
                "agent-cascading-failure",
            }
        ),
        {"retrieval_provenance": True},
    ),
    "memory-write-guard": (
        frozenset({"agent-memory-poisoning", "agent-memory-persistence"}),
        {"memory_write_guard": True},
    ),
    "output-sanitization": (
        frozenset(
            {
                "agent-canary-exfiltration",
                "agent-covert-channel",
                "agent-unsafe-output",
                "agent-direct-injection",
            }
        ),
        {"output_sanitization": True},
    ),
    "capability-scoping": (
        frozenset(
            {
                "agent-excessive-agency",
                "agent-confused-deputy",
                "agent-tool-misuse",
                "agent-code-execution",
            }
        ),
        {"capability_scoping": True},
    ),
    "prompt-isolation": (
        frozenset({"agent-system-prompt-leakage"}),
        {"prompt_isolation": True},
    ),
    "schema-validation": (
        frozenset({"agent-schema-injection", "agent-argument-injection"}),
        {"schema_validation": True},
    ),
    "workflow-approval": (
        DEFENSES["workflow-approval"][0] | frozenset({"agent-approval-spoofing"}),
        {"workflow_approval": True},
    ),
}

#: The Phase 2 profiles plus the agent additions. ``workflow-approval`` is widened rather than
#: duplicated, so one defense keeps one configuration value across both lanes.
COMBINED_DEFENSES: dict[str, tuple[frozenset[str], dict[str, bool]]] = {**DEFENSES}
COMBINED_DEFENSES.update(AGENT_DEFENSES)

CONFIGURATION_KEYS = frozenset(key for _, config in COMBINED_DEFENSES.values() for key in config)

AGENT_CROSS_TENANT_OPERATIONS = CROSS_TENANT_OPERATIONS

AGENT_ACTORS = ACTORS

__all__ = [
    "AGENT_ACTORS",
    "AGENT_CROSS_TENANT_OPERATIONS",
    "AGENT_DEFENSES",
    "AGENT_DEFINITIONS",
    "AGENT_OPERATIONS",
    "COMBINED_DEFENSES",
    "CONFIGURATION_KEYS",
    "DATA_OPERATIONS",
    "INTENT_ADAPTERS",
    "INTENT_OPERATIONS",
    "LANE",
    "SUPPORTLAB_AGENT_TOOLS",
    "AgentContextArgs",
    "AgentResult",
    "AgentToolIntent",
    "CrmArgs",
    "EmailArgs",
    "MemoryReadArgs",
    "MemoryWriteArgs",
    "OperationResult",
    "RetrievedChunk",
]
