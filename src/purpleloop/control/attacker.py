"""Bounded adaptive attacker: proposes typed plan nodes, and nothing else.

The attacker is a bounded, ordered mutation search over the typed argument space the tool
registry already declares. It is deterministic on purpose, so the attack leg stays replayable and
the proposal/rejection path can be measured rather than sampled. A model-driven attacker is an
optional profile behind the same caps; the caps, not the search, are the control.

What the attacker can do is exactly what a compiled step can do, because a proposal *is* a
``Step``. It cannot introduce an adapter, a target, a credential, or a budget, and it cannot widen
scope: every proposal goes through ``compile_step`` as untrusted data, and a refusal is recorded
as evidence rather than raised as a harness error.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, get_args, get_origin

from purpleloop.control.phase3_tools import INTENT_ADAPTERS, INTENT_ARGUMENT_MODELS
from purpleloop.schemas.common import StrictModel


@dataclass(frozen=True)
class Proposal:
    """One typed proposal, before compilation decides whether it is allowed."""

    index: int
    depth: int
    operation: str
    target_tenant: str
    resource_id: str | None
    arguments: dict[str, Any]
    #: What the mutation was trying, recorded whether or not it is permitted.
    rationale: str


def _corners(model: type[StrictModel]) -> list[dict[str, Any]]:
    """Enumerate the typed argument corners a model admits, in a stable order.

    Only closed vocabularies (``Literal``) and bounded numerics are enumerated. The search never
    invents a free string, because a free string is not a corner of a typed space -- it is a
    different attack, and it belongs in a scenario, not in a mutation search.
    """
    base: dict[str, Any] = {}
    choices: list[tuple[str, list[Any]]] = []
    for name, info in sorted(model.model_fields.items()):
        annotation = info.annotation
        options = [a for a in get_args(annotation) if a is not type(None)]
        if get_origin(annotation) is Literal:
            choices.append((name, sorted(get_args(annotation), key=str)))
        elif len(options) == 1 and get_origin(options[0]) is Literal:
            choices.append((name, sorted(get_args(options[0]), key=str)))
        elif info.is_required():
            base[name] = _placeholder(annotation)
    corners: list[dict[str, Any]] = [dict(base)]
    for name, values in choices:
        corners = [{**corner, name: value} for corner in corners for value in values]
    return corners[:64]


def _placeholder(annotation: Any) -> Any:
    if annotation is int:
        return 1
    if annotation is float:
        return 1.0
    if annotation is bool:
        return False
    return "probe"


class BoundedAttacker:
    """Deterministic, ordered, capped. The caps come from the signed manifest."""

    name = "bounded-mutation-v1"
    version = "attacker-v1"

    def __init__(
        self,
        *,
        max_proposals: int,
        max_depth: int,
        operations: Sequence[str],
        own_tenant: str,
        other_tenants: Sequence[str] = (),
        resource_id: str | None = None,
    ) -> None:
        self.max_proposals = max_proposals
        self.max_depth = max_depth
        self.operations = tuple(sorted(set(operations) & set(INTENT_ARGUMENT_MODELS)))
        self.own_tenant = own_tenant
        self.other_tenants = tuple(sorted(other_tenants))
        self.resource_id = resource_id

    def proposals(self) -> tuple[Proposal, ...]:
        """The full ordered proposal set, capped. Identical for identical inputs."""
        built: list[Proposal] = []
        depth = 1
        for operation in self.operations:
            model = INTENT_ARGUMENT_MODELS[operation]
            for corner in _corners(model):
                for tenant in (self.own_tenant, *self.other_tenants):
                    if depth > self.max_depth or len(built) >= self.max_proposals:
                        return tuple(built)
                    built.append(
                        Proposal(
                            index=len(built),
                            depth=depth,
                            operation=operation,
                            target_tenant=tenant,
                            resource_id=self.resource_id,
                            arguments=dict(corner),
                            rationale=(
                                "own-tenant argument corner"
                                if tenant == self.own_tenant
                                else "cross-tenant probe"
                            ),
                        )
                    )
            depth += 1
        return tuple(built)

    @staticmethod
    def adapter_for(operation: str) -> str:
        return INTENT_ADAPTERS[operation]
