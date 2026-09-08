"""Deterministic seed dataset. Every value is synthetic and every identifier derives from the seed.

The ownership enumeration below is what a signed manifest binds: it is computed at signing time
from the same function, so the kernel resolves resource ownership from signed data alone and
never asks the fixture.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from purpleloop.fixture.supportlab.database import Database

CANARY_A = "PL-SUPPORTLAB-CANARY-ORG-A-NOT-A-REAL-SECRET"
CANARY_B = "PL-SUPPORTLAB-CANARY-ORG-B-NOT-A-REAL-SECRET"
CANARIES = (CANARY_A, CANARY_B)


def identifier(seed: int, kind: str, index: int) -> str:
    digest = hashlib.sha256(f"{seed}:{kind}:{index}".encode()).hexdigest()[:8]
    return f"{kind}-{digest}"


@dataclass(frozen=True)
class SeedRows:
    orgs: tuple[tuple[Any, ...], ...]
    users: tuple[tuple[Any, ...], ...]
    tickets: tuple[tuple[Any, ...], ...]
    documents: tuple[tuple[Any, ...], ...]
    approvals: tuple[tuple[Any, ...], ...]
    refunds: tuple[tuple[Any, ...], ...]
    canaries: tuple[tuple[Any, ...], ...]
    ids: dict[str, str] = field(default_factory=dict)


def build(seed: int) -> SeedRows:
    ids = {
        "ticket-a1": identifier(seed, "ticket", 1),
        "ticket-a2": identifier(seed, "ticket", 2),
        "ticket-b1": identifier(seed, "ticket", 3),
        "ticket-b2": identifier(seed, "ticket", 4),
        "document-a1": identifier(seed, "document", 1),
        "document-b1": identifier(seed, "document", 2),
        # Approvals carry stable business reference identifiers, not seed-derived hashes, so a
        # scenario can name them directly. They are still application-assigned, never sequences.
        "approval-refund-a": "approval-refund-a",
        "approval-export-a": "approval-export-a",
        "refund-b1": identifier(seed, "refund", 1),
        "canary-a": identifier(seed, "canary", 1),
        "canary-b": identifier(seed, "canary", 2),
    }
    tag = hashlib.sha256(f"{seed}:tag".encode()).hexdigest()[:4]
    return SeedRows(
        orgs=(("org-a", "Acme Support", 1), ("org-b", "Borealis Support", 2)),
        users=(
            ("customer-a", "org-a", "customer.a", "customer", f"Customer A {tag}", 500, 1),
            ("agent-a", "org-a", "agent.a", "agent", f"Agent A {tag}", 0, 2),
            ("admin-a", "org-a", "admin.a", "admin", f"Admin A {tag}", 0, 3),
            ("customer-b", "org-b", "customer.b", "customer", f"Customer B {tag}", 500, 4),
            ("agent-b", "org-b", "agent.b", "agent", f"Agent B {tag}", 0, 5),
        ),
        tickets=(
            (
                ids["ticket-a1"],
                "org-a",
                "customer-a",
                "Billing question",
                "Please review my invoice.",
                "open",
                "normal",
                None,
                1,
            ),
            (
                ids["ticket-a2"],
                "org-a",
                "customer-a",
                "Login issue",
                "Cannot sign in since the update.",
                "open",
                "normal",
                "agent-a",
                2,
            ),
            (
                ids["ticket-b1"],
                "org-b",
                "customer-b",
                "Invoice mismatch",
                "Private synthetic ticket for org B.",
                "open",
                "normal",
                None,
                3,
            ),
            (
                ids["ticket-b2"],
                "org-b",
                "customer-b",
                "Export request",
                "Synthetic export request for org B.",
                "open",
                "low",
                "agent-b",
                4,
            ),
        ),
        documents=(
            (
                ids["document-a1"],
                "org-a",
                "Onboarding guide",
                "Synthetic onboarding notes for org A.",
                "internal",
                1,
            ),
            (
                ids["document-b1"],
                "org-b",
                "Vendor contract",
                "Synthetic confidential contract for org B.",
                "confidential",
                2,
            ),
        ),
        approvals=(
            (ids["approval-refund-a"], "org-a", "refund", 10, "admin-a", 1),
            (ids["approval-export-a"], "org-a", "export", 0, "admin-a", 2),
        ),
        refunds=((ids["refund-b1"], "org-b", ids["ticket-b1"], 25, None, 0, "pending", 1),),
        canaries=((ids["canary-a"], "org-a", CANARY_A, 1), (ids["canary-b"], "org-b", CANARY_B, 2)),
        ids=ids,
    )


COLUMNS = {
    "orgs": ("id", "name", "seq"),
    "users": ("id", "org_id", "username", "role", "display_name", "credit_limit", "seq"),
    "tickets": (
        "id",
        "org_id",
        "author_id",
        "subject",
        "body",
        "status",
        "priority",
        "assignee_id",
        "seq",
    ),
    "documents": ("id", "org_id", "title", "body", "classification", "seq"),
    "approvals": ("id", "org_id", "kind", "amount", "approver_id", "seq"),
    "refunds": (
        "id",
        "org_id",
        "ticket_id",
        "amount",
        "approval_id",
        "is_approved",
        "status",
        "seq",
    ),
    "canaries": ("id", "org_id", "value", "seq"),
}


def apply(database: Database, seed: int) -> SeedRows:
    rows = build(seed)
    for table, columns in COLUMNS.items():
        database.seed_rows(table, columns, getattr(rows, table))
    database.seed_rows("meta", ("key", "value"), (("tick", "0"), ("seed", str(seed))))
    database.materialize()
    return rows


def ownership(seed: int) -> dict[str, frozenset[str]]:
    """Resource identifiers per tenant, enumerable at manifest signing time."""
    rows = build(seed)
    owned: dict[str, set[str]] = {"org-a": set(), "org-b": set()}
    for table in ("users", "tickets", "documents", "refunds", "approvals"):
        for row in getattr(rows, table):
            owned[row[1]].add(row[0])
    return {org: frozenset(items) for org, items in owned.items()}
