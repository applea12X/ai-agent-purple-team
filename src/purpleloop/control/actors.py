from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Role = Literal["customer", "agent", "admin"]


@dataclass(frozen=True)
class ActorBinding:
    """Trusted binding from a scenario actor to its role, tenant, and opaque credential handle."""

    actor_id: str
    role: Role
    tenant_id: str
    credential_handle: str
