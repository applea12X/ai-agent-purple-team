from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

import rfc8785
from pydantic import BaseModel, ConfigDict, field_validator

IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    def canonical_bytes(self, *, exclude: set[str] | None = None) -> bytes:
        payload = self.model_dump(mode="json", exclude_none=True, exclude=exclude or set())
        return rfc8785.dumps(payload)

    def digest(self, *, exclude: set[str] | None = None) -> str:
        return hashlib.sha256(self.canonical_bytes(exclude=exclude)).hexdigest()


def require_identifier(value: str) -> str:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError("must be a canonical identifier")
    return value


def require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value.astimezone(UTC)


class IdentifiedModel(StrictModel):
    id: str

    _validate_id = field_validator("id")(require_identifier)


def digest_data(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()
