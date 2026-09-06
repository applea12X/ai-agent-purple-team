from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

import rfc8785
from pydantic import BaseModel, ConfigDict, field_validator

IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


def order_sets(structural: Any, serialized: Any) -> Any:
    """Sort set-derived arrays so canonical bytes never depend on iteration order.

    JCS sorts object keys but preserves array order, and a `frozenset` serializes to an array in
    hash order. That order varies with `PYTHONHASHSEED` and with how the set was built, so a
    signature or digest taken before a JSON round-trip could disagree with one taken after it.
    `structural` is a python-mode dump, which still holds real sets; `serialized` is the json-mode
    dump that supplies the exact leaf encoding. The two mirror each other, so walking them in
    parallel reorders only the arrays that came from sets and leaves ordered tuples untouched.
    """
    if isinstance(structural, (set, frozenset)):
        items = [
            order_sets(item, value) for item, value in zip(structural, serialized, strict=True)
        ]
        return sorted(items, key=rfc8785.dumps)
    if isinstance(structural, dict) and isinstance(serialized, dict):
        return {
            key: order_sets(structural[key], value) if key in structural else value
            for key, value in serialized.items()
        }
    if isinstance(structural, (list, tuple)) and isinstance(serialized, list):
        return [order_sets(item, value) for item, value in zip(structural, serialized, strict=True)]
    return serialized


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    def canonical_bytes(self, *, exclude: set[str] | None = None) -> bytes:
        excluded = exclude or set()
        payload = self.model_dump(mode="json", exclude_none=True, exclude=excluded)
        structural = self.model_dump(mode="python", exclude_none=True, exclude=excluded)
        return rfc8785.dumps(order_sets(structural, payload))

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
