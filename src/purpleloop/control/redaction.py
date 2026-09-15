from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"
#: Keys whose names match the sensitive-key heuristic but whose values are accounting integers,
#: never secrets. The allowlist is explicit and integer-only: a credential is never a bare int, so
#: naming a counter here does not weaken the matcher. Phase 2 hit the same class of defect with a
#: defense flag called ``function_authorization`` and fixed it by renaming the flag; a token
#: counter cannot be renamed out of the way without making the evidence harder to read.
NUMERIC_KEYS = frozenset(
    {
        "tokens",
        "tokens_used",
        "input_tokens",
        "output_tokens",
        "max_output_tokens",
        "token_budget",
        "estimated_tokens",
        "actual_tokens",
    }
)
SENSITIVE_KEY = re.compile(r"(authorization|api[-_]?key|password|secret|token)", re.IGNORECASE)
BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")


class Redactor:
    def __init__(self, secrets: Sequence[str] = ()) -> None:
        self._secrets = tuple(secret for secret in secrets if secret)

    def with_secrets(self, secrets: Sequence[str]) -> Redactor:
        return Redactor((*self._secrets, *(secret for secret in secrets if secret)))

    def redact(self, value: Any) -> Any:
        if isinstance(value, str):
            result = BEARER.sub(f"Bearer {REDACTED}", value)
            for secret in self._secrets:
                result = result.replace(secret, REDACTED)
            return result
        if isinstance(value, Mapping):
            return {
                str(key): (
                    item
                    if key in NUMERIC_KEYS and isinstance(item, int)
                    else REDACTED
                    if SENSITIVE_KEY.search(str(key))
                    else self.redact(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        return value
