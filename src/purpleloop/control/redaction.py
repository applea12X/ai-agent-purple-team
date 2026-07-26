from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"
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
                str(key): REDACTED if SENSITIVE_KEY.search(str(key)) else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        return value
