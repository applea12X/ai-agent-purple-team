from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol


class CredentialError(RuntimeError):
    reason_code = "CREDENTIAL_UNAVAILABLE"


class CredentialBroker(Protocol):
    def resolve(self, handle: str) -> str: ...


class InMemoryCredentialBroker:
    def __init__(self, credentials: Mapping[str, str]) -> None:
        self._credentials = dict(credentials)

    def resolve(self, handle: str) -> str:
        try:
            return self._credentials[handle]
        except KeyError as exc:
            raise CredentialError("credential handle is unavailable") from exc

    def secret_values(self) -> tuple[str, ...]:
        return tuple(self._credentials.values())
