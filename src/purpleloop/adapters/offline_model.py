from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from purpleloop.schemas.common import StrictModel, digest_data


class OfflineModelResponse(StrictModel):
    schema_version: str = "1.0.0"
    model: str
    profile: str
    request_digest: str
    response: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class OfflineResponseMissing(LookupError):
    reason_code = "OFFLINE_RESPONSE_MISSING"


class OfflineModelStore:
    """Deterministic fixture-only model responses. This class has no network fallback."""

    def __init__(self, path: Path) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        responses = tuple(
            OfflineModelResponse.model_validate(item) for item in payload["responses"]
        )
        self._responses = {
            (item.model, item.profile, item.request_digest): item for item in responses
        }
        if len(self._responses) != len(responses):
            raise ValueError("offline model response keys must be unique")

    @staticmethod
    def request_digest(request: dict[str, object]) -> str:
        return digest_data(request)

    def complete(
        self, *, model: str, profile: str, request: dict[str, object]
    ) -> OfflineModelResponse:
        key = (model, profile, self.request_digest(request))
        try:
            return self._responses[key]
        except KeyError as exc:
            raise OfflineResponseMissing("no exact offline response fixture exists") from exc
