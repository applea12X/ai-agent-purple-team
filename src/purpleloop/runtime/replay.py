from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from purpleloop.schemas.common import StrictModel, digest_data
from purpleloop.schemas.event import EvidenceEvent


class ReplaySummary(StrictModel):
    event_replay_hash: str
    score_hash: str


def replay_fingerprint(events: Sequence[EvidenceEvent]) -> str:
    normalized: list[dict[str, Any]] = []
    references = {
        event.event_hash: f"event:{event.sequence}" for event in events if event.event_hash
    }

    def normalize_references(value: Any) -> Any:
        if isinstance(value, str):
            return references.get(value, value)
        if isinstance(value, dict):
            return {key: normalize_references(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [normalize_references(item) for item in value]
        return value

    for event in events:
        payload = event.model_dump(
            mode="json",
            exclude={"timestamp", "event_hash", "parent_hash", "run_id", "trace_id"},
            exclude_none=True,
        )
        data = payload.get("data")
        if isinstance(data, dict):
            data.pop("latency_ms", None)
        normalized.append(
            normalize_references(payload) if event.schema_version == "1.1.0" else payload
        )
    return digest_data(normalized)


def replay_summary(events: Sequence[EvidenceEvent], score_hash: str) -> ReplaySummary:
    return ReplaySummary(event_replay_hash=replay_fingerprint(events), score_hash=score_hash)


def compare_replays(
    first: Sequence[EvidenceEvent],
    second: Sequence[EvidenceEvent],
    *,
    first_score_hash: str | None = None,
    second_score_hash: str | None = None,
) -> bool:
    if replay_fingerprint(first) != replay_fingerprint(second):
        return False
    return first_score_hash is None or (
        first_score_hash == second_score_hash and second_score_hash is not None
    )
