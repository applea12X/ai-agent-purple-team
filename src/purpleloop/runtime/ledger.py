from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from pydantic import ValidationError

from purpleloop.schemas.event import EvidenceEvent


class LedgerError(RuntimeError):
    reason_code = "LEDGER_INVALID"


class EvidenceLedger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.anchor_path = path.with_suffix(f"{path.suffix}.anchor")
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: EvidenceEvent) -> EvidenceEvent:
        with self._lock:
            existing = self.verify() if self.path.exists() or self.anchor_path.exists() else []
            prepared = event.model_copy(
                update={
                    "sequence": len(existing),
                    "parent_hash": existing[-1].event_hash if existing else None,
                    "event_hash": None,
                }
            )
            final = prepared.model_copy(update={"event_hash": prepared.calculated_hash()})
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(final.model_dump_json(exclude_none=True))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary_anchor = self.anchor_path.with_suffix(f"{self.anchor_path.suffix}.tmp")
            temporary_anchor.write_text(final.event_hash or "", encoding="ascii")
            temporary_anchor.replace(self.anchor_path)
            return final

    def read_all(self) -> list[EvidenceEvent]:
        with self._lock:
            if not self.path.exists():
                return []
            events: list[EvidenceEvent] = []
            try:
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        events.append(EvidenceEvent.model_validate_json(line))
            except (OSError, ValidationError, json.JSONDecodeError) as exc:
                raise LedgerError("ledger contains an invalid or partial event") from exc
            return events

    def verify(self) -> list[EvidenceEvent]:
        with self._lock:
            events = self.read_all()
            parent_hash: str | None = None
            for index, event in enumerate(events):
                if event.sequence != index:
                    raise LedgerError("ledger sequence is not monotonic")
                if event.parent_hash != parent_hash:
                    raise LedgerError("ledger parent hash is broken")
                if event.event_hash != event.calculated_hash():
                    raise LedgerError("ledger event hash is invalid")
                parent_hash = event.event_hash
            expected_anchor = (
                self.anchor_path.read_text(encoding="ascii") if self.anchor_path.exists() else ""
            )
            if events and expected_anchor != events[-1].event_hash:
                raise LedgerError("ledger anchor does not match the final event")
            if not events and expected_anchor:
                raise LedgerError("ledger is missing anchored events")
            return events
