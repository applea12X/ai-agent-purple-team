from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from purpleloop.schemas.action import BudgetRequest
from purpleloop.schemas.authorization import BudgetLimits


class BudgetError(RuntimeError):
    reason_code = "BUDGET_EXCEEDED"


@dataclass(frozen=True)
class Reservation:
    reservation_id: int
    requested: BudgetRequest


class BudgetLedger:
    def __init__(self, limits: BudgetLimits) -> None:
        self._limits = limits
        self._used = BudgetRequest(requests=0, records=0)
        self._active = 0
        self._next_id = 1
        self._reservations: dict[int, Reservation] = {}
        self._started = time.monotonic()
        self._lock = asyncio.Lock()

    async def reserve(self, requested: BudgetRequest) -> Reservation:
        async with self._lock:
            if time.monotonic() - self._started >= self._limits.wall_time_seconds:
                raise BudgetError("wall-time budget exhausted")
            if self._active >= self._limits.concurrency:
                raise BudgetError("concurrency budget exhausted")
            proposed = {
                name: getattr(self._used, name) + getattr(requested, name)
                for name in BudgetRequest.model_fields
            }
            for name, amount in proposed.items():
                if amount > getattr(self._limits, name):
                    raise BudgetError(f"{name} budget exhausted")
            self._used = BudgetRequest(**proposed)
            reservation = Reservation(self._next_id, requested)
            self._next_id += 1
            self._active += 1
            self._reservations[reservation.reservation_id] = reservation
            return reservation

    async def finalize(
        self, reservation: Reservation, *, unused: BudgetRequest | None = None
    ) -> None:
        async with self._lock:
            actual = self._reservations.pop(reservation.reservation_id, None)
            if actual != reservation:
                raise BudgetError("reservation is unknown or already finalized")
            if unused is not None:
                if any(
                    getattr(unused, name) > getattr(reservation.requested, name)
                    for name in BudgetRequest.model_fields
                ):
                    self._reservations[reservation.reservation_id] = reservation
                    raise BudgetError("unused budget exceeds the reservation")
                updated = {
                    name: getattr(self._used, name) - getattr(unused, name)
                    for name in BudgetRequest.model_fields
                }
                self._used = BudgetRequest(**updated)
            self._active = max(0, self._active - 1)

    @property
    def used(self) -> BudgetRequest:
        return self._used

    @property
    def active(self) -> int:
        return self._active

    @property
    def remaining_wall_time(self) -> float:
        return max(0.0, self._limits.wall_time_seconds - (time.monotonic() - self._started))
