from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from enum import StrEnum
from typing import Any


class KernelState(StrEnum):
    RUNNING = "running"
    PAUSED = "paused"
    TERMINATED = "terminated"


class KernelStopped(RuntimeError):
    reason_code = "KERNEL_STOPPED"


class KillSwitch:
    def __init__(self) -> None:
        self._state = KernelState.RUNNING
        self._tasks: set[asyncio.Task[object]] = set()
        self._lock = asyncio.Lock()

    @property
    def state(self) -> KernelState:
        return self._state

    async def ensure_running(self) -> None:
        if self._state != KernelState.RUNNING:
            raise KernelStopped(f"kernel is {self._state}")

    async def spawn(
        self, factory: Callable[[], Coroutine[Any, Any, object]]
    ) -> asyncio.Task[object]:
        async with self._lock:
            await self.ensure_running()
            task: asyncio.Task[object] = asyncio.create_task(factory())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            return task

    async def register(self, task: asyncio.Task[object]) -> None:
        """Compatibility helper for externally created tasks; prefer spawn()."""
        async with self._lock:
            await self.ensure_running()
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def pause(self) -> None:
        async with self._lock:
            if self._state != KernelState.TERMINATED:
                self._state = KernelState.PAUSED

    async def resume(self) -> None:
        async with self._lock:
            if self._state == KernelState.PAUSED:
                self._state = KernelState.RUNNING

    async def terminate(self) -> None:
        async with self._lock:
            self._state = KernelState.TERMINATED
            tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()
            self._tasks.clear()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
