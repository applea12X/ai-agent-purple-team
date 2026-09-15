"""The agent seed must reach the template before the single materialize, on every engine.

SQLite keeps its template connection open after materializing; PostgreSQL commits and closes it so
it can serve as ``CREATE DATABASE ... TEMPLATE``. Seeding agent rows after an early materialize
therefore passed in process and failed on the container lane with
``AttributeError: 'NoneType' object has no attribute 'execute'``. This test enforces PostgreSQL's
semantics on the in-process engine, so the class of defect fails here without a container.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from typing import Any

import httpx
import pytest

from purpleloop.fixture.supportlab.app import SupportlabState, create_apps, in_process_upstream
from purpleloop.fixture.supportlab.database import SqliteDatabase

CONTROL = "materialize-test-control-token"
AGENT_SEED = {
    "seed": 42,
    "scenario_id": "agent-indirect-ticket",
    "surface": "agent",
    "capabilities": ["email.send"],
}


class TemplateClosesOnMaterialize(SqliteDatabase):
    """SQLite with PostgreSQL's rule: the template is unwritable once materialized."""

    def __init__(self) -> None:
        super().__init__()
        self.materializations = 0
        self._sealed = False

    def provision(self) -> None:
        super().provision()
        self._sealed = False

    def seed_rows(self, table: str, columns: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
        if self._sealed:
            raise AssertionError(f"wrote {table} to the template after it was materialized")
        super().seed_rows(table, columns, rows)

    def materialize(self) -> None:
        self.materializations += 1
        super().materialize()
        self._sealed = True


async def _seed(database: SqliteDatabase, body: dict[str, Any]) -> dict[str, Any]:
    state = SupportlabState(
        database, actor_tokens={}, control_token=CONTROL, upstream=in_process_upstream()
    )
    _, control = create_apps(state)
    headers = {"Authorization": f"Bearer {CONTROL}"}
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=control), base_url="http://control"
        ) as client:
            for operation, payload in (("provision", {}), ("seed", body)):
                response = await client.post(f"/control/{operation}", json=payload, headers=headers)
                assert response.status_code == 200, response.text[:300]
            snapshot = await client.get("/control/snapshot", headers=headers)
            value: dict[str, Any] = snapshot.json()["value"]
            return value
    finally:
        state.dispose()


@pytest.mark.parametrize("surface", ["api", "agent"])
async def test_the_seed_route_writes_the_template_before_its_single_materialize(
    surface: str,
) -> None:
    database = TemplateClosesOnMaterialize()
    body = {**AGENT_SEED, "surface": surface}
    value = await _seed(database, body)
    assert database.materializations == 1, "the seed route materialized more than once"
    assert ("chunks" in value["state"]) is (surface == "agent")


@pytest.mark.skipif(
    os.environ.get("PURPLELOOP_CONTAINER_TESTS") != "1"
    or not os.environ.get("PURPLELOOP_TEST_POSTGRES_DSN"),
    reason="needs PURPLELOOP_CONTAINER_TESTS=1 and PURPLELOOP_TEST_POSTGRES_DSN",
)
async def test_the_agent_surface_hash_is_identical_on_postgres_and_sqlite() -> None:
    """The cross-engine determinism Phase 2 measured, extended to the agent tables."""
    from purpleloop.fixture.supportlab.database import PostgresDatabase

    postgres = await _seed(
        PostgresDatabase(os.environ["PURPLELOOP_TEST_POSTGRES_DSN"]),  # type: ignore[arg-type]
        AGENT_SEED,
    )
    sqlite = await _seed(SqliteDatabase(), AGENT_SEED)
    assert postgres["engine"] != sqlite["engine"]
    assert postgres["state_hash"] == sqlite["state_hash"]
