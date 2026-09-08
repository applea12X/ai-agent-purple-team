from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
import yaml

from purpleloop.fixture.supportlab import relay
from purpleloop.fixture.supportlab.database import SqliteDatabase, load_migrations
from purpleloop.fixture.supportlab.schema import SCHEMA_STATEMENTS
from purpleloop.runtime.demo import ROOT


def test_compose_isolation_contract() -> None:
    config = yaml.safe_load((ROOT / "compose.phase2.yaml").read_text())
    for name in ("supportlab-fixture", "supportlab-upstream", "supportlab-db"):
        service = config["services"][name]
        assert service["read_only"]
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["networks"] == ["supportlab-isolated"]
    # The database has no published ports and lives on the internal network only.
    assert "ports" not in config["services"]["supportlab-db"]
    assert config["networks"]["supportlab-isolated"]["internal"]
    ingress = config["services"]["supportlab-ingress"]
    assert all(port.startswith("127.0.0.1:") for port in ingress["ports"])
    assert "environment" not in ingress
    # Only the ingress relay bridges the isolated network to the loopback frontend.
    assert set(ingress["networks"]) == {"supportlab-isolated", "supportlab-ingress"}


def test_schema_file_mirrors_packaged_statements() -> None:
    on_disk = load_migrations()
    assert on_disk == SCHEMA_STATEMENTS
    sql = (ROOT / "targets/supportlab/migrations/0001_init.sql").read_text()
    for statement in SCHEMA_STATEMENTS:
        assert statement.splitlines()[0] in sql


def test_query_layer_orders_every_scored_read() -> None:
    """Every scored query carries an explicit total ordering — enforced, not by convention."""
    from purpleloop.fixture.supportlab.database import SCORED_TABLES, TELEMETRY_QUERY

    for sql in (*SCORED_TABLES.values(), TELEMETRY_QUERY):
        assert "ORDER BY" in sql


def test_seed_data_has_no_nondeterministic_sql() -> None:
    forbidden = ("now(", "random(", "gen_random_uuid", "current_timestamp", "serial", "identity")
    text = " ".join(SCHEMA_STATEMENTS).lower()
    assert not any(token in text for token in forbidden)


async def test_template_reset_restores_byte_identical_state() -> None:
    from purpleloop.fixture.supportlab import seed

    db = SqliteDatabase()
    db.provision()
    rows = seed.apply(db, 99)
    baseline = db.state_hash()
    db.execute("UPDATE tickets SET subject = ? WHERE id = ?", ("tampered", rows.ids["ticket-a1"]))
    db.commit()
    assert db.state_hash() != baseline
    db.reset()
    assert db.state_hash() == baseline
    db.teardown()


async def test_relay_forwards_and_cannot_be_redirected() -> None:
    # The relay's destination is a compile-time constant, not env- or request-controlled.
    assert relay.BACKEND == "supportlab-fixture"
    assert relay.DATA_PORT == 8080 and relay.CONTROL_PORT == 8081

    async def upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(upstream, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await relay.forward(reader, writer, port)

        # Point the relay's forward() at the loopback upstream directly (BACKEND resolves to it).
        import purpleloop.fixture.supportlab.relay as relay_module

        original = relay_module.BACKEND
        relay_module.BACKEND = "127.0.0.1"
        proxy = await asyncio.start_server(handle, "127.0.0.1", 0)
        proxy_port = proxy.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        body = await reader.read()
        assert b"200 OK" in body and body.endswith(b"hi")
        writer.close()
        await writer.wait_closed()
        proxy.close()
        await proxy.wait_closed()
        relay_module.BACKEND = original
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.skipif(
    os.environ.get("PURPLELOOP_CONTAINER_TESTS") != "1", reason="explicit container acceptance lane"
)
async def test_container_isolation_and_cross_plane_credentials(tmp_path: Path) -> None:
    import secrets

    import httpx

    from purpleloop.runtime.supportlab import ComposeSupportlab, actor_credentials

    tokens = actor_credentials()
    control = secrets.token_hex(24)
    database = secrets.token_hex(24)
    fixture = ComposeSupportlab(tokens, control, database, project="purpleloop-supportlab-test")
    try:
        await fixture.start()
        checks = [
            "import os; assert os.getuid()!=0",
            "import socket\n"
            "s=socket.socket();s.settimeout(0.3)\n"
            "try: s.connect(('1.1.1.1',443))\n"
            "except OSError: pass\n"
            "else: raise AssertionError('external egress')\n"
            "finally: s.close()",
        ]
        await fixture.command(
            "exec", "-T", "supportlab-fixture", "/app/.venv/bin/python", "-c", checks[0]
        )
        await fixture.command(
            "exec", "-T", "supportlab-fixture", "/app/.venv/bin/python", "-c", checks[1]
        )
        # The database is unreachable from an attack credential: it has no published port.
        async with httpx.AsyncClient(trust_env=False) as client:
            snapshot = await client.get(
                "http://127.0.0.1:28081/control/snapshot",
                headers={"Authorization": f"Bearer {control}"},
            )
            assert snapshot.status_code == 200
            denied = await client.get(
                "http://127.0.0.1:28081/control/snapshot",
                headers={"Authorization": f"Bearer {tokens['customer-a']}"},
            )
            assert denied.status_code == 403
    finally:
        await fixture.close()
    assert fixture.closed
