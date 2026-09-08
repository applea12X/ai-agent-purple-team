"""WP2.0.1: the Phase 1 ingress relay is unit-tested on the host, not only in the container lane."""

from __future__ import annotations

import asyncio

import purpleloop.fixture.relay as phase1_relay


async def test_phase1_relay_forwards_to_fixed_backend(monkeypatch: object) -> None:
    async def upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(upstream, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    real_open = asyncio.open_connection

    async def fake_open(host: str, target_port: int, *args: object, **kwargs: object) -> object:
        # The relay always dials the fixed backend name; redirect only that to the loopback stub.
        assert host == "phase1-fixture"
        return await real_open("127.0.0.1", port)

    monkeypatch.setattr(asyncio, "open_connection", fake_open)  # type: ignore[attr-defined]
    try:

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await phase1_relay.forward(reader, writer, 8080)

        proxy = await asyncio.start_server(handle, "127.0.0.1", 0)
        proxy_port = proxy.sockets[0].getsockname()[1]
        reader, writer = await real_open("127.0.0.1", proxy_port)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        body = await reader.read()
        assert b"200 OK" in body and body.endswith(b"hello")
        writer.close()
        await writer.wait_closed()
        proxy.close()
        await proxy.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
