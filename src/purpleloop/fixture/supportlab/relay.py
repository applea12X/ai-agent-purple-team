"""Fixed-destination ingress for supportlab, mirroring the Phase 1 relay.

The untrusted fixture and its database sit on an internal-only network. This stateless trusted
relay owns the loopback publications and cannot be instructed to choose a different backend or
port: the destination host and ports are compile-time constants, never environment or request
controlled.
"""

from __future__ import annotations

import asyncio

BACKEND = "supportlab-fixture"
DATA_PORT = 8080
CONTROL_PORT = 8081


async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> None:
    upstream: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(5):
            incoming, upstream = await asyncio.open_connection(BACKEND, port)

            async def pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
                remaining = 1048576
                while remaining:
                    chunk = await source.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    destination.write(chunk)
                    await destination.drain()
                if destination.can_write_eof():
                    destination.write_eof()

            await asyncio.gather(pipe(reader, upstream), pipe(incoming, writer))
    except (OSError, TimeoutError):
        writer.close()
    finally:
        writer.close()
        if upstream is not None:
            upstream.close()
        await writer.wait_closed()


async def serve() -> None:
    async def data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await forward(reader, writer, DATA_PORT)

    async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await forward(reader, writer, CONTROL_PORT)

    servers = [
        await asyncio.start_server(handler, "0.0.0.0", port)  # noqa: S104 -- loopback-published ingress
        for handler, port in ((data, DATA_PORT), (control, CONTROL_PORT))
    ]
    try:
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(serve())
