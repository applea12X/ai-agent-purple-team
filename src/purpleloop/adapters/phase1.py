from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from types import MappingProxyType
from urllib.parse import urljoin, urlsplit

import httpx

from purpleloop.adapters.base import Adapter, AdapterResult
from purpleloop.adapters.offline_model import OfflineModelStore
from purpleloop.control.phase1_tools import PHASE1_TOOLS, ChatArgs, ChatResult
from purpleloop.control.tools import ToolRegistry
from purpleloop.schemas.action import ActionRequest, TargetObservation

Authorize = Callable[[TargetObservation], Awaitable[None]]


class HttpAdapter:
    name = "http"

    def __init__(
        self,
        *,
        transports: Mapping[int, httpx.ASGITransport] | None = None,
        timeout: float = 2.0,
        max_bytes: int = 262144,
        tools: ToolRegistry = PHASE1_TOOLS,
    ) -> None:
        self.transports = dict(transports or {})
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.tools = tools

    async def preflight(self, action: ActionRequest) -> None:
        self.tools.require(action)
        if urlsplit(action.target.url).scheme != "http":
            raise ValueError("Phase 1 fixture transport is HTTP only")

    async def execute(
        self, action: ActionRequest, *, credential: str | None, authorize_target: Authorize
    ) -> AdapterResult:
        started = time.monotonic()
        async with asyncio.timeout(self.timeout):
            url = action.target.url
            for hop in range(4):
                if hop >= action.budget.requests:
                    raise ValueError("redirect request budget exhausted")
                parts = urlsplit(url)
                port = parts.port or 80
                host = parts.hostname or ""
                observations = await asyncio.get_running_loop().getaddrinfo(
                    host, port, type=socket.SOCK_STREAM
                )
                addresses = tuple(sorted({str(item[4][0]) for item in observations}))
                await authorize_target(
                    TargetObservation(
                        url=url,
                        resolved_addresses=tuple(ipaddress.ip_address(a) for a in addresses),
                        hop_index=hop,
                    )
                )
                headers = {
                    "Authorization": f"Bearer {credential}",
                    "Idempotency-Key": action.idempotency_key,
                    "Host": f"{host}:{port}",
                    "Content-Type": "application/json",
                    "Connection": "close",
                }
                body = (
                    json.dumps(action.arguments or {}).encode() if action.method != "GET" else b""
                )
                if port in self.transports:
                    async with httpx.AsyncClient(
                        transport=self.transports[port], follow_redirects=False, trust_env=False
                    ) as client:
                        response = await client.request(
                            action.method, url, headers=headers, content=body
                        )
                        status, response_headers, content = (
                            response.status_code,
                            dict(response.headers),
                            response.content,
                        )
                else:
                    status, response_headers, content = await self._request(
                        addresses[0], port, parts.path or "/", action.method, headers, body
                    )
                if len(content) > self.max_bytes:
                    raise ValueError("response limit exceeded")
                if status in {301, 302, 303, 307, 308}:
                    if action.method != "GET" or "location" not in response_headers:
                        raise ValueError("write redirects or missing location forbidden")
                    url = urljoin(url, response_headers["location"])
                    continue
                if status != 200:
                    raise ValueError(f"fixture transport status {status}")
                definition = self.tools.require(action)
                assert definition.output_model is not None
                result = definition.output_model.model_validate_json(content)
                return AdapterResult(
                    status="ok",
                    data=result.model_dump(mode="json"),
                    latency_ms=(time.monotonic() - started) * 1000,
                )
            raise ValueError("redirect limit exceeded")

    async def _request(
        self, address: str, port: int, path: str, method: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        # Connect to the exact authorized IP, never resolve the hostname a second time.
        reader, writer = await asyncio.open_connection(address, port, limit=16384)
        try:
            headers["Content-Length"] = str(len(body))
            request = (
                f"{method} {path} HTTP/1.1\r\n"
                + "".join(f"{key}: {value}\r\n" for key, value in headers.items())
                + "\r\n"
            )
            writer.write(request.encode("ascii") + body)
            await writer.drain()
            raw_headers = await reader.readuntil(b"\r\n\r\n")
            lines = raw_headers.decode("ascii").split("\r\n")
            status = int(lines[0].split()[1])
            response_headers: dict[str, str] = {}
            for line in lines[1:]:
                if line:
                    key, value = line.split(":", 1)
                    if key.lower() in response_headers:
                        raise ValueError("ambiguous response headers")
                    response_headers[key.lower()] = value.strip()
            length = int(response_headers.get("content-length", "-1"))
            if "transfer-encoding" in response_headers or not 0 <= length <= self.max_bytes:
                raise ValueError("unbounded response framing")
            return status, response_headers, await reader.readexactly(length)
        finally:
            writer.close()
            await writer.wait_closed()

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        definition = self.tools.require(action)
        assert definition.output_model is not None
        definition.output_model.model_validate(result.data)
        return True

    async def cancel(self) -> None:
        pass  # All socket activity belongs to the runtime's cancellable task.


class ToolAdapter(HttpAdapter):
    name = "tool"


class ChatAdapter:
    name = "chat"

    def __init__(self, store: OfflineModelStore) -> None:
        self.store = store

    async def preflight(self, action: ActionRequest) -> None:
        PHASE1_TOOLS.require(action)

    async def execute(
        self, action: ActionRequest, *, credential: str | None, authorize_target: Authorize
    ) -> AdapterResult:
        args = ChatArgs.model_validate(action.arguments)
        response = self.store.complete(
            model="offline", profile="deterministic", request=args.model_dump(mode="json")
        )
        parsed = json.loads(response.response)
        result = ChatResult.model_validate(
            {
                **parsed,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
            }
        )
        return AdapterResult(status="ok", data=result.model_dump(mode="json"), latency_ms=0)

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        ChatResult.model_validate(result.data)
        return True

    async def cancel(self) -> None:
        pass


class AdapterRegistry:
    """Immutable dispatch; adapter selection comes only from an admitted ActionRequest."""

    name = "registry"

    def __init__(
        self,
        registrations: tuple[tuple[str, str, Adapter], ...],
        *,
        tools: ToolRegistry = PHASE1_TOOLS,
    ) -> None:
        table = {(name, operation): adapter for name, operation, adapter in registrations}
        if len(table) != len(registrations):
            raise ValueError("duplicate adapter registration")
        self._adapters = MappingProxyType(table)
        self.tools = tools

    def require(self, action: ActionRequest) -> Adapter:
        self.tools.require(action)
        try:
            return self._adapters[(action.adapter, action.operation)]
        except KeyError as exc:
            raise ValueError("adapter not registered") from exc

    async def preflight(self, action: ActionRequest) -> None:
        await self.require(action).preflight(action)

    async def execute(
        self, action: ActionRequest, *, credential: str | None, authorize_target: Authorize
    ) -> AdapterResult:
        return await self.require(action).execute(
            action, credential=credential, authorize_target=authorize_target
        )

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        return await self.require(action).postcondition(action, result)

    async def cancel(self) -> None:
        for adapter in self._adapters.values():
            await adapter.cancel()
