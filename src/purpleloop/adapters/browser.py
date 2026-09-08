"""Browser adapter: typed flows under the same authority as every other adapter.

The adapter never selects a target. It executes a registered flow whose typed steps resolve
from the signed asset in the admitted action, authorizes every document hop and subresource
origin through the runtime's target guard before the request happens, bounds time and output,
redacts artifacts, and kills the browser in its ``finally`` path.

Two drivers implement the same session protocol:

* :class:`HtmlFormDriver` renders the fixture's server-side HTML in process through an ASGI
  transport, parses forms, and submits them. It has no browser process and is exact.
* :class:`PlaywrightDriver` drives pinned Chromium through Playwright with route-level
  interception. It reports its own replay numbers because a browser is not bit-reproducible.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import io
import ipaddress
import time
import zipfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlencode, urljoin, urlsplit

import httpx

from purpleloop.adapters.base import AdapterResult, SubresourceDenied
from purpleloop.control.phase2_tools import (
    CONTROLS,
    FIELDS,
    FLOWS,
    PAGES,
    REGIONS,
    SUPPORTLAB_TOOLS,
    Flow,
    OperationResult,
)
from purpleloop.control.tools import ToolRegistry
from purpleloop.schemas.action import ActionRequest, TargetObservation
from purpleloop.schemas.phase2 import BrowserArtifact

Authorize = Callable[[TargetObservation], Awaitable[None]]
OriginAuthorize = Callable[[str, str], Awaitable[bool]]
SESSION_COOKIE = "supportlab_session"
REDACTED = b"[REDACTED]"
VIEWPORT = {"width": 1280, "height": 800}
LOCALE = "en-US"
TIMEZONE = "UTC"
FROZEN_TIME = "2026-01-01T00:00:00Z"


class BrowserSession(Protocol):
    async def navigate(self, url: str) -> None: ...

    async def fill(self, selector: str, value: str) -> None: ...

    async def click(self, selector: str) -> None: ...

    async def read(self, selector: str) -> str: ...

    async def artifacts(self, directory: Path) -> list[tuple[str, Path]]: ...

    async def close(self) -> None: ...


class BrowserDriver(Protocol):
    name: str

    async def open(
        self,
        *,
        origin: str,
        cookie: tuple[str, str],
        headers: Mapping[str, str],
        authorize: OriginAuthorize,
        deadline: float,
    ) -> BrowserSession: ...

    async def shutdown(self) -> None: ...

    @property
    def alive(self) -> bool: ...

    def version(self) -> dict[str, str]: ...


def redact_bytes(payload: bytes, secrets: Sequence[str]) -> bytes:
    for secret in secrets:
        if secret:
            payload = payload.replace(secret.encode("utf-8"), REDACTED)
    return payload


def redact_zip(path: Path, secrets: Sequence[str]) -> None:
    """Rewrite every entry of a trace ZIP with secrets replaced. Entry order is preserved."""
    with zipfile.ZipFile(path) as source:
        entries = [(item, source.read(item.filename)) for item in source.infolist()]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for item, payload in entries:
            target.writestr(item.filename, redact_bytes(payload, secrets))
    path.write_bytes(buffer.getvalue())


def coerce(text: str, value_type: str) -> Any:
    stripped = text.strip()
    if value_type == "int":
        return int(stripped)
    if value_type == "bool":
        if stripped not in {"true", "false"}:
            raise ValueError("region is not a boolean")
        return stripped == "true"
    return stripped


class BrowserAdapter:
    name = "browser"

    def __init__(
        self,
        driver: BrowserDriver,
        *,
        artifact_root: Path,
        tools: ToolRegistry = SUPPORTLAB_TOOLS,
        flows: Mapping[str, Flow] = FLOWS,
        secrets: Sequence[str] = (),
        timeout: float = 20.0,
        max_text: int = 4096,
    ) -> None:
        self.driver = driver
        self.artifact_root = artifact_root
        self.tools = tools
        self.flows = flows
        self.secrets = tuple(secrets)
        self.timeout = timeout
        self.max_text = max_text
        self.contexts_opened = 0
        self.blocked_subresources = 0
        self._artifacts: list[BrowserArtifact] = []
        self._active: set[BrowserSession] = set()

    @property
    def driver_name(self) -> str:
        return self.driver.name

    @property
    def artifacts(self) -> tuple[BrowserArtifact, ...]:
        return tuple(self._artifacts)

    async def preflight(self, action: ActionRequest) -> None:
        self.tools.require(action)
        parts = urlsplit(action.target.url)
        if parts.scheme != "http":
            raise ValueError("browser fixture transport is HTTP only")
        if action.operation not in self.flows:
            raise ValueError("browser operation is not a registered flow")

    async def execute(
        self, action: ActionRequest, *, credential: str | None, authorize_target: Authorize
    ) -> AdapterResult:
        if credential is None:
            raise ValueError("browser flows require an actor credential")
        started = time.monotonic()
        flow = self.flows[action.operation]
        steps = flow.expand(action.arguments or {}, action.target.resource_id)
        parts = urlsplit(action.target.url)
        origin = f"{parts.scheme}://{parts.hostname}:{parts.port or 80}"
        hop = 0

        async def authorize(url: str, kind: str) -> bool:
            nonlocal hop
            host = urlsplit(url).hostname or ""
            try:
                address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(host)
            except ValueError:
                address = ipaddress.IPv4Address("0.0.0.0")  # noqa: S104 -- unresolved marker, never connected to
            observation = TargetObservation(
                url=url,
                resolved_addresses=(address,),
                hop_index=hop if kind == "document" else 0,
                kind="document" if kind == "document" else "subresource",
            )
            try:
                await authorize_target(observation)
            except SubresourceDenied:
                self.blocked_subresources += 1
                return False
            if kind == "document":
                hop += 1
            return True

        self.contexts_opened += 1
        ordinal = self.contexts_opened
        session = await self.driver.open(
            origin=origin,
            cookie=(SESSION_COOKIE, credential),
            headers={"Idempotency-Key": action.idempotency_key},
            authorize=authorize,
            deadline=self.timeout,
        )
        self._active.add(session)
        value: dict[str, Any] = {}
        executed: list[dict[str, Any]] = []
        killed = False
        try:
            async with asyncio.timeout(self.timeout):
                for step in steps:
                    if step.kind == "navigate":
                        page = PAGES[step.page]
                        path = page.path_template.format(resource_id=step.resource_id or "")
                        await session.navigate(f"{origin}{path}")
                    elif step.kind == "fill":
                        await session.fill(FIELDS[step.field].selector, step.value)
                    elif step.kind == "click":
                        await session.click(CONTROLS[step.control].selector)
                    else:
                        region = REGIONS[step.region]
                        text = await session.read(region.selector)
                        if len(text) > self.max_text:
                            raise ValueError("region text exceeds the output bound")
                        assert region.result_key is not None
                        # An empty region means the page withheld the value (a denied page). Leave
                        # the key absent so the browser result matches the API's empty value.
                        if text.strip():
                            value[region.result_key] = coerce(text, region.value_type)
                    executed.append(step.model_dump(mode="json"))
                outcome = value.pop("outcome", None)
                if outcome not in {"ok", "denied"}:
                    raise ValueError("page did not report a typed outcome")
                directory = self.artifact_root / f"{ordinal:02d}-{action.action_id}"
                directory.mkdir(parents=True, exist_ok=True)
                produced = await session.artifacts(directory)
        except asyncio.CancelledError:
            killed = True
            raise
        finally:
            self._active.discard(session)
            await asyncio.shield(session.close())
            if killed:
                # Emergency stop: the browser process itself dies with the cancelled action.
                await asyncio.shield(self.driver.shutdown())
        paths = self._record_artifacts(action.action_id, produced, (credential, *self.secrets))
        result = OperationResult(outcome=outcome, value=value)
        return AdapterResult(
            status="ok",
            data={
                **result.model_dump(mode="json"),
                "steps": executed,
                "artifacts": paths,
                "driver": self.driver.name,
                "blocked_subresources": self.blocked_subresources,
            },
            latency_ms=(time.monotonic() - started) * 1000,
        )

    def _record_artifacts(
        self, action_id: str, produced: list[tuple[str, Path]], secrets: Sequence[str]
    ) -> list[str]:
        paths: list[str] = []
        for kind, path in produced:
            if kind == "trace":
                redact_zip(path, secrets)
            elif kind == "html":
                path.write_bytes(redact_bytes(path.read_bytes(), secrets))
            relative = path.relative_to(self.artifact_root.parent).as_posix()
            self._artifacts.append(
                BrowserArtifact(
                    action_id=action_id,
                    driver=self.driver.name,
                    kind=kind,  # type: ignore[arg-type]
                    path=relative,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
            paths.append(relative)
        return paths

    async def postcondition(self, action: ActionRequest, result: AdapterResult) -> bool:
        definition = self.tools.require(action)
        assert definition.output_model is not None
        payload = {key: result.data[key] for key in ("outcome", "value")}
        definition.output_model.model_validate(payload)
        extras = set(result.data) - {
            "outcome",
            "value",
            "steps",
            "artifacts",
            "driver",
            "blocked_subresources",
        }
        return not extras

    async def cancel(self) -> None:
        for session in tuple(self._active):
            await session.close()
        self._active.clear()
        await self.driver.shutdown()

    async def shutdown(self) -> None:
        await self.cancel()


# --- in-process HTML form driver ----------------------------------------------------------


@dataclass
class Node:
    tag: str
    attrs: dict[str, str]
    parent: Node | None
    children: list[Node] = field(default_factory=list)
    text: list[str] = field(default_factory=list)

    def inner_text(self) -> str:
        parts = list(self.text)
        for child in self.children:
            parts.append(child.inner_text())
        return "".join(parts)


VOID_TAGS = frozenset({"input", "meta", "link", "img", "br", "hr"})


class _TreeBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("document", {}, None)
        self.current = self.root
        self.by_id: dict[str, Node] = {}
        self.subresources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = Node(tag, {key: value or "" for key, value in attrs}, self.current)
        self.current.children.append(node)
        if "id" in node.attrs:
            self.by_id[node.attrs["id"]] = node
        if tag == "img" and node.attrs.get("src"):
            self.subresources.append(node.attrs["src"])
        if tag == "link" and node.attrs.get("href"):
            self.subresources.append(node.attrs["href"])
        if tag not in VOID_TAGS:
            self.current = node

    def handle_endtag(self, tag: str) -> None:
        node: Node | None = self.current
        while node is not None and node.tag != tag:
            node = node.parent
        if node is not None and node.parent is not None:
            self.current = node.parent

    def handle_data(self, data: str) -> None:
        self.current.text.append(data)


@dataclass
class ParsedPage:
    url: str
    html: str
    tree: _TreeBuilder

    def element(self, selector: str) -> Node:
        if not selector.startswith("#") or len(selector) < 2:
            raise ValueError("only registered id selectors are supported")
        node = self.tree.by_id.get(selector[1:])
        if node is None:
            raise ValueError(f"element not found: {selector}")
        return node


class HtmlFormDriver:
    """Exact, in-process page driver over the fixture's ASGI apps."""

    name = "html-form"

    def __init__(
        self, transports: Mapping[int, httpx.ASGITransport], *, max_bytes: int = 262144
    ) -> None:
        self.transports = dict(transports)
        self.max_bytes = max_bytes
        self.sessions = 0
        self._alive = True

    async def open(
        self,
        *,
        origin: str,
        cookie: tuple[str, str],
        headers: Mapping[str, str],
        authorize: OriginAuthorize,
        deadline: float,
    ) -> HtmlFormSession:
        self.sessions += 1
        self._alive = True
        return HtmlFormSession(self, origin, cookie, dict(headers), authorize)

    async def shutdown(self) -> None:
        self._alive = False

    @property
    def alive(self) -> bool:
        return self._alive

    def version(self) -> dict[str, str]:
        return {"driver": self.name, "engine": "html.parser"}


class HtmlFormSession:
    def __init__(
        self,
        driver: HtmlFormDriver,
        origin: str,
        cookie: tuple[str, str],
        headers: dict[str, str],
        authorize: OriginAuthorize,
    ) -> None:
        self.driver = driver
        self.origin = origin
        self.cookie = cookie
        self.headers = headers
        self.authorize = authorize
        self.page: ParsedPage | None = None
        self.form_values: dict[str, str] = {}
        self.closed = False

    async def _request(
        self, method: str, url: str, body: bytes = b"", content_type: str | None = None
    ) -> None:
        for _ in range(5):
            await self.authorize(url, "document")
            parts = urlsplit(url)
            port = parts.port or 80
            transport = self.driver.transports.get(port)
            if transport is None:
                raise ValueError("no transport for the authorized origin")
            headers = {**self.headers, "Cookie": f"{self.cookie[0]}={self.cookie[1]}"}
            if content_type:
                headers["Content-Type"] = content_type
            async with httpx.AsyncClient(
                transport=transport, follow_redirects=False, trust_env=False
            ) as client:
                response = await client.request(method, url, headers=headers, content=body)
            if len(response.content) > self.driver.max_bytes:
                raise ValueError("page exceeds the response bound")
            if response.status_code in {301, 302, 303, 307, 308}:
                url = urljoin(url, response.headers.get("location", ""))
                method, body, content_type = "GET", b"", None
                continue
            if response.status_code != 200:
                raise ValueError(f"page status {response.status_code}")
            builder = _TreeBuilder()
            builder.feed(response.text)
            self.page = ParsedPage(url, response.text, builder)
            self.form_values = {}
            for reference in builder.subresources:
                target = urljoin(url, reference)
                if await self.authorize(target, "subresource"):
                    sub_port = urlsplit(target).port or 80
                    sub_transport = self.driver.transports.get(sub_port)
                    if sub_transport is not None:
                        async with httpx.AsyncClient(
                            transport=sub_transport, trust_env=False
                        ) as client:
                            await client.get(target, headers=headers)
            return
        raise ValueError("redirect limit exceeded")

    async def navigate(self, url: str) -> None:
        await self._request("GET", url)

    async def fill(self, selector: str, value: str) -> None:
        assert self.page is not None
        node = self.page.element(selector)
        if node.tag != "input" or not node.attrs.get("name"):
            raise ValueError("fill target is not a named input")
        self.form_values[node.attrs["name"]] = value

    async def click(self, selector: str) -> None:
        assert self.page is not None
        node = self.page.element(selector)
        form = node.parent
        while form is not None and form.tag != "form":
            form = form.parent
        if node.tag != "button" or form is None:
            raise ValueError("click target is not a form submit control")
        fields: dict[str, str] = {}

        def collect(item: Node) -> None:
            if item.tag == "input" and item.attrs.get("name"):
                fields[item.attrs["name"]] = item.attrs.get("value", "")
            for child in item.children:
                collect(child)

        collect(form)
        fields.update(self.form_values)
        action = urljoin(self.page.url, form.attrs.get("action", self.page.url))
        method = form.attrs.get("method", "get").upper()
        await self._request(
            method, action, urlencode(fields).encode(), "application/x-www-form-urlencoded"
        )

    async def read(self, selector: str) -> str:
        assert self.page is not None
        return self.page.element(selector).inner_text()

    async def artifacts(self, directory: Path) -> list[tuple[str, Path]]:
        if self.page is None:
            return []
        path = directory / "page.html"
        path.write_text(self.page.html, encoding="utf-8")
        return [("html", path)]

    async def close(self) -> None:
        self.closed = True


# --- Playwright driver -------------------------------------------------------------------------


class PlaywrightDriver:  # pragma: no cover - browser lane
    """Pinned Chromium through Playwright. Only the browser lane exercises this class."""

    name = "playwright-chromium"

    def __init__(self, *, headless: bool = True) -> None:
        self.headless = headless
        self._playwright: Any = None
        self._browser: Any = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        async with self._lock:
            if self._browser is not None and self._browser.is_connected():
                return
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.headless)

    @property
    def alive(self) -> bool:
        return bool(self._browser is not None and self._browser.is_connected())

    def version(self) -> dict[str, str]:
        from importlib.metadata import version as package_version

        return {
            "driver": self.name,
            "playwright": package_version("playwright"),
            "chromium": str(self._browser.version) if self._browser is not None else "not-started",
        }

    async def open(
        self,
        *,
        origin: str,
        cookie: tuple[str, str],
        headers: Mapping[str, str],
        authorize: OriginAuthorize,
        deadline: float,
    ) -> PlaywrightSession:
        await self.start()
        context = await self._browser.new_context(
            viewport=VIEWPORT,
            locale=LOCALE,
            timezone_id=TIMEZONE,
            accept_downloads=False,
            reduced_motion="reduce",
            java_script_enabled=False,
            storage_state=None,
        )
        await context.clock.install(time=FROZEN_TIME)
        await context.add_cookies([{"name": cookie[0], "value": cookie[1], "url": origin}])
        await context.set_extra_http_headers(dict(headers))
        await context.tracing.start(screenshots=True, snapshots=True)
        page = await context.new_page()
        session = PlaywrightSession(context, page, authorize, deadline)
        await context.route("**/*", session.route)
        return session

    async def shutdown(self) -> None:
        async with self._lock:
            browser, playwright = self._browser, self._playwright
            self._browser = self._playwright = None
        if browser is not None:
            await browser.close()
        if playwright is not None:
            await playwright.stop()


class PlaywrightSession:  # pragma: no cover - browser lane
    def __init__(
        self, context: Any, page: Any, authorize: OriginAuthorize, deadline: float
    ) -> None:
        self.context = context
        self.page = page
        self.authorize = authorize
        self.timeout_ms = int(deadline * 1000)
        self.fatal: BaseException | None = None
        self.closed = False

    async def route(self, route: Any, request: Any) -> None:
        kind = (
            "document"
            if request.is_navigation_request() and request.frame == self.page.main_frame
            else "subresource"
        )
        try:
            allowed = await self.authorize(request.url, kind)
        except BaseException as exc:
            # A guard failure inside a route handler must surface through the flow itself.
            self.fatal = exc
            await route.abort("blockedbyclient")
            return
        if allowed:
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    def _raise_fatal(self) -> None:
        if self.fatal is not None:
            fatal, self.fatal = self.fatal, None
            raise fatal

    async def navigate(self, url: str) -> None:
        from playwright.async_api import Error

        try:
            response = await self.page.goto(url, wait_until="load", timeout=self.timeout_ms)
        except Error:
            self._raise_fatal()
            raise
        self._raise_fatal()
        if response is None or response.status != 200:
            raise ValueError(f"page status {response.status if response else 'none'}")

    async def fill(self, selector: str, value: str) -> None:
        await self.page.fill(selector, value, timeout=self.timeout_ms)

    async def click(self, selector: str) -> None:
        from playwright.async_api import Error

        try:
            await self.page.click(selector, timeout=self.timeout_ms)
            await self.page.wait_for_load_state("load", timeout=self.timeout_ms)
        except Error:
            self._raise_fatal()
            raise
        self._raise_fatal()

    async def read(self, selector: str) -> str:
        locator = self.page.locator(selector)
        await locator.wait_for(state="attached", timeout=self.timeout_ms)
        return str(await locator.inner_text(timeout=self.timeout_ms))

    async def artifacts(self, directory: Path) -> list[tuple[str, Path]]:
        screenshot = directory / "screenshot.png"
        trace = directory / "trace.zip"
        await self.page.screenshot(path=str(screenshot), full_page=True)
        await self.context.tracing.stop(path=str(trace))
        return [("screenshot", screenshot), ("trace", trace)]

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        with contextlib.suppress(Exception):
            # The browser may already be gone after an emergency stop.
            await self.context.close()
