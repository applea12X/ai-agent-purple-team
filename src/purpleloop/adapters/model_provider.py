"""Model-plane client: the only path in the project that reaches a model.

Three properties matter here and each is enforced rather than described.

*It is not plan-addressable.* A model endpoint is never a signed target asset, so no compiled
action can aim at one. Only a trusted collaborator inside an adapter can raise a model call, and
the endpoint is authorized through the runtime's ``authorize_target`` -- with ``kind="model"`` --
before any connection is opened.

*There is no fallback.* A networked profile that cannot resolve its credential raises. It never
quietly answers from the offline store, because a silent downgrade would report a network result
as a deterministic one. ``tests/phase3`` asserts no such path exists.

*Consumption is charged, not counted afterwards.* Tokens and cost go through the same
``BudgetLedger`` as every other resource, inside the enclosing action's reservation, so exhausting
a cap fails the action closed instead of being noticed at the end of the run.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from purpleloop.adapters.base import Authorize
from purpleloop.adapters.offline_model import OfflineModelStore
from purpleloop.control.budgets import BudgetLedger
from purpleloop.schemas.action import BudgetRequest, TargetObservation
from purpleloop.schemas.common import digest_data
from purpleloop.schemas.phase3 import ModelCallRecord, ModelPin, ProviderProfile


class ModelUnavailable(RuntimeError):
    reason_code = "MODEL_PROVIDER_UNAVAILABLE"


class ModelCredentialMissing(ModelUnavailable):
    reason_code = "MODEL_CREDENTIAL_MISSING"


class ModelResponseInvalid(RuntimeError):
    reason_code = "MODEL_RESPONSE_INVALID"


@dataclass(frozen=True)
class Completion:
    """One model response, with everything the evidence record needs."""

    text: str
    record: ModelCallRecord


class Provider(Protocol):
    profile: ProviderProfile

    async def complete(
        self, *, pin: ModelPin, system: str, prompt: str, deadline: float
    ) -> tuple[str, int, int]:
        """Return ``(text, input_tokens, output_tokens)``."""
        ...

    @property
    def endpoint(self) -> str | None:
        """The origin this provider connects to, or ``None`` when it makes no network call."""
        ...


class OfflineProvider:
    """Deterministic fixture responses. Makes no network call and has no endpoint."""

    profile: ProviderProfile = "offline"

    def __init__(self, store: OfflineModelStore) -> None:
        self.store = store

    @property
    def endpoint(self) -> str | None:
        return None

    async def complete(
        self, *, pin: ModelPin, system: str, prompt: str, deadline: float
    ) -> tuple[str, int, int]:
        response = self.store.complete(
            model=pin.model_id,
            profile="deterministic",
            request={"system": system, "prompt": prompt},
        )
        return response.response, response.input_tokens, response.output_tokens


class OpenAICompatibleProvider:  # pragma: no cover - stochastic lane only
    """OpenAI-compatible chat completions, covering configured APIs, Ollama, and vLLM.

    The three profiles differ only in base URL and whether a credential is required, so they share
    one implementation rather than three that can drift apart.
    """

    def __init__(
        self,
        *,
        base_url: str,
        credential: str | None,
        profile: ProviderProfile = "openai-compatible",
        transport: httpx.AsyncBaseTransport | None = None,
        max_output_chars: int = 16384,
    ) -> None:
        if profile == "offline":
            raise ValueError("the offline profile is not a network provider")
        if profile == "openai-compatible" and not credential:
            # Ollama and vLLM are commonly unauthenticated on a local socket; a hosted API is not.
            raise ModelCredentialMissing("a hosted model API requires a broker-held credential")
        self.profile: ProviderProfile = profile
        self.base_url = base_url.rstrip("/")
        self._credential = credential
        self._transport = transport
        self.max_output_chars = max_output_chars

    @property
    def endpoint(self) -> str | None:
        parts = urlsplit(self.base_url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return f"{parts.scheme}://{parts.hostname}:{port}"

    async def complete(
        self, *, pin: ModelPin, system: str, prompt: str, deadline: float
    ) -> tuple[str, int, int]:
        payload: dict[str, Any] = {
            "model": pin.model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": pin.decoding.temperature,
            "top_p": pin.decoding.top_p,
            "max_tokens": pin.decoding.max_output_tokens,
            "stream": False,
        }
        if pin.decoding.seed is not None:
            payload["seed"] = pin.decoding.seed
        headers = {"Content-Type": "application/json"}
        if self._credential:
            headers["Authorization"] = f"Bearer {self._credential}"
        async with httpx.AsyncClient(
            timeout=deadline, transport=self._transport, follow_redirects=False
        ) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
        if response.is_redirect:
            # A model endpoint that redirects is a denial, not a hop: following it would reach an
            # origin the manifest never signed.
            raise ModelUnavailable("model endpoint attempted a redirect")
        if response.status_code >= 400:
            raise ModelUnavailable(f"model endpoint returned {response.status_code}")
        try:
            body = response.json()
            text = str(body["choices"][0]["message"]["content"])
            usage = body.get("usage") or {}
            input_tokens = int(usage.get("prompt_tokens", 0))
            output_tokens = int(usage.get("completion_tokens", 0))
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelResponseInvalid("model response did not match the expected shape") from exc
        return text[: self.max_output_chars], input_tokens, output_tokens


class ModelClient:
    """Resolves a pin to a provider, authorizes the endpoint, and charges what it costs."""

    def __init__(
        self,
        *,
        pins: Sequence[ModelPin],
        providers: Mapping[ProviderProfile, Provider],
        budgets: BudgetLedger,
        timeout: float = 30.0,
        max_output_chars: int = 16384,
    ) -> None:
        self._pins = {pin.pin_id: pin for pin in pins}
        if len(self._pins) != len(pins):
            raise ValueError("model pin ids must be unique")
        self._providers = dict(providers)
        self.budgets = budgets
        self.timeout = timeout
        self.max_output_chars = max_output_chars
        self.calls = 0
        self.tokens = 0
        self.cost_microusd = 0
        self.records: list[ModelCallRecord] = []

    def pin(self, pin_id: str) -> ModelPin:
        try:
            return self._pins[pin_id]
        except KeyError as exc:
            raise ModelUnavailable(f"model pin is not authorized: {pin_id}") from exc

    async def _authorize(self, provider: Provider, authorize_target: Authorize) -> None:
        endpoint = provider.endpoint
        if endpoint is None:
            return
        parts = urlsplit(endpoint)
        host, port = parts.hostname or "", parts.port or 0
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = tuple(
            sorted({ipaddress.ip_address(str(info[4][0])) for info in infos}, key=str)
        )
        await authorize_target(
            TargetObservation(url=endpoint, resolved_addresses=addresses, hop_index=0, kind="model")
        )

    async def complete(
        self, *, pin_id: str, system: str, prompt: str, authorize_target: Authorize
    ) -> Completion:
        pin = self.pin(pin_id)
        provider = self._providers.get(pin.provider)
        if provider is None:
            raise ModelUnavailable(f"no provider is configured for profile {pin.provider}")
        await self._authorize(provider, authorize_target)
        async with asyncio.timeout(self.timeout):
            text, input_tokens, output_tokens = await provider.complete(
                pin=pin, system=system, prompt=prompt, deadline=self.timeout
            )
        text = text[: self.max_output_chars]
        cost = pin.cost_microusd(input_tokens, output_tokens)
        # Charged inside the enclosing reservation, so a cap breach fails this action closed
        # rather than surfacing as an accounting discrepancy after the run.
        await self.budgets.charge(
            BudgetRequest(
                requests=0, records=0, tokens=input_tokens + output_tokens, cost_microusd=cost
            )
        )
        record = ModelCallRecord(
            pin_id=pin.pin_id,
            provider=pin.provider,
            model_id=pin.model_id,
            model_version=pin.model_version,
            decoding=pin.decoding,
            system_prompt_hash=pin.system_prompt_hash,
            prompt_digest=digest_data({"system": system, "prompt": prompt}),
            response_digest=digest_data(text),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_microusd=cost,
            reproducible_pin=pin.reproducible,
        )
        self.calls += 1
        self.tokens += input_tokens + output_tokens
        self.cost_microusd += cost
        self.records.append(record)
        return Completion(text=text, record=record)
