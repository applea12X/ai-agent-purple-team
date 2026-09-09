"""The model plane's runtime enforcement (ADR 0008), and the model client's contract behaviour.

Until these tests existed the two-plane split was enforced at the schema boundary and asserted in
prose, but its *runtime* path had never executed: the offline provider reports no endpoint, so
``ModelClient._authorize`` returned immediately and ``SafetyRuntime.authorize_model`` was never
reached by any test. The phase's headline security claim was therefore an assertion about code
rather than a measured fact. These tests execute that path.
"""

from __future__ import annotations

import asyncio
import json
from ipaddress import IPv4Address
from typing import Any

import httpx
import pytest

from purpleloop.adapters.base import AdapterResult
from purpleloop.adapters.model_provider import (
    Completion,
    ModelClient,
    ModelCredentialMissing,
    ModelResponseInvalid,
    ModelUnavailable,
    OfflineProvider,
    OpenAICompatibleProvider,
)
from purpleloop.adapters.offline_model import OfflineModelStore
from purpleloop.control.budgets import BudgetError, BudgetLedger
from purpleloop.control.lanes import AGENT_LANE
from purpleloop.control.plan_compiler import compile_step
from purpleloop.schemas.action import BudgetRequest, TargetObservation
from purpleloop.schemas.authorization import BudgetLimits
from purpleloop.schemas.event import EventKind
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin

DIGEST = "a" * 64
SIGNED_ENDPOINT = "http://127.0.0.1:11434"


def pin(**overrides: Any) -> ModelPin:
    fields: dict[str, Any] = {
        "pin_id": "networked",
        "provider": "ollama",
        "model_id": "synthetic",
        "model_version": "v1",
        "decoding": DecodingParameters(seed=7),
        "system_prompt_hash": DIGEST,
    }
    fields.update(overrides)
    return ModelPin(**fields)


# --- the runtime guard --------------------------------------------------------------------------


class _ModelPlaneAdapter:
    """A trusted collaborator raising a model observation, as ModelClient does."""

    name = "agent"

    def __init__(self, urls: list[str], addresses: tuple[IPv4Address, ...] | None = None) -> None:
        self.urls = urls
        self.addresses = addresses or (IPv4Address("127.0.0.1"),)
        self.results: list[str] = []

    async def preflight(self, action: Any) -> None:
        return None

    async def execute(
        self, action: Any, *, credential: str | None, authorize_target: Any
    ) -> AdapterResult:
        for url in self.urls:
            try:
                await authorize_target(
                    TargetObservation(
                        url=url, resolved_addresses=self.addresses, hop_index=0, kind="model"
                    )
                )
                self.results.append("permitted")
            except Exception as exc:  # noqa: BLE001 -- the reason code is what is under test
                self.results.append(str(getattr(exc, "reason_code", type(exc).__name__)))
        return AdapterResult(status="ok", data={"outcome": "ok", "value": {}}, latency_ms=0)

    async def postcondition(self, action: Any, result: AdapterResult) -> bool:
        return True

    async def cancel(self) -> None:
        return None


async def _drive(
    make_agent_runner: Any,
    agent_scenarios: Any,
    signing_key: Any,
    urls: list[str],
    *,
    addresses: tuple[IPv4Address, ...] | None = None,
    endpoint: str | None = SIGNED_ENDPOINT,
) -> tuple[_ModelPlaneAdapter, Any, Any]:
    from purpleloop.runtime.supportlab import supportlab_agent_manifest

    manifest = supportlab_agent_manifest(
        signing_key,
        seed=42,
        model_endpoint=endpoint,
        model_pin=pin() if endpoint else None,
    )
    scenario = next(s for s in agent_scenarios if s.scenario_id == "agent-indirect-ticket")
    action = compile_step(scenario.clean_steps[0], scenario, manifest, lane=AGENT_LANE)
    runner, _, _ = make_agent_runner(manifest=manifest)
    adapter = _ModelPlaneAdapter(urls, addresses)
    runner.runtime.adapter = adapter
    before = runner.runtime.budgets.used.requests
    await runner.runtime.run(manifest, action, run_id="model", trace_id="model")
    return adapter, runner, before


async def test_a_signed_model_origin_is_permitted_and_charged(
    make_agent_runner: Any, agent_scenarios: Any, signing_key: Any
) -> None:
    adapter, runner, before = await _drive(
        make_agent_runner, agent_scenarios, signing_key, [SIGNED_ENDPOINT]
    )
    assert adapter.results == ["permitted"]
    # Charged whether permitted or denied, so a model call is never free or unrecorded.
    assert runner.runtime.budgets.used.requests >= before + 1


async def test_an_unsigned_model_origin_is_denied(
    make_agent_runner: Any, agent_scenarios: Any, signing_key: Any
) -> None:
    adapter, runner, before = await _drive(
        make_agent_runner,
        agent_scenarios,
        signing_key,
        ["https://models.evil.invalid:443", SIGNED_ENDPOINT],
    )
    assert adapter.results[0] == "MODEL_ENDPOINT_NOT_SIGNED"
    assert adapter.results[1] == "permitted"
    # The denied attempt is charged too: a blocked call is paid for, not silently dropped.
    assert runner.runtime.budgets.used.requests >= before + 2


async def test_a_model_origin_that_resolves_onto_the_fixture_is_denied(
    make_agent_runner: Any, agent_scenarios: Any, signing_key: Any
) -> None:
    """A rebind aiming a model call at the target endpoint is refused after resolution."""
    from purpleloop.control.phase2_tools import DATA_PORT

    rebound = f"http://127.0.0.1:{DATA_PORT}"
    # The origin itself is unsigned, so it is refused on that ground first ...
    adapter, _, _ = await _drive(
        make_agent_runner, agent_scenarios, signing_key, [rebound], endpoint=SIGNED_ENDPOINT
    )
    assert adapter.results == ["MODEL_ENDPOINT_NOT_SIGNED"]

    # ... and a *signed* origin whose resolution lands on a signed target endpoint is refused on
    # the rebind ground, which is the case a DNS answer could actually create.
    signed_but_rebound = f"http://127.0.0.1:{DATA_PORT}"
    adapter2, _, _ = await _drive(
        make_agent_runner,
        agent_scenarios,
        signing_key,
        [signed_but_rebound],
        endpoint=signed_but_rebound,
    )
    assert adapter2.results == ["MODEL_ENDPOINT_RESOLVES_TO_TARGET"]


async def test_a_model_call_is_denied_when_no_model_plane_is_granted(
    make_agent_runner: Any, agent_scenarios: Any, signing_key: Any
) -> None:
    """The offline manifest authorizes no endpoint; the absence of the grant is the control."""
    adapter, _, _ = await _drive(
        make_agent_runner, agent_scenarios, signing_key, [SIGNED_ENDPOINT], endpoint=None
    )
    assert adapter.results == ["MODEL_ENDPOINT_NOT_SIGNED"]


async def test_the_model_decision_is_recorded_as_a_policy_event(
    make_agent_runner: Any, agent_scenarios: Any, signing_key: Any
) -> None:
    adapter, runner, _ = await _drive(
        make_agent_runner,
        agent_scenarios,
        signing_key,
        ["https://models.evil.invalid:443", SIGNED_ENDPOINT],
    )
    events = runner.runtime.ledger.verify()
    model_events = [
        e for e in events if e.kind == EventKind.POLICY and (e.data or {}).get("kind") == "model"
    ]
    assert len(model_events) == 2
    assert {e.decision for e in model_events} == {"deny", "permit"}
    assert all("resolved_addresses" in (e.data or {}) for e in model_events)


# --- the client's own contract ------------------------------------------------------------------


def _client(provider: Any, *, limits: BudgetLimits | None = None) -> ModelClient:
    return ModelClient(
        pins=(pin(pin_id="networked"), pin(pin_id="offline", provider="offline")),
        providers={provider.profile: provider},
        budgets=BudgetLedger(
            limits or BudgetLimits(requests=100, records=100, tokens=10_000, cost_microusd=10_000)
        ),
        timeout=2.0,
        max_output_chars=64,
    )


async def _authorize(observation: TargetObservation) -> None:
    assert observation.kind == "model"


def _transport(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _ok(payload: dict[str, Any] | None = None, status: int = 200) -> Any:
    body = (
        payload
        if payload is not None
        else {
            "choices": [{"message": {"content": "hello " * 40}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 3},
        }
    )
    return lambda request: httpx.Response(status, json=body)


def _networked(handler: Any, **kwargs: Any) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        base_url=f"{SIGNED_ENDPOINT}/v1",
        credential=kwargs.pop("credential", None),
        profile=kwargs.pop("profile", "ollama"),
        transport=_transport(handler),
        **kwargs,
    )


async def test_the_client_authorizes_the_endpoint_before_it_connects() -> None:
    seen: list[TargetObservation] = []

    async def capture(observation: TargetObservation) -> None:
        seen.append(observation)

    client = _client(_networked(_ok()))
    await client.complete(pin_id="networked", system="s", prompt="p", authorize_target=capture)
    assert len(seen) == 1
    assert seen[0].kind == "model" and seen[0].url == SIGNED_ENDPOINT
    assert seen[0].resolved_addresses  # resolution happened before the request


async def test_a_denied_endpoint_stops_the_call() -> None:
    calls: list[int] = []

    async def refuse(observation: TargetObservation) -> None:
        raise RuntimeError("MODEL_ENDPOINT_NOT_SIGNED")

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json={})

    client = _client(_networked(handler))
    with pytest.raises(RuntimeError, match="NOT_SIGNED"):
        await client.complete(pin_id="networked", system="s", prompt="p", authorize_target=refuse)
    assert calls == [], "the request was sent despite a denied endpoint"


async def test_output_is_bounded_and_tokens_and_cost_are_charged() -> None:
    priced = pin(price_input_microusd_per_1k=1000, price_output_microusd_per_1k=2000)
    client = ModelClient(
        pins=(priced,),
        providers={"ollama": _networked(_ok())},
        budgets=BudgetLedger(BudgetLimits(requests=10, records=10, tokens=100, cost_microusd=100)),
        max_output_chars=32,
    )
    completion = await client.complete(
        pin_id="networked", system="s", prompt="p", authorize_target=_authorize
    )
    assert len(completion.text) == 32
    assert completion.record.input_tokens == 11 and completion.record.output_tokens == 3
    # 11 * 1000 + 3 * 2000 = 17000 micro-USD per 1k tokens -> 17, rounded up.
    assert completion.record.cost_microusd == 17
    assert client.tokens == 14 and client.cost_microusd == 17
    assert client.budgets.used.tokens == 14


async def test_a_token_cap_breach_fails_the_call_closed() -> None:
    client = ModelClient(
        pins=(pin(),),
        providers={"ollama": _networked(_ok())},
        budgets=BudgetLedger(BudgetLimits(requests=10, records=10, tokens=5, cost_microusd=10)),
    )
    with pytest.raises(BudgetError, match="tokens budget exhausted"):
        await client.complete(
            pin_id="networked", system="s", prompt="p", authorize_target=_authorize
        )


async def test_a_redirect_from_a_model_endpoint_is_a_denial_not_a_hop() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://elsewhere.invalid"})

    client = _client(_networked(handler))
    with pytest.raises(ModelUnavailable, match="redirect"):
        await client.complete(
            pin_id="networked", system="s", prompt="p", authorize_target=_authorize
        )


@pytest.mark.parametrize("status", [400, 401, 429, 500, 503])
async def test_an_error_response_is_surfaced_not_swallowed(status: int) -> None:
    client = _client(_networked(_ok(status=status)))
    with pytest.raises(ModelUnavailable, match=str(status)):
        await client.complete(
            pin_id="networked", system="s", prompt="p", authorize_target=_authorize
        )


@pytest.mark.parametrize(
    "payload",
    [{}, {"choices": []}, {"choices": [{}]}, {"choices": [{"message": {}}]}, {"choices": "no"}],
)
async def test_a_malformed_response_is_refused_not_guessed_at(payload: dict[str, Any]) -> None:
    client = _client(_networked(_ok(payload)))
    with pytest.raises(ModelResponseInvalid):
        await client.complete(
            pin_id="networked", system="s", prompt="p", authorize_target=_authorize
        )


async def test_the_credential_reaches_the_header_and_never_the_record() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization", ""))
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    secret = "SUPPORTLAB-MODEL-KEY-NOT-A-REAL-SECRET"  # noqa: S105 -- synthetic fixture value
    hosted = pin(provider="openai-compatible")
    client = ModelClient(
        pins=(hosted,),
        providers={
            "openai-compatible": _networked(handler, credential=secret, profile="openai-compatible")
        },
        budgets=BudgetLedger(BudgetLimits(requests=10, records=10, tokens=100)),
    )
    completion = await client.complete(
        pin_id="networked", system="s", prompt="p", authorize_target=_authorize
    )
    assert seen == [f"Bearer {secret}"]
    # The record carries digests and counts, never the credential or the prompt text.
    serialized = json.dumps(completion.record.model_dump(mode="json"))
    assert secret not in serialized
    assert "Bearer" not in serialized


async def test_a_hosted_profile_refuses_to_construct_without_a_credential() -> None:
    with pytest.raises(ModelCredentialMissing):
        OpenAICompatibleProvider(base_url=SIGNED_ENDPOINT, credential=None)


def test_the_offline_profile_is_not_a_network_provider() -> None:
    with pytest.raises(ValueError, match="not a network provider"):
        OpenAICompatibleProvider(base_url=SIGNED_ENDPOINT, credential="x", profile="offline")


async def test_a_deadline_cancels_the_call() -> None:
    class _Slow:
        profile = "ollama"
        endpoint = None

        async def complete(self, **kwargs: Any) -> tuple[str, int, int]:
            await asyncio.sleep(30)
            return "never", 0, 0

    client = ModelClient(
        pins=(pin(),),
        providers={"ollama": _Slow()},
        budgets=BudgetLedger(BudgetLimits(requests=10, records=10, tokens=100)),
        timeout=0.05,
    )
    with pytest.raises(TimeoutError):
        await client.complete(
            pin_id="networked", system="s", prompt="p", authorize_target=_authorize
        )


async def test_an_unauthorized_pin_and_an_unconfigured_profile_are_refused() -> None:
    client = _client(_networked(_ok()))
    with pytest.raises(ModelUnavailable, match="pin is not authorized"):
        await client.complete(
            pin_id="not-a-pin", system="s", prompt="p", authorize_target=_authorize
        )
    with pytest.raises(ModelUnavailable, match="no provider is configured"):
        await client.complete(pin_id="offline", system="s", prompt="p", authorize_target=_authorize)


def test_duplicate_pin_ids_fail_at_construction() -> None:
    with pytest.raises(ValueError, match="unique"):
        ModelClient(
            pins=(pin(), pin()),
            providers={},
            budgets=BudgetLedger(BudgetLimits(requests=1, records=1)),
        )


async def test_the_offline_provider_makes_no_network_call(tmp_path: Any) -> None:
    """The fixture-backed offline provider reports no endpoint, so it has nowhere to go."""
    request = {"system": "s", "prompt": "p"}
    fixture = tmp_path / "responses.json"
    fixture.write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "model": "synthetic",
                        "profile": "deterministic",
                        "request_digest": OfflineModelStore.request_digest(request),
                        "response": "recorded answer",
                        "input_tokens": 4,
                        "output_tokens": 2,
                    }
                ]
            }
        )
    )
    provider = OfflineProvider(OfflineModelStore(fixture))
    assert provider.endpoint is None and provider.profile == "offline"
    client = ModelClient(
        pins=(pin(pin_id="offline", provider="offline"),),
        providers={"offline": provider},
        budgets=BudgetLedger(BudgetLimits(requests=10, records=10, tokens=100)),
    )

    async def never(observation: TargetObservation) -> None:
        raise AssertionError("the offline provider must not authorize an endpoint")

    completion: Completion = await client.complete(
        pin_id="offline", system="s", prompt="p", authorize_target=never
    )
    assert completion.text == "recorded answer"
    assert completion.record.provider == "offline"
    assert client.budgets.used == BudgetRequest(requests=0, records=0, tokens=6, cost_microusd=0)


async def test_the_pin_decoding_parameters_reach_the_request() -> None:
    """ "Pinned" has to mean the parameters were actually sent, not merely recorded."""
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    seeded = pin(
        decoding=DecodingParameters(temperature=0.2, top_p=0.9, max_output_tokens=64, seed=7)
    )
    unseeded = pin(pin_id="unseeded", decoding=DecodingParameters(seed=None))
    client = ModelClient(
        pins=(seeded, unseeded),
        providers={"ollama": _networked(handler)},
        budgets=BudgetLedger(BudgetLimits(requests=10, records=10, tokens=100)),
    )
    await client.complete(pin_id="networked", system="s", prompt="p", authorize_target=_authorize)
    assert bodies[0]["temperature"] == 0.2
    assert bodies[0]["top_p"] == 0.9
    assert bodies[0]["max_tokens"] == 64
    assert bodies[0]["seed"] == 7
    assert bodies[0]["stream"] is False

    # A provider without seed support gets no seed key, and the pin reports itself unreproducible.
    await client.complete(pin_id="unseeded", system="s", prompt="p", authorize_target=_authorize)
    assert "seed" not in bodies[1]
    assert not unseeded.reproducible and seeded.reproducible
    assert client.records[1].reproducible_pin is False
