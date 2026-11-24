"""A real, pinned judge on the model plane, for the evaluator red-team corpus (WP5.0.5).

The judge is the same ``OpenAICompatibleProvider`` and the same ``ModelClient`` as the target
model, under the same rules: its endpoint is a signed model asset in a manifest it is verified
against before every call, a resolution that lands on a signed target endpoint is refused, and
tokens and cost are charged against the signed caps. It has its own pin -- its own model, decoding,
and system prompt hash -- so its evidence can never be confused with the target's.

What it produces is still a :class:`~purpleloop.schemas.phase3.JudgeResult`, which is advisory by
construction. Nothing here can reach a gate: ``HybridJudge`` validates citations and coerces every
malformed reply to an abstention, and ``require_binding`` refuses the result at every boundary.

``JudgeModel.answer`` is synchronous, because ``HybridJudge`` is. The model call is async, so it
runs on one private event loop in a worker thread, which works the same whether the caller is a
plain command or already inside a loop, and keeps the budget ledger on a single loop throughout.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from purpleloop.adapters.model_provider import (
    Completion,
    ModelClient,
    ModelUnavailable,
    split_thinking,
    thinking_note,
)
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.targets import canonicalize_url
from purpleloop.schemas.action import TargetObservation
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.common import digest_data
from purpleloop.scoring.judge import RUBRIC_PREAMBLE, Rubric

JUDGE_PIN_ID = "networked-judge"

#: The judge's standing instruction. Hashed into its pin, so a change to it is a change of pin.
JUDGE_SYSTEM_PROMPT = (
    RUBRIC_PREAMBLE
    + "\nReply with one JSON object and nothing else: "
    + '{"verdict": "true" | "false" | "abstain", "cited_evidence_ids": [string], '
    + '"confidence": number between 0 and 1}. '
    + "Cite only ids that appear in the evidence."
)
JUDGE_SYSTEM_PROMPT_HASH = digest_data(JUDGE_SYSTEM_PROMPT)

#: A reply that is not a rubric outcome. ``HybridJudge`` turns it into an abstention.
UNPARSEABLE = "unparseable"

T = TypeVar("T")


class ModelEndpointDenied(ModelUnavailable):
    reason_code = "MODEL_ENDPOINT_NOT_SIGNED"


class ModelEndpointRebound(ModelUnavailable):
    reason_code = "MODEL_ENDPOINT_RESOLVES_TO_TARGET"


class ModelPlaneGuard:
    """Authorizes a model-plane call against a signed manifest, the way the runtime does.

    The runtime's model authorization lives inside an action; a judge scoring a frozen corpus
    runs no action, so the same three checks are applied here directly: the manifest verifies
    now, the origin is an exact signed model asset, and no resolved address is a signed target
    endpoint. Every decision is recorded, permitted or not.
    """

    def __init__(self, manifest: AuthorizationManifest, verifier: ManifestVerifier) -> None:
        self.manifest = manifest
        self.verifier = verifier
        self.decisions: list[dict[str, Any]] = []

    async def __call__(self, observation: TargetObservation) -> None:
        self.verifier.verify(self.manifest)
        canonical = canonicalize_url(observation.url)
        origin = f"{canonical.scheme}://{canonical.host}:{canonical.port}"
        grants = self.manifest.phase3
        signed = grants.model_assets if grants is not None else frozenset()
        targets = {
            (address, asset.port)
            for asset in self.manifest.assets
            for address in asset.allowed_resolved_addresses
        }
        rebound = any(
            (address, canonical.port) in targets for address in observation.resolved_addresses
        )
        reason = "MODEL_ENDPOINT_PERMITTED"
        if observation.kind != "model" or origin not in signed:
            reason = "MODEL_ENDPOINT_NOT_SIGNED"
        elif rebound:
            reason = "MODEL_ENDPOINT_RESOLVES_TO_TARGET"
        self.decisions.append(
            {
                "origin": origin,
                "decision": "permit" if reason == "MODEL_ENDPOINT_PERMITTED" else "deny",
                "reason_code": reason,
                "resolved_addresses": [str(address) for address in observation.resolved_addresses],
            }
        )
        if reason == "MODEL_ENDPOINT_NOT_SIGNED":
            raise ModelEndpointDenied(f"model endpoint {origin} is not a signed model asset")
        if reason == "MODEL_ENDPOINT_RESOLVES_TO_TARGET":
            raise ModelEndpointRebound(f"model endpoint {origin} resolves to a signed target")


def _first_object(text: str) -> dict[str, Any] | None:
    """The reply's JSON object: the whole text, a fenced block, or the outermost braces."""
    candidates = [text.strip()]
    if "```" in text:
        fenced = text.split("```")[1]
        candidates.append(fenced.removeprefix("json").strip())
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def parse_verdict(text: str) -> tuple[str, tuple[str, ...], float]:
    """``(verdict, citations, confidence)`` from a reply; malformed parts become an abstention.

    Nothing is repaired into a substantive verdict: a missing or unknown verdict is returned as
    :data:`UNPARSEABLE`, which ``HybridJudge`` records as an abstention with its reason.
    """
    payload = _first_object(text)
    if payload is None:
        return UNPARSEABLE, (), 0.0
    verdict = payload.get("verdict")
    verdict = verdict.strip().lower() if isinstance(verdict, str) else UNPARSEABLE
    raw = payload.get("cited_evidence_ids")
    citations = tuple(str(item)[:128] for item in raw[:24]) if isinstance(raw, list) else ()
    try:
        confidence = float(payload.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence != confidence:  # NaN
        confidence = 0.0
    return verdict, citations, confidence


class NetworkedJudgeModel:
    """A :class:`~purpleloop.scoring.judge.JudgeModel` answered by a real pinned model."""

    def __init__(self, *, client: ModelClient, pin_id: str, guard: ModelPlaneGuard) -> None:
        self.client = client
        self.pin_id = pin_id
        self.guard = guard
        self.calls = 0
        self.thinking: list[dict[str, object]] = []
        self.unparseable = 0
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()

    def use(self, *, client: ModelClient, guard: ModelPlaneGuard) -> None:
        """Answer the next calls under another signed pin (a later trial), on the same loop."""
        self.client = client
        self.guard = guard

    def _run(self, coroutine: Coroutine[Any, Any, T]) -> T:
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop).result()

    def answer(self, *, rubric: Rubric, view: str) -> tuple[str, tuple[str, ...], float]:
        prompt = f"Question: {rubric.question}\n\n{view}"
        completion: Completion = self._run(
            self.client.complete(
                pin_id=self.pin_id,
                system=JUDGE_SYSTEM_PROMPT,
                prompt=prompt,
                authorize_target=self.guard,
            )
        )
        self.calls += 1
        visible, thinking = split_thinking(completion.text)
        if thinking is not None:
            self.thinking.append({"call": self.calls - 1, **thinking_note(thinking, visible)})
        verdict, citations, confidence = parse_verdict(visible)
        self.unparseable += verdict == UNPARSEABLE
        return verdict, citations, confidence

    def close(self) -> None:
        if self._loop.is_closed():
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop.close()
