"""Per-pin token calibration: the measured figures a pin's pre-run estimate is built from.

A calibration is a committed reference document (``baselines/model-calibration/``), written once
by ``purpleloop calibrate-pin`` from the ``MODEL_CALLED`` records of a measured run and then held
fixed -- the same discipline as ``ResourceCalibration``. It is keyed by the pin's identity,
including the system prompt hash: the prompt is most of every call's input, so a calibration for
one prompt says nothing about another, and loading refuses the mismatch rather than applying it.

It records its own evidence: how many calls it was computed from, their ranges, the decodings
they ran under, and the digest of every evidence file read. A figure without its n is not a
figure. This is a new, additive document; no earlier contract changes.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase3 import DecodingParameters, ProviderProfile


class PinCalibration(StrictModel):
    schema_version: Literal["1.5.0"] = "1.5.0"
    provider: ProviderProfile
    model_id: str = Field(min_length=1, max_length=200)
    model_version: str | None = Field(default=None, max_length=200)
    system_prompt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    #: Mean per-call tokens, rounded half up. These become the pin's declared expectations.
    expected_input_tokens_per_call: int = Field(ge=1, le=1_000_000)
    expected_output_tokens_per_call: int = Field(ge=1, le=1_000_000)
    calls: int = Field(ge=1)
    input_tokens_min: int = Field(ge=0)
    input_tokens_max: int = Field(ge=0)
    output_tokens_min: int = Field(ge=0)
    output_tokens_max: int = Field(ge=0)
    #: Every distinct decoding the measured calls ran under, so a reader can see whether the
    #: expectation was measured at the temperature it is later applied to.
    decodings: tuple[DecodingParameters, ...] = Field(min_length=1)
    bundles: int = Field(ge=1)
    #: SHA-256 of each evidence file read, sorted. Ties the figures to exactly those runs.
    evidence_digests: tuple[str, ...] = Field(min_length=1)
    method: str = Field(
        default="mean of MODEL_CALLED input/output tokens over verified bundles, rounded half up",
        max_length=300,
    )

    @model_validator(mode="after")
    def validate_ranges(self) -> PinCalibration:
        if not (
            self.input_tokens_min
            <= self.expected_input_tokens_per_call
            <= max(self.input_tokens_max, 1)
        ):
            raise ValueError("expected input tokens lie outside the measured range")
        if not (
            self.output_tokens_min
            <= self.expected_output_tokens_per_call
            <= max(self.output_tokens_max, 1)
        ):
            raise ValueError("expected output tokens lie outside the measured range")
        if self.bundles != len(self.evidence_digests):
            raise ValueError("one evidence digest is recorded per bundle")
        return self
