"""Model-plane configuration: how a networked pin gets its decoding, its price, and its calibration.

Before this module the networked pin was assembled inline with ``DecodingParameters(seed=42)`` and
no price, which had two consequences. Every real-model run was greedy, so a repetition set could
only ever measure greedy decoding; and a hosted run's cost was recorded as zero, so the signed
cost cap -- which is charged in micro-USD -- could never fire. Both were silent.

Three rules hold here and each is enforced rather than described.

*Defaults are exactly the old pin.* With nothing set, the resolved pin is temperature 0, top_p 1,
seed 42, 512 output tokens, price zero -- byte for byte what the inline construction produced, so
every recorded hash and ``make agent-stochastic`` run is unchanged. A command-line value wins over
the environment, and the environment wins over the default.

*A hosted price is never assumed.* For a non-local profile (``openai-compatible``) a missing price
is refused with ``MODEL_PRICE_UNDECLARED``, and so is a declared price of zero: a zero that came
from a forgotten variable and a zero that is true look identical in the evidence, so a free hosted
model must be acknowledged by **naming it** (``--declared-free <model-id>``). The acknowledgement is
command-line only -- a leftover environment variable cannot carry it into the next run -- and it
must equal the pin's model id, so an acknowledgement for one model never covers another. Local
profiles (Ollama, vLLM) cost nothing per token and default to zero, as before.

*Calibration is a committed file, held fixed.* The pre-run estimate uses the pin's declared
per-call expectations (``ModelPin.expected_*``). They are measured once by ``calibrate-pin`` from a
real run, committed under ``baselines/model-calibration/``, and loaded by identity. A calibration
recorded against a different system prompt is refused rather than silently applied: the prompt is
most of the input tokens, and the existing offline pin was re-measured for exactly that reason.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.model_calibration import PinCalibration
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin, ProviderProfile

#: Profiles served on a local socket. They cost nothing per token, so their price defaults to zero.
LOCAL_PROFILES: frozenset[str] = frozenset({"ollama", "vllm"})
NETWORKED_PROFILES: frozenset[str] = frozenset({"openai-compatible", "ollama", "vllm"})

#: The networked pin's decoding before this module existed. Changing it changes every recorded pin.
DEFAULT_DECODING = DecodingParameters(seed=42)
DEFAULT_CALIBRATION_DIR = ROOT / "baselines" / "model-calibration"
#: Spelling of "no seed" on the command line and in the environment.
UNSEEDED = "none"


class ModelConfigError(ValueError):
    """A model-plane setting is malformed or inconsistent. The run is refused, never adjusted."""

    reason_code = "MODEL_CONFIG_INVALID"


class ModelPriceUndeclared(ModelConfigError):
    reason_code = "MODEL_PRICE_UNDECLARED"


class CalibrationMismatch(ModelConfigError):
    reason_code = "MODEL_CALIBRATION_MISMATCH"


@dataclass(frozen=True)
class EnvNames:
    """Where one model role (the target or the judge) reads its environment."""

    prefix: str
    model_id: str
    model_version: str

    def name(self, suffix: str) -> str:
        return f"{self.prefix}_{suffix}"


MODEL_ENV = EnvNames("PURPLELOOP_MODEL", "PURPLELOOP_MODEL_ID", "PURPLELOOP_MODEL_VERSION")
JUDGE_ENV = EnvNames(
    "PURPLELOOP_JUDGE", "PURPLELOOP_JUDGE_MODEL_ID", "PURPLELOOP_JUDGE_MODEL_VERSION"
)


@dataclass(frozen=True)
class ModelSettings:
    """Command-line overrides for one model role. ``None`` means "not given on the command line"."""

    temperature: float | None = None
    top_p: float | None = None
    seed: str | None = None
    max_output_tokens: int | None = None
    price_input_microusd_per_1k: int | None = None
    price_output_microusd_per_1k: int | None = None
    #: Command-line only, and it must name the model it acknowledges.
    declared_free: str | None = None
    model_id: str | None = None
    model_version: str | None = None


def _lookup(cli: object | None, names: EnvNames, suffix: str, env: Mapping[str, str]) -> str | None:
    if cli is not None:
        return str(cli)
    value = env.get(names.name(suffix))
    return value if value not in (None, "") else None


def _float(raw: str | None, name: str) -> float | None:
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError as exc:
        raise ModelConfigError(f"{name} must be a number, got {raw!r}") from exc


def _int(raw: str | None, name: str) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ModelConfigError(f"{name} must be an integer, got {raw!r}") from exc


def resolve_decoding(
    settings: ModelSettings, *, names: EnvNames = MODEL_ENV, env: Mapping[str, str] | None = None
) -> DecodingParameters:
    """Decoding for a networked pin: command line, then environment, then the old default."""
    source = os.environ if env is None else env
    temperature = _float(_lookup(settings.temperature, names, "TEMPERATURE", source), "temperature")
    top_p = _float(_lookup(settings.top_p, names, "TOP_P", source), "top_p")
    max_tokens = _int(
        _lookup(settings.max_output_tokens, names, "MAX_OUTPUT_TOKENS", source),
        "max_output_tokens",
    )
    raw_seed = _lookup(settings.seed, names, "SEED", source)
    seed: int | None
    if raw_seed is None:
        seed = DEFAULT_DECODING.seed
    elif raw_seed.strip().lower() == UNSEEDED:
        # Recorded as unseeded, so the pin reports itself as not reproducible.
        seed = None
    else:
        seed = _int(raw_seed, "seed")
    try:
        return DecodingParameters(
            temperature=DEFAULT_DECODING.temperature if temperature is None else temperature,
            top_p=DEFAULT_DECODING.top_p if top_p is None else top_p,
            max_output_tokens=(
                DEFAULT_DECODING.max_output_tokens if max_tokens is None else max_tokens
            ),
            seed=seed,
        )
    except ValueError as exc:
        raise ModelConfigError(f"decoding parameters out of range: {exc}") from exc


def resolve_price(
    profile: str,
    model_id: str,
    settings: ModelSettings,
    *,
    names: EnvNames = MODEL_ENV,
    env: Mapping[str, str] | None = None,
) -> tuple[int, int]:
    """``(input, output)`` micro-USD per 1,000 tokens, or a refusal. Never a silent zero."""
    source = os.environ if env is None else env
    price_in = _int(
        _lookup(settings.price_input_microusd_per_1k, names, "PRICE_INPUT_MICROUSD_PER_1K", source),
        "input price",
    )
    price_out = _int(
        _lookup(
            settings.price_output_microusd_per_1k, names, "PRICE_OUTPUT_MICROUSD_PER_1K", source
        ),
        "output price",
    )
    if (price_in is None) != (price_out is None):
        # Half a price is a misconfiguration, and treating the missing half as zero would
        # under-charge every call by exactly the part nobody wrote down.
        raise ModelPriceUndeclared(
            f"both {names.name('PRICE_INPUT_MICROUSD_PER_1K')} and "
            f"{names.name('PRICE_OUTPUT_MICROUSD_PER_1K')} must be set, or neither"
        )
    if any(value is not None and value < 0 for value in (price_in, price_out)):
        raise ModelConfigError("a price cannot be negative")
    declared = settings.declared_free
    if declared is not None and declared != model_id:
        raise ModelPriceUndeclared(
            f"--declared-free names {declared!r}, but the pinned model is {model_id!r}; an "
            "acknowledgement covers only the model it names"
        )
    priced = price_in is not None and price_out is not None and (price_in > 0 or price_out > 0)
    if declared is not None and priced:
        raise ModelPriceUndeclared("a model cannot be both priced and declared free")
    if profile in LOCAL_PROFILES:
        return price_in or 0, price_out or 0
    if priced:
        assert price_in is not None and price_out is not None
        return price_in, price_out
    if declared is not None:
        return 0, 0
    raise ModelPriceUndeclared(
        f"profile {profile} is billed per token, and no price is declared for {model_id}: set "
        f"{names.name('PRICE_INPUT_MICROUSD_PER_1K')} and "
        f"{names.name('PRICE_OUTPUT_MICROUSD_PER_1K')} (a zero price needs --declared-free "
        f"{model_id}); refusing rather than recording the run's cost as zero"
    )


# --- calibration --------------------------------------------------------------------------------

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def calibration_filename(profile: str, model_id: str, model_version: str | None) -> str:
    """``<profile>-<model_id>-<version>.json`` with path-unsafe characters replaced."""
    parts = (profile, model_id, model_version or "unversioned")
    return "-".join(_UNSAFE.sub("_", part) for part in parts) + ".json"


def calibration_dir(env: Mapping[str, str] | None = None) -> Path:
    source = os.environ if env is None else env
    configured = source.get("PURPLELOOP_MODEL_CALIBRATION_DIR")
    return Path(configured) if configured else DEFAULT_CALIBRATION_DIR


def load_calibration(path: Path) -> PinCalibration:
    try:
        return PinCalibration.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise CalibrationMismatch(f"calibration file {path.name} is invalid: {exc}") from exc


def apply_calibration(pin: ModelPin, calibration: PinCalibration) -> ModelPin:
    """The pin with its declared expectations set, or a refusal if the identity differs."""
    expected = (pin.provider, pin.model_id, pin.model_version, pin.system_prompt_hash)
    recorded = (
        calibration.provider,
        calibration.model_id,
        calibration.model_version,
        calibration.system_prompt_hash,
    )
    if expected != recorded:
        names = ("provider", "model_id", "model_version", "system_prompt_hash")
        differing = [name for name, a, b in zip(names, expected, recorded, strict=True) if a != b]
        raise CalibrationMismatch(
            f"calibration was measured for a different pin ({', '.join(differing)} differ); "
            "re-run calibrate-pin rather than reusing a stale expectation"
        )
    return pin.model_copy(
        update={
            "expected_input_tokens_per_call": calibration.expected_input_tokens_per_call,
            "expected_output_tokens_per_call": calibration.expected_output_tokens_per_call,
        }
    )


def calibrated(pin: ModelPin, *, directory: Path | None = None) -> ModelPin:
    """Apply the committed calibration for this pin's identity when one exists."""
    root = calibration_dir() if directory is None else directory
    path = root / calibration_filename(pin.provider, pin.model_id, pin.model_version)
    if not path.is_file():
        return pin
    return apply_calibration(pin, load_calibration(path))


def build_pin(
    *,
    pin_id: str,
    profile: str,
    system_prompt_hash: str,
    settings: ModelSettings,
    names: EnvNames = MODEL_ENV,
    env: Mapping[str, str] | None = None,
    calibration_root: Path | None = None,
) -> ModelPin:
    """Resolve a networked pin in full: identity, decoding, price, then calibration."""
    source = os.environ if env is None else env
    if profile not in NETWORKED_PROFILES:
        raise ModelConfigError(f"{profile!r} is not a networked provider profile")
    model_id = settings.model_id or source.get(names.model_id) or "unspecified-model"
    model_version = settings.model_version or source.get(names.model_version) or None
    price_in, price_out = resolve_price(profile, model_id, settings, names=names, env=source)
    profile_name: ProviderProfile = profile  # type: ignore[assignment]
    pin = ModelPin(
        pin_id=pin_id,
        provider=profile_name,
        model_id=model_id,
        model_version=model_version,
        decoding=resolve_decoding(settings, names=names, env=source),
        system_prompt_hash=system_prompt_hash,
        price_input_microusd_per_1k=price_in,
        price_output_microusd_per_1k=price_out,
    )
    return calibrated(pin, directory=calibration_root or calibration_dir(source))


def with_seed(pin: ModelPin, seed: int | None) -> ModelPin:
    """The same pin under another decoding seed; used for per-repetition seeding."""
    try:
        decoding = DecodingParameters.model_validate({**pin.decoding.model_dump(), "seed": seed})
    except ValueError as exc:
        raise ModelConfigError(f"seed out of range: {exc}") from exc
    return pin.model_copy(update={"decoding": decoding})
