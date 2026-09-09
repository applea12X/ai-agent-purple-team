"""Phase 3 contracts: verdict provenance, model pins, judging, and repetition sets.

The central contract of this phase is :data:`VerdictProvenance`. Phases 0-2 produced exactly one
kind of verdict, so its provenance never had to be written down. Phase 3 introduces real model
calls, an adaptive attacker, and an LLM judge, and their results appear in the same summary and
the same bundle as the deterministic ones. The discriminator exists so that a release gate can
never read an advisory number by accident: gates accept ``deterministic`` only, and
:func:`require_binding` is the single place that check is written.

Everything here is additive. Phase 0, 1, and 2 manifests and scenarios never carry these fields,
and every new field on an existing model defaults to ``None`` so their canonical bytes -- and
therefore their signatures -- are unchanged.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from purpleloop.schemas.common import StrictModel, require_identifier

# --- verdict provenance -----------------------------------------------------------------------

VerdictProvenance = Literal["deterministic", "advisory", "pinned-stochastic"]

#: The only provenance a release-blocking gate may read. Named once so the rule is greppable.
BINDING_PROVENANCE: VerdictProvenance = "deterministic"

ADVISORY_PROVENANCES: frozenset[str] = frozenset({"advisory", "pinned-stochastic"})


class AdvisoryVerdictError(ValueError):
    """Raised when an advisory verdict reaches a binding decision path."""

    reason_code = "ADVISORY_VERDICT_REJECTED"


class Scored(StrictModel):
    """Base for anything carrying a verdict. ``provenance`` is required to be explicit."""

    provenance: VerdictProvenance = BINDING_PROVENANCE


def require_binding(*scored: Scored | None) -> None:
    """Refuse advisory input at a binding boundary.

    Called by every gate: run status, corpus metrics, and finding construction. A stochastic
    component cannot reach a gate by being averaged in, because it is rejected by type here
    before any arithmetic happens.
    """
    for item in scored:
        if item is not None and item.provenance != BINDING_PROVENANCE:
            raise AdvisoryVerdictError(
                f"{type(item).__name__} is {item.provenance}; gates read "
                f"{BINDING_PROVENANCE} verdicts only"
            )


def is_binding(item: Scored | None) -> bool:
    return item is not None and item.provenance == BINDING_PROVENANCE


# --- model pins -------------------------------------------------------------------------------

ProviderProfile = Literal["offline", "openai-compatible", "ollama", "vllm"]


class DecodingParameters(StrictModel):
    """Recorded on every model event. A pin without these is not a pin."""

    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=1.0, ge=0.0, le=1.0)
    max_output_tokens: int = Field(default=512, ge=1, le=32768)
    seed: int | None = Field(default=None, ge=0, le=2**32 - 1)


class ModelPin(StrictModel):
    """An authorized model, pinned exactly. An unpinned model is not runnable."""

    pin_id: str
    provider: ProviderProfile
    model_id: str = Field(min_length=1, max_length=200)
    #: Provider-reported version or digest where one is exposed; ``None`` is recorded as unknown
    #: rather than silently treated as pinned.
    model_version: str | None = Field(default=None, max_length=200)
    decoding: DecodingParameters = DecodingParameters()
    system_prompt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    #: Published price, in micro-USD per 1,000 tokens. Zero for a local profile, which costs
    #: nothing per token; the estimate-versus-actual check then reports a true zero rather than
    #: an unmeasured blank.
    price_input_microusd_per_1k: int = Field(default=0, ge=0, le=10_000_000)
    price_output_microusd_per_1k: int = Field(default=0, ge=0, le=10_000_000)
    #: Declared per-call expectations for the pre-run estimate, calibrated once from a measured
    #: run and then held fixed -- the same discipline as ``ResourceCalibration``. When either is
    #: zero the estimator falls back to ``max_output_tokens`` as an explicit upper bound, and the
    #: report says the estimate is a bound rather than an expectation.
    expected_input_tokens_per_call: int = Field(default=0, ge=0, le=1_000_000)
    expected_output_tokens_per_call: int = Field(default=0, ge=0, le=1_000_000)

    def cost_microusd(self, input_tokens: int, output_tokens: int) -> int:
        """Cost of one call, rounded up so an estimate is never optimistic by rounding."""
        return -(
            -(
                input_tokens * self.price_input_microusd_per_1k
                + output_tokens * self.price_output_microusd_per_1k
            )
            // 1000
        )

    @field_validator("pin_id")
    @classmethod
    def validate_pin(cls, value: str) -> str:
        return require_identifier(value)

    @property
    def reproducible(self) -> bool:
        """True only when the provider exposes both a version and a decoding seed."""
        return self.model_version is not None and self.decoding.seed is not None


# --- manifest 1.3 -----------------------------------------------------------------------------


class Phase3Grants(StrictModel):
    """Manifest 1.3 additions.

    ``model_assets`` is disjoint from every target asset by construction: the model plane and the
    target plane are separate, and the fixture never calls a model. See ADR 0008.

    An offline-only engagement authorizes **no** model endpoint at all -- ``model_assets`` stays
    empty, and the validator refuses a networked provider profile without one. The absence of a
    grant is the control; the offline provider simply has nowhere to go.
    """

    model_assets: frozenset[str] = frozenset()
    model_credential_handle: str
    model_pins: tuple[ModelPin, ...] = Field(min_length=1)
    token_budget: int = Field(ge=0, le=100_000_000)
    cost_microusd_budget: int = Field(ge=0, le=1_000_000_000)
    max_agent_steps: int = Field(default=8, ge=1, le=64)
    max_tool_intents_per_turn: int = Field(default=4, ge=1, le=16)
    max_attacker_proposals: int = Field(default=8, ge=0, le=128)
    max_attacker_depth: int = Field(default=3, ge=0, le=16)
    judge_enabled: bool = False
    judge_model_pin: str | None = None
    #: Scenario repetitions required before a stochastic figure may be reported.
    min_repetitions: int = Field(default=5, ge=1, le=100)

    @field_validator("model_credential_handle")
    @classmethod
    def validate_handle(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("judge_model_pin")
    @classmethod
    def validate_judge_pin(cls, value: str | None) -> str | None:
        return require_identifier(value) if value is not None else None

    @field_validator("model_assets")
    @classmethod
    def validate_origins(cls, values: frozenset[str]) -> frozenset[str]:
        for origin in values:
            scheme, separator, rest = origin.partition("://")
            if scheme not in {"http", "https"} or not separator or "/" in rest or not rest:
                raise ValueError("model assets must be scheme://host:port with no path")
        return values

    @model_validator(mode="after")
    def validate_pins(self) -> Phase3Grants:
        ids = [pin.pin_id for pin in self.model_pins]
        if len(ids) != len(set(ids)):
            raise ValueError("model pin ids must be unique")
        if self.judge_enabled and self.judge_model_pin is None:
            raise ValueError("an enabled judge requires a pinned judge model")
        if self.judge_model_pin is not None and self.judge_model_pin not in ids:
            raise ValueError("the judge model pin must be an authorized pin")
        if any(pin.provider != "offline" for pin in self.model_pins) and not self.model_assets:
            raise ValueError("a networked model provider requires a signed model endpoint")
        if self.model_assets and all(pin.provider == "offline" for pin in self.model_pins):
            raise ValueError("an offline-only engagement must not authorize a model endpoint")
        return self

    def pin(self, pin_id: str) -> ModelPin:
        for candidate in self.model_pins:
            if candidate.pin_id == pin_id:
                return candidate
        raise KeyError(f"model pin is not authorized: {pin_id}")


# --- scenario 1.3 -----------------------------------------------------------------------------

#: Every channel through which hostile content can reach the agent. The PRD requires at least one
#: scenario per channel; a corpus-coverage test asserts each is populated.
InjectionChannel = Literal[
    "ticket",
    "document",
    "html",
    "markdown",
    "api-response",
    "tool-description",
    "memory",
    "log",
    "inter-agent",
]

INJECTION_CHANNELS: tuple[InjectionChannel, ...] = (
    "ticket",
    "document",
    "html",
    "markdown",
    "api-response",
    "tool-description",
    "memory",
    "log",
    "inter-agent",
)

RiskClass = Literal[
    "prompt-injection",
    "system-prompt-leakage",
    "rag-poisoning",
    "memory-poisoning",
    "goal-hijacking",
    "confused-deputy",
    "excessive-agency",
    "schema-injection",
    "unsafe-output-handling",
    "canary-exfiltration",
    "covert-channel",
    "code-execution",
    "cascading-failure",
    "approval-spoofing",
    "object-authorization",
    "function-authorization",
    "property-authorization",
    "workflow-authorization",
    "ssrf",
    "misconfiguration",
    "unsafe-upstream",
]


class AgentTask(StrictModel):
    """The agent's legitimate objective and the capability set it is granted for this task.

    ``capabilities`` is resolved against the lane's tool registry at compile time. An intent
    naming an operation outside this set is refused before any I/O.
    """

    objective: str = Field(min_length=1, max_length=500)
    capabilities: frozenset[str] = Field(min_length=1)
    max_steps: int = Field(default=4, ge=1, le=64)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)


# --- judging ----------------------------------------------------------------------------------


class JudgeResult(Scored):
    """A semantic judgement. Always advisory; the type refuses to be anything else.

    ``abstain`` is a first-class outcome, never coerced to ``false`` and never counted as a judge
    failure. A citation naming an evidence id absent from the judge's input forces abstention --
    the judge cannot mint evidence.
    """

    provenance: VerdictProvenance = "advisory"
    verdict: Literal["true", "false", "abstain"]
    rubric_id: str
    rubric_version: str = "rubric-v1"
    cited_evidence_ids: tuple[str, ...] = ()
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = Field(default="", max_length=2000)
    abstention_reason: str | None = Field(default=None, max_length=200)
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_pin_id: str
    trials: int = Field(default=1, ge=1)
    order_swapped: bool = False

    @field_validator("rubric_id", "model_pin_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @model_validator(mode="after")
    def enforce_advisory_and_abstention(self) -> JudgeResult:
        if self.provenance != "advisory":
            raise ValueError("a judge verdict is advisory by construction")
        if self.verdict == "abstain" and self.abstention_reason is None:
            raise ValueError("abstention must record its reason")
        if self.verdict != "abstain" and not self.cited_evidence_ids:
            raise ValueError("a non-abstaining judgement must cite evidence")
        return self


class JudgeAgreement(StrictModel):
    """Agreement with human-adjudicated labels, reported with n and an interval."""

    schema_version: Literal["1.3.0"] = "1.3.0"
    label_set_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    n: int = Field(ge=0)
    krippendorff_alpha: float
    cohen_kappa: float | None = None
    kappa_n: int = Field(default=0, ge=0)
    alpha_ci_low: float
    alpha_ci_high: float
    abstentions: int = Field(default=0, ge=0)
    order_swap_consistency: float = Field(ge=0.0, le=1.0)
    order_swap_trials: int = Field(default=0, ge=0)


class EvaluatorRedTeamResult(StrictModel):
    """Held-out evaluator-injection resistance.

    A critical false pass is reported by name, never averaged into the rate.
    """

    schema_version: Literal["1.3.0"] = "1.3.0"
    corpus_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    cases: int = Field(ge=0)
    resisted: int = Field(ge=0)
    resistance: float = Field(ge=0.0, le=1.0)
    critical_false_passes: tuple[str, ...] = ()


# --- stochastic reporting ---------------------------------------------------------------------


class Measurement(Scored):
    """One reported number, carrying everything needed to read it honestly.

    A figure without its n, seed policy, and model pin does not serialize, because the fields are
    required. Deterministic measurements carry ``n=1`` and a degenerate interval.
    """

    value: float
    n: int = Field(ge=0)
    ci_low: float
    ci_high: float
    seed_policy: str = Field(max_length=200)
    model_pin_id: str | None = None
    #: Repetitions that were requested but did not produce a result, reported beside the number.
    excluded: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_interval(self) -> Measurement:
        if self.ci_low > self.ci_high:
            raise ValueError("confidence interval is inverted")
        if self.provenance != BINDING_PROVENANCE and self.model_pin_id is None:
            raise ValueError("a stochastic measurement must name its model pin")
        return self


class RepetitionRecord(Scored):
    """One trial of a stochastic scenario."""

    provenance: VerdictProvenance = "pinned-stochastic"
    repetition_index: int = Field(ge=0)
    run_id: str
    status: str
    security_verdict: Literal["true", "false", "inconclusive"]
    utility_verdict: Literal["true", "false", "inconclusive"]
    utility_under_attack_verdict: Literal["true", "false", "inconclusive", "not-measured"] = (
        "not-measured"
    )
    susceptible: bool = False
    unauthorized_side_effects: int = Field(default=0, ge=0)
    tokens_used: int = Field(default=0, ge=0)
    cost_microusd: int = Field(default=0, ge=0)
    model_pin_id: str | None = None
    judge: JudgeResult | None = None


class RepetitionSet(StrictModel):
    """The repetition machinery behind every stochastic figure."""

    schema_version: Literal["1.3.0"] = "1.3.0"
    scenario_id: str
    requested: int = Field(ge=1)
    records: tuple[RepetitionRecord, ...] = ()
    seed_policy: str = Field(default="fixed-per-repetition", max_length=200)
    model_pin_id: str | None = None
    #: Why a requested repetition produced no record. Reported beside the numbers it reduces.
    exclusion_reasons: tuple[str, ...] = ()

    @property
    def completed(self) -> int:
        return len(self.records)

    @property
    def excluded(self) -> int:
        return max(self.requested - self.completed, 0)


class StochasticReport(StrictModel):
    """The four numbers, kept separate, plus the reproducibility they support."""

    schema_version: Literal["1.3.0"] = "1.3.0"
    scenario_id: str
    clean_utility: Measurement
    utility_under_attack: Measurement
    attack_success: Measurement
    executed_unauthorized_side_effects: Measurement
    repetitions: RepetitionSet
    reproducible: bool = False
    judge_agreement: JudgeAgreement | None = None


class TokenAccounting(StrictModel):
    """Real token and cost use beside the pre-run estimate, with the same +/-10% machinery."""

    schema_version: Literal["1.3.0"] = "1.3.0"
    estimated_tokens: int = Field(ge=0)
    actual_tokens: int = Field(ge=0)
    estimated_cost_microusd: int = Field(ge=0)
    actual_cost_microusd: int = Field(ge=0)
    delta_percent: dict[str, float]
    within_tolerance: dict[str, bool]


class ModelCallRecord(StrictModel):
    """What a MODEL event carries. Credentials are absent by construction, never by redaction."""

    schema_version: Literal["1.3.0"] = "1.3.0"
    pin_id: str
    provider: ProviderProfile
    model_id: str
    model_version: str | None = None
    decoding: DecodingParameters
    system_prompt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    cost_microusd: int = Field(ge=0)
    reproducible_pin: bool = False


class ProposalRecord(StrictModel):
    """An adaptive-attacker proposal and its decision. A rejection is evidence, not an error."""

    schema_version: Literal["1.3.0"] = "1.3.0"
    proposal_index: int = Field(ge=0)
    depth: int = Field(ge=0)
    operation: str
    accepted: bool
    reason_code: str
    node_id: str | None = None
