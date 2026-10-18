"""Phase 4 contracts: attestation, retention, nightly scope, gates, and the regression registry.

Phase 4 adds the project's first real-model numbers and its first enforcing CI gates at the same
time, and the two must never meet. Everything here is on the deterministic side of that line: a
:class:`GateDecision` is computed only from binding verdicts (``require_binding`` refuses the
rest), an attestation binds a bundle to the exact code and corpus that produced it, and the
stochastic lane gets its own closed outcome vocabulary so a real endpoint's failure can be
surfaced as what it is rather than tolerated as noise.

Everything is additive. Manifest 1.0-1.3 documents never carry these fields, and every new field
on an existing model defaults to ``None``, so their canonical bytes -- and therefore their
signatures -- are unchanged.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from purpleloop.schemas.common import StrictModel, require_identifier, require_utc

# --- manifest 1.4 -----------------------------------------------------------------------------

RetentionKind = Literal[
    "raw-ledgers",
    "bundles",
    "browser-artifacts",
    "model-transcripts",
    "attestations",
]

RETENTION_KINDS: tuple[RetentionKind, ...] = (
    "raw-ledgers",
    "bundles",
    "browser-artifacts",
    "model-transcripts",
    "attestations",
)


class RetentionRule(StrictModel):
    """Retention for one artifact kind. ``days=0`` means kept for the life of the repository."""

    artifact_kind: RetentionKind
    days: int = Field(ge=0, le=3650)
    rationale: str = Field(min_length=1, max_length=500)


class NightlyScope(StrictModel):
    """The scenario subset and repetition count authorized for unattended real-model runs.

    Signed manifest data, not workflow configuration: the nightly lane's spend authority is part
    of the engagement, so narrowing or widening it is a signed change, never a quiet YAML edit.
    """

    scenario_ids: frozenset[str] = Field(min_length=1)
    repetitions: int = Field(ge=5, le=100)
    rotation: str = Field(default="", max_length=500)

    @field_validator("scenario_ids")
    @classmethod
    def validate_ids(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)


class Phase4Grants(StrictModel):
    """Manifest 1.4 additions: which keys may attest runs, retention, and the nightly scope."""

    attestation_key_ids: frozenset[str] = Field(min_length=1)
    retention: tuple[RetentionRule, ...] = Field(min_length=1)
    nightly_scope: NightlyScope | None = None

    @field_validator("attestation_key_ids")
    @classmethod
    def validate_keys(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)

    @model_validator(mode="after")
    def validate_retention(self) -> Phase4Grants:
        kinds = [rule.artifact_kind for rule in self.retention]
        if len(kinds) != len(set(kinds)):
            raise ValueError("one retention rule per artifact kind")
        return self

    def retention_for(self, kind: RetentionKind) -> RetentionRule | None:
        for rule in self.retention:
            if rule.artifact_kind == kind:
                return rule
        return None


# --- run attestation --------------------------------------------------------------------------


class AttestationMaterials(StrictModel):
    """What went into the attested run. Every digest is SHA-256 over canonical bytes."""

    code_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    lockfile_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    #: Digest over the sorted scenario digests of the attested run -- the corpus as executed.
    corpus_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    manifest_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    scenario_digests: tuple[str, ...] = ()
    model_pin_ids: tuple[str, ...] = ()

    @field_validator("scenario_digests")
    @classmethod
    def validate_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError("scenario digests must be lowercase SHA-256")
        return values


class RunAttestation(StrictModel):
    """A signed statement binding one evidence bundle to the code and corpus that produced it.

    In-toto/SLSA-shaped and deliberately not SLSA-certified: the trust claim is exactly that
    *this bundle* (subject) was produced from *these materials* under *this key*. The subject is
    the SHA-256 of the bundle's ``inventory.json`` bytes, which itself carries the digest of every
    artifact in the bundle, so a change to any artifact changes the subject. Signed with the same
    Ed25519/JCS machinery as the authorization manifest (ADR 0002); no new cryptographic
    constructions. See ADR 0012.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    subject_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject_kind: Literal["run-bundle", "suite-bundle"]
    builder: str = Field(min_length=1, max_length=200)
    #: Whether the signing key was a provided per-environment key or generated for this run.
    #: An ephemeral key still binds bundle to materials, but proves nothing about who ran it,
    #: and the attestation says which it was rather than letting a reader assume.
    key_provenance: Literal["provided", "ephemeral"]
    created_at: datetime
    materials: AttestationMaterials
    byproducts: dict[str, JsonValue] = Field(default_factory=dict)
    key_id: str
    signature: str

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("created_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    def signed_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"signature"})

    def attestation_digest(self) -> str:
        return self.digest(exclude={"signature"})


# --- stochastic lane outcomes -----------------------------------------------------------------

#: The nightly lane's closed outcome vocabulary. An endpoint error (DNS, TLS, exhaustion of
#: retries, provider outage) is a distinct class from a scenario failure, the way an image-build
#: failure was separated from an evaluation failure in WP2.0 -- so a flaky endpoint cannot make
#: real regressions look like noise, and a "failure surfaced, never silently tolerated" rule has
#: a type to hang on.
StochasticOutcome = Literal[
    "pass",
    "fail",
    "budget-stop",
    "skip-no-credential",
    "endpoint-error",
]


class StochasticRunOutcome(StrictModel):
    schema_version: Literal["1.4.0"] = "1.4.0"
    outcome: StochasticOutcome
    reason_code: str = Field(min_length=1, max_length=100)
    detail: str = Field(default="", max_length=2000)
    scenario_id: str | None = None
    model_pin_id: str | None = None


class ReproductionRecord(StrictModel):
    """The stochastic lane's replay number: same pin, same seeds, same budget, re-run.

    Reported beside -- never inside -- the deterministic lanes' replay figure, the way the
    browser lane's replay number already is. ``gap_reason`` is required whenever the rate is
    below 1, so a gap is always explained rather than averaged away.
    """

    schema_version: Literal["1.4.0"] = "1.4.0"
    scenario_id: str
    n: int = Field(ge=0)
    matching: int = Field(ge=0)
    rate: float = Field(ge=0.0, le=1.0)
    mismatched_repetitions: tuple[int, ...] = ()
    model_pin_id: str | None = None
    seed_policy: str = Field(max_length=200)
    gap_reason: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def validate_gap(self) -> ReproductionRecord:
        if self.matching > self.n:
            raise ValueError("matching repetitions cannot exceed n")
        if self.rate < 1.0 and self.n > 0 and not self.gap_reason:
            raise ValueError("a reproduction rate below 1 must state its gap reason")
        return self


# --- per-risk-class baseline and comparison ---------------------------------------------------


class RiskClassMetrics(StrictModel):
    """Deterministic corpus metrics for one risk class, from labelled controls only."""

    risk_class: str = Field(min_length=1, max_length=100)
    scenarios: int = Field(ge=0)
    seeded_true_positives: int = Field(ge=0)
    seeded_false_negatives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    negative_controls: int = Field(ge=0)
    #: Unauthorized side effects executed in defended replays across the class; zero when every
    #: defense held.
    defended_unauthorized_side_effects: int = Field(ge=0)

    @property
    def recall(self) -> float:
        seeded = self.seeded_true_positives + self.seeded_false_negatives
        return self.seeded_true_positives / seeded if seeded else 0.0


class RiskClassBaseline(StrictModel):
    """The committed baseline the per-risk-class regression gate compares against.

    Updated only by an explicit, reviewed baseline-bump commit (``purpleloop corpus-baseline``),
    never as a side effect of a run.
    """

    schema_version: Literal["1.4.0"] = "1.4.0"
    recorded_at: datetime
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    #: Which corpus the baseline covers, so a narrower current run cannot look like a loss.
    corpus: str = Field(min_length=1, max_length=200)
    classes: tuple[RiskClassMetrics, ...] = Field(min_length=1)

    @field_validator("recorded_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @model_validator(mode="after")
    def validate_classes(self) -> RiskClassBaseline:
        names = [entry.risk_class for entry in self.classes]
        if len(names) != len(set(names)):
            raise ValueError("one metrics entry per risk class")
        return self

    def metrics_for(self, risk_class: str) -> RiskClassMetrics | None:
        for entry in self.classes:
            if entry.risk_class == risk_class:
                return entry
        return None


class RiskClassComparison(StrictModel):
    """One class's baseline-versus-current decision, with the fact that produced it."""

    schema_version: Literal["1.4.0"] = "1.4.0"
    risk_class: str
    baseline: RiskClassMetrics | None = None
    current: RiskClassMetrics | None = None
    newly_missed_seeded_findings: int = Field(default=0, ge=0)
    p_value: float | None = Field(default=None, ge=0.0, le=1.0)
    blocked: bool
    reason_code: str = Field(min_length=1, max_length=100)


# --- gate decisions ---------------------------------------------------------------------------

GateName = Literal[
    "scope-bypass",
    "critical-regression",
    "schema-drift",
    "budget-failure",
    "risk-class-regression",
]

GATE_NAMES: tuple[GateName, ...] = (
    "scope-bypass",
    "critical-regression",
    "schema-drift",
    "budget-failure",
    "risk-class-regression",
)


class GateDecision(StrictModel):
    """One gate's decision: a pure function of typed, binding inputs.

    CI calls the same decision functions the unit tests call; the red-branch protocol proves the
    wiring and the unit tests prove the logic, and neither substitutes for the other (ADR 0013).
    """

    schema_version: Literal["1.4.0"] = "1.4.0"
    gate: GateName
    blocked: bool
    reason_code: str = Field(min_length=1, max_length=100)
    detail: str = Field(default="", max_length=4000)


# --- smoke set --------------------------------------------------------------------------------

SmokeLane = Literal["phase1", "supportlab", "agent"]

SMOKE_LANES: tuple[SmokeLane, ...] = ("phase1", "supportlab", "agent")


class SmokeMember(StrictModel):
    lane: SmokeLane
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")


class SmokeSet(StrictModel):
    """The named PR-lane smoke subset: 10-20 scenarios, at least one per lane.

    A named list, not copies: each member must exist and be labelled in its lane's corpus,
    which a test asserts, so the smoke lane cannot drift away from the scenarios it claims.
    """

    schema_version: Literal["1.4.0"] = "1.4.0"
    wall_time_target_seconds: int = Field(ge=1, le=3600)
    scenarios: tuple[SmokeMember, ...] = Field(min_length=10, max_length=20)

    @model_validator(mode="after")
    def validate_members(self) -> SmokeSet:
        ids = [member.scenario_id for member in self.scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("smoke scenarios must be unique")
        lanes = {member.lane for member in self.scenarios}
        if lanes != set(SMOKE_LANES):
            raise ValueError("the smoke set must cover every lane")
        return self


# --- regression registry ----------------------------------------------------------------------

RegressionStatus = Literal["covered", "uncovered", "retired"]


class RegressionEntry(StrictModel):
    """One accepted finding class and the test that pins it.

    ``test`` is a pytest node id (``path::function``). A ``covered`` entry must name one; an
    ``uncovered`` or ``retired`` entry must say why instead, so the registry cannot drift into
    decoration.
    """

    finding_class: str
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    test: str = Field(default="", max_length=300)
    status: RegressionStatus
    reason: str | None = Field(default=None, max_length=500)

    @field_validator("finding_class")
    @classmethod
    def validate_class(cls, value: str) -> str:
        return require_identifier(value)

    @model_validator(mode="after")
    def validate_status(self) -> RegressionEntry:
        if self.status == "covered" and "::" not in self.test:
            raise ValueError("a covered finding must name its pinning test as a pytest node id")
        if self.status != "covered" and not self.reason:
            raise ValueError("an uncovered or retired finding must record why")
        return self


class RegressionRegistry(StrictModel):
    schema_version: Literal["1.4.0"] = "1.4.0"
    entries: tuple[RegressionEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_entries(self) -> RegressionRegistry:
        names = [entry.finding_class for entry in self.entries]
        if len(names) != len(set(names)):
            raise ValueError("finding classes must be unique")
        return self

    @property
    def coverage(self) -> float:
        """Covered share of non-retired findings. Retired entries carry their reason instead."""
        active = [entry for entry in self.entries if entry.status != "retired"]
        if not active:
            return 0.0
        return sum(entry.status == "covered" for entry in active) / len(active)

    def covered(self) -> tuple[RegressionEntry, ...]:
        return tuple(entry for entry in self.entries if entry.status == "covered")
