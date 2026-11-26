"""Phase 5 contracts: manifest 1.5, risk approval, the evaluation matrix, and scenario 1.4.

Phase 5 is the first phase allowed to make the harness more capable rather than more
trustworthy, so its contracts are split cleanly along the line every earlier phase drew:

- **Signed authority** -- :class:`Phase5Grants` (manifest 1.5), :class:`RiskApproval`, and the
  :class:`EvaluationMatrix` spec. Each is data a human signs; the kernel only verifies it.
- **Deterministic evidence** -- :class:`ShadowReport`, an ordinary sealed bundle member whose
  digest an approval names.
- **Non-binding output** -- :class:`MatrixCell` and :class:`DefenseDependence` carry advisory or
  pinned-stochastic provenance by type (they cannot be constructed as ``deterministic``), and
  :class:`AdjudicationRecord` is a human label that is deliberately *not* a
  :data:`~purpleloop.schemas.phase3.VerdictProvenance` value at all. The gate boundary refuses all
  three by type (``reporting.gates``).

Everything is additive. Manifest 1.0-1.4 and scenario 1.1-1.3 documents never carry these
fields, and every new field on an existing model defaults to ``None``, so their canonical bytes
-- and therefore their signatures and seed hashes -- are unchanged. Signing reuses the
Ed25519/JCS construction of ADR 0002 and ADR 0012 (``control.phase5_signing``); nothing here is
new cryptography.

This module must not import ``schemas.phase1`` or ``schemas.authorization``: both import it.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from purpleloop.schemas.action import BudgetRequest
from purpleloop.schemas.common import StrictModel, require_identifier, require_utc
from purpleloop.schemas.phase3 import ModelPin, Scored

#: Lowercase SHA-256 hex, the digest format every signed reference in the project uses.
DIGEST_PATTERN = r"^[0-9a-f]{64}$"
SCENARIO_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
_SCENARIO_ID = re.compile(SCENARIO_ID_PATTERN)


def _require_digest(value: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("digests must be lowercase SHA-256")
    return value


def _require_counts(values: dict[str, int]) -> dict[str, int]:
    for key, count in values.items():
        require_identifier(key)
        if count < 1:
            raise ValueError("a recorded count must be positive; omit keys that never occurred")
    return values


# --- action classes and capability increases ---------------------------------------------------


class ActionClass(StrEnum):
    """The closed, ordered set of action classes an engagement may exercise.

    The order is ``read < write < external-send < code-exec`` and is exposed through
    :attr:`rank` rather than through ``<``: these are ``str`` values, and overriding string
    comparison would change how they sort everywhere else (including canonical bytes).
    """

    READ = "read"
    WRITE = "write"
    EXTERNAL_SEND = "external-send"
    CODE_EXEC = "code-exec"

    @property
    def rank(self) -> int:
        return ACTION_CLASS_ORDER.index(self)


ACTION_CLASS_ORDER: tuple[ActionClass, ...] = (
    ActionClass.READ,
    ActionClass.WRITE,
    ActionClass.EXTERNAL_SEND,
    ActionClass.CODE_EXEC,
)


def highest_action_class(classes: Iterable[ActionClass]) -> ActionClass | None:
    """The most capable class in ``classes``, or ``None`` for an empty set."""
    ranked = sorted(classes, key=lambda item: item.rank)
    return ranked[-1] if ranked else None


class CapabilityIncrease(StrEnum):
    """Every kind of autonomy or action-class increase, as a closed enum (plan §2.2).

    ``capability_delta`` (WP5.1) maps two manifests to a set of these, and treats any change it
    does not recognize as a narrowing as an increase -- fail closed. This module defines only the
    vocabulary; the function that computes it is not a schema concern.
    """

    NEW_ACTION_CLASS = "new-action-class"
    NEW_ADAPTER_OR_OPERATION = "new-adapter-or-operation"
    NEW_TARGET_FIXTURE = "new-target-fixture"
    WIDENED_EGRESS = "widened-egress"
    RAISED_ATTACKER_CAPS = "raised-attacker-caps"
    PROPOSAL_SOURCE_CHANGE = "proposal-source-change"


CAPABILITY_INCREASES: tuple[CapabilityIncrease, ...] = tuple(CapabilityIncrease)


# --- manifest 1.5 ------------------------------------------------------------------------------

RunMode = Literal["execute", "shadow"]
#: Where adaptive-attacker proposals come from, in increasing order of autonomy (WP5.1). Absent
#: in a manifest means ``bounded-search``: the deterministic mutation search of Phase 3, which
#: is the v1 surface. ``model-driven`` is the optional profile ``control.attacker`` promised.
ProposalSource = Literal["bounded-search", "model-driven"]
PROPOSAL_SOURCE_ORDER: tuple[ProposalSource, ...] = ("bounded-search", "model-driven")


class LoopGuardGrant(StrictModel):
    """The signed thresholds of the kernel's runaway-loop detector (ADR 0018, loose end 5.3).

    ``repeat_limit`` (N): the N-th occurrence, within one stage, of the same action-state hash --
    the same canonical action taken while the kernel's observed-state digest is unchanged -- is
    refused before dispatch and ends the run. ``no_progress_limit`` (K): K consecutive actions in
    one stage that change nothing the kernel has observed end the run after the K-th. Both are
    stop rules: they can only end a run sooner, never let it do anything its surface does not
    already allow, which is why ``capability_delta`` classifies the grant as not-a-capability.
    The upper bounds keep a signed value meaningful: a limit above every structural cap the
    manifest can sign would be the detector switched off under another name.
    """

    repeat_limit: int = Field(ge=2, le=64)
    no_progress_limit: int = Field(ge=1, le=256)


class Phase5Grants(StrictModel):
    """Manifest 1.5 additions.

    ``run_mode`` defaults to ``execute`` so a 1.5 manifest behaves as 1.4 did unless it asks to
    shadow. ``risk_approvals`` names, by digest, the signed :class:`RiskApproval` documents that
    cover this manifest's capability delta; an empty set means the manifest claims no increase
    over the approved baseline, which WP5.1's admission check verifies rather than trusts.
    ``telemetry`` is absent by default -- no export -- and when present must name a signed asset.
    """

    action_classes: frozenset[ActionClass] = Field(min_length=1)
    risk_approvals: frozenset[str] = frozenset()
    run_mode: RunMode = "execute"
    #: The signed :class:`EvaluationMatrix` digest authorized for unattended spend, if any.
    matrix_scope: str | None = Field(default=None, pattern=DIGEST_PATTERN)
    #: The collector asset id; it must be one of the manifest's signed assets.
    telemetry: str | None = None
    #: The attacker's proposal source (WP5.1). ``None`` is ``bounded-search``; the field defaults
    #: to ``None`` so every 1.5 document written before it existed keeps its canonical bytes.
    proposal_source: ProposalSource | None = None
    #: The runaway-loop detector's thresholds (ADR 0018). ``None`` -- every 1.5 document written
    #: before the field existed -- leaves the detector disarmed, exactly as for manifests 1.0-1.4,
    #: so their canonical bytes and every pinned outcome are unchanged.
    loop_guard: LoopGuardGrant | None = None

    @field_validator("risk_approvals")
    @classmethod
    def validate_approvals(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(_require_digest(value) for value in values)

    @field_validator("telemetry")
    @classmethod
    def validate_telemetry(cls, value: str | None) -> str | None:
        return require_identifier(value) if value is not None else None


# --- shadow report -----------------------------------------------------------------------------


class ShadowReport(StrictModel):
    """What a shadow run decided, without anything having executed (plan §2.2).

    An ordinary sealed bundle member; a :class:`RiskApproval` names its :meth:`report_digest`.
    ``adapter_calls`` is typed as the literal ``0``: a shadow run that reached an adapter cannot
    produce a report at all, which is the fail-closed reading of a leaking shadow.
    ``unreachable_steps`` is the stated representativeness limit -- steps that depend on a
    response nothing produced -- recorded rather than estimated away.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    run_id: str
    engagement_id: str
    #: Digest of the shadow-mode manifest the run was admitted under.
    manifest_digest: str = Field(pattern=DIGEST_PATTERN)
    scenario_digests: tuple[str, ...] = ()
    action_classes_reached: frozenset[ActionClass]
    #: Operation -> number of times it was proposed (by a plan or by a proposal source).
    operations_proposed: dict[str, int] = Field(default_factory=dict)
    #: Reason code -> number of policy, admission, or budget denials with that code.
    denials_by_reason: dict[str, int] = Field(default_factory=dict)
    #: Budget the run would have consumed had every permitted action executed.
    would_be_budget: BudgetRequest
    proposals_total: int = Field(ge=0)
    proposals_rejected: int = Field(ge=0)
    proposal_rejection_rate: float = Field(ge=0.0, le=1.0)
    #: Would-be executions recorded as suppressed instead of dispatched.
    suppressed_executions: int = Field(ge=0)
    unreachable_steps: int = Field(ge=0)
    adapter_calls: Literal[0] = 0
    created_at: datetime
    #: Action-state hashes that reached the signed repeat limit during the walk -- runs an armed
    #: loop guard (ADR 0018) would have stopped. ``None`` when there were none, so every report
    #: written before the field existed, and every report of a clean walk, keeps its digest.
    would_be_loops: int | None = Field(default=None, ge=1)

    @field_validator("run_id", "engagement_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("scenario_digests")
    @classmethod
    def validate_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_require_digest(value) for value in values)

    @field_validator("operations_proposed", "denials_by_reason")
    @classmethod
    def validate_counts(cls, values: dict[str, int]) -> dict[str, int]:
        return _require_counts(values)

    @field_validator("created_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @model_validator(mode="after")
    def validate_rate(self) -> ShadowReport:
        if self.proposals_rejected > self.proposals_total:
            raise ValueError("rejected proposals cannot exceed proposals made")
        expected = self.proposals_rejected / self.proposals_total if self.proposals_total else 0.0
        if not math.isclose(self.proposal_rejection_rate, expected, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("proposal rejection rate must equal rejected / total")
        return self

    def report_digest(self) -> str:
        return self.digest()


# --- signed records ----------------------------------------------------------------------------


class SignedRecord(StrictModel):
    """Base for Phase 5 documents a human signs: Ed25519 over JCS bytes without ``signature``.

    The same construction as :meth:`AuthorizationManifest.signed_bytes` (ADR 0002) and
    :meth:`RunAttestation.signed_bytes` (ADR 0012). Sign and verify through
    ``purpleloop.control.phase5_signing``.
    """

    signature: str

    @property
    def signing_key_id(self) -> str:  # pragma: no cover - every subclass overrides it
        raise NotImplementedError

    def signed_bytes(self) -> bytes:
        return self.canonical_bytes(exclude={"signature"})

    def record_digest(self) -> str:
        """The digest other documents reference: canonical bytes without the signature."""
        return self.digest(exclude={"signature"})


class RiskApproval(SignedRecord):
    """A human's signed grant of one exact capability increase, on named shadow evidence.

    Binding, so an approval cannot be replayed onto a different manifest:

    - ``engagement_id`` -- the engagement it was granted for;
    - ``baseline_digest`` -- the approved capability surface the delta was computed against;
    - ``manifest_surface_digest`` -- the requested manifest's
      :meth:`AuthorizationManifest.capability_surface_digest`, i.e. its digest with its own
      approval list removed (the manifest names the approval, so the approval cannot name the
      full manifest digest without a cycle);
    - ``capability_delta`` -- the exact increase set; :meth:`covers` is set equality;
    - ``shadow_report_digest`` -- the :class:`ShadowReport` it was granted on.

    ``approver_key_id`` must never be a key that may attest or sign the manifest it covers; the
    check is ``control.phase5_signing.require_key_separation``. No model, attacker, or judge
    component produces one of these; the kernel only verifies them.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    approval_id: str
    engagement_id: str
    baseline_digest: str = Field(pattern=DIGEST_PATTERN)
    manifest_surface_digest: str = Field(pattern=DIGEST_PATTERN)
    capability_delta: frozenset[CapabilityIncrease] = Field(min_length=1)
    shadow_report_digest: str = Field(pattern=DIGEST_PATTERN)
    #: Who approved, in plain words. A key id is not a person; this field says who held it.
    approver: str = Field(min_length=1, max_length=200)
    approver_key_id: str
    issued_at: datetime
    expires_at: datetime
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("approval_id", "engagement_id", "approver_key_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @model_validator(mode="after")
    def validate_window(self) -> RiskApproval:
        if self.expires_at <= self.issued_at:
            raise ValueError("an approval must expire after it is issued")
        return self

    @property
    def signing_key_id(self) -> str:
        return self.approver_key_id

    def approval_digest(self) -> str:
        return self.record_digest()

    def covers(self, delta: frozenset[CapabilityIncrease]) -> bool:
        """Exact coverage: the approval names precisely this delta, no more and no less."""
        return frozenset(delta) == self.capability_delta


# --- evaluation matrix -------------------------------------------------------------------------

#: The deterministic stand-ins that anchor every real-model row (plan §2.3).
AnchorModel = Literal["scripted-compliant", "delimitation-blind", "hostile"]
MatrixRowKind = Literal["deterministic-anchor", "real-pin"]
DecodingLabel = Literal["sampled", "greedy"]


class MatrixRow(StrictModel):
    """One model row: a pin with its decoding, and the seed for each repetition.

    A real pin at temperature 0 is labelled ``greedy`` and a sampled one ``sampled``; the label
    is validated against the decoding so a greedy measurement can never be reported as sampled.
    """

    row_id: str
    kind: MatrixRowKind
    anchor: AnchorModel | None = None
    pin: ModelPin
    seeds: tuple[int, ...] = Field(min_length=1)
    decoding_label: DecodingLabel
    #: Declared wall time per model call, for the pre-flight wall-time estimate (WP5.2). Signed
    #: with the spec so the time a run may take is authority, like its cost. The pre-flight
    #: refuses a real pin without one rather than estimating its time as zero; an anchor row
    #: runs in process and leaves it unset. Absent, it adds nothing to the canonical bytes.
    expected_seconds_per_call: float | None = Field(default=None, gt=0.0, le=3600.0)

    @field_validator("row_id")
    @classmethod
    def validate_row(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("seeds")
    @classmethod
    def validate_seeds(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(seed < 0 or seed > 2**32 - 1 for seed in values):
            raise ValueError("seeds must be 32-bit unsigned integers")
        if len(values) != len(set(values)):
            raise ValueError("repetition seeds must be distinct")
        return values

    @model_validator(mode="after")
    def validate_kind(self) -> MatrixRow:
        if (self.kind == "deterministic-anchor") != (self.anchor is not None):
            raise ValueError("a deterministic-anchor row names its anchor; a real pin does not")
        if self.kind == "deterministic-anchor" and self.pin.provider != "offline":
            raise ValueError("a deterministic anchor runs on the offline provider only")
        if self.kind == "real-pin" and self.pin.provider == "offline":
            raise ValueError("a real-pin row must name a real model provider")
        greedy = self.pin.decoding.temperature == 0.0
        if greedy != (self.decoding_label == "greedy"):
            raise ValueError("decoding label must match the pin's temperature")
        return self


ContrastFamily = Literal["each-defense-vs-baseline"]


class EvaluationMatrix(SignedRecord):
    """The signed models x defenses spec: spend authority and pre-registration as data.

    The contrast family is fixed before the first run: per row, each non-baseline defense column
    against ``baseline_column``, paired by scenario, McNemar's exact test, Holm-corrected at
    ``alpha``. Anything else a report shows is exploratory. ``cost_cap_microusd`` is checked by a
    pre-flight estimate before the first call (WP5.2).
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    matrix_id: str
    engagement_id: str
    rows: tuple[MatrixRow, ...] = Field(min_length=1)
    defense_columns: tuple[str, ...] = Field(min_length=2)
    baseline_column: str
    scenario_ids: frozenset[str] = Field(min_length=1)
    repetitions: int = Field(ge=5, le=100)
    cost_cap_microusd: int = Field(ge=0, le=1_000_000_000)
    #: The pre-flight wall-time cap (WP5.2), checked beside the cost cap before the first call.
    #: Optional so the 1.0 reference document keeps its canonical bytes; the pre-flight refuses
    #: a spec with a real-pin row and no cap.
    wall_time_cap_seconds: int | None = Field(default=None, ge=1, le=30 * 24 * 3600)
    #: Why ``scenario_ids`` is the subset it is, when it is one (plan open question 4): the cut
    #: is written into the signed spec, never applied after a run.
    subset_rationale: str | None = Field(default=None, min_length=1, max_length=2000)
    alpha: float = Field(gt=0.0, lt=1.0)
    contrast_family: ContrastFamily = "each-defense-vs-baseline"
    contrast_test: Literal["mcnemar-exact"] = "mcnemar-exact"
    correction: Literal["holm"] = "holm"
    issued_at: datetime
    key_id: str

    @field_validator("matrix_id", "engagement_id", "baseline_column", "key_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("defense_columns")
    @classmethod
    def validate_columns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("defense columns must be unique")
        return tuple(require_identifier(value) for value in values)

    @field_validator("scenario_ids")
    @classmethod
    def validate_scenarios(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            if not _SCENARIO_ID.fullmatch(value):
                raise ValueError("scenario ids must be canonical scenario identifiers")
        return values

    @field_validator("issued_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @model_validator(mode="after")
    def validate_matrix(self) -> EvaluationMatrix:
        ids = [row.row_id for row in self.rows]
        if len(ids) != len(set(ids)):
            raise ValueError("matrix row ids must be unique")
        if self.baseline_column not in self.defense_columns:
            raise ValueError("the baseline column must be one of the defense columns")
        if any(len(row.seeds) != self.repetitions for row in self.rows):
            raise ValueError("every row needs exactly one seed per repetition")
        if not any(row.anchor == "delimitation-blind" for row in self.rows):
            # Defense dependence is defined by credit under the delimitation-blind stand-in; a
            # matrix without that row cannot classify anything as model-independent.
            raise ValueError("the matrix must include the delimitation-blind anchor row")
        return self

    @property
    def signing_key_id(self) -> str:
        return self.key_id

    def matrix_digest(self) -> str:
        return self.record_digest()

    def registered_contrasts(self) -> tuple[tuple[str, str], ...]:
        """``(row_id, defense_column)`` for every pre-registered contrast, in spec order."""
        return tuple(
            (row.row_id, column)
            for row in self.rows
            for column in self.defense_columns
            if column != self.baseline_column
        )


#: Matrix output is never binding. Narrower than ``VerdictProvenance`` on purpose: a
#: ``deterministic`` matrix cell does not validate.
NonBindingProvenance = Literal["advisory", "pinned-stochastic"]
MatrixMetric = Literal["attack-success-rate", "utility-rate"]


class MatrixCell(Scored):
    """One matrix cell: a rate with its n, interval, pin, and seed policy.

    ``value`` must equal ``successes / n`` and lie inside its interval, so a cell's headline number
    cannot be edited without its evidence counts. Provenance is advisory or pinned-stochastic by
    type; ``require_binding`` and the gate input checks refuse it.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    provenance: NonBindingProvenance = "pinned-stochastic"
    matrix_digest: str = Field(pattern=DIGEST_PATTERN)
    row_id: str
    defense_column: str
    scenario_id: str = Field(pattern=SCENARIO_ID_PATTERN)
    metric: MatrixMetric = "attack-success-rate"
    successes: int = Field(ge=0)
    n: int = Field(ge=1)
    value: float = Field(ge=0.0, le=1.0)
    ci_low: float = Field(ge=0.0, le=1.0)
    ci_high: float = Field(ge=0.0, le=1.0)
    interval_method: Literal["wilson", "clopper-pearson"] = "wilson"
    model_pin_id: str
    seed_policy: str = Field(min_length=1, max_length=200)
    #: Repetitions requested but without a result, reported beside the number.
    excluded: int = Field(default=0, ge=0)
    #: True for anything outside the pre-registered contrast family.
    exploratory: bool = False

    @field_validator("row_id", "defense_column", "model_pin_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @model_validator(mode="after")
    def validate_cell(self) -> MatrixCell:
        if self.successes > self.n:
            raise ValueError("successes cannot exceed n")
        if not math.isclose(self.value, self.successes / self.n, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("a cell's value must equal successes / n")
        if not self.ci_low <= self.value <= self.ci_high:
            raise ValueError("a cell's value must lie inside its interval")
        return self


DependenceClass = Literal["model-independent", "model-dependent", "ineffective"]
EnforcementKind = Literal["application-side", "prompt-only"]


def classify_dependence(credited: frozenset[str], uncredited: frozenset[str]) -> DependenceClass:
    """The headline classification (plan §2.3), from which rows credited the defense.

    Model-independent when credited under every evaluated row, ineffective when credited under
    none, model-dependent otherwise.
    """
    if not credited and not uncredited:
        raise ValueError("a classification needs at least one evaluated row")
    if not uncredited:
        return "model-independent"
    if not credited:
        return "ineffective"
    return "model-dependent"


class DefenseDependence(Scored):
    """Whether one defense still works, on one scenario, when the model stops cooperating.

    The classification is validated against the evidence counts it summarizes, and the
    delimitation-blind row must be among the evaluated rows, so "model-independent" cannot be
    claimed without the row that defines it. Advisory by type, never binding.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    provenance: NonBindingProvenance = "advisory"
    matrix_digest: str = Field(pattern=DIGEST_PATTERN)
    defense_column: str
    scenario_id: str = Field(pattern=SCENARIO_ID_PATTERN)
    enforcement: EnforcementKind
    classification: DependenceClass
    credited_rows: frozenset[str]
    uncredited_rows: frozenset[str]
    delimitation_blind_row: str
    #: Trials summed across every evaluated row.
    trials: int = Field(ge=1)

    @field_validator("defense_column", "delimitation_blind_row")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("credited_rows", "uncredited_rows")
    @classmethod
    def validate_rows(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(require_identifier(value) for value in values)

    @model_validator(mode="after")
    def validate_classification(self) -> DefenseDependence:
        if self.credited_rows & self.uncredited_rows:
            raise ValueError("a row cannot both credit and fail to credit a defense")
        evaluated = self.credited_rows | self.uncredited_rows
        if self.delimitation_blind_row not in evaluated:
            raise ValueError("the delimitation-blind row must be among the evaluated rows")
        if self.trials < len(evaluated):
            raise ValueError("every evaluated row needs at least one trial")
        if classify_dependence(self.credited_rows, self.uncredited_rows) != self.classification:
            raise ValueError("classification does not follow from the credited rows")
        return self


# --- adjudication record -----------------------------------------------------------------------

AdjudicationLabel = Literal["true-positive", "false-positive", "cannot-tell"]


class AdjudicationRecord(SignedRecord):
    """A human's signed label on one finding, stored beside -- never inside -- its bundle.

    Deliberately not a :class:`~purpleloop.schemas.phase3.Scored` value: a human label is not a
    verdict of any provenance. It feeds the precision checkpoint and never a gate; the gate input
    checks refuse it by type. ``blinded`` records whether the oracle's verdict was hidden while
    the label was chosen.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    finding_id: str
    bundle_digest: str = Field(pattern=DIGEST_PATTERN)
    label: AdjudicationLabel
    rationale: str = Field(min_length=1, max_length=4000)
    cited_evidence_ids: tuple[str, ...] = ()
    blinded: bool
    reviewer_key_id: str
    recorded_at: datetime

    @field_validator("finding_id", "reviewer_key_id")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        return require_identifier(value)

    @field_validator("cited_evidence_ids")
    @classmethod
    def validate_evidence(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(require_identifier(value) for value in values)

    @field_validator("recorded_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return require_utc(value)

    @model_validator(mode="after")
    def validate_citation(self) -> AdjudicationRecord:
        if self.label != "cannot-tell" and not self.cited_evidence_ids:
            raise ValueError("a true- or false-positive label must cite the evidence it rests on")
        return self

    @property
    def signing_key_id(self) -> str:
        return self.reviewer_key_id


# --- scenario 1.4 ------------------------------------------------------------------------------

ScenarioOrigin = Literal["authored", "imported"]
ImportFramework = Literal["pyrit", "garak", "promptfoo", "agentdojo"]

#: Every lane a scenario may belong to. ``codelab`` is the Phase 5 second fixture (WP5.5). The
#: Phase 4 ``SmokeLane`` is a different, frozen vocabulary and is not widened.
ScenarioLane = Literal["phase1", "supportlab", "agent", "codelab"]
SCENARIO_LANES: tuple[ScenarioLane, ...] = ("phase1", "supportlab", "agent", "codelab")


class ImportSource(StrictModel):
    """Where an imported case came from, recorded at import time (WP5.6)."""

    framework: ImportFramework
    upstream_version: str | None = Field(default=None, min_length=1, max_length=200)
    upstream_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,40}$")
    license: str = Field(min_length=1, max_length=100)
    case_id: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_upstream(self) -> ImportSource:
        if self.upstream_version is None and self.upstream_commit is None:
            raise ValueError("an import source must name an upstream version or commit")
        return self


# --- contract versions -------------------------------------------------------------------------

#: Every contract this phase introduces or bumps, for ``purpleloop phase5-contracts``.
CONTRACT_VERSIONS: tuple[tuple[str, str], ...] = (
    ("authorization-manifest", "1.5.0"),
    ("scenario", "1.4.0"),
    ("risk-approval", "1.0.0"),
    ("shadow-report", "1.0.0"),
    ("evaluation-matrix", "1.0.0"),
    ("matrix-cell", "1.0.0"),
    ("defense-dependence", "1.0.0"),
    ("adjudication-record", "1.0.0"),
)
