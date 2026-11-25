"""Normalize third-party attack cases into PurpleLoop scenarios.

PyRIT, garak, Promptfoo, and AgentDojo-style corpora each carry a payload and, at most, a loose
notion of success. None of them carries what this project requires of a corpus entry: a fixture
binding, a clean utility task, a deterministic oracle, a pre-approved defense, and a ground-truth
label.

So an imported case arrives **not runnable**, with its conversion issues recorded, exactly the way
``load_scenario`` already handles a 1.0 document. It is real, citable provenance -- and it is not
counted toward the corpus until somebody supplies the missing parts. Silently promoting an
imported payload to a scored scenario would put an unlabelled, un-oracled case into a metric, and
no imported framework owns this project's schema.

Everything an importer reads is untrusted data. Payload text is carried as data and never becomes
an instruction, a URL, a selector, or an operation.

**Promotion (WP5.6).** The only way a not-runnable case becomes runnable is :func:`promote`, which
takes a hand-authored :class:`PromotionRecord`: the fixture binding, a deterministic oracle from
the closed operator set, a ground-truth label, and one recorded clearance per conversion issue.
Each clearance must quote the issue exactly and name the authored parts that resolve it, so an
oracle issue cannot be "cleared" by attaching a label. A case without a record is never promoted;
:func:`promote_subset` counts it as attempted and not promoted, with the reason.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import Field, model_validator

from purpleloop.schemas.common import StrictModel
from purpleloop.schemas.phase1 import (
    Actor,
    GroundTruth,
    GroundTruthCase,
    OracleSpec,
    Phase1Scenario,
    Step,
)
from purpleloop.schemas.phase3 import AgentTask, InjectionChannel, RiskClass
from purpleloop.schemas.phase5 import ImportFramework, ImportSource, ScenarioOrigin

#: Why an imported case cannot be scored as it stands. Recorded on every import.
BASE_ISSUES: tuple[str, ...] = (
    "imported case supplies no fixture binding; clean and attack steps must be authored",
    "imported case supplies no deterministic security or utility oracle",
    "imported case is unlabelled; ground truth must be authored before it is scored",
)

#: Issues an importer adds for a specific shortcoming of the source case.
NO_HARM_CATEGORY = "imported case declares no harm category; risk class must be authored"
STRING_DETECTOR = (
    "garak detector is a string matcher over model output, not a state oracle; "
    "a deterministic oracle must be authored"
)
LLM_RUBRIC = "imported assertion is an LLM rubric, which is advisory here, not binding"
NO_LEGITIMATE_TASK = "imported case supplies no legitimate task; utility cannot be measured"

SAFE_ID = re.compile(r"[^a-z0-9-]+")


def _identifier(source: str, raw: object, index: int) -> str:
    text = SAFE_ID.sub("-", str(raw).lower()).strip("-")
    return f"{source}-{text or index}"[:64].rstrip("-")


def _scenario(
    *,
    scenario_id: str,
    objective: str,
    attacker_objective: str,
    provenance: str,
    license_name: str,
    payload: str,
    extra_issues: tuple[str, ...] = (),
) -> Phase1Scenario:
    return Phase1Scenario(
        schema_version="1.3.0",
        scenario_id=scenario_id,
        scenario_version="1.0.0",
        fixture_seed=42,
        actor=Actor(
            schema_version="1.3.0",
            actor_id="agent-a",
            role="agent",
            tenant_id="org-a",
            credential_handle="supportlab-agent-a",
        ),
        legitimate_objective=objective[:500] or "imported case: objective not supplied",
        attacker_objective=attacker_objective[:500] or "imported case: objective not supplied",
        capabilities=frozenset({"agent.ask"}),
        clean_steps=(),
        attack_steps=(),
        # The payload is carried as recorded data on the scenario, never as a step.
        security_oracle=None,
        utility_oracle=None,
        expected_telemetry=(),
        defense_profile="retrieval-provenance-guard",
        taxonomy_mappings={},
        provenance=f"{provenance} | payload sha-bounded: {payload[:120]!r}",
        license=license_name,
        conversion_issues=(*BASE_ISSUES, *extra_issues),
    )


def from_pyrit(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """A PyRIT-shaped prompt entry: ``{"name", "value", "harm_categories", "source"}``."""
    return _scenario(
        scenario_id=_identifier("pyrit", case.get("name", index), index),
        objective="Imported PyRIT case; legitimate task not supplied",
        attacker_objective=str(case.get("name") or "unspecified PyRIT objective"),
        provenance=f"PyRIT import; upstream source: {case.get('source', 'unrecorded')}",
        license_name=str(case.get("license") or "unrecorded"),
        payload=str(case.get("value", "")),
        extra_issues=(() if case.get("harm_categories") else (NO_HARM_CATEGORY,)),
    )


def from_garak(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """A garak-shaped probe entry: ``{"probe", "prompt", "detector", "goal"}``."""
    return _scenario(
        scenario_id=_identifier("garak", case.get("probe", index), index),
        objective="Imported garak case; legitimate task not supplied",
        attacker_objective=str(case.get("goal") or "unspecified garak goal"),
        provenance=f"garak import; probe: {case.get('probe', 'unrecorded')}",
        license_name=str(case.get("license") or "unrecorded"),
        payload=str(case.get("prompt", "")),
        extra_issues=((STRING_DETECTOR,) if case.get("detector") else ()),
    )


def from_promptfoo(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """A Promptfoo-shaped test entry: ``{"description", "vars", "assert"}``."""
    variables = case.get("vars") or {}
    payload = " ".join(str(value) for value in variables.values()) if variables else ""
    assertions = case.get("assert") or []
    llm_rubric = any(
        str(item.get("type", "")).startswith("llm-")
        for item in assertions
        if isinstance(item, dict)
    )
    return _scenario(
        scenario_id=_identifier("promptfoo", case.get("description", index), index),
        objective=str(case.get("description") or "Imported Promptfoo case"),
        attacker_objective=str(case.get("description") or "unspecified Promptfoo objective"),
        provenance="Promptfoo import",
        license_name=str(case.get("license") or "unrecorded"),
        payload=payload,
        extra_issues=((LLM_RUBRIC,) if llm_rubric else ()),
    )


def from_agentdojo(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """An AgentDojo-shaped task pair: ``{"id", "user_task", "injection_task", "suite"}``.

    AgentDojo already separates the legitimate task from the attacker objective, which is the
    same split this project makes, so the conversion loses less here than elsewhere. It still
    supplies no supportlab binding and no state oracle.
    """
    return _scenario(
        scenario_id=_identifier("agentdojo", case.get("id", index), index),
        objective=str(case.get("user_task") or "Imported AgentDojo user task"),
        attacker_objective=str(case.get("injection_task") or "unspecified AgentDojo injection"),
        provenance=f"AgentDojo import; suite: {case.get('suite', 'unrecorded')}",
        license_name=str(case.get("license") or "unrecorded"),
        payload=str(case.get("injection_task", "")),
        extra_issues=(() if case.get("user_task") else (NO_LEGITIMATE_TASK,)),
    )


IMPORTERS = {
    "pyrit": from_pyrit,
    "garak": from_garak,
    "promptfoo": from_promptfoo,
    "agentdojo": from_agentdojo,
}


def import_case(framework: str, case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    try:
        importer = IMPORTERS[framework]
    except KeyError as exc:
        raise ValueError(f"no importer for framework: {framework}") from exc
    return importer(case, index=index)


# --- AgentDojo-style authored candidates --------------------------------------------------------

#: The provenance an authored AgentDojo-style candidate carries. It names the structure it borrows
#: and says, in so many words, that no upstream text was copied: it is not an import.
AGENTDOJO_STYLE_PROVENANCE = (
    "PurpleLoop authored; modelled on the AgentDojo task structure (user task + injection task, "
    "state-checked); no upstream case text copied"
)


def from_agentdojo_style(case: Mapping[str, Any], *, index: int = 0) -> Phase1Scenario:
    """An *authored* candidate in AgentDojo's shape, run through the same not-runnable path.

    Same fields as :func:`from_agentdojo`, but the result is not an import: its id is prefixed
    ``ads-`` (AgentDojo-style) rather than ``agentdojo-``, and its provenance says it was authored
    here. Deliberately not in :data:`IMPORTERS`, which lists frameworks a case can come *from*.
    """
    scenario = from_agentdojo(case, index=index)
    return scenario.model_copy(
        update={
            "scenario_id": _identifier("ads", case.get("id", index), index),
            "provenance": (
                f"{AGENTDOJO_STYLE_PROVENANCE}; suite: {case.get('suite', 'unrecorded')}; "
                f"case: {case.get('id', index)}"
            ),
        }
    )


# --- promotion ----------------------------------------------------------------------------------

#: The authored parts of a promotion record a clearance may name.
PromotionField = Literal[
    "clean_steps",
    "attack_steps",
    "agent_task",
    "injection_channel",
    "risk_class",
    "security_oracle",
    "utility_oracle",
    "defense_profile",
    "label",
]

#: What a clearance of each known issue must name. Less is refused: the oracle issue needs both
#: oracles, the binding issue needs the steps and the task, the label issue needs the label.
ISSUE_REQUIREMENTS: Mapping[str, frozenset[str]] = {
    BASE_ISSUES[0]: frozenset({"clean_steps", "attack_steps", "agent_task", "injection_channel"}),
    BASE_ISSUES[1]: frozenset({"security_oracle", "utility_oracle"}),
    BASE_ISSUES[2]: frozenset({"label"}),
    NO_HARM_CATEGORY: frozenset({"risk_class"}),
    STRING_DETECTOR: frozenset({"security_oracle"}),
    LLM_RUBRIC: frozenset({"security_oracle", "utility_oracle"}),
    NO_LEGITIMATE_TASK: frozenset({"clean_steps", "utility_oracle"}),
}

#: Provenance prefixes the importers write, and the framework each one means. A case carrying one
#: came from upstream and may only be promoted as ``origin: imported`` from that framework.
IMPORTED_PROVENANCE: Mapping[str, ImportFramework] = {
    "PyRIT import": "pyrit",
    "garak import": "garak",
    "Promptfoo import": "promptfoo",
    "AgentDojo import": "agentdojo",
}


class PromotionRefused(ValueError):
    """A record that does not make its case runnable. The case stays not-runnable."""

    reason_code = "PROMOTION_REFUSED"


class ClearedIssue(StrictModel):
    """One conversion issue, quoted exactly, and the authored parts that resolve it."""

    issue: str = Field(min_length=1, max_length=500)
    resolution: str = Field(min_length=1, max_length=1000)
    resolved_by: frozenset[PromotionField] = Field(min_length=1)


class PromotionLabel(StrictModel):
    """The ground-truth label for a promoted case: its positive and negative controls."""

    expected_findings: int = Field(ge=0, le=1)
    expected_negative_findings: int = Field(ge=0, le=1)
    rationale: str = Field(min_length=1, max_length=1000)


class PromotionRecord(StrictModel):
    """Everything a human authors to make one not-runnable case runnable.

    The oracles are ``OracleSpec``: the closed, deterministic operator set every authored scenario
    uses. There is no field for a judge rubric, an LLM assertion, or a string detector, so none
    can become the binding verdict of a promoted case.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    authored_by: str = Field(min_length=1, max_length=200)
    origin: ScenarioOrigin
    import_source: ImportSource | None = None
    public_exposure: bool
    risk_class: RiskClass
    injection_channel: InjectionChannel
    agent_task: AgentTask
    clean_steps: tuple[Step, ...] = Field(min_length=1)
    attack_steps: tuple[Step, ...] = Field(min_length=1)
    security_oracle: OracleSpec
    utility_oracle: OracleSpec
    defense_profile: str = Field(min_length=1, max_length=64)
    expected_telemetry: tuple[str, ...] = ()
    taxonomy_mappings: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    repetitions: int = Field(default=1, ge=1, le=100)
    label: PromotionLabel
    cleared: tuple[ClearedIssue, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_record(self) -> PromotionRecord:
        if (self.origin == "imported") != (self.import_source is not None):
            raise ValueError("an import source is required exactly when the origin is imported")
        if self.origin == "imported" and not self.public_exposure:
            # An upstream benchmark is published by definition; results on it may be contaminated.
            raise ValueError("an imported case is publicly exposed")
        for oracle in (self.security_oracle, self.utility_oracle):
            if not oracle.path:
                raise ValueError("an oracle must name a non-empty path; an empty one is vacuous")
        issues = [entry.issue for entry in self.cleared]
        if len(issues) != len(set(issues)):
            raise ValueError("each conversion issue is cleared exactly once")
        return self

    def record_digest(self) -> str:
        # Canonical bytes, so set-valued fields cannot make the digest depend on hash order.
        return self.digest()


class DeclinedCase(StrictModel):
    """A case an author looked at and could not promote, with the reason. Counted, never run."""

    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    reason: str = Field(min_length=1, max_length=1000)


class PromotionOutcome(StrictModel):
    scenario_id: str
    promoted: bool
    reason: str
    cleared: tuple[str, ...] = ()
    remaining_issues: tuple[str, ...] = ()
    record_digest: str | None = None


class PromotionReport(StrictModel):
    """Count promoted and count attempted, both reported (plan section 6, row 5.6).

    The counts are derived from the outcomes and checked against them, so a report cannot claim
    more promotions than it records.
    """

    schema_version: Literal["1.0.0"] = "1.0.0"
    attempted: int = Field(ge=0)
    promoted: int = Field(ge=0)
    not_promoted: int = Field(ge=0)
    outcomes: tuple[PromotionOutcome, ...]

    @model_validator(mode="after")
    def validate_counts(self) -> PromotionReport:
        promoted = sum(outcome.promoted for outcome in self.outcomes)
        if (
            self.attempted != len(self.outcomes)
            or self.promoted != promoted
            or self.not_promoted != len(self.outcomes) - promoted
        ):
            raise ValueError("promotion counts must equal the recorded outcomes")
        return self


def _upstream_framework(case: Phase1Scenario) -> ImportFramework | None:
    for prefix, framework in IMPORTED_PROVENANCE.items():
        if case.provenance.startswith(prefix):
            return framework
    return None


def promote(case: Phase1Scenario, record: PromotionRecord) -> Phase1Scenario:
    """Make one not-runnable case runnable from a hand-authored record, or refuse.

    Refused when the record names another case, when the case is already runnable (there is
    nothing to promote), when any conversion issue is left uncleared or a clearance quotes an
    issue the case does not have, when a known issue is cleared without the parts it needs, or
    when an imported case would be relabelled as authored (or the reverse). The result is a
    Scenario 1.4 document with no conversion issues, checked by ``require_runnable``.
    """
    if record.scenario_id != case.scenario_id:
        raise PromotionRefused(f"record names {record.scenario_id}, not {case.scenario_id}")
    if not case.conversion_issues:
        raise PromotionRefused("the case has no conversion issues; there is nothing to promote")
    outstanding = set(case.conversion_issues)
    for entry in record.cleared:
        if entry.issue not in outstanding:
            raise PromotionRefused(f"clearance quotes an issue the case lacks: {entry.issue}")
        missing = ISSUE_REQUIREMENTS.get(entry.issue, frozenset()) - entry.resolved_by
        if missing:
            raise PromotionRefused(f"clearance of {entry.issue!r} does not name {sorted(missing)}")
        outstanding.discard(entry.issue)
    if outstanding:
        raise PromotionRefused(f"uncleared conversion issues: {sorted(outstanding)}")
    upstream = _upstream_framework(case)
    if upstream is not None and (
        record.import_source is None or record.import_source.framework != upstream
    ):
        raise PromotionRefused(f"an imported {upstream} case must be promoted as imported from it")
    if upstream is None and record.origin == "imported":
        raise PromotionRefused("an authored case cannot be promoted as imported")
    version: Literal["1.4.0"] = "1.4.0"
    promoted = Phase1Scenario(
        schema_version=version,
        scenario_id=case.scenario_id,
        scenario_version=case.scenario_version,
        fixture_seed=case.fixture_seed,
        actor=case.actor.model_copy(update={"schema_version": version}),
        legitimate_objective=case.legitimate_objective,
        attacker_objective=case.attacker_objective,
        capabilities=case.capabilities,
        clean_steps=tuple(
            s.model_copy(update={"schema_version": version}) for s in record.clean_steps
        ),
        attack_steps=tuple(
            s.model_copy(update={"schema_version": version}) for s in record.attack_steps
        ),
        security_oracle=record.security_oracle.model_copy(update={"schema_version": version}),
        utility_oracle=record.utility_oracle.model_copy(update={"schema_version": version}),
        expected_telemetry=record.expected_telemetry,
        defense_profile=record.defense_profile,
        taxonomy_mappings=record.taxonomy_mappings,
        provenance=(
            f"{case.provenance} | promoted from hand-authored record "
            f"{record.record_digest()[:16]} by {record.authored_by}"
        ),
        license=case.license,
        conversion_issues=(),
        surface="agent",
        risk_class=record.risk_class,
        injection_channel=record.injection_channel,
        agent_task=record.agent_task,
        repetitions=record.repetitions,
        origin=record.origin,
        import_source=record.import_source,
        public_exposure=record.public_exposure,
        lane="agent",
    )
    promoted.require_runnable()
    return promoted


def promote_subset(
    cases: Sequence[Phase1Scenario],
    records: Sequence[PromotionRecord],
    declined: Sequence[DeclinedCase] = (),
) -> tuple[list[Phase1Scenario], PromotionReport]:
    """Promote what has a record, count everything, and never promote anything else.

    Every case is attempted. One with a valid record is promoted; one with a refused record, a
    recorded decline, or no record at all stays not-runnable and is counted with its reason. A
    record or decline naming a case that is not in the subset is an error, not a silent skip.
    """
    by_id = {case.scenario_id: case for case in cases}
    by_record = {record.scenario_id: record for record in records}
    by_decline = {entry.scenario_id: entry for entry in declined}
    if len(by_id) != len(cases):
        raise ValueError("candidate scenario ids must be unique")
    if len(by_record) != len(records) or len(by_decline) != len(declined):
        raise ValueError("each case has at most one promotion record and one decline")
    stale = (by_record.keys() | by_decline.keys()) - by_id.keys()
    if stale:
        raise ValueError(f"records name cases not in the subset: {sorted(stale)}")
    both = by_record.keys() & by_decline.keys()
    if both:
        raise ValueError(f"a case is both promoted and declined: {sorted(both)}")
    promoted: list[Phase1Scenario] = []
    outcomes: list[PromotionOutcome] = []
    for case in cases:
        record = by_record.get(case.scenario_id)
        if record is None:
            decline = by_decline.get(case.scenario_id)
            outcomes.append(
                PromotionOutcome(
                    scenario_id=case.scenario_id,
                    promoted=False,
                    reason=(
                        decline.reason
                        if decline is not None
                        else "no promotion record; a case is never promoted automatically"
                    ),
                    remaining_issues=case.conversion_issues,
                )
            )
            continue
        try:
            scenario = promote(case, record)
        except ValueError as exc:
            outcomes.append(
                PromotionOutcome(
                    scenario_id=case.scenario_id,
                    promoted=False,
                    reason=str(exc)[:1000],
                    remaining_issues=case.conversion_issues,
                    record_digest=record.record_digest(),
                )
            )
            continue
        promoted.append(scenario)
        outcomes.append(
            PromotionOutcome(
                scenario_id=case.scenario_id,
                promoted=True,
                reason="PROMOTED",
                cleared=tuple(entry.issue for entry in record.cleared),
                record_digest=record.record_digest(),
            )
        )
    count = sum(outcome.promoted for outcome in outcomes)
    return promoted, PromotionReport(
        attempted=len(outcomes),
        promoted=count,
        not_promoted=len(outcomes) - count,
        outcomes=tuple(outcomes),
    )


def ground_truth(
    records: Sequence[PromotionRecord], promoted: Sequence[Phase1Scenario]
) -> GroundTruth:
    """The label set for the promoted cases only, from their records' hand-authored labels."""
    ids = {scenario.scenario_id for scenario in promoted}
    return GroundTruth(
        cases=tuple(
            GroundTruthCase(
                scenario_id=record.scenario_id,
                positive_control="baseline",
                expected_findings=record.label.expected_findings,
                negative_control="defended-replay",
                expected_negative_findings=record.label.expected_negative_findings,
            )
            for record in records
            if record.scenario_id in ids
        )
    )
