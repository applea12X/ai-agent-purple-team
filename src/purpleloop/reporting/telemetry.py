"""Ledger-derived OpenTelemetry export (WP5.3, plan §2.4, ADR 0016).

The evidence ledger stays authoritative; telemetry is a projection of it. Every span and metric
here is computed from an :class:`EvidenceEvent` *after* it was redacted and appended -- from the
event :meth:`EvidenceLedger.append` returns, which is exactly what the ledger persisted. Nothing
in the adapters, the model plane, or the fixture imports this module, and a test asserts it.
Telemetry therefore cannot contain anything the ledger does not.

Telemetry is outside the trusted computing base, which inverts the kernel's fail-closed rule on
purpose: an exporter that fails, stalls, or refuses never changes an outcome, a verdict, a budget,
or a byte of the evidence ledger. The run continues and the failure is recorded as a
``TELEMETRY_EXPORT_FAILED`` lifecycle event in a separate hash-chained status ledger beside the
evidence ledger (``telemetry-status.jsonl``) -- not in the evidence ledger itself, because a
non-TCB component's health must not move the evidence chain, the replay fingerprint, or the
replay-determinism measurement. ADR 0016 records the trade-off: when an export fails, the bundle
gains that one status member, and every other member stays byte-identical.

The encoding is OTLP/JSON (``ExportTraceServiceRequest`` / ``ExportMetricsServiceRequest``),
written with the standard library. The default sink is a file of OTLP JSON lines, so no service
is required; the HTTP sink posts the same payloads to a collector that a signed Manifest 1.5
names as an asset, and to nothing else.

Names live in the versioned ``purpleloop.*`` namespace (``docs/telemetry-namespace.md``), which
is rendered from :class:`EventKind` by :func:`render_namespace_doc` so the two cannot drift. An
event kind this module has never heard of still maps -- generically, to
``purpleloop.event.<kind>`` -- because a new kind (WP5.1 adds one) must never break a run.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import math
import re
import statistics
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from pydantic import Field

from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.schemas.common import StrictModel, digest_data
from purpleloop.schemas.event import EventKind, EvidenceEvent

if TYPE_CHECKING:
    from purpleloop.control.manifest import ManifestVerifier
    from purpleloop.runtime.runner import PurpleTeamRunner
    from purpleloop.schemas.authorization import AuthorizationManifest

#: The version of the ``purpleloop.*`` span, attribute, and metric namespace. A rename, removal,
#: or change of meaning is a major bump; an added attribute is a minor bump.
NAMESPACE_VERSION = "1.0.0"
SCOPE_NAME = "purpleloop.telemetry"
SERVICE_NAME = "purpleloop"
#: Where every attribute value comes from. Resource attribute, so a collector can tell a
#: projection from a first-hand instrumentation stream.
SOURCE = "ledger-projection"

RUN_SPAN = "purpleloop.run"
STAGE_SPAN = "purpleloop.stage"
EVENT_SPAN_PREFIX = "purpleloop.event."
EVENTS_METRIC = "purpleloop.events"

#: Status-ledger reason codes. Both are LIFECYCLE events written by :data:`TELEMETRY_ACTOR`.
EXPORT_FAILED = "TELEMETRY_EXPORT_FAILED"
SPANS_DROPPED = "TELEMETRY_SPANS_DROPPED"
TELEMETRY_ACTOR = "telemetry-exporter"
#: The status ledger's file name, beside ``evidence.jsonl``; a bundle member only when a failure
#: was recorded, since the ledger file is created on its first append.
STATUS_LEDGER = "telemetry-status.jsonl"

#: Cumulative wall time one run may spend inside its exporter before the circuit opens. It bounds
#: what a slow collector can cost a run, so telemetry cannot push a run into its wall-time budget.
DEFAULT_TIME_BUDGET_SECONDS = 2.0
DEFAULT_CALL_TIMEOUT_SECONDS = 1.0
DEFAULT_BATCH_SIZE = 64

#: The label every wall-clock figure carries (plan §2.4). It is advisory and machine-specific.
WALL_CLOCK_LABEL: Literal["wall clock on this machine"] = "wall clock on this machine"

_SPAN_KIND_INTERNAL = 1
_AGGREGATION_CUMULATIVE = 2
_UNSAFE_NAME = re.compile(r"[^a-z0-9_]+")
#: Data keys projected as attribute-name segments must already be plain identifiers, so the
#: attribute name is the ledger key verbatim and never a sanitized rewrite of attacker text.
_SAFE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ATTACK_STAGES: dict[str, Literal["baseline", "replay"]] = {
    "attack": "baseline",
    "replay": "replay",
}


# --- the namespace ------------------------------------------------------------------------------


def kind_value(kind: object) -> str:
    """The wire value of an event kind, tolerating a value outside the current enum."""
    return str(getattr(kind, "value", kind))


def event_span_name(kind: object) -> str:
    """``purpleloop.event.<kind>`` for any kind, known or not.

    Generic on purpose: the mapping is a rule, not a table, so an event kind added after this
    module was written (WP5.1's ``SHADOW_SUPPRESSED``, say) projects without a code change.
    """
    token = _UNSAFE_NAME.sub("_", kind_value(kind).lower()).strip("_") or "unknown"
    return f"{EVENT_SPAN_PREFIX}{token}"


#: Every current event kind and its span name, generated from the enum.
SPAN_NAMES: Mapping[str, str] = {kind.value: event_span_name(kind) for kind in EventKind}


@dataclass(frozen=True)
class AttributeSpec:
    name: str
    type: str
    applies_to: str
    source: str


ATTRIBUTES: tuple[AttributeSpec, ...] = (
    AttributeSpec("service.name", "string", "resource", f"constant `{SERVICE_NAME}`"),
    AttributeSpec(
        "purpleloop.telemetry.namespace_version", "string", "resource", "`NAMESPACE_VERSION`"
    ),
    AttributeSpec("purpleloop.telemetry.source", "string", "resource", f"constant `{SOURCE}`"),
    AttributeSpec("purpleloop.run.id", "string", "resource, run span", "`run_id`"),
    AttributeSpec("purpleloop.manifest.digest", "string", "resource", "`manifest_digest`"),
    AttributeSpec("purpleloop.policy.digest", "string", "resource", "`policy_digest`"),
    AttributeSpec("purpleloop.scenario.id", "string", "run span", "`scenario_id`"),
    AttributeSpec("purpleloop.scenario.version", "string", "run span", "`scenario_version`"),
    AttributeSpec("purpleloop.run.events", "int", "run span", "events projected"),
    AttributeSpec("purpleloop.run.terminated", "bool", "run span", "a TERMINATION event seen"),
    AttributeSpec(
        "purpleloop.run.termination_reason", "string", "run span", "TERMINATION `reason_code`"
    ),
    AttributeSpec("purpleloop.run.status", "string", "run span", "TERMINATION `data.status`"),
    AttributeSpec("purpleloop.stage.name", "string", "stage span", "`stage`"),
    AttributeSpec("purpleloop.stage.events", "int", "stage span", "events in the stage"),
    AttributeSpec("purpleloop.event.kind", "string", "event span", "`kind`"),
    AttributeSpec("purpleloop.event.sequence", "int", "event span", "`sequence`"),
    AttributeSpec("purpleloop.event.hash", "string", "event span", "`event_hash`"),
    AttributeSpec("purpleloop.event.parent_hash", "string", "event span", "`parent_hash`"),
    AttributeSpec("purpleloop.event.actor", "string", "event span", "`actor`"),
    AttributeSpec("purpleloop.event.trace", "string", "event span", "`trace_id`"),
    AttributeSpec("purpleloop.event.stage", "string", "event span", "`stage`"),
    AttributeSpec("purpleloop.event.decision", "string", "event span", "`decision`"),
    AttributeSpec("purpleloop.event.reason_code", "string", "event span", "`reason_code`"),
    AttributeSpec("purpleloop.event.action_digest", "string", "event span", "`action_digest`"),
    AttributeSpec("purpleloop.event.schema_version", "string", "event span", "`schema_version`"),
    AttributeSpec(
        "purpleloop.event.component_version", "string", "event span", "`component_version`"
    ),
    AttributeSpec("purpleloop.event.data_digest", "string", "event span", "SHA-256 of JCS(`data`)"),
    AttributeSpec(
        "purpleloop.event.data_keys", "string[]", "event span", "identifier keys of `data`"
    ),
    AttributeSpec(
        "purpleloop.data.<key>[.<key>]",
        "int, double, or bool",
        "event span",
        "numeric or boolean `data` leaves, depth ≤ 2, identifier keys only",
    ),
    AttributeSpec(
        "purpleloop.detector.rules_observed",
        "string[]",
        "detector event span",
        "`data.results[].rule_id` where `observed`",
    ),
    AttributeSpec(
        "purpleloop.detector.time_to_detect_ticks",
        "int[]",
        "detector event span",
        "`data.results[].time_to_detect`, aligned with `rules_observed`",
    ),
    AttributeSpec(
        "purpleloop.event.kind, purpleloop.event.decision",
        "string",
        f"`{EVENTS_METRIC}` data point",
        "count of ledger events with that kind and decision",
    ),
)

_DOC_BEGIN = "<!-- BEGIN GENERATED: purpleloop telemetry-namespace -->"
_DOC_END = "<!-- END GENERATED -->"


def render_namespace_tables() -> str:
    """The generated part of ``docs/telemetry-namespace.md``."""
    lines = [
        _DOC_BEGIN,
        "",
        f"Namespace version **{NAMESPACE_VERSION}**, instrumentation scope `{SCOPE_NAME}`.",
        "",
        "### Spans",
        "",
        "| Span name | One per | Parent |",
        "| --- | --- | --- |",
        f"| `{RUN_SPAN}` | run (`run_id`) | — |",
        f"| `{STAGE_SPAN}` | run of consecutive events in one `stage` | `{RUN_SPAN}` |",
        "",
        "### Event spans, generated from `EventKind`",
        "",
        "| `EventKind` | Wire value | Span name |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| `{kind.name}` | `{kind.value}` | `{SPAN_NAMES[kind.value]}` |" for kind in EventKind
    )
    lines.extend(
        [
            f"| *(any other value)* | `<kind>` | `{EVENT_SPAN_PREFIX}<kind>` (lower-cased, "
            "`[a-z0-9_]` only) |",
            "",
            "### Attributes",
            "",
            "| Attribute | Type | On | Ledger source |",
            "| --- | --- | --- | --- |",
        ]
    )
    lines.extend(
        f"| `{spec.name}` | {spec.type} | {spec.applies_to} | {spec.source} |"
        for spec in ATTRIBUTES
    )
    lines.extend(
        [
            "",
            "### Metrics",
            "",
            "| Metric | Instrument | Unit |",
            "| --- | --- | --- |",
            f"| `{EVENTS_METRIC}` | cumulative monotonic sum, one point per (kind, decision) "
            "| `{event}` |",
            "",
            "### Status-ledger reason codes (LIFECYCLE events, `telemetry-status.jsonl`)",
            "",
            f"- `{EXPORT_FAILED}` — the first export failure of a run; the circuit opens.",
            f"- `{SPANS_DROPPED}` — at termination, how many spans and metric payloads were "
            "never exported.",
            "",
            _DOC_END,
        ]
    )
    return "\n".join(lines) + "\n"


def namespace_doc_drift(document: str) -> bool:
    """True when ``document``'s generated block differs from :func:`render_namespace_tables`."""
    if _DOC_BEGIN not in document or _DOC_END not in document:
        return True
    start = document.index(_DOC_BEGIN)
    end = document.index(_DOC_END) + len(_DOC_END)
    return document[start:end] + "\n" != render_namespace_tables()


def render_namespace_doc(document: str) -> str:
    """``document`` with its generated block replaced by the current one."""
    start = document.index(_DOC_BEGIN)
    end = document.index(_DOC_END) + len(_DOC_END)
    return document[:start] + render_namespace_tables().rstrip("\n") + document[end:]


# --- OTLP/JSON encoding -------------------------------------------------------------------------

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def unix_nanos(timestamp: datetime) -> int:
    """Exact integer nanoseconds; microsecond timestamps never round through a float."""
    return (timestamp - _EPOCH) // timedelta(microseconds=1) * 1000


def _any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [_any_value(item) for item in value]}}
    return {"stringValue": str(value)}


def attributes(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    """OTLP key-value list, keys sorted, ``None`` values left out."""
    return [
        {"key": key, "value": _any_value(value)}
        for key, value in sorted(values.items())
        if value is not None
    ]


def _hex_id(seed: str, length: int) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:length]


def _scope() -> dict[str, str]:
    return {"name": SCOPE_NAME, "version": NAMESPACE_VERSION}


def encode_traces(resource: Mapping[str, Any], spans: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": attributes(resource)},
                "scopeSpans": [{"scope": _scope(), "spans": list(spans)}],
            }
        ]
    }


def encode_metrics(
    resource: Mapping[str, Any], metrics: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "resourceMetrics": [
            {
                "resource": {"attributes": attributes(resource)},
                "scopeMetrics": [{"scope": _scope(), "metrics": list(metrics)}],
            }
        ]
    }


def _numeric_leaves(data: Mapping[str, Any]) -> dict[str, Any]:
    leaves: dict[str, Any] = {}
    for key, value in data.items():
        if not _SAFE_KEY.fullmatch(str(key)):
            continue
        if isinstance(value, (bool, int)) or (isinstance(value, float) and math.isfinite(value)):
            leaves[f"purpleloop.data.{key}"] = value
        elif isinstance(value, Mapping):
            for inner, item in value.items():
                if _SAFE_KEY.fullmatch(str(inner)) and (
                    isinstance(item, (bool, int))
                    or (isinstance(item, float) and math.isfinite(item))
                ):
                    leaves[f"purpleloop.data.{key}.{inner}"] = item
    return leaves


def _detector_attributes(data: Mapping[str, Any]) -> dict[str, Any]:
    results = data.get("results")
    if not isinstance(results, list):
        return {}
    observed = [
        result
        for result in results
        if isinstance(result, Mapping)
        and result.get("observed") is True
        and isinstance(result.get("rule_id"), str)
    ]
    return {
        "purpleloop.detector.rules_observed": [result["rule_id"] for result in observed],
        "purpleloop.detector.time_to_detect_ticks": [
            int(result["time_to_detect"]) if isinstance(result.get("time_to_detect"), int) else -1
            for result in observed
        ],
    }


def event_attributes(event: EvidenceEvent) -> dict[str, Any]:
    """Every attribute of one event span. A pure function of the persisted event."""
    data = event.data
    values: dict[str, Any] = {
        "purpleloop.event.kind": kind_value(event.kind),
        "purpleloop.event.sequence": event.sequence,
        "purpleloop.event.hash": event.event_hash,
        "purpleloop.event.parent_hash": event.parent_hash,
        "purpleloop.event.actor": event.actor,
        "purpleloop.event.trace": event.trace_id,
        "purpleloop.event.stage": event.stage,
        "purpleloop.event.decision": event.decision,
        "purpleloop.event.reason_code": event.reason_code,
        "purpleloop.event.action_digest": event.action_digest,
        "purpleloop.event.schema_version": event.schema_version,
        "purpleloop.event.component_version": event.component_version,
        "purpleloop.event.data_digest": digest_data(data),
        "purpleloop.event.data_keys": sorted(key for key in data if _SAFE_KEY.fullmatch(key)),
        **_numeric_leaves(data),
    }
    if kind_value(event.kind) == EventKind.DETECTOR.value:
        values.update(_detector_attributes(data))
    return values


# --- projection ---------------------------------------------------------------------------------


def _span(
    trace_id: str,
    span_id: str,
    parent: str | None,
    name: str,
    start: datetime,
    end: datetime,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    span: dict[str, Any] = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": _SPAN_KIND_INTERNAL,
        "startTimeUnixNano": str(unix_nanos(start)),
        "endTimeUnixNano": str(unix_nanos(end)),
        "attributes": attributes(values),
        "status": {},
    }
    if parent is not None:
        span["parentSpanId"] = parent
    return span


class RunProjector:
    """Turns one run's ledger events, in order, into OTLP spans and one metrics payload.

    Incremental, so the live exporter and the after-the-fact :func:`project_events` share every
    line of it: :meth:`feed` returns the spans an event completes (its own span; the previous
    stage's span when the stage changes; the run span on TERMINATION), and :meth:`finish` closes
    whatever is still open. Identifiers are derived from ledger hashes, so the same ledger always
    projects to the same bytes.
    """

    def __init__(self) -> None:
        self.first: EvidenceEvent | None = None
        self.last: EvidenceEvent | None = None
        self.terminated: EvidenceEvent | None = None
        self.closed = False
        self.events = 0
        self.counts: Counter[tuple[str, str]] = Counter()
        self._stage: str | None = None
        self._stage_start: datetime | None = None
        self._stage_index = 0
        self._stage_events = 0

    @property
    def trace_id(self) -> str:
        assert self.first is not None
        return _hex_id(f"purpleloop-trace:{self.first.event_hash}", 32)

    @property
    def run_span_id(self) -> str:
        assert self.first is not None
        return _hex_id(f"purpleloop-run:{self.first.event_hash}", 16)

    def resource(self) -> dict[str, Any]:
        assert self.first is not None
        return {
            "service.name": SERVICE_NAME,
            "purpleloop.telemetry.namespace_version": NAMESPACE_VERSION,
            "purpleloop.telemetry.source": SOURCE,
            "purpleloop.run.id": self.first.run_id,
            "purpleloop.manifest.digest": self.first.manifest_digest,
            "purpleloop.policy.digest": self.first.policy_digest,
        }

    def accepts(self, event: EvidenceEvent) -> bool:
        return not self.closed and (self.first is None or event.run_id == self.first.run_id)

    def _stage_span_id(self) -> str:
        assert self.first is not None
        return _hex_id(f"purpleloop-stage:{self.first.event_hash}:{self._stage_index}", 16)

    def _close_stage(self, end: datetime) -> dict[str, Any]:
        assert self._stage_start is not None
        span = _span(
            self.trace_id,
            self._stage_span_id(),
            self.run_span_id,
            STAGE_SPAN,
            self._stage_start,
            end,
            {"purpleloop.stage.name": self._stage, "purpleloop.stage.events": self._stage_events},
        )
        self._stage_index += 1
        return span

    def feed(self, event: EvidenceEvent) -> list[dict[str, Any]]:
        if not self.accepts(event):
            raise ValueError("event belongs to another run or follows termination")
        completed: list[dict[str, Any]] = []
        if self.first is None:
            self.first = event
        stage = event.stage or "unstaged"
        if self._stage_start is None or stage != self._stage:
            if self._stage_start is not None:
                completed.append(self._close_stage(event.timestamp))
            self._stage, self._stage_start, self._stage_events = stage, event.timestamp, 0
        self._stage_events += 1
        self.events += 1
        self.last = event
        self.counts[(kind_value(event.kind), event.decision or "none")] += 1
        span_id = (event.event_hash or _hex_id(f"{event.run_id}:{event.sequence}", 64))[:16]
        completed.append(
            _span(
                self.trace_id,
                span_id,
                self._stage_span_id(),
                event_span_name(event.kind),
                event.timestamp,
                event.timestamp,
                event_attributes(event),
            )
        )
        if kind_value(event.kind) == EventKind.TERMINATION.value:
            self.terminated = event
            completed.extend(self.finish())
        return completed

    def finish(self) -> list[dict[str, Any]]:
        """Close the open stage span and the run span. Idempotent; empty before any event."""
        if self.closed or self.first is None or self.last is None:
            return []
        self.closed = True
        end = self.last.timestamp
        terminated = self.terminated
        status = terminated.data.get("status") if terminated is not None else None
        return [
            self._close_stage(end),
            _span(
                self.trace_id,
                self.run_span_id,
                None,
                RUN_SPAN,
                self.first.timestamp,
                end,
                {
                    "purpleloop.run.id": self.first.run_id,
                    "purpleloop.scenario.id": self.first.scenario_id,
                    "purpleloop.scenario.version": self.first.scenario_version,
                    "purpleloop.run.events": self.events,
                    "purpleloop.run.terminated": terminated is not None,
                    "purpleloop.run.termination_reason": (
                        terminated.reason_code if terminated is not None else None
                    ),
                    "purpleloop.run.status": status if isinstance(status, str) else None,
                },
            ),
        ]

    def metrics(self) -> list[dict[str, Any]]:
        if self.first is None or self.last is None:
            return []
        start, now = str(unix_nanos(self.first.timestamp)), str(unix_nanos(self.last.timestamp))
        points = [
            {
                "attributes": attributes(
                    {"purpleloop.event.kind": kind, "purpleloop.event.decision": decision}
                ),
                "startTimeUnixNano": start,
                "timeUnixNano": now,
                "asInt": str(count),
            }
            for (kind, decision), count in sorted(self.counts.items())
        ]
        return [
            {
                "name": EVENTS_METRIC,
                "unit": "{event}",
                "description": "Evidence-ledger events by kind and decision.",
                "sum": {
                    "aggregationTemporality": _AGGREGATION_CUMULATIVE,
                    "isMonotonic": True,
                    "dataPoints": points,
                },
            }
        ]


@dataclass
class Projection:
    """Every payload a ledger projects to, in export order."""

    payloads: list[tuple[Literal["traces", "metrics"], dict[str, Any]]] = field(
        default_factory=list
    )

    @property
    def spans(self) -> list[dict[str, Any]]:
        return export_spans(payload for signal, payload in self.payloads if signal == "traces")


def _payload_spans(payload: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    for resource_spans in payload.get("resourceSpans", []):
        for scope_spans in resource_spans.get("scopeSpans", []):
            yield from scope_spans.get("spans", [])


def project_events(events: Iterable[EvidenceEvent]) -> Projection:
    """The whole projection of a ledger, one trace payload and one metrics payload per run.

    The after-the-fact counterpart of :class:`TelemetryLedger`: the spans are identical; only
    the batching differs (the live path may split a run's spans across several payloads).
    """
    projection = Projection()
    projector = RunProjector()
    spans: list[dict[str, Any]] = []

    def close() -> None:
        nonlocal spans
        spans.extend(projector.finish())
        if projector.first is not None:
            projection.payloads.append(("traces", encode_traces(projector.resource(), spans)))
            projection.payloads.append(
                ("metrics", encode_metrics(projector.resource(), projector.metrics()))
            )
        spans = []

    for event in events:
        if not projector.accepts(event):
            close()
            projector = RunProjector()
        spans.extend(projector.feed(event))
    close()
    return projection


# --- exporters ----------------------------------------------------------------------------------


class TelemetryExportError(RuntimeError):
    """An export did not complete. ``reason_code`` is bounded and carries no payload content."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class TelemetryNotAuthorized(ValueError):
    reason_code = "TELEMETRY_NOT_AUTHORIZED"


class TelemetryExporter(Protocol):
    #: A non-secret description of the sink, recorded on failure (never a path or a URL).
    sink: str

    def export(
        self, signal: Literal["traces", "metrics"], payload: dict[str, Any], *, timeout: float
    ) -> None: ...


def _line(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


class FileExporter:
    """OTLP JSON lines appended to a local file -- the default sink; no service, no egress."""

    sink = "otlp-json-file"

    def __init__(self, path: Path) -> None:
        self.path = path

    def export(
        self, signal: Literal["traces", "metrics"], payload: dict[str, Any], *, timeout: float
    ) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(_line(payload))
        except OSError as exc:
            raise TelemetryExportError("FILE_WRITE_FAILED") from exc


class OtlpHttpExporter:
    """OTLP/HTTP JSON to the collector a signed Manifest 1.5 names, and nowhere else.

    The only way to build one is :meth:`from_manifest`: the endpoint is read from the signed
    asset that ``phase5.telemetry`` names, after the manifest's signature and validity are
    verified. A URL is never accepted, so telemetry cannot become a new egress path.
    """

    def __init__(self, *, asset_id: str, host: str, port: int) -> None:
        self.sink = f"otlp-http:{asset_id}"
        self.host = host
        self.port = port

    @classmethod
    def from_manifest(
        cls,
        manifest: AuthorizationManifest,
        verifier: ManifestVerifier,
        *,
        now: datetime | None = None,
    ) -> OtlpHttpExporter:
        verifier.verify(manifest, now=now)
        grants = manifest.phase5
        if grants is None or grants.telemetry is None:
            raise TelemetryNotAuthorized("the manifest grants no telemetry collector")
        asset = next(asset for asset in manifest.assets if asset.asset_id == grants.telemetry)
        if asset.scheme != "http":
            raise TelemetryNotAuthorized("the collector asset must speak OTLP over loopback http")
        return cls(asset_id=asset.asset_id, host=asset.host, port=asset.port)

    def export(
        self, signal: Literal["traces", "metrics"], payload: dict[str, Any], *, timeout: float
    ) -> None:
        body = _line(payload).encode("ascii")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        try:
            connection.request(
                "POST", f"/v1/{signal}", body=body, headers={"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            response.read(65536)
            if not 200 <= response.status < 300:
                raise TelemetryExportError(f"HTTP_{response.status}")
        except TelemetryExportError:
            raise
        except TimeoutError as exc:
            raise TelemetryExportError("TIMEOUT") from exc
        except ConnectionRefusedError as exc:
            raise TelemetryExportError("CONNECTION_REFUSED") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise TelemetryExportError("CONNECTION_FAILED") from exc
        finally:
            connection.close()


# --- the evidence-writer hook -------------------------------------------------------------------


class TelemetryLedger(EvidenceLedger):
    """An :class:`EvidenceLedger` that also projects each appended event to an exporter.

    :meth:`append` writes the event exactly as the base class does and returns the same value;
    the projection reads only that returned, persisted event. Everything after the write is
    wrapped so no telemetry fault -- in projection, encoding, or export -- can propagate into the
    run. After the first failure the circuit opens: no further export is attempted for the run,
    spans are counted as dropped, and the status ledger records the failure once and the drop
    count at termination.
    """

    def __init__(
        self,
        path: Path,
        exporter: TelemetryExporter,
        *,
        time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS,
        call_timeout_seconds: float = DEFAULT_CALL_TIMEOUT_SECONDS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(path)
        self.exporter = exporter
        self.status = EvidenceLedger(path.parent / STATUS_LEDGER)
        self.time_budget_seconds = time_budget_seconds
        self.call_timeout_seconds = call_timeout_seconds
        self.batch_size = batch_size
        self._monotonic = monotonic
        self._projector = RunProjector()
        self._pending: list[dict[str, Any]] = []
        self._spent = 0.0
        self.failure: str | None = None
        self.exported_spans = 0
        self.dropped_spans = 0
        self.dropped_payloads = 0

    def append(self, event: EvidenceEvent) -> EvidenceEvent:
        final = super().append(event)
        try:
            self._observe(final)
        except Exception as exc:  # noqa: BLE001 - telemetry is outside the TCB by design
            self._fail(final, getattr(exc, "reason_code", f"PROJECTION_{type(exc).__name__}"))
        return final

    def _observe(self, event: EvidenceEvent) -> None:
        if not self._projector.accepts(event):
            self._projector = RunProjector()
        spans = self._projector.feed(event)
        if self.failure is None:
            self._pending.extend(spans)
            if self._projector.closed or len(self._pending) >= self.batch_size:
                self._flush(event)
        else:
            self.dropped_spans += len(spans)
        if not self._projector.closed:
            return
        metrics = encode_metrics(self._projector.resource(), self._projector.metrics())
        if self.failure is None:
            self._export(event, "metrics", metrics)
        else:
            self.dropped_payloads += 1
        if self.failure is not None:
            self._record(event, SPANS_DROPPED, self._drop_counts())

    def _drop_counts(self) -> dict[str, object]:
        return {
            "spans_exported": self.exported_spans,
            "spans_dropped": self.dropped_spans,
            "payloads_dropped": self.dropped_payloads,
        }

    def _flush(self, event: EvidenceEvent) -> None:
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        if self._export(event, "traces", encode_traces(self._projector.resource(), batch)):
            self.exported_spans += len(batch)
        else:
            self.dropped_spans += len(batch)

    def _export(
        self, event: EvidenceEvent, signal: Literal["traces", "metrics"], payload: dict[str, Any]
    ) -> bool:
        remaining = self.time_budget_seconds - self._spent
        if remaining <= 0:
            self._fail(event, "TIME_BUDGET_EXHAUSTED")
            if signal == "metrics":
                self.dropped_payloads += 1
            return False
        started = self._monotonic()
        try:
            self.exporter.export(signal, payload, timeout=min(self.call_timeout_seconds, remaining))
        except Exception as exc:  # noqa: BLE001 - any exporter fault opens the circuit
            self._spent += self._monotonic() - started
            self._fail(event, getattr(exc, "reason_code", f"EXPORTER_{type(exc).__name__}"))
            if signal == "metrics":
                self.dropped_payloads += 1
            return False
        self._spent += self._monotonic() - started
        if self._spent >= self.time_budget_seconds:
            # This payload arrived; the next one would overrun the budget, so stop here.
            self._fail(event, "TIME_BUDGET_EXHAUSTED")
        return True

    def _fail(self, event: EvidenceEvent, reason: str) -> None:
        if self.failure is not None:
            return
        self.failure = reason
        self.dropped_spans += len(self._pending)
        self._pending = []
        self._record(
            event,
            EXPORT_FAILED,
            {"sink": self.exporter.sink, "failure": reason, "at_sequence": event.sequence},
        )

    def _record(self, event: EvidenceEvent, reason: str, data: dict[str, object]) -> None:
        """Append to the status ledger, never to the evidence ledger; swallow its own faults.

        The timestamp is the triggering ledger event's, not a fresh clock read, so identical runs
        with an identically failing sink write identical status ledgers.
        """
        try:
            self.status.append(
                EvidenceEvent(
                    schema_version="1.1.0",
                    scenario_id=event.scenario_id,
                    scenario_version=event.scenario_version,
                    stage=event.stage,
                    component_version="telemetry-v1",
                    run_id=event.run_id,
                    trace_id=f"{event.run_id}-telemetry",
                    sequence=0,
                    timestamp=event.timestamp,
                    actor=TELEMETRY_ACTOR,
                    kind=EventKind.LIFECYCLE,
                    manifest_digest=event.manifest_digest,
                    policy_digest=event.policy_digest,
                    reason_code=reason,
                    data={**data, "at_event": event.event_hash},
                )
            )
        except Exception:  # noqa: BLE001, S110 - a status-ledger fault must not reach the run
            pass


def attach_telemetry(
    runner: PurpleTeamRunner, exporter: TelemetryExporter, **options: Any
) -> TelemetryLedger:
    """Swap a runner's evidence ledger for a :class:`TelemetryLedger` over the same file.

    Called before the run starts. The two classes share the file format and every byte written,
    so the swap changes nothing the kernel reads. A file sink inside the bundle directory is
    refused, because the export would then become an inventoried bundle member.
    """
    current = runner.runtime.ledger
    if isinstance(current, TelemetryLedger):
        raise ValueError("telemetry is already attached to this runner")
    if current.path.exists() and current.path.stat().st_size:
        raise ValueError("telemetry must be attached before the run writes evidence")
    if isinstance(exporter, FileExporter) and exporter.path.resolve().is_relative_to(
        current.path.parent.resolve()
    ):
        raise ValueError("the telemetry file sink must live outside the evidence bundle")
    ledger = TelemetryLedger(current.path, exporter, **options)
    runner.runtime.ledger = ledger
    return ledger


def read_status(directory: Path) -> list[EvidenceEvent]:
    """The verified telemetry status ledger of one run directory; empty when none was written."""
    return EvidenceLedger(directory / STATUS_LEDGER).verify()


# --- reading an export back ---------------------------------------------------------------------


def read_export(path: Path) -> list[dict[str, Any]]:
    """Every OTLP JSON line in an export file, in order."""
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def export_spans(payloads: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [span for payload in payloads for span in _payload_spans(payload)]


def span_attributes(span: Mapping[str, Any]) -> dict[str, Any]:
    """Decode an OTLP attribute list back to plain values."""

    def decode(value: Mapping[str, Any]) -> Any:
        if "intValue" in value:
            return int(value["intValue"])
        if "arrayValue" in value:
            return [decode(item) for item in value["arrayValue"].get("values", [])]
        for key in ("stringValue", "boolValue", "doubleValue"):
            if key in value:
                return value[key]
        return None

    return {item["key"]: decode(item["value"]) for item in span.get("attributes", [])}


# --- 5.3.5 wall-clock detection latency ---------------------------------------------------------


class WallClockDetectionLatency(StrictModel):
    """One advisory wall-clock detection figure, beside -- never replacing -- the tick figure.

    Measured from span timestamps, which are the ledger's own event timestamps: the time from
    the first event of an attack stage (``attack`` for the baseline leg, ``replay`` for the
    replay leg) to the DETECTOR event that recorded the rule as observed. It therefore includes
    the harness's own scoring work, and it is a property of this machine and this fixture
    placement. ``provenance`` is advisory by type and no gate reads this type (ADR 0009, 0013).
    """

    provenance: Literal["advisory"] = "advisory"
    label: Literal["wall clock on this machine"] = WALL_CLOCK_LABEL
    run_id: str
    scenario_id: str | None = None
    leg: Literal["baseline", "replay"]
    rule_id: str
    logical_ticks: int | None = None
    wall_clock_ms: float = Field(ge=0)


def wall_clock_detection_latency(
    spans: Sequence[Mapping[str, Any]],
) -> list[WallClockDetectionLatency]:
    """Every observed detection in an export, with its tick figure and its wall-clock figure."""
    by_trace: dict[str, list[Mapping[str, Any]]] = {}
    for span in spans:
        by_trace.setdefault(str(span["traceId"]), []).append(span)
    figures: list[WallClockDetectionLatency] = []
    for trace in by_trace.values():
        run = next((s for s in trace if s["name"] == RUN_SPAN), None)
        run_values = span_attributes(run) if run is not None else {}
        stages = sorted(
            (
                (int(s["startTimeUnixNano"]), span_attributes(s).get("purpleloop.stage.name"))
                for s in trace
                if s["name"] == STAGE_SPAN
            ),
            key=lambda item: item[0],
        )
        detectors = sorted(
            (s for s in trace if s["name"] == event_span_name(EventKind.DETECTOR)),
            key=lambda s: int(s["startTimeUnixNano"]),
        )
        for detector in detectors:
            at = int(detector["startTimeUnixNano"])
            attack = [(start, name) for start, name in stages if name in _ATTACK_STAGES]
            preceding = [(start, name) for start, name in attack if start <= at]
            if not preceding:
                continue
            started, stage = preceding[-1]
            values = span_attributes(detector)
            rules = values.get("purpleloop.detector.rules_observed") or []
            ticks = values.get("purpleloop.detector.time_to_detect_ticks") or []
            for index, rule in enumerate(rules):
                tick = ticks[index] if index < len(ticks) else -1
                figures.append(
                    WallClockDetectionLatency(
                        run_id=str(run_values.get("purpleloop.run.id", "unknown")),
                        scenario_id=run_values.get("purpleloop.scenario.id"),
                        leg=_ATTACK_STAGES[str(stage)],
                        rule_id=str(rule),
                        logical_ticks=tick if tick >= 0 else None,
                        wall_clock_ms=(at - started) / 1_000_000,
                    )
                )
    return figures


def latency_summary(figures: Sequence[WallClockDetectionLatency]) -> dict[str, Any]:
    """Count, median, and range of both figures, each named for what it is."""
    walls = [figure.wall_clock_ms for figure in figures]
    ticks = [figure.logical_ticks for figure in figures if figure.logical_ticks is not None]
    return {
        "provenance": "advisory",
        "detections": len(figures),
        "logical_ticks": {
            "label": "injected logical ticks (the binding-report figure)",
            "median": statistics.median(ticks) if ticks else None,
            "max": max(ticks) if ticks else None,
        },
        "wall_clock_ms": {
            "label": WALL_CLOCK_LABEL,
            "median": round(statistics.median(walls), 3) if walls else None,
            "min": round(min(walls), 3) if walls else None,
            "max": round(max(walls), 3) if walls else None,
        },
    }
