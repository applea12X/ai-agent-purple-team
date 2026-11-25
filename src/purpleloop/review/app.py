"""The local review UI (ADR 0017): read-only views, and one write -- an adjudication record.

Server-rendered with :mod:`.markup`, which escapes by default; no template engine, no client
framework, and no JavaScript on any page. Every response carries a Content-Security-Policy with
``default-src 'none'`` and no ``script-src``, so even markup that slipped past escaping could not
run a script, load a frame, or send a form anywhere but here.

What keeps the UI read-only and inert:

- **No bundle file is ever served or opened for writing.** Views are rendered from the
  :class:`~purpleloop.review.sources.ReviewSource` loaded (and verified) at startup. The only
  write is :func:`~purpleloop.review.adjudication.write_adjudication`, the CLI's code path.
- **No bundle content in a URL.** Links use integer indexes (``/s/0/r/3/e/41``), so a hostile
  scenario id or evidence id can appear in text, escaped, but never in an ``href``.
- **Local only.** :func:`serve` refuses any bind but ``127.0.0.1``. Requests whose ``Host`` is
  not the bound address are refused (DNS rebinding), and every POST must carry the session's
  random form token and, when the browser sends one, a same-origin ``Origin`` (cross-site form
  posts to a localhost port).
- **Blinded by default.** Verdict-bearing events and fields are masked until the reviewer labels
  the finding or explicitly reveals it; a reveal is remembered, and a later record says
  ``blinded: false``.
"""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from purpleloop.review.adjudication import (
    LABELS,
    AdjudicationError,
    BlindingState,
    ReviewerKey,
    check_records_dir,
    default_records_dir,
    separation_violations,
    write_adjudication,
)
from purpleloop.review.markup import STYLESHEET, Markup, el, page, path
from purpleloop.review.sources import (
    SUMMARY_VERDICT_FIELDS,
    VERDICT_KINDS,
    ReviewFinding,
    ReviewRun,
    ReviewSource,
)
from purpleloop.schemas.phase5 import AdjudicationRecord

BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_FORM_BYTES = 64 * 1024

#: No script source anywhere; styles only from this origin; forms post only here.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; img-src 'none'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class BindError(ValueError):
    pass


@dataclass
class SourceSession:
    source: ReviewSource
    records_dir: Path
    blinding: BlindingState
    written: list[tuple[str, AdjudicationRecord, Path]] = field(default_factory=list)


@dataclass
class ReviewSession:
    sources: list[SourceSession]
    key: ReviewerKey | None
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _pre(value: Any) -> Markup:
    return el("pre", _json(value))


def _table(header: tuple[str, ...], rows: Sequence[Sequence[object]]) -> Markup:
    return el(
        "table",
        el("thead", el("tr", [el("th", name) for name in header])),
        el("tbody", [el("tr", [el("td", cell) for cell in row]) for row in rows]),
    )


def _nav(*crumbs: tuple[str, str | None]) -> Markup:
    items = [el("a", "Index", href=path())]
    for label, target in crumbs:
        items.append(Markup(" / "))
        items.append(el("a", label, href=target) if target else el("span", label))
    return el("header", el("nav", items))


def _banner(source: ReviewSource) -> Markup:
    if source.verified:
        return el("p", el("strong", "Verified: "), source.verification)
    if source.kind == "ledger" and source.runs:
        return el(
            "div",
            el("strong", "Ledger only -- no sealed bundle; adjudication is disabled. "),
            source.verification,
            class_="blinded",
        )
    return el(
        "div",
        el("strong", "NOT VERIFIED -- do not rely on this evidence; adjudication is disabled. "),
        source.verification,
        class_="unverified",
    )


def _blinded_note(where: str) -> Markup:
    return el(
        "div",
        el("strong", "Blinded. "),
        f"The oracle's verdict ({where}) is hidden until you record a label, so the label is "
        "your reading of the evidence rather than of the oracle.",
        class_="blinded",
    )


def _run_blinded(session: SourceSession, run: ReviewRun) -> bool:
    return any(
        session.blinding.is_blinded(finding)
        for finding in session.source.findings
        if finding.run_index == run.index
    )


def _event_row(
    si: int, run: ReviewRun, position: int, event: Mapping[str, Any], blinded: bool
) -> tuple[object, ...]:
    masked = blinded and event.get("kind") in VERDICT_KINDS
    hidden = el("em", "hidden while blinded")
    link: object = (
        el("a", event.get("sequence"), href=path("s", si, "r", run.index, "e", position))
        if run.events_complete
        else event.get("sequence")
    )
    return (
        link,
        event.get("stage"),
        event.get("kind"),
        event.get("actor", ""),
        hidden if masked else event.get("decision"),
        hidden if masked else event.get("reason_code"),
    )


def index_page(session: ReviewSession) -> Markup:
    rows = []
    for si, item in enumerate(session.sources):
        source = item.source
        rows.append(
            (
                el("a", source.path.name, href=path("s", si)),
                source.kind,
                el("code", source.bundle_digest),
                "verified" if source.verified else "NOT VERIFIED",
                len(source.findings),
                len(source.classes()),
            )
        )
    key = session.key
    writer = (
        el("p", "Adjudication enabled as reviewer key ", el("code", key.key_id), ".")
        if key is not None
        else el("p", "Read-only: no reviewer key was given, so no label can be recorded.")
    )
    return page(
        "PurpleLoop review",
        _nav(),
        el(
            "main",
            el("h1", "PurpleLoop review"),
            el(
                "p",
                "Read-only views over verified evidence. The only thing this UI writes is a "
                "signed adjudication record, beside the bundle. A label is a human judgement, "
                "not a verdict, and it gates nothing.",
            ),
            writer,
            el(
                "section",
                _table(("Source", "Kind", "Bundle digest", "Status", "Findings", "Classes"), rows),
            ),
        ),
    )


def source_page(session: ReviewSession, si: int) -> Markup:
    item = session.sources[si]
    source = item.source
    run_rows = []
    for run in source.runs:
        blinded = _run_blinded(item, run)
        run_rows.append(
            (
                el("a", run.name, href=path("s", si, "r", run.index)),
                run.scenario_id,
                el("em", "hidden while blinded") if blinded else run.summary.get("status"),
                len(run.events),
                sum(finding.run_index == run.index for finding in source.findings),
            )
        )
    finding_rows = []
    for fi, finding in enumerate(source.findings):
        labelled = sum(key == finding.key for key, _, _ in item.written)
        finding_rows.append(
            (
                el("a", finding.key, href=path("s", si, "f", fi)),
                finding.finding_class,
                len(finding.evidence_ids),
                "blinded" if item.blinding.is_blinded(finding) else "verdict shown",
                labelled,
            )
        )
    notes = []
    if source.adjudication_blocked:
        notes.append(el("p", el("strong", "Adjudication disabled: "), source.adjudication_blocked))
    return page(
        f"Source {source.path.name}",
        _nav((source.path.name, None)),
        el(
            "main",
            el("h1", source.path.name),
            _banner(source),
            notes,
            el(
                "p",
                "Bundle digest ",
                el("code", source.bundle_digest),
                f" ({source.kind}). Records are written to ",
                el("code", str(item.records_dir)),
                ".",
            ),
            el(
                "section",
                el("h2", "Runs"),
                _table(("Run", "Scenario", "Status", "Events", "Findings"), run_rows),
            ),
            el(
                "section",
                el("h2", "Accepted findings"),
                _table(
                    ("Finding", "Class", "Evidence", "Blinding", "Labels this session"),
                    finding_rows,
                ),
            ),
        ),
    )


def _oracle_inputs(si: int, run: ReviewRun) -> Markup:
    specs = {
        name: (run.scenario or {}).get(name)
        for name in ("security_oracle", "utility_oracle")
        if (run.scenario or {}).get(name) is not None
    }
    snapshot_links = [
        el("li", el("a", name, href=path("s", si, "r", run.index, "snapshot", position)))
        for position, name in enumerate(run.snapshots)
    ]
    return el(
        "section",
        el("h2", "Oracle inputs"),
        el(
            "p",
            "The closed-operator oracle specifications and the state snapshots they read. "
            "These are inputs, not the verdict.",
        ),
        _pre(specs) if specs else el("p", "No scenario document in this source."),
        el("ul", snapshot_links) if snapshot_links else el("p", "No snapshots in this source."),
    )


def run_page(session: ReviewSession, si: int, ri: int) -> Markup:
    item = session.sources[si]
    run = item.source.runs[ri]
    blinded = _run_blinded(item, run)
    summary = (
        {k: v for k, v in run.summary.items() if k not in SUMMARY_VERDICT_FIELDS}
        if blinded
        else dict(run.summary)
    )
    scenario = run.scenario or {}
    attempted = (
        ("Scenario", run.scenario_id),
        ("Legitimate objective", scenario.get("legitimate_objective", "")),
        ("Attacker objective", scenario.get("attacker_objective", "")),
        ("Actor", _json(scenario.get("actor", ""))),
    )
    reveal = (
        el(
            "form",
            _token(session),
            el("button", "Reveal oracle verdicts for this run", type="submit"),
            " Records written after this say blinded: false.",
            method="post",
            action=path("s", si, "r", ri, "unblind"),
        )
        if blinded
        else None
    )
    timeline_note = (
        None
        if run.events_complete
        else el(
            "p",
            "An audit export embeds the decision records only; the full ledger and evidence "
            "bodies are in the bundle.",
        )
    )
    decisions = [
        (event.get("sequence"), event.get("kind"), event.get("decision"), event.get("reason_code"))
        for event in run.decisions()
    ]
    return page(
        f"Run {run.name}",
        _nav((item.source.path.name, path("s", si)), (run.name, None)),
        el(
            "main",
            el("h1", "Run ", el("code", run.name)),
            _banner(item.source),
            _blinded_note("run status, oracle, detector and judge events") if blinded else None,
            reveal,
            el(
                "section",
                el("h2", "What was attempted"),
                _table(("", ""), [(k, el("pre", v)) for k, v in attempted]),
            ),
            el(
                "section",
                el("h2", "Decisions and reason codes"),
                _table(("Seq", "Kind", "Decision", "Reason code"), decisions),
            ),
            _oracle_inputs(si, run),
            el(
                "section",
                el("h2", "Timeline"),
                timeline_note,
                _table(
                    ("Seq", "Stage", "Kind", "Actor", "Decision", "Reason code"),
                    [
                        _event_row(si, run, position, event, blinded)
                        for position, event in enumerate(run.events)
                    ],
                ),
            ),
            el(
                "section",
                el("h2", "Summary" + (" (verdict fields hidden)" if blinded else "")),
                _pre(summary),
            ),
        ),
    )


def evidence_page(session: ReviewSession, si: int, ri: int, ei: int) -> Markup:
    item = session.sources[si]
    run = item.source.runs[ri]
    event = run.events[ei]
    masked = _run_blinded(item, run) and event.get("kind") in VERDICT_KINDS
    shown = (
        {k: v for k, v in event.items() if k not in {"data", "decision", "reason_code"}}
        if masked
        else dict(event)
    )
    return page(
        "Evidence",
        _nav(
            (item.source.path.name, path("s", si)),
            (run.name, path("s", si, "r", ri)),
            (f"event {event.get('sequence')}", None),
        ),
        el(
            "main",
            el("h1", "Evidence ", el("code", event.get("event_hash", ""))),
            _blinded_note("this event's content") if masked else None,
            el("section", _pre(shown)),
        ),
    )


def snapshot_page(session: ReviewSession, si: int, ri: int, ni: int) -> Markup:
    item = session.sources[si]
    run = item.source.runs[ri]
    name = list(run.snapshots)[ni]
    return page(
        "Snapshot",
        _nav(
            (item.source.path.name, path("s", si)),
            (run.name, path("s", si, "r", ri)),
            (name, None),
        ),
        el(
            "main",
            el("h1", "Snapshot ", el("code", name)),
            el("p", "Redacted fixture state, as the oracle read it."),
            el("section", _pre(run.snapshots[name])),
        ),
    )


def _token(session: ReviewSession) -> Markup:
    return el("input", type="hidden", name="token", value=session.token)


def _evidence_block(si: int, run: ReviewRun, finding: ReviewFinding, blinded: bool) -> Markup:
    rows = []
    for evidence_id in finding.evidence_ids:
        position = run.event_by_id(evidence_id)
        if position is None:
            rows.append((el("code", evidence_id), el("em", "not embedded in this source")))
            continue
        event = run.events[position]
        masked = blinded and event.get("kind") in VERDICT_KINDS
        body = (
            el("em", "hidden while blinded")
            if masked
            else _pre(
                {
                    "sequence": event.get("sequence"),
                    "stage": event.get("stage"),
                    "kind": event.get("kind"),
                    "decision": event.get("decision"),
                    "reason_code": event.get("reason_code"),
                    "data": event.get("data"),
                }
            )
        )
        rows.append(
            (
                el("a", el("code", evidence_id), href=path("s", si, "r", run.index, "e", position)),
                body,
            )
        )
    return _table(("Evidence id", "Content"), rows)


def _label_form(
    session: ReviewSession, si: int, fi: int, finding: ReviewFinding, blinded: bool
) -> Markup:
    item = session.sources[si]
    if session.key is None:
        return el("p", "Read-only: start the UI with --reviewer-key to record a label.")
    if not item.source.adjudicable:
        return el("p", "Adjudication disabled for this source.")
    if separation_violations(session.key, item.source):
        return el(
            "p",
            el("strong", "Adjudication refused: "),
            "the reviewer key signs or attests under this bundle (REVIEWER_KEY_NOT_SEPARATE).",
        )
    radios = [
        el(
            "label",
            el("input", type="radio", name="label", value=label, required=True),
            f" {label} ",
        )
        for label in LABELS
    ]
    boxes = [
        el(
            "label",
            el("input", type="checkbox", name="cited", value=evidence_id),
            " ",
            el("code", evidence_id),
            el("br"),
        )
        for evidence_id in finding.evidence_ids
    ]
    return el(
        "form",
        _token(session),
        el("fieldset", el("legend", "Label"), radios),
        el(
            "fieldset",
            el("legend", "Rationale"),
            el("textarea", name="rationale", rows="5", required=True),
        ),
        el(
            "fieldset",
            el("legend", "Cited evidence (required for true- or false-positive)"),
            boxes,
        ),
        el(
            "p",
            "This record will say ",
            el("strong", f"blinded: {'true' if blinded else 'false'}"),
            f", and is signed as reviewer {session.key.key_id}.",
        ),
        el("button", "Sign and record label", type="submit"),
        method="post",
        action=path("s", si, "f", fi, "label"),
    )


def finding_page(session: ReviewSession, si: int, fi: int, message: str | None = None) -> Markup:
    item = session.sources[si]
    finding = item.source.findings[fi]
    run = item.source.runs[finding.run_index]
    blinded = item.blinding.is_blinded(finding)
    scenario = run.scenario or {}
    attempted = [
        ("Finding", finding.key),
        ("Class", finding.finding_class),
        ("Bundle digest", item.source.bundle_digest),
        ("Legitimate objective", scenario.get("legitimate_objective", "")),
        ("Attacker objective", scenario.get("attacker_objective", "")),
        ("Attacker goal (finding)", finding.shown.get("attacker_goal", "")),
        ("Asset", finding.shown.get("asset_id", "")),
    ]
    written = [
        (record.label, str(record.blinded).lower(), record.rationale, str(target))
        for key, record, target in item.written
        if key == finding.key
    ]
    reveal = (
        el(
            "form",
            _token(session),
            el("button", "Reveal the oracle verdict before labelling", type="submit"),
            " The record will then say blinded: false.",
            method="post",
            action=path("s", si, "f", fi, "unblind"),
        )
        if blinded
        else None
    )
    verdict = (
        None
        if blinded
        else el(
            "section",
            el("h2", "Oracle verdict"),
            el("p", "Deterministic oracle output for this finding, shown after labelling."),
            _pre(dict(finding.verdict)),
        )
    )
    return page(
        f"Finding {finding.key}",
        _nav(
            (item.source.path.name, path("s", si)),
            (run.name, path("s", si, "r", run.index)),
            (finding.key, None),
        ),
        el(
            "main",
            el("h1", "Finding ", el("code", finding.key)),
            _banner(item.source),
            el("p", el("strong", message)) if message else None,
            _blinded_note("finding status, impact, severity and oracle results")
            if blinded
            else None,
            reveal,
            el(
                "section",
                el("h2", "What was attempted"),
                _table(("", ""), [(k, el("pre", v)) for k, v in attempted]),
            ),
            _oracle_inputs(si, run),
            el("section", el("h2", "Cited evidence"), _evidence_block(si, run, finding, blinded)),
            verdict,
            el(
                "section",
                el("h2", "Record a label"),
                _label_form(session, si, fi, finding, blinded),
            ),
            el(
                "section",
                el("h2", "Labels recorded this session"),
                _table(("Label", "Blinded", "Rationale", "Record"), written)
                if written
                else el("p", "None yet."),
            ),
        ),
    )


def error_page(status: int, message: str) -> HTMLResponse:
    body = page("Review error", _nav(), el("main", el("h1", f"Error {status}"), el("p", message)))
    return HTMLResponse(body, status_code=status)


def _lookup(session: ReviewSession, si: int, ri: int | None = None) -> SourceSession | None:
    if not 0 <= si < len(session.sources):
        return None
    item = session.sources[si]
    if ri is not None and not 0 <= ri < len(item.source.runs):
        return None
    return item


async def _form(request: Request) -> dict[str, list[str]] | None:
    body = await request.body()
    if len(body) > MAX_FORM_BYTES:
        return None
    return parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)


def create_app(
    sources: list[ReviewSource],
    *,
    key: ReviewerKey | None = None,
    records_dirs: list[Path] | None = None,
    port: int = DEFAULT_PORT,
) -> FastAPI:
    """Build the review app over already-loaded sources. Bundles are not reopened after this."""
    dirs = records_dirs or [default_records_dir(source) for source in sources]
    if len(dirs) != len(sources):
        raise ValueError("one records directory per source")
    session = ReviewSession(
        sources=[
            SourceSession(
                source=source,
                records_dir=check_records_dir(directory, source),
                blinding=(
                    BlindingState.from_records(directory, source, key.key_id)
                    if key is not None
                    else BlindingState()
                ),
            )
            for source, directory in zip(sources, dirs, strict=True)
        ],
        key=key,
    )
    allowed_hosts = {f"{BIND_HOST}:{port}", f"localhost:{port}"}
    origins = {f"http://{host}" for host in allowed_hosts}
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.session = session

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response: Response
        if request.headers.get("host") not in allowed_hosts:
            response = PlainTextResponse("host not allowed", status_code=421)
        elif request.method not in {"GET", "HEAD", "POST"}:
            response = PlainTextResponse("method not allowed", status_code=405)
        elif request.method == "POST" and request.headers.get("origin") not in (None, *origins):
            response = PlainTextResponse("cross-origin form post refused", status_code=403)
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def check_token(form: dict[str, list[str]] | None) -> bool:
        supplied = (form or {}).get("token", [""])[0]
        return hmac.compare_digest(supplied.encode(), session.token.encode())

    @app.get("/static/review.css")
    def stylesheet() -> Response:
        return Response(STYLESHEET, media_type="text/css")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(index_page(session))

    @app.get("/s/{si}", response_class=HTMLResponse)
    def source_view(si: int) -> HTMLResponse:
        if _lookup(session, si) is None:
            return error_page(404, "no such source")
        return HTMLResponse(source_page(session, si))

    @app.get("/s/{si}/r/{ri}", response_class=HTMLResponse)
    def run_view(si: int, ri: int) -> HTMLResponse:
        if _lookup(session, si, ri) is None:
            return error_page(404, "no such run")
        return HTMLResponse(run_page(session, si, ri))

    @app.get("/s/{si}/r/{ri}/e/{ei}", response_class=HTMLResponse)
    def evidence_view(si: int, ri: int, ei: int) -> HTMLResponse:
        item = _lookup(session, si, ri)
        run = item.source.runs[ri] if item is not None else None
        if run is None or not run.events_complete or not 0 <= ei < len(run.events):
            return error_page(404, "no such evidence (an audit export embeds no event bodies)")
        return HTMLResponse(evidence_page(session, si, ri, ei))

    @app.get("/s/{si}/r/{ri}/snapshot/{ni}", response_class=HTMLResponse)
    def snapshot_view(si: int, ri: int, ni: int) -> HTMLResponse:
        item = _lookup(session, si, ri)
        if item is None or not 0 <= ni < len(item.source.runs[ri].snapshots):
            return error_page(404, "no such snapshot")
        return HTMLResponse(snapshot_page(session, si, ri, ni))

    @app.post("/s/{si}/r/{ri}/unblind")
    async def unblind_run(si: int, ri: int, request: Request) -> Response:
        item = _lookup(session, si, ri)
        if item is None:
            return error_page(404, "no such run")
        if not check_token(await _form(request)):
            return error_page(403, "missing or wrong form token")
        for finding in item.source.findings:
            if finding.run_index == ri:
                item.blinding.unblind(finding)
        return RedirectResponse(path("s", si, "r", ri), status_code=303)

    @app.get("/s/{si}/f/{fi}", response_class=HTMLResponse)
    def finding_view(si: int, fi: int) -> HTMLResponse:
        item = _lookup(session, si)
        if item is None or not 0 <= fi < len(item.source.findings):
            return error_page(404, "no such finding")
        return HTMLResponse(finding_page(session, si, fi))

    @app.post("/s/{si}/f/{fi}/unblind")
    async def unblind_finding(si: int, fi: int, request: Request) -> Response:
        item = _lookup(session, si)
        if item is None or not 0 <= fi < len(item.source.findings):
            return error_page(404, "no such finding")
        if not check_token(await _form(request)):
            return error_page(403, "missing or wrong form token")
        item.blinding.unblind(item.source.findings[fi])
        return RedirectResponse(path("s", si, "f", fi), status_code=303)

    @app.post("/s/{si}/f/{fi}/label")
    async def label_finding(si: int, fi: int, request: Request) -> Response:
        item = _lookup(session, si)
        if item is None or not 0 <= fi < len(item.source.findings):
            return error_page(404, "no such finding")
        form = await _form(request)
        if form is None:
            return error_page(413, "form too large")
        if not check_token(form):
            return error_page(403, "missing or wrong form token")
        if session.key is None:
            return error_page(403, "read-only: no reviewer key")
        finding = item.source.findings[fi]
        try:
            record, target = write_adjudication(
                item.source,
                finding.key,
                label=form.get("label", [""])[0],
                rationale=form.get("rationale", [""])[0],
                cited_evidence_ids=tuple(form.get("cited", [])),
                blinded=item.blinding.is_blinded(finding),
                key=session.key,
                records_dir=item.records_dir,
            )
        except AdjudicationError as exc:
            return HTMLResponse(finding_page(session, si, fi, message=str(exc)), status_code=400)
        item.blinding.record(finding)
        item.written.append((finding.key, record, target))
        return RedirectResponse(path("s", si, "f", fi), status_code=303)

    return app


def serve(app: FastAPI, *, host: str = BIND_HOST, port: int = DEFAULT_PORT) -> None:
    """Run the UI. Refuses every bind address but 127.0.0.1."""
    if host != BIND_HOST:
        raise BindError(f"the review UI binds to {BIND_HOST} only; refused {host!r}")
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False)
