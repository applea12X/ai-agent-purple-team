"""``adjudicate``, ``precision-report``, ``adjudication-keygen`` and ``review`` (WP5.0.8, WP5.4).

Registered from ``phase5_cli.register``. The CLI and the UI share one write path
(:func:`~purpleloop.review.adjudication.write_adjudication`); this module only gathers input.

Evidence printed to the terminal is passed through :func:`terminal_safe` first: the corpus is
hostile by design, and an ANSI or OSC escape sequence in a payload would otherwise be executed by
the reviewer's terminal rather than shown to them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pydantic import ValidationError

from purpleloop.review.adjudication import (
    LABELS,
    AdjudicationError,
    BlindingState,
    ReviewerKey,
    default_records_dir,
    load_reviewer_key,
    read_records,
    require_adjudicable,
    separation_violations,
    write_adjudication,
)
from purpleloop.review.precision import precision_report
from purpleloop.review.sources import ReviewFinding, ReviewSource, SourceError, load_source

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_SHORT_LABELS = {"tp": "true-positive", "fp": "false-positive", "ct": "cannot-tell"}


def terminal_safe(value: object) -> str:
    """Render control characters (ESC, CSI, BEL, ...) visibly instead of letting them act."""
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", str(value))


def _echo(value: object = "") -> None:
    typer.echo(terminal_safe(value))


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _load_sources(paths: list[Path]) -> list[ReviewSource]:
    try:
        return [load_source(path) for path in paths]
    except (OSError, ValueError, SourceError) as exc:
        typer.echo(f"FAILED: {terminal_safe(exc)}", err=True)
        raise typer.Exit(1) from None


def _reviewer(key_path: Path | None, key_id: str | None) -> ReviewerKey | None:
    if key_path is None and key_id is None:
        return None
    if key_path is None or key_id is None:
        typer.echo("FAILED: --reviewer-key and --reviewer-key-id go together", err=True)
        raise typer.Exit(1)
    try:
        return load_reviewer_key(key_path, key_id)
    except (OSError, ValueError) as exc:
        typer.echo(f"FAILED: {exc}", err=True)
        raise typer.Exit(1) from None


def _show_finding(source: ReviewSource, finding: ReviewFinding, *, blinded: bool) -> None:
    run = source.runs[finding.run_index]
    scenario = run.scenario or {}
    _echo(f"=== finding {finding.key}  class={finding.finding_class}")
    _echo(f"bundle {source.bundle_digest} ({source.kind})")
    _echo(f"legitimate objective: {scenario.get('legitimate_objective', '-')}")
    _echo(f"attacker objective:   {scenario.get('attacker_objective', '-')}")
    _echo(f"attacker goal:        {finding.shown.get('attacker_goal', '-')}")
    specs = {
        name: scenario[name]
        for name in ("security_oracle", "utility_oracle")
        if scenario.get(name) is not None
    }
    _echo(f"oracle inputs:        {_compact(specs) if specs else '(no scenario document)'}")
    _echo("evidence:")
    for number, evidence_id in enumerate(finding.evidence_ids, start=1):
        position = run.event_by_id(evidence_id)
        if position is None:
            _echo(f"  [{number}] {evidence_id}  (not embedded in this source)")
            continue
        event = run.events[position]
        _echo(
            f"  [{number}] {evidence_id} seq={event.get('sequence')} kind={event.get('kind')} "
            f"stage={event.get('stage')} reason={event.get('reason_code')}"
        )
        _echo(f"      data={_compact(event.get('data'))}")
    if blinded:
        _echo("(the oracle's verdict is hidden until you enter a label)")
    else:
        _echo(f"UNBLINDED oracle verdict: {_compact(dict(finding.verdict))}")


def _cited(answer: str, finding: ReviewFinding) -> tuple[str, ...]:
    cited: list[str] = []
    for part in (piece.strip() for piece in answer.split(",")):
        if not part:
            continue
        if part.isdigit() and 1 <= int(part) <= len(finding.evidence_ids):
            cited.append(finding.evidence_ids[int(part) - 1])
        else:
            cited.append(part)
    return tuple(cited)


def _interactive(  # noqa: PLR0913 -- the reviewer's inputs are explicit
    source: ReviewSource,
    findings: list[ReviewFinding],
    key: ReviewerKey,
    records_dir: Path,
    blinding: BlindingState,
    *,
    unblinded: bool,
) -> int:
    written = 0
    for finding in findings:
        if unblinded:
            blinding.unblind(finding)
        _show_finding(source, finding, blinded=blinding.is_blinded(finding))
        while True:
            raw = typer.prompt(f"label [{'/'.join(LABELS)}/skip]").strip().lower()
            label = _SHORT_LABELS.get(raw, raw)
            if label == "skip":
                break
            if label not in LABELS:
                _echo(f"not a label: {raw}")
                continue
            rationale = typer.prompt("rationale")
            cited = _cited(
                typer.prompt("cite evidence (numbers or ids, comma-separated)", default=""),
                finding,
            )
            try:
                record, target = write_adjudication(
                    source,
                    finding.key,
                    label=label,
                    rationale=rationale,
                    cited_evidence_ids=cited,
                    blinded=blinding.is_blinded(finding),
                    key=key,
                    records_dir=records_dir,
                )
            except AdjudicationError as exc:
                _echo(f"REFUSED {exc}; enter the label again")
                continue
            blinding.record(finding)
            written += 1
            _echo(f"WROTE {record.label} blinded={str(record.blinded).lower()} -> {target}")
            _echo(f"oracle verdict was: {_compact(dict(finding.verdict))}")
            break
    return written


def _from_labels_file(
    sources: list[ReviewSource],
    labels_path: Path,
    key: ReviewerKey,
    records_dirs: list[Path],
) -> int:
    document = json.loads(labels_path.read_text(encoding="utf-8"))
    entries = document.get("labels") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ValueError('a labels file is {"labels": [ ... ]}')
    written = 0
    for number, entry in enumerate(entries, start=1):
        if not isinstance(entry.get("blinded"), bool):
            raise ValueError(
                f"entry {number}: state 'blinded' explicitly; the tool cannot observe what the "
                "reviewer saw when the label was chosen in a file"
            )
        candidates = [
            (index, source)
            for index, source in enumerate(sources)
            if entry.get("bundle_digest") in (None, source.bundle_digest)
            and any(finding.key == entry.get("finding_id") for finding in source.findings)
        ]
        if len(candidates) != 1:
            raise ValueError(
                f"entry {number}: finding {entry.get('finding_id')!r} matches "
                f"{len(candidates)} sources; name its bundle_digest"
            )
        index, source = candidates[0]
        record, target = write_adjudication(
            source,
            str(entry["finding_id"]),
            label=str(entry.get("label", "")),
            rationale=str(entry.get("rationale", "")),
            cited_evidence_ids=tuple(str(ref) for ref in entry.get("cited_evidence_ids", ())),
            blinded=entry["blinded"],
            key=key,
            records_dir=records_dirs[index],
        )
        written += 1
        _echo(f"WROTE {record.finding_id} {record.label} -> {target}")
    return written


def _trusted(values: list[str]) -> dict[str, Ed25519PublicKey]:
    trusted: dict[str, Ed25519PublicKey] = {}
    for value in values:
        key_id, separator, pem_path = value.partition("=")
        if not separator or not key_id or not pem_path:
            raise ValueError(f"--trusted-key takes KEY_ID=PUBLIC_PEM, got {value!r}")
        key = load_pem_public_key(Path(pem_path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"{pem_path} is not an Ed25519 public key")
        trusted[key_id] = key
    return trusted


def register(app: typer.Typer) -> None:  # noqa: C901 -- one closure per command
    @app.command("adjudication-keygen")
    def adjudication_keygen(private_path: Path, public_path: Path) -> None:
        """Create a reviewer Ed25519 key pair (private key written mode 0600, never overwritten)."""
        from purpleloop.review.adjudication import generate_reviewer_key

        try:
            generate_reviewer_key(private_path, public_path)
        except OSError as exc:
            typer.echo(f"FAILED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(
            f"WROTE private {private_path} (keep it off the bundle host), public {public_path}"
        )

    @app.command("adjudicate")
    def adjudicate(  # noqa: PLR0913 -- the reviewer's inputs are explicit
        sources: list[Path],
        list_only: bool = typer.Option(False, "--list", help="List accepted findings and stop"),
        reviewer_key: Path | None = typer.Option(None, help="Reviewer Ed25519 private key PEM"),  # noqa: B008
        reviewer_key_id: str | None = typer.Option(None, help="Key id recorded in each record"),
        labels: Path | None = typer.Option(  # noqa: B008
            None, help="Non-interactive: labels from a JSON file"
        ),
        records_dir: Path | None = typer.Option(  # noqa: B008
            None, help="Where records go (default <bundle>.adjudications beside the bundle)"
        ),
        finding: list[str] = typer.Option(  # noqa: B008
            [], help="Adjudicate only these finding ids"
        ),
        unblinded: bool = typer.Option(
            False, help="Show the oracle verdict before labelling (records say blinded: false)"
        ),
    ) -> None:
        """Label accepted findings with signed AdjudicationRecords, blinded by default."""
        loaded = _load_sources(sources)
        if list_only:
            classes: set[str] = set()
            total = 0
            for source in loaded:
                for item in source.findings:
                    _echo(
                        f"{item.key}\tclass={item.finding_class}\tevidence="
                        f"{len(item.evidence_ids)}\tbundle={source.bundle_digest}"
                    )
                classes |= source.classes()
                total += len(source.findings)
                status = "verified" if source.verified else "NOT VERIFIED"
                _echo(
                    f"SOURCE {source.path} {source.kind} {status} findings="
                    f"{len(source.findings)} classes={len(source.classes())}"
                )
            _echo(f"TOTAL findings={total} classes={len(classes)} sources={len(loaded)}")
            if any(not source.verified for source in loaded):
                raise typer.Exit(1)
            return
        key = _reviewer(reviewer_key, reviewer_key_id)
        if key is None:
            typer.echo("FAILED: adjudication needs --reviewer-key and --reviewer-key-id", err=True)
            raise typer.Exit(1)
        if records_dir is not None and len(loaded) != 1:
            typer.echo("FAILED: --records-dir applies to a single source", err=True)
            raise typer.Exit(1)
        dirs = [records_dir or default_records_dir(source) for source in loaded]
        try:
            for source in loaded:
                require_adjudicable(source)
                violations = separation_violations(key, source)
                if violations:
                    raise AdjudicationError("REVIEWER_KEY_NOT_SEPARATE", "; ".join(violations))
            if labels is not None:
                written = _from_labels_file(loaded, labels, key, dirs)
            else:
                written = 0
                for source, directory in zip(loaded, dirs, strict=True):
                    chosen = [
                        item for item in source.findings if not finding or item.key in finding
                    ]
                    blinding = BlindingState.from_records(directory, source, key.key_id)
                    written += _interactive(
                        source, chosen, key, directory, blinding, unblinded=unblinded
                    )
        except (OSError, ValueError, KeyError) as exc:
            typer.echo(f"REFUSED: {terminal_safe(exc)}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"recorded {written} adjudication(s)")

    @app.command("precision-report")
    def precision_report_command(
        records: list[Path],
        bundle: list[Path] = typer.Option(  # noqa: B008
            ..., help="Every bundle (or audit export) the records label; defines the census"
        ),
        trusted_key: list[str] = typer.Option(  # noqa: B008
            ..., help="KEY_ID=PUBLIC_PEM of a reviewer whose signature is trusted"
        ),
        output: Path | None = typer.Option(None, help="Also write the report as JSON"),  # noqa: B008
    ) -> None:
        """Precision on adjudicated findings, with Wilson interval, n, and method."""
        try:
            trusted = _trusted(trusted_key)
            sources = _load_sources(bundle)
            parsed = [item for path in records for item in read_records(path)]
            report = precision_report(parsed, sources, trusted)
        except (OSError, ValueError, ValidationError) as exc:
            typer.echo(f"FAILED: {terminal_safe(exc)}", err=True)
            raise typer.Exit(1) from None
        for refused in report.records_refused:
            _echo(f"REFUSED {refused.reason_code} {refused.path}: {refused.detail}")
        _echo(
            f"method={report.method} classes={report.classes_covered}/"
            f"{report.classes_in_population} findings={report.findings_labelled}/"
            f"{report.findings_in_population}"
        )
        _echo(
            f"tp={report.true_positives} fp={report.false_positives} "
            f"cannot-tell={report.cannot_tell} disputed={report.disputed} n={report.n}"
        )
        if report.precision is None:
            _echo("precision: not computable (no counted true- or false-positive label)")
        else:
            _echo(
                f"precision={report.precision:.4f} wilson95=[{report.wilson_low:.4f}, "
                f"{report.wilson_high:.4f}] threshold={report.threshold} "
                f"point_meets={report.point_meets_threshold} "
                f"lower_bound_meets={report.wilson_low_meets_threshold}"
            )
        _echo(
            f"records counted={report.records_counted} refused={len(report.records_refused)} "
            f"blinded={report.blinded_records} unblinded={report.unblinded_records} "
            f"reviewers={','.join(report.reviewer_key_ids) or '-'}"
        )
        if output is not None:
            output.write_text(
                json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
        if report.precision is None:
            raise typer.Exit(1)

    @app.command("review")
    def review(  # noqa: PLR0913 -- the server's inputs are explicit
        sources: list[Path],
        reviewer_key: Path | None = typer.Option(None, help="Reviewer Ed25519 private key PEM"),  # noqa: B008
        reviewer_key_id: str | None = typer.Option(None, help="Key id recorded in each record"),
        records_dir: Path | None = typer.Option(None, help="Records directory (single source)"),  # noqa: B008
        host: str = typer.Option("127.0.0.1", help="Bind address; only 127.0.0.1 is accepted"),
        port: int = typer.Option(8765, help="Port on 127.0.0.1"),
    ) -> None:
        """Serve the local, read-only review UI over bundles and audit exports."""
        from purpleloop.review.app import BIND_HOST, create_app, serve

        if host != BIND_HOST:
            typer.echo(f"REFUSED: the review UI binds to {BIND_HOST} only, not {host!r}", err=True)
            raise typer.Exit(1)
        loaded = _load_sources(sources)
        key = _reviewer(reviewer_key, reviewer_key_id)
        if records_dir is not None and len(loaded) != 1:
            typer.echo("FAILED: --records-dir applies to a single source", err=True)
            raise typer.Exit(1)
        try:
            app_ = create_app(
                loaded,
                key=key,
                records_dirs=[records_dir] if records_dir is not None else None,
                port=port,
            )
        except ValueError as exc:
            typer.echo(f"REFUSED: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(f"review UI on http://{BIND_HOST}:{port}/ (Ctrl-C to stop)")
        serve(app_, host=host, port=port)  # pragma: no cover - blocks; exercised by hand
