from __future__ import annotations

import base64
import hashlib
import html
import json
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from purpleloop.control.redaction import Redactor
from purpleloop.runtime.ledger import EvidenceLedger
from purpleloop.runtime.replay import replay_fingerprint
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import ExecutionPlan, Phase1Scenario, RunSummary
from purpleloop.scoring.phase1 import detection_metrics

REQUIRED = {
    "manifest.json",
    "scenario.json",
    "plan.json",
    "summary.json",
    "report.xml",
    "report.sarif",
    "report.html",
    "evidence.jsonl",
    "evidence.jsonl.anchor",
}


class BundleError(ValueError):
    pass


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8"
    )


def reports(directory: Path, summaries: list[RunSummary]) -> None:
    suite = ET.Element("testsuite", name="PurpleLoop Phase 1", tests=str(len(summaries)))
    sarif_results = []
    rows = []
    for summary in summaries:
        case = ET.SubElement(
            suite, "testcase", name=summary.scenario_id, classname="purpleloop.phase1"
        )
        if summary.status != "passed":
            tag = {"regression": "failure", "error": "error", "inconclusive": "skipped"}[
                summary.status
            ]
            ET.SubElement(case, tag, message=summary.reason)
        for finding in summary.findings:
            sarif_results.append(
                {
                    "ruleId": finding.scenario_id,
                    "level": "warning",
                    "message": {"text": finding.observed_impact},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": "scenario.json"}}}
                    ],
                    "properties": {
                        "taxonomy": finding.taxonomy_mappings,
                        "mitigation": finding.mitigation,
                        "evidence": list(finding.evidence_ids),
                        "status": finding.status,
                    },
                }
            )
        detectors = (
            (*summary.baseline.detectors, *summary.replay.detectors)
            if summary.baseline and summary.replay
            else ()
        )
        display = {
            **summary.model_dump(mode="json"),
            "detection_metrics": detection_metrics(detectors),
        }
        prefix = f"{summary.scenario_id}/" if len(summaries) > 1 else ""
        metric_rows = []
        if summary.baseline and summary.replay:
            pairs = [
                (
                    "Clean task utility",
                    summary.baseline.utility.verdict,
                    summary.replay.utility.verdict,
                ),
                (
                    "Attack achieved its objective",
                    summary.baseline.security.verdict,
                    summary.replay.security.verdict,
                ),
                ("Attack susceptibility", summary.baseline.susceptible, summary.replay.susceptible),
                (
                    "Unauthorized application writes",
                    summary.baseline.unauthorized_side_effects,
                    summary.replay.unauthorized_side_effects,
                ),
            ]
            metric_rows = [
                f"<tr><th>{html.escape(label)}</th><td>{html.escape(str(before))}</td>"
                f"<td>{html.escape(str(after))}</td></tr>"
                for label, before, after in pairs
            ]
        rows.append(
            f"<section><h2>{html.escape(summary.scenario_id)} — {html.escape(summary.status)}</h2>"
            "<table><thead><tr><th>Measure</th><th>Baseline</th><th>Defended replay</th></tr>"
            "</thead><tbody>" + "".join(metric_rows) + "</tbody></table>"
            "<p>Defense: <strong>"
            f"{html.escape(summary.defense.profile if summary.defense else 'none')}</strong>"
            f" · Utility regression: {summary.utility_regression}</p>"
            f"<p>Detector metrics: {html.escape(json.dumps(detection_metrics(detectors)))}</p>"
            f"<p>Executed actions: {summary.executed_actions}; "
            f"offline model tokens: {summary.tokens_used}; "
            f"elapsed: {summary.elapsed_seconds:.3f}s; cloud cost: $0.</p>"
            f"<p>Reserved resources: {summary.budget_used.requests} requests, "
            f"{summary.budget_used.writes} writes, {summary.budget_used.tokens} token capacity.</p>"
            + advisory_section(summary)
            + f"<p><a href='{prefix}evidence.jsonl'>Redacted evidence</a> · "
            f"<a href='{prefix}summary.json'>Canonical result</a></p>"
            f"<details><summary>Full results and evidence references</summary>"
            f"<pre>{html.escape(json.dumps(display, indent=2))}</pre></details></section>"
        )
    for status, attribute in (
        ("regression", "failures"),
        ("error", "errors"),
        ("inconclusive", "skipped"),
    ):
        suite.set(attribute, str(sum(s.status == status for s in summaries)))
    ET.ElementTree(suite).write(directory / "report.xml", encoding="utf-8", xml_declaration=True)
    write_json(
        directory / "report.sarif",
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "PurpleLoop", "version": "0.2.0"}},
                    "results": sarif_results,
                }
            ],
        },
    )
    (directory / "report.html").write_text(
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'><title>PurpleLoop Phase 1</title>"
        "<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;"
        "padding:0 20px;background:#faf8ff;color:#211a32}"
        "section{background:white;padding:24px;margin:24px 0;"
        "border:1px solid #ddd;border-radius:12px}"
        ".advisory{background:#fff8e6;border:1px dashed #b8860b;border-radius:8px;"
        "padding:12px 16px;margin:16px 0}"
        ".advisory h3{margin:0 0 8px;font-size:15px;color:#7a5c00}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}a{color:#6531a0}"
        "table{width:100%;border-collapse:collapse}"
        "th,td{text-align:left;padding:12px;border-bottom:1px solid #ddd}</style>"
        "<h1>PurpleLoop · Deterministic evaluation</h1>"
        "<p>Synthetic local fixtures. Findings describe the baseline; "
        "passing means the paired defense blocked that attack and preserved clean utility. "
        "Detection times use logical ticks.</p>"
        "<p><strong>Reading this report.</strong> Everything in a white panel is "
        "<em>deterministic</em>: it comes from a closed-operator oracle over observed state, and "
        "it is what gates a release. Everything in a yellow dashed panel is <em>advisory</em> — a "
        "semantic judgement or a repeated stochastic measurement. Advisory figures are recorded "
        "and reported, and they move no status, no finding, and no gate.</p>"
        + "".join(rows)
        + "</html>",
        encoding="utf-8",
    )


def advisory_section(summary: RunSummary) -> str:
    """Render the advisory half of a result, visually separated from the binding half.

    An advisory number that sits in the same panel as a deterministic one inherits its
    credibility at a glance, which is exactly the failure this separation exists to prevent.
    """
    blocks: list[str] = []
    judgements = [
        (name, leg.judge)
        for name, leg in (("Baseline", summary.baseline), ("Defended replay", summary.replay))
        if leg is not None and leg.judge is not None
    ]
    for name, judgement in judgements:
        assert judgement is not None
        blocks.append(
            f"<p>{html.escape(name)} judgement: <strong>{html.escape(judgement.verdict)}</strong>"
            f" (rubric {html.escape(judgement.rubric_id)} {html.escape(judgement.rubric_version)},"
            f" model pin {html.escape(judgement.model_pin_id)},"
            f" confidence {judgement.confidence:.2f},"
            f" {judgement.trials} trial(s))"
            + (
                f" — abstained: {html.escape(judgement.abstention_reason)}"
                if judgement.abstention_reason
                else ""
            )
            + "</p>"
        )
    report = summary.stochastic
    if report is not None:
        figures = [
            ("Clean utility", report.clean_utility),
            ("Utility under attack", report.utility_under_attack),
            ("Attack success", report.attack_success),
            ("Executed unauthorized side effects", report.executed_unauthorized_side_effects),
        ]
        cells = "".join(
            f"<tr><th>{html.escape(label)}</th><td>{figure.value:.3f}</td>"
            f"<td>[{figure.ci_low:.3f}, {figure.ci_high:.3f}]</td>"
            f"<td>{figure.n}</td><td>{figure.excluded}</td>"
            f"<td>{html.escape(figure.model_pin_id or '—')}</td>"
            f"<td>{html.escape(figure.seed_policy)}</td></tr>"
            for label, figure in figures
        )
        blocks.append(
            "<table><thead><tr><th>Measure</th><th>Value</th><th>95% interval</th><th>n</th>"
            "<th>excluded</th><th>model pin</th><th>seed policy</th></tr></thead>"
            f"<tbody>{cells}</tbody></table>"
            "<p>Four separate numbers, never composited. Proportions use a Wilson interval and "
            "counts a seeded percentile bootstrap; both are rough at this n and are reported with "
            f"it. Reproducible across repetitions: <strong>{report.reproducible}</strong>.</p>"
        )
        if report.repetitions.exclusion_reasons:
            blocks.append(
                "<p>Excluded repetitions: "
                + html.escape(", ".join(report.repetitions.exclusion_reasons))
                + "</p>"
            )
    if summary.proposals:
        accepted = sum(p.accepted for p in summary.proposals)
        blocks.append(
            f"<p>Adaptive attacker: {len(summary.proposals)} proposals, {accepted} compiled, "
            f"{len(summary.proposals) - accepted} refused. A refusal is evidence about what the "
            "attacker tried, not a harness error.</p>"
        )
    if not blocks:
        return ""
    return (
        "<div class='advisory'><h3>Advisory — not binding, gates nothing</h3>"
        + "".join(blocks)
        + "</div>"
    )


def inventory(directory: Path, *, complete: bool) -> None:
    files = {
        p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.rglob("*"))
        if p.is_file() and p != directory / "inventory.json"
    }
    write_json(
        directory / "inventory.json",
        {"schema_version": "1.1.0", "complete": complete, "artifacts": files},
    )


def write_run(
    directory: Path,
    summary: RunSummary,
    scenario: Phase1Scenario,
    manifest: AuthorizationManifest,
    plan: ExecutionPlan | None,
    ledger: EvidenceLedger,
    snapshots: dict[str, dict[str, Any]],
    redactor: Redactor,
    public_key: bytes,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "authorization-public.pem").write_bytes(public_key)
    for name, obj in (
        ("manifest", manifest),
        ("scenario", scenario),
        ("plan", plan),
        ("summary", summary),
    ):
        payload = obj.model_dump(mode="json", exclude_none=True) if obj is not None else None
        # Signed manifest contains handles, not credentials. Canary contents are redacted elsewhere.
        write_json(
            directory / f"{name}.json", payload if name == "manifest" else redactor.redact(payload)
        )
    for name, snapshot in snapshots.items():
        write_json(directory / "snapshots" / f"{name}.json", redactor.redact(snapshot))
    for source in (ledger.path, ledger.anchor_path):
        if source.exists() and source.resolve() != (directory / source.name).resolve():
            shutil.copyfile(source, directory / source.name)
    reports(directory, [summary])
    if summary.evidence_integrity_incident:
        write_json(
            directory / "integrity-incident.json",
            {"reason": "evidence could not be verified; do not accept this run"},
        )
    inventory(directory, complete=False)


def verify_bundle(directory: Path, *, allow_partial: bool = False) -> dict[str, Any]:
    raw = json.loads((directory / "inventory.json").read_text())
    if raw.get("schema_version") != "1.1.0" or not isinstance(raw.get("artifacts"), dict):
        raise BundleError("invalid inventory")
    if not raw.get("complete") and not allow_partial:
        raise BundleError("bundle incomplete")
    artifacts = raw["artifacts"]
    is_suite = "suite.json" in artifacts
    if not is_suite and not REQUIRED <= set(artifacts):
        raise BundleError("required artifact missing")
    actual = {
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file() and p != directory / "inventory.json"
    }
    if actual != set(artifacts):
        raise BundleError("artifact inventory differs from directory")
    for name, digest in artifacts.items():
        path = directory / name
        if (
            Path(name).is_absolute()
            or ".." in Path(name).parts
            or path.is_symlink()
            or not path.resolve().is_relative_to(directory.resolve())
        ):
            raise BundleError("unsafe artifact path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise BundleError(f"artifact digest mismatch: {name}")
    if is_suite:
        suite = json.loads((directory / "suite.json").read_text())
        names = suite.get("scenarios", [])
        if not names or len(names) != len(set(names)):
            raise BundleError("invalid suite scenario list")
        for name in names:
            if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
                raise BundleError("unsafe suite path")
            verify_bundle(directory / name, allow_partial=allow_partial)
        return {"valid": True, "complete": raw["complete"], "scenarios": len(names)}
    events = EvidenceLedger(directory / "evidence.jsonl").verify()
    ids = {e.event_hash for e in events}
    summary = RunSummary.model_validate_json((directory / "summary.json").read_text())
    manifest = AuthorizationManifest.model_validate_json((directory / "manifest.json").read_text())
    scenario = Phase1Scenario.model_validate_json((directory / "scenario.json").read_text())
    key = load_pem_public_key((directory / "authorization-public.pem").read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise BundleError("invalid authorization key type")
    key.verify(base64.b64decode(manifest.signature, validate=True), manifest.signed_bytes())
    if (
        manifest.manifest_digest() != summary.manifest_digest
        or scenario.digest() != summary.scenario_digest
    ):
        raise BundleError("canonical input digest mismatch")
    if summary.plan_digest is not None:
        plan = ExecutionPlan.model_validate_json((directory / "plan.json").read_text())
        if plan.digest() != summary.plan_digest or plan.manifest_digest != summary.manifest_digest:
            raise BundleError("compiled plan digest mismatch")
    if summary.event_replay_hash != replay_fingerprint(events):
        raise BundleError("normalized event hash mismatch")
    if any(e.manifest_digest != summary.manifest_digest for e in events):
        raise BundleError("event authorization binding mismatch")
    if summary.evidence_integrity_incident:
        raise BundleError("explicit evidence-integrity incident")
    if summary.status in {"passed", "regression", "inconclusive"}:
        if not {
            f"snapshots/{leg}-{point}.json"
            for leg in ("baseline", "replay")
            for point in ("before", "after")
        } <= set(artifacts):
            raise BundleError("paired snapshots missing")
    if raw.get("complete") and not any(
        n.startswith("inspect/") and n.endswith(".json") for n in artifacts
    ):
        raise BundleError("Inspect log missing")

    def references(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"evidence_ids", "evidence"} and isinstance(item, list):
                    if any(ref not in ids for ref in item):
                        raise BundleError("dangling evidence reference")
                else:
                    references(item)
        elif isinstance(value, list):
            for item in value:
                references(item)

    references(summary.model_dump(mode="json"))
    references(json.loads((directory / "report.sarif").read_text()))
    for event in events:
        references(event.data)
    return {
        "valid": True,
        "complete": raw["complete"],
        "artifacts": len(artifacts),
        "events": len(events),
    }
