"""``purpleloop analyze``: verified bundles to Parquet, queried with DuckDB (WP5.3.6, PRD §4).

The analysis export is a convenience copy of evidence, never a second source of truth, so it is
built only from bundles that :func:`verify_bundle` accepts -- an unverified, tampered, or
incomplete bundle is refused before a single row is written. ``analysis.json`` records which
bundles (by inventory digest) produced which Parquet files (by SHA-256), and a query re-checks
those digests before it reads anything, so an edited Parquet file is refused the same way.

Queries run in an in-memory DuckDB with the tables loaded first and external access then
switched off and the configuration locked: an analyst's SQL can read the tables and cannot read
or write any file.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

from purpleloop.reporting.bundle import BundleError, verify_bundle
from purpleloop.reporting.telemetry import EXPORT_FAILED, read_status
from purpleloop.runtime.ledger import EvidenceLedger, LedgerError
from purpleloop.schemas.phase1 import RunSummary

ANALYSIS_VERSION = "1.0.0"
MANIFEST = "analysis.json"

#: Table name -> ordered (column, DuckDB type). The schema is fixed, so a query written against
#: one export runs against the next.
TABLES: dict[str, tuple[tuple[str, str], ...]] = {
    "runs": (
        ("bundle", "VARCHAR"),
        ("run_id", "VARCHAR"),
        ("scenario_id", "VARCHAR"),
        ("lane", "VARCHAR"),
        ("status", "VARCHAR"),
        ("reason", "VARCHAR"),
        ("risk_class", "VARCHAR"),
        ("model_pin_id", "VARCHAR"),
        ("manifest_digest", "VARCHAR"),
        ("scenario_digest", "VARCHAR"),
        ("oracle_hash", "VARCHAR"),
        ("event_replay_hash", "VARCHAR"),
        ("findings", "INTEGER"),
        ("executed_actions", "INTEGER"),
        ("tokens_used", "BIGINT"),
        ("cost_microusd", "BIGINT"),
        ("requests_used", "INTEGER"),
        ("records_used", "INTEGER"),
        ("elapsed_seconds", "DOUBLE"),
        ("mitigation_effective", "BOOLEAN"),
        ("utility_regression", "BOOLEAN"),
        ("telemetry_export_failures", "INTEGER"),
    ),
    "events": (
        ("run_id", "VARCHAR"),
        ("scenario_id", "VARCHAR"),
        ("sequence", "INTEGER"),
        ("timestamp", "TIMESTAMPTZ"),
        ("kind", "VARCHAR"),
        ("actor", "VARCHAR"),
        ("stage", "VARCHAR"),
        ("decision", "VARCHAR"),
        ("reason_code", "VARCHAR"),
        ("trace_id", "VARCHAR"),
        ("action_digest", "VARCHAR"),
        ("event_hash", "VARCHAR"),
        ("parent_hash", "VARCHAR"),
        ("data_json", "VARCHAR"),
    ),
    "findings": (
        ("run_id", "VARCHAR"),
        ("scenario_id", "VARCHAR"),
        ("finding_id", "VARCHAR"),
        ("asset_id", "VARCHAR"),
        ("severity", "VARCHAR"),
        ("confidence", "VARCHAR"),
        ("status", "VARCHAR"),
        ("provenance", "VARCHAR"),
        ("reproducible", "BOOLEAN"),
        ("evidence_ids", "INTEGER"),
    ),
    "detections": (
        ("run_id", "VARCHAR"),
        ("scenario_id", "VARCHAR"),
        ("leg", "VARCHAR"),
        ("rule_id", "VARCHAR"),
        ("expected", "BOOLEAN"),
        ("observed", "BOOLEAN"),
        ("time_to_detect_ticks", "INTEGER"),
    ),
}


class AnalysisRefused(ValueError):
    """A bundle or an export failed verification; nothing was written or read."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(f"{reason_code}: {detail}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class AnalysisExport:
    directory: Path
    bundles: int
    runs: int
    rows: dict[str, int]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_runs(bundle: Path, *, allow_partial: bool = False) -> list[Path]:
    """The run directories inside one verified bundle, or :class:`AnalysisRefused`."""
    try:
        verify_bundle(bundle, allow_partial=allow_partial)
    except (BundleError, LedgerError, OSError, ValueError) as exc:
        raise AnalysisRefused("BUNDLE_NOT_VERIFIED", f"{bundle}: {exc}") from exc
    suite = bundle / "suite.json"
    if suite.exists():
        names = json.loads(suite.read_text(encoding="utf-8"))["scenarios"]
        return [bundle / name for name in names]
    return [bundle]


def _rows(run: Path, bundle: Path) -> dict[str, list[tuple[Any, ...]]]:
    summary = RunSummary.model_validate_json((run / "summary.json").read_text(encoding="utf-8"))
    events = EvidenceLedger(run / "evidence.jsonl").verify()
    try:
        status = read_status(run)
    except LedgerError as exc:
        raise AnalysisRefused("TELEMETRY_STATUS_NOT_VERIFIED", f"{run}: {exc}") from exc
    rows: dict[str, list[tuple[Any, ...]]] = {name: [] for name in TABLES}
    rows["runs"].append(
        (
            str(bundle),
            summary.run_id,
            summary.scenario_id,
            summary.lane,
            summary.status,
            summary.reason,
            summary.risk_class,
            summary.model_pin_id,
            summary.manifest_digest,
            summary.scenario_digest,
            summary.oracle_hash,
            summary.event_replay_hash,
            len(summary.findings),
            summary.executed_actions,
            summary.tokens_used,
            summary.cost_microusd,
            summary.budget_used.requests,
            summary.budget_used.records,
            summary.elapsed_seconds,
            summary.mitigation_effective,
            summary.utility_regression,
            sum(event.reason_code == EXPORT_FAILED for event in status),
        )
    )
    for event in events:
        rows["events"].append(
            (
                event.run_id,
                event.scenario_id,
                event.sequence,
                event.timestamp,
                str(event.kind),
                event.actor,
                event.stage,
                event.decision,
                event.reason_code,
                event.trace_id,
                event.action_digest,
                event.event_hash,
                event.parent_hash,
                json.dumps(event.data, sort_keys=True, separators=(",", ":")),
            )
        )
    for finding in summary.findings:
        rows["findings"].append(
            (
                summary.run_id,
                finding.scenario_id,
                finding.finding_id,
                finding.asset_id,
                finding.severity,
                finding.confidence,
                finding.status,
                finding.provenance,
                finding.reproducible,
                len(finding.evidence_ids),
            )
        )
    for leg_name, leg in (("baseline", summary.baseline), ("replay", summary.replay)):
        for detector in leg.detectors if leg is not None else ():
            rows["detections"].append(
                (
                    summary.run_id,
                    summary.scenario_id,
                    leg_name,
                    detector.rule_id,
                    detector.expected,
                    detector.observed,
                    detector.time_to_detect,
                )
            )
    return rows


def _quote(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def analyze(
    bundles: Sequence[Path], output_dir: Path, *, allow_partial: bool = False
) -> AnalysisExport:
    """Verify every bundle, then write one Parquet file per table and ``analysis.json``.

    Verification happens for every bundle before any file is written, so a refusal leaves the
    output directory untouched.
    """
    if not bundles:
        raise AnalysisRefused("NO_BUNDLES", "at least one bundle is required")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise AnalysisRefused("OUTPUT_NOT_EMPTY", f"{output_dir} is not empty")
    plan = [(bundle, verified_runs(bundle, allow_partial=allow_partial)) for bundle in bundles]
    rows: dict[str, list[tuple[Any, ...]]] = {name: [] for name in TABLES}
    for bundle, runs in plan:
        for run in runs:
            for name, table_rows in _rows(run, bundle).items():
                rows[name].extend(table_rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(":memory:")
    tables: dict[str, dict[str, Any]] = {}
    try:
        for name, columns in TABLES.items():
            connection.execute(f"CREATE TABLE {name} ({', '.join(f'{c} {t}' for c, t in columns)})")
            if rows[name]:
                placeholders = ", ".join("?" for _ in columns)
                # ``name`` is a TABLES constant, never input.
                statement = f"INSERT INTO {name} VALUES ({placeholders})"  # noqa: S608
                connection.executemany(statement, rows[name])
            target = output_dir / f"{name}.parquet"
            connection.execute(f"COPY {name} TO {_quote(target)} (FORMAT parquet)")
            tables[name] = {
                "file": target.name,
                "rows": len(rows[name]),
                "sha256": _sha256(target),
            }
    finally:
        connection.close()
    manifest = {
        "schema_version": ANALYSIS_VERSION,
        "bundles": [
            {"path": str(bundle), "inventory_sha256": _sha256(bundle / "inventory.json")}
            for bundle, _ in plan
        ],
        "tables": tables,
    }
    (output_dir / MANIFEST).write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return AnalysisExport(
        directory=output_dir,
        bundles=len(plan),
        runs=sum(len(runs) for _, runs in plan),
        rows={name: len(table_rows) for name, table_rows in rows.items()},
    )


def query(export_dir: Path, sql: str) -> tuple[list[str], list[tuple[Any, ...]]]:
    """Run read-only SQL over a verified export; returns column names and rows."""
    try:
        manifest = json.loads((export_dir / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AnalysisRefused("EXPORT_NOT_VERIFIED", f"{export_dir}: no analysis.json") from exc
    if manifest.get("schema_version") != ANALYSIS_VERSION or set(manifest.get("tables", {})) != set(
        TABLES
    ):
        raise AnalysisRefused("EXPORT_NOT_VERIFIED", "analysis.json does not match this version")
    connection = duckdb.connect(":memory:")
    try:
        # Table names come from TABLES, never from the (untrusted) analysis.json.
        for name in TABLES:
            entry = manifest["tables"][name]
            path = export_dir / Path(entry["file"]).name
            if not path.exists() or _sha256(path) != entry["sha256"]:
                raise AnalysisRefused("EXPORT_NOT_VERIFIED", f"{path.name} digest mismatch")
            load = f"CREATE TABLE {name} AS SELECT * FROM read_parquet({_quote(path)})"  # noqa: S608
            connection.execute(load)
        connection.execute("SET enable_external_access = false")
        connection.execute("SET lock_configuration = true")
        cursor = connection.execute(sql)
        columns = [column[0] for column in cursor.description or ()]
        return columns, cursor.fetchall()
    finally:
        connection.close()
