"""The evaluation matrix's report section and its written outputs (WP5.2.6).

The section is visually and structurally separate from the deterministic report: it sits in the
advisory (yellow, dashed) style the Phase 3 report already uses for non-binding figures, and it
says so in words before any table. Every table is followed by its limitations. There is no
per-model score, no ranking, and no column that aggregates a row across scenarios -- worst cases
are listed per row instead, so a reader sees where each model broke a defense rather than a
number to sort models by.

Everything is escaped: scenario ids and reasons are project-authored, but the habit costs nothing
and the review-UI work (WP5.4) renders the same records.
"""

from __future__ import annotations

import html
from collections.abc import Iterable, Sequence
from pathlib import Path

from purpleloop.reporting.bundle import inventory, verify_bundle, write_json
from purpleloop.runtime.matrix import (
    ASSIGNED_COLUMN,
    BASELINE_COLUMN,
    MATRIX_COLUMNS,
    MatrixPreflight,
    MatrixResults,
    MatrixRun,
    cell_table,
)
from purpleloop.schemas.phase5 import EvaluationMatrix, MatrixCell

#: Limitations printed under every table. A reader who sees one table sees its caveats.
LIMITATIONS = (
    "Advisory, never binding: these figures move no status, finding, or gate.",
    "Deterministic stand-in rows are susceptibility simulators, not models; repetitions of a "
    "stand-in are identical by construction, so their n measures nothing about variance.",
    "One corpus: 25 synthetic agent scenarios on one disposable fixture. Nothing here is a claim "
    "about any other application or a model's safety in general.",
    "Each single-defense column is measured only on the scenarios its registry entry names; every "
    "other pairing is not applicable and was not executed.",
    "Per-scenario outcomes collapse repetitions: one successful repetition means the defense did "
    "not hold there. Small n gives wide Wilson intervals.",
)


def _limitations() -> str:
    items = "".join(f"<li>{html.escape(text)}</li>" for text in LIMITATIONS)
    return f"<details class='limits'><summary>Limitations</summary><ul>{items}</ul></details>"


def _table(head: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    header = "".join(f"<th>{html.escape(str(item))}</th>" for item in head)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(item))}</td>" for item in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>" + _limitations()


def _rate(cell: MatrixCell) -> str:
    return f"{cell.successes}/{cell.n} [{cell.ci_low:.2f}, {cell.ci_high:.2f}]"


def render_section(
    spec: EvaluationMatrix,
    preflight: MatrixPreflight,
    results: MatrixResults,
    run: MatrixRun | None = None,
) -> str:
    """The matrix section, as one ``<section id='evaluation-matrix'>`` element."""
    parts = [
        "<section id='evaluation-matrix' class='advisory'>",
        "<h2>Evaluation matrix — advisory</h2>",
        "<p>Models × defenses on the agent corpus. The headline is <strong>which defenses still "
        "work when the model stops cooperating</strong>, per scenario. It is not a ranking of "
        "models, and no per-model score is computed anywhere.</p>",
        f"<p>Spec <code>{html.escape(spec.matrix_id)}</code>, digest "
        f"<code>{html.escape(spec.matrix_digest())}</code>; {len(spec.scenario_ids)} scenarios × "
        f"{spec.repetitions} repetitions; alpha {spec.alpha} ({spec.contrast_test}, "
        f"{spec.correction}).</p>",
    ]
    if spec.subset_rationale:
        parts.append(f"<p>Scenario subset: {html.escape(spec.subset_rationale)}</p>")
    parts.append("<h3>Rows</h3>")
    parts.append(
        _table(
            ("Row", "Kind", "Provider", "Model", "Version", "Temperature", "Seeds", "Decoding"),
            (
                (
                    row.row_id,
                    row.kind,
                    row.pin.provider,
                    row.pin.model_id,
                    row.pin.model_version or "unknown",
                    row.pin.decoding.temperature,
                    ",".join(str(seed) for seed in row.seeds),
                    row.decoding_label,
                )
                for row in spec.rows
            ),
        )
    )
    parts.append("<h3>Pre-flight</h3>")
    parts.append(
        f"<p>Decision <strong>{html.escape(preflight.decision)}</strong>"
        f"{': ' + html.escape(', '.join(preflight.reasons)) if preflight.reasons else ''}; "
        f"estimated {preflight.trials} trials, {preflight.cost_microusd} micro-USD (cap "
        f"{preflight.cost_cap_microusd}), {preflight.wall_seconds:.0f} s (cap "
        f"{preflight.wall_time_cap_seconds}).</p>"
    )
    if run is not None:
        parts.append(
            f"<p>Measured: {len(run.trials)} trials in {run.elapsed_seconds:.0f} s, "
            f"{run.cost_microusd} micro-USD; not run: {len(run.not_run)}.</p>"
        )
    parts.append("<h3>Defense dependence — the headline</h3>")
    parts.append(
        _table(
            (
                "Defense",
                "Scenarios",
                "Model-independent",
                "Model-dependent",
                "Ineffective",
                "Unclassified",
                "Enforcement at the attacked sink",
            ),
            (
                (
                    item.defense_column,
                    item.scenarios,
                    item.model_independent,
                    item.model_dependent,
                    item.ineffective,
                    item.unclassified,
                    ", ".join(
                        f"{kind} ×{count}" for kind, count in sorted(item.enforcement.items())
                    ),
                )
                for item in results.defenses
            ),
        )
    )
    parts.append(
        "<ul>"
        + "".join(
            f"<li><strong>{html.escape(item.defense_column)}</strong>: "
            f"{html.escape(item.mechanism)}</li>"
            for item in results.defenses
        )
        + "</ul>"
    )
    parts.append("<h3>Per scenario</h3>")
    parts.append(
        _table(
            (
                "Defense",
                "Scenario",
                "Enforcement",
                "Classification",
                "Credited",
                "Not credited",
                "Trials",
            ),
            (
                (
                    item.defense_column,
                    item.scenario_id,
                    item.enforcement,
                    item.classification,
                    ", ".join(sorted(item.credited_rows)) or "—",
                    ", ".join(sorted(item.uncredited_rows)) or "—",
                    item.trials,
                )
                for item in sorted(
                    results.dependence, key=lambda d: (d.defense_column, d.scenario_id)
                )
            ),
        )
    )
    if results.unclassified:
        parts.append(
            _table(
                ("Defense", "Scenario", "Why unclassified"),
                (
                    (item.defense_column, item.scenario_id, item.reason)
                    for item in results.unclassified
                ),
            )
        )
    parts.append("<h3>Pre-registered contrasts (Holm-corrected)</h3>")
    parts.append(
        _table(
            (
                "Row",
                "Column vs no-defense",
                "Scenarios paired",
                "Held only with defense (b)",
                "Succeeded only with defense (c)",
                "Exact p",
                "Holm p",
                "Reject at alpha",
            ),
            (
                (
                    item.row_id,
                    item.defense_column,
                    item.scenarios_paired,
                    item.held_only_under_defense,
                    item.succeeded_only_under_defense,
                    f"{item.p_value:.6g}",
                    f"{item.p_holm:.6g}" if item.p_holm is not None else "—",
                    item.reject,
                )
                for item in results.contrasts
            ),
        )
    )
    parts.append("<h3>Worst cases, per row</h3>")
    for row in spec.rows:
        worst = results.worst_cases.get(row.row_id, ())
        parts.append(f"<h4>{html.escape(row.row_id)}</h4>")
        if not worst:
            parts.append("<p>No defended cell in which the attack succeeded.</p>" + _limitations())
            continue
        parts.append(
            _table(
                ("Defense", "Scenario", "Attack success under the defense", "Provenance"),
                ((c.defense_column, c.scenario_id, _rate(c), c.provenance) for c in worst),
            )
        )
    parts.append("<h3>Cells</h3>")
    columns = [c for c in MATRIX_COLUMNS if c in spec.defense_columns]
    index = {(c.row_id, c.defense_column, c.scenario_id): c for c in results.cells}
    for row in spec.rows:
        parts.append(f"<h4>{html.escape(row.row_id)} — attack success k/n [Wilson 95%]</h4>")
        parts.append(
            _table(
                ("Scenario", *columns),
                (
                    (
                        sid,
                        *(
                            _rate(index[(row.row_id, column, sid)])
                            if (row.row_id, column, sid) in index
                            else "n/a"
                            for column in columns
                        ),
                    )
                    for sid in sorted(spec.scenario_ids)
                ),
            )
        )
    parts.append(
        f"<p>n/a: not applicable under the defense registry, or no completed repetition "
        f"({len(results.not_applicable)} such cells, listed in <code>not-applicable.json</code>). "
        f"<code>{BASELINE_COLUMN}</code> is each run's baseline leg; "
        f"<code>{ASSIGNED_COLUMN}</code> is its defended replay.</p>"
    )
    parts.append("<h3>Exploratory — not pre-registered</h3>")
    parts.append(
        "<p><em>Exploratory.</em> Each column on one row against the same column on the "
        "delimitation-blind row, paired by scenario, unadjusted. Not a finding.</p>"
    )
    parts.append(
        _table(
            ("Row", "Column", "Against", "Paired", "b", "c", "Exact p (unadjusted)"),
            (
                (
                    item.row_id,
                    item.defense_column,
                    item.against,
                    item.scenarios_paired,
                    item.held_only_under_defense,
                    item.succeeded_only_under_defense,
                    f"{item.p_value:.6g}",
                )
                for item in results.exploratory
            ),
        )
    )
    parts.append("</section>")
    return "".join(parts)


STYLE = (
    "<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 16px;"
    "background:#faf8ff;color:#211a32}.advisory{background:#fff8e6;border:1px dashed #b8860b;"
    "border-radius:8px;padding:12px 16px;margin:16px 0}table{width:100%;border-collapse:collapse;"
    "font-size:13px;display:block;overflow-x:auto}th,td{text-align:left;padding:6px;"
    "border-bottom:1px solid #ddd}code{overflow-wrap:anywhere}.limits{font-size:13px;"
    "margin:4px 0 16px}</style>"
)


def render_page(
    spec: EvaluationMatrix,
    preflight: MatrixPreflight,
    results: MatrixResults,
    run: MatrixRun | None = None,
) -> str:
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'><title>PurpleLoop matrix</title>"
        + STYLE
        + "<h1>PurpleLoop · Evaluation matrix</h1>"
        + render_section(spec, preflight, results, run)
        + "</html>"
    )


def write_matrix(
    root: Path,
    spec: EvaluationMatrix,
    preflight: MatrixPreflight,
    run: MatrixRun,
    results: MatrixResults,
    public_key_pem: bytes,
) -> None:
    """Write every matrix output, inventory the root, and verify it as a suite bundle.

    Each trial is its own verified bundle; the root is a suite over them, so ``verify-bundle``
    on the root re-verifies every trial and every digest of the matrix outputs.
    """
    write_json(root / "spec.json", spec.model_dump(mode="json", exclude_none=True))
    write_json(root / "preflight.json", preflight.model_dump(mode="json"))
    write_json(root / "trials.json", [trial.model_dump(mode="json") for trial in run.trials])
    write_json(root / "matrix-cells.json", cell_table(results))
    write_json(root / "results.json", results.model_dump(mode="json"))
    write_json(
        root / "not-applicable.json",
        [item.model_dump(mode="json") for item in results.not_applicable],
    )
    (root / "matrix.html").write_text(render_page(spec, preflight, results, run), encoding="utf-8")
    (root / "authorization-public.pem").write_bytes(public_key_pem)
    write_json(
        root / "suite.json",
        {
            "schema_version": "1.3.0",
            "lane": "supportlab-agent",
            "kind": "evaluation-matrix",
            "matrix_digest": spec.matrix_digest(),
            "scenarios": run.bundles,
            "not_run": run.not_run,
            "elapsed_seconds": run.elapsed_seconds,
            "cost_microusd": run.cost_microusd,
        },
    )
    inventory(root, complete=bool(run.bundles))
    if run.bundles:
        verify_bundle(root)
