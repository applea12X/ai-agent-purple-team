"""WP5.0.8: ``purpleloop adjudicate`` and ``purpleloop precision-report``.

Every record here is *constructed* by the test, with labels the test chose. None of them is a
human judgement and none is evidence about the corpus's precision; they exercise the tooling
only. The precision checkpoint itself needs a human adjudicator (docs/phase5/wp5.0.8-acceptance.md).
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from purpleloop.cli import app
from purpleloop.reporting.audit_export import export_audit
from purpleloop.reporting.gates import GateInputError, budget_gate, scope_gate
from purpleloop.review.adjudication import (
    AdjudicationError,
    BlindingState,
    ReviewerKey,
    default_records_dir,
    load_reviewer_key,
    read_records,
    write_adjudication,
)
from purpleloop.review.cli import terminal_safe
from purpleloop.review.precision import precision_report
from purpleloop.review.sources import ReviewSource, load_source
from purpleloop.runtime.demo import ROOT
from purpleloop.schemas.phase5 import AdjudicationRecord
from purpleloop.scoring.phase3 import wilson_interval

runner = CliRunner()
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def tree_digest(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def reviewer(key_id: str = "reviewer-1") -> ReviewerKey:
    return ReviewerKey(key_id=key_id, private_key=Ed25519PrivateKey.generate())


def label_all(
    source: ReviewSource,
    key: ReviewerKey,
    records: Path,
    labels: dict[str, str],
    *,
    now: datetime = T0,
) -> list[AdjudicationRecord]:
    written = []
    for finding in source.findings:
        label = labels.get(finding.finding_class, "true-positive")
        record, _ = write_adjudication(
            source,
            finding.key,
            label=label,
            rationale=f"constructed test label: {label}",
            cited_evidence_ids=finding.evidence_ids[:1] if label != "cannot-tell" else (),
            blinded=True,
            key=key,
            records_dir=records,
            now=now,
        )
        written.append(record)
    return written


# --- sources ----------------------------------------------------------------------------------


def test_a_run_bundle_lists_its_accepted_finding_with_a_class(
    review_copy: Callable[[str], Path],
) -> None:
    source = load_source(review_copy("agent-indirect-html"))
    assert source.verified and source.kind == "run-bundle"
    assert [f.key for f in source.findings] == ["agent-indirect-html-seeded"]
    finding = source.findings[0]
    assert finding.finding_class == "agent-indirect-html"
    assert finding.evidence_ids and all(len(ref) == 64 for ref in finding.evidence_ids)
    inventory = (source.path / "inventory.json").read_bytes()
    assert source.bundle_digest == hashlib.sha256(inventory).hexdigest()
    # Blinding: no verdict-derived field is in what may be shown.
    assert "status" not in finding.shown and "observed_impact" not in finding.shown
    assert finding.verdict["status"] == "confirmed"
    assert finding.verdict["baseline.security"]["verdict"] == "true"


def test_a_suite_and_its_audit_export_name_findings_identically(
    review_copy: Callable[[str], Path], tmp_path: Path
) -> None:
    suite = review_copy("suite")
    bundle = load_source(suite)
    export_path = tmp_path / "audit.json"
    export_audit(suite, export_path)
    export = load_source(export_path)
    assert bundle.kind == "suite-bundle" and export.kind == "audit-export"
    assert export.verified, export.verification
    assert export.bundle_digest == bundle.bundle_digest
    assert [f.key for f in export.findings] == [f.key for f in bundle.findings]
    assert len(bundle.classes()) == 2
    assert not export.runs[0].events_complete and bundle.runs[0].events_complete


def test_repetitions_qualify_finding_ids_by_run_and_exports_refuse_them(
    review_copy: Callable[[str], Path], tmp_path: Path
) -> None:
    repeated = review_copy("repeated")
    source = load_source(repeated)
    assert sorted(f.key for f in source.findings) == [
        "agent-indirect-html-rep-0:agent-indirect-html-seeded",
        "agent-indirect-html-rep-1:agent-indirect-html-seeded",
    ]
    assert source.adjudicable and len(source.classes()) == 1
    export_audit(repeated, tmp_path / "audit.json")
    export = load_source(tmp_path / "audit.json")
    assert export.verified and not export.adjudicable
    with pytest.raises(AdjudicationError, match="SOURCE_NOT_ADJUDICABLE"):
        write_adjudication(
            export,
            export.findings[0].key,
            label="cannot-tell",
            rationale="x",
            cited_evidence_ids=(),
            blinded=True,
            key=reviewer(),
            records_dir=tmp_path / "records",
        )


def test_a_tampered_audit_export_does_not_verify(
    review_copy: Callable[[str], Path], tmp_path: Path
) -> None:
    export_path = tmp_path / "audit.json"
    export_audit(review_copy("agent-indirect-html"), export_path)
    document = json.loads(export_path.read_text())
    document["runs"][0]["summary"]["content"]["findings"][0]["status"] = "likely"
    export_path.write_text(json.dumps(document))
    source = load_source(export_path)
    assert not source.verified and "SHA-256" in source.verification


def test_an_unverifiable_bundle_loads_for_viewing_but_cannot_be_labelled(tmp_path: Path) -> None:
    incident = tmp_path / "incident"
    shutil.copytree(ROOT / "docs" / "samples" / "incident", incident)
    source = load_source(incident)
    assert not source.verified and "FAILED" in source.verification
    with pytest.raises(AdjudicationError, match="SOURCE_NOT_VERIFIED"):
        write_adjudication(
            source,
            "anything",
            label="cannot-tell",
            rationale="x",
            cited_evidence_ids=(),
            blinded=True,
            key=reviewer(),
            records_dir=tmp_path / "records",
        )


# --- the write path ---------------------------------------------------------------------------


def test_a_record_is_signed_verifiable_and_written_beside_the_bundle(
    review_copy: Callable[[str], Path],
) -> None:
    bundle = review_copy("agent-indirect-html")
    before = tree_digest(bundle)
    source = load_source(bundle)
    key = reviewer()
    finding = source.findings[0]
    record, target = write_adjudication(
        source,
        finding.key,
        label="true-positive",
        rationale="constructed",
        cited_evidence_ids=finding.evidence_ids[:2],
        blinded=True,
        key=key,
        records_dir=default_records_dir(source),
        now=T0,
    )
    assert target.parent == bundle.parent / f"{bundle.name}.adjudications"
    assert not target.resolve().is_relative_to(bundle.resolve())
    assert tree_digest(bundle) == before
    stored = AdjudicationRecord.model_validate_json(target.read_bytes())
    assert stored == record and stored.bundle_digest == source.bundle_digest
    public = key.private_key.public_key()
    public.verify(base64.b64decode(stored.signature), stored.signed_bytes())
    load_source(bundle)  # still verifies


def test_records_are_never_overwritten(review_copy: Callable[[str], Path]) -> None:
    source = load_source(review_copy("agent-indirect-html"))
    finding, key, records = source.findings[0], reviewer(), default_records_dir(source)
    arguments = {
        "label": "cannot-tell",
        "rationale": "same",
        "cited_evidence_ids": (),
        "blinded": True,
        "key": key,
        "records_dir": records,
        "now": T0,
    }
    write_adjudication(source, finding.key, **arguments)  # type: ignore[arg-type]
    with pytest.raises(FileExistsError):
        write_adjudication(source, finding.key, **arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"cited_evidence_ids": ("f" * 64,)}, "CITATION_NOT_IN_FINDING"),
        ({"label": "probably"}, "INVALID_LABEL"),
        ({"label": "true-positive", "cited_evidence_ids": ()}, "INVALID_RECORD"),
        ({"rationale": "   "}, "INVALID_RECORD"),
        ({"finding_key": "not-a-finding"}, "UNKNOWN_FINDING"),
    ],
)
def test_invalid_labels_are_refused_with_a_reason_code(
    review_copy: Callable[[str], Path], change: dict[str, object], reason: str
) -> None:
    source = load_source(review_copy("agent-indirect-html"))
    finding = source.findings[0]
    arguments: dict[str, object] = {
        "finding_key": finding.key,
        "label": "false-positive",
        "rationale": "constructed",
        "cited_evidence_ids": finding.evidence_ids[:1],
        "blinded": True,
        "key": reviewer(),
        "records_dir": default_records_dir(source),
    }
    arguments.update(change)
    key = arguments.pop("finding_key")
    with pytest.raises(AdjudicationError) as caught:
        write_adjudication(source, key, **arguments)  # type: ignore[arg-type]
    assert caught.value.reason_code == reason
    assert not default_records_dir(source).exists()


def test_a_harness_key_cannot_adjudicate(
    review_copy: Callable[[str], Path], tmp_path: Path
) -> None:
    source = load_source(review_copy("agent-indirect-html"))
    manifest = json.loads((source.path / "manifest.json").read_text())
    finding = source.findings[0]
    # The agent lane signs manifest 1.3 (no attestation keys); the key id is the harness's.
    key_ids = (manifest["key_id"], *(manifest.get("phase4") or {}).get("attestation_key_ids", ()))
    for key_id in key_ids:
        with pytest.raises(AdjudicationError) as caught:
            write_adjudication(
                source,
                finding.key,
                label="cannot-tell",
                rationale="x",
                cited_evidence_ids=(),
                blinded=True,
                key=reviewer(key_id),
                records_dir=tmp_path / "records",
            )
        assert caught.value.reason_code == "REVIEWER_KEY_NOT_SEPARATE"


def test_the_attestation_key_material_cannot_adjudicate_under_any_key_id(tmp_path: Path) -> None:
    """The committed sample is attested; a reviewer holding that key is refused by material."""
    bundle = tmp_path / "passing-run"
    shutil.copytree(ROOT / "docs" / "samples" / "passing-run", bundle)
    source = load_source(bundle)
    assert "ephemeral-local" in source.harness_key_ids  # the attestation's key id
    assert len(source.harness_public_keys) == 2  # authorization and attestation keys
    with pytest.raises(AdjudicationError, match="REVIEWER_KEY_NOT_SEPARATE"):
        write_adjudication(
            source,
            source.findings[0].key,
            label="cannot-tell",
            rationale="x",
            cited_evidence_ids=(),
            blinded=True,
            key=reviewer("ephemeral-local"),
            records_dir=tmp_path / "records",
        )


def test_records_inside_a_bundle_are_refused(review_copy: Callable[[str], Path]) -> None:
    suite = review_copy("suite")
    source = load_source(suite)
    for inside in (suite / "adjudications", suite / source.runs[0].name / "x"):
        with pytest.raises(AdjudicationError, match="RECORDS_INSIDE_BUNDLE"):
            write_adjudication(
                source,
                source.findings[0].key,
                label="cannot-tell",
                rationale="x",
                cited_evidence_ids=(),
                blinded=True,
                key=reviewer(),
                records_dir=inside,
            )
    # A records directory inside a *different* bundle is refused too.
    other = review_copy("agent-indirect-markdown")
    with pytest.raises(AdjudicationError, match="RECORDS_INSIDE_BUNDLE"):
        write_adjudication(
            source,
            source.findings[0].key,
            label="cannot-tell",
            rationale="x",
            cited_evidence_ids=(),
            blinded=True,
            key=reviewer(),
            records_dir=other / "records",
        )


def test_blinding_state_remembers_reveals_and_earlier_labels(
    review_copy: Callable[[str], Path],
) -> None:
    source = load_source(review_copy("suite"))
    key = reviewer()
    records = default_records_dir(source)
    first, second = source.findings
    state = BlindingState()
    assert state.is_blinded(first) and state.is_blinded(second)
    state.unblind(first)
    assert not state.is_blinded(first) and state.is_blinded(second)
    write_adjudication(
        source,
        second.key,
        label="cannot-tell",
        rationale="x",
        cited_evidence_ids=(),
        blinded=True,
        key=key,
        records_dir=records,
    )
    returning = BlindingState.from_records(records, source, key.key_id)
    assert not returning.is_blinded(second) and returning.is_blinded(first)
    assert BlindingState.from_records(records, source, "someone-else").is_blinded(second)


def test_evaluator_redteam_payloads_in_rationales_change_no_stored_verdict(
    review_copy: Callable[[str], Path],
) -> None:
    bundle = review_copy("agent-indirect-html")
    before = tree_digest(bundle)
    source = load_source(bundle)
    finding = source.findings[0]
    cases = json.loads((ROOT / "scenarios" / "evaluator-redteam" / "cases.json").read_text())
    bodies = [item["body"] for case in cases["cases"] for item in case["items"]]
    key, records = reviewer(), default_records_dir(source)
    for index, body in enumerate(bodies):
        write_adjudication(
            source,
            finding.key,
            label="cannot-tell",
            rationale=body[:4000],
            cited_evidence_ids=(),
            blinded=False,
            key=key,
            records_dir=records,
            now=T0 + timedelta(seconds=index),
        )
    assert tree_digest(bundle) == before
    reloaded = load_source(bundle)
    assert reloaded.findings[0].verdict == finding.verdict
    report = precision_report(
        read_records(records), [reloaded], {key.key_id: key.private_key.public_key()}
    )
    # Only the latest label per reviewer counts, and it is the one the reviewer chose.
    assert report.records_counted == 1 and report.cannot_tell == 1 and report.n == 0


# --- precision --------------------------------------------------------------------------------


def test_precision_is_tp_over_tp_plus_fp_with_a_wilson_interval(
    review_copy: Callable[[str], Path],
) -> None:
    source = load_source(review_copy("suite"))
    key = reviewer()
    records = default_records_dir(source)
    label_all(source, key, records, {"agent-indirect-markdown": "false-positive"})
    report = precision_report(
        read_records(records), [source], {key.key_id: key.private_key.public_key()}
    )
    assert (report.true_positives, report.false_positives, report.n) == (1, 1, 2)
    assert report.precision == 0.5
    assert (report.wilson_low, report.wilson_high) == wilson_interval(1, 2)
    assert report.method == "census" and report.classes_covered == 2
    assert not report.point_meets_threshold and not report.wilson_low_meets_threshold


def test_the_wilson_bound_is_the_published_formula() -> None:
    """Fails if the interval is faked: 19/20 has a well-known Wilson 95% interval."""
    low, high = wilson_interval(19, 20)
    assert low == pytest.approx(0.7639, abs=1e-4) and high == pytest.approx(0.9911, abs=1e-4)


def test_a_partial_labelling_is_a_sample_not_a_census(review_copy: Callable[[str], Path]) -> None:
    source = load_source(review_copy("suite"))
    key = reviewer()
    records = default_records_dir(source)
    finding = source.findings[0]
    write_adjudication(
        source,
        finding.key,
        label="true-positive",
        rationale="constructed",
        cited_evidence_ids=finding.evidence_ids[:1],
        blinded=True,
        key=key,
        records_dir=records,
    )
    report = precision_report(
        read_records(records), [source], {key.key_id: key.private_key.public_key()}
    )
    assert report.method == "sample" and report.classes_covered == 1
    assert report.uncovered_classes == (source.findings[1].finding_class,)
    assert report.precision == 1.0 and report.point_meets_threshold
    assert not report.wilson_low_meets_threshold  # n=1 cannot meet a 95% lower bound


def test_forged_unsigned_unknown_and_harness_records_are_refused(
    review_copy: Callable[[str], Path], tmp_path: Path
) -> None:
    """The metric cannot be faked: every forged record is refused and changes nothing."""
    source = load_source(review_copy("suite"))
    key = reviewer()
    records = default_records_dir(source)
    honest = label_all(source, key, records, {"agent-indirect-markdown": "false-positive"})
    trusted = {key.key_id: key.private_key.public_key()}
    baseline = precision_report(read_records(records), [source], trusted)

    forged = tmp_path / "forged"
    forged.mkdir()
    flipped = honest[1].model_copy(update={"label": "true-positive"})
    (forged / "flipped.json").write_text(flipped.model_dump_json())
    unsigned = honest[1].model_copy(update={"signature": "", "label": "true-positive"})
    (forged / "unsigned.json").write_text(unsigned.model_dump_json())
    stranger = reviewer("stranger")
    (forged / "stranger.json").write_text(
        label_all(source, stranger, tmp_path / "s", {})[1].model_dump_json()
    )
    from purpleloop.control.phase5_signing import sign_record

    other_bundle = sign_record(
        honest[0].model_copy(update={"bundle_digest": "0" * 64}), key.private_key
    )
    (forged / "other-bundle.json").write_text(other_bundle.model_dump_json())
    (forged / "garbage.json").write_text("{not json")

    manifest_key_id = json.loads((source.path / source.runs[0].name / "manifest.json").read_text())[
        "key_id"
    ]
    harness = reviewer(manifest_key_id)
    harness_record = label_all(source, reviewer("tmp"), tmp_path / "h", {})[1]
    signed_by_harness = sign_record(
        harness_record.model_copy(
            update={"reviewer_key_id": manifest_key_id, "label": "true-positive"}
        ),
        harness.private_key,
    )
    (forged / "harness.json").write_text(signed_by_harness.model_dump_json())
    trusted_with_harness = {**trusted, manifest_key_id: harness.private_key.public_key()}

    report = precision_report(
        [*read_records(records), *read_records(forged)], [source], trusted_with_harness
    )
    codes = sorted(refused.reason_code for refused in report.records_refused)
    assert codes == [
        "INVALID_SIGNATURE",
        "INVALID_SIGNATURE",
        "MALFORMED_RECORD",
        "REVIEWER_KEY_NOT_SEPARATE",
        "UNKNOWN_BUNDLE",
        "UNKNOWN_SIGNING_KEY",
    ]
    assert (report.precision, report.n) == (baseline.precision, baseline.n)


def test_a_trusted_key_that_is_harness_key_material_is_refused(tmp_path: Path) -> None:
    """Refused by key material even when the key id was chosen to look separate."""
    bundle = tmp_path / "passing-run"
    shutil.copytree(ROOT / "docs" / "samples" / "passing-run", bundle)
    source = load_source(bundle)
    finding = source.findings[0]
    record = AdjudicationRecord(
        signature="",
        finding_id=finding.key,
        bundle_digest=source.bundle_digest,
        label="true-positive",
        rationale="constructed",
        cited_evidence_ids=finding.evidence_ids[:1],
        blinded=True,
        reviewer_key_id="looks-independent",
        recorded_at=T0,
    )
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from purpleloop.control.phase5_signing import sign_record

    stand_in = Ed25519PrivateKey.generate()
    signed = sign_record(record, stand_in)
    (tmp_path / "r.json").write_text(signed.model_dump_json())
    # Pretend the attestation public key is the trusted reviewer key: its material is refused.
    attestation_key = load_pem_public_key((bundle / "attestation-public.pem").read_bytes())
    report = precision_report(
        read_records(tmp_path / "r.json"),
        [source],
        {"looks-independent": attestation_key},  # type: ignore[dict-item]
    )
    assert [r.reason_code for r in report.records_refused] == ["INVALID_SIGNATURE"]
    # With a matching signature it is refused for the material, not the signature.
    report = precision_report(
        read_records(tmp_path / "r.json"),
        [
            ReviewSource(
                **{
                    **source.__dict__,
                    "harness_public_keys": source.harness_public_keys
                    | {stand_in.public_key().public_bytes_raw()},
                }
            )
        ],
        {"looks-independent": stand_in.public_key()},
    )
    assert [r.reason_code for r in report.records_refused] == ["REVIEWER_KEY_NOT_SEPARATE"]


def test_disagreeing_reviewers_make_a_finding_disputed_and_latest_label_wins(
    review_copy: Callable[[str], Path],
) -> None:
    source = load_source(review_copy("agent-indirect-html"))
    one, two = reviewer("reviewer-1"), reviewer("reviewer-2")
    records = default_records_dir(source)
    label_all(source, one, records, {"agent-indirect-html": "false-positive"}, now=T0)
    label_all(source, one, records, {}, now=T0 + timedelta(minutes=1))  # changes mind: TP
    label_all(source, two, records, {"agent-indirect-html": "false-positive"}, now=T0)
    trusted = {k.key_id: k.private_key.public_key() for k in (one, two)}
    report = precision_report(read_records(records), [source], trusted)
    assert report.disputed == 1 and report.n == 0 and report.precision is None
    assert report.records_counted == 2 and report.reviewer_key_ids == ("reviewer-1", "reviewer-2")


def test_an_unverified_source_cannot_define_a_census(tmp_path: Path) -> None:
    incident = tmp_path / "incident"
    shutil.copytree(ROOT / "docs" / "samples" / "incident", incident)
    with pytest.raises(ValueError, match="does not verify"):
        precision_report([], [load_source(incident)], {})


def test_the_precision_report_is_refused_at_every_gate_by_type(
    review_copy: Callable[[str], Path],
) -> None:
    source = load_source(review_copy("agent-indirect-html"))
    report = precision_report([], [source], {})
    with pytest.raises(GateInputError):
        scope_gate([report])  # type: ignore[list-item]
    with pytest.raises(GateInputError):
        budget_gate([], report, [])  # type: ignore[arg-type]


# --- the CLI ----------------------------------------------------------------------------------


def test_cli_list_counts_findings_and_classes(review_copy: Callable[[str], Path]) -> None:
    result = runner.invoke(
        app, ["adjudicate", "--list", str(review_copy("suite")), str(review_copy("repeated"))]
    )
    assert result.exit_code == 0, result.output
    assert "TOTAL findings=4 classes=2 sources=2" in result.output


def test_cli_list_fails_on_an_unverified_source(tmp_path: Path) -> None:
    incident = tmp_path / "incident"
    shutil.copytree(ROOT / "docs" / "samples" / "incident", incident)
    result = runner.invoke(app, ["adjudicate", "--list", str(incident)])
    assert result.exit_code == 1 and "NOT VERIFIED" in result.output


def test_cli_labels_file_then_precision_report(
    review_copy: Callable[[str], Path],
    reviewer_key_file: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    suite = review_copy("suite")
    before = tree_digest(suite)
    source = load_source(suite)
    private, public = reviewer_key_file
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            {
                "labels": [
                    {
                        "finding_id": finding.key,
                        "label": "true-positive",
                        "rationale": "constructed test label",
                        "cited_evidence_ids": list(finding.evidence_ids[:1]),
                        "blinded": True,
                    }
                    for finding in source.findings
                ]
            }
        )
    )
    keyed = ["--reviewer-key", str(private), "--reviewer-key-id", "test-reviewer"]
    result = runner.invoke(app, ["adjudicate", str(suite), *keyed, "--labels", str(labels)])
    assert result.exit_code == 0, result.output
    assert "recorded 2 adjudication(s)" in result.output
    assert tree_digest(suite) == before
    records = default_records_dir(source)
    out = tmp_path / "precision.json"
    result = runner.invoke(
        app,
        [
            "precision-report",
            str(records),
            "--bundle",
            str(suite),
            "--trusted-key",
            f"test-reviewer={public}",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "method=census classes=2/2 findings=2/2" in result.output
    assert "precision=1.0000" in result.output
    assert json.loads(out.read_text())["n"] == 2


def test_cli_labels_file_must_state_blinding(
    review_copy: Callable[[str], Path], reviewer_key_file: tuple[Path, Path], tmp_path: Path
) -> None:
    bundle = review_copy("agent-indirect-html")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"labels": [{"finding_id": "agent-indirect-html-seeded"}]}))
    private, _ = reviewer_key_file
    result = runner.invoke(
        app,
        [
            "adjudicate",
            str(bundle),
            "--reviewer-key",
            str(private),
            "--reviewer-key-id",
            "test-reviewer",
            "--labels",
            str(labels),
        ],
    )
    assert result.exit_code == 1 and "blinded" in result.output


def test_cli_interactive_is_blinded_until_a_label_is_entered(
    review_copy: Callable[[str], Path], reviewer_key_file: tuple[Path, Path]
) -> None:
    bundle = review_copy("agent-indirect-html")
    source = load_source(bundle)
    finding = source.findings[0]
    private, _ = reviewer_key_file
    result = runner.invoke(
        app,
        [
            "adjudicate",
            str(bundle),
            "--reviewer-key",
            str(private),
            "--reviewer-key-id",
            "test-reviewer",
        ],
        # A bad label, then a citation that is not the finding's (refused, re-asked), then a
        # valid TP citing evidence [1].
        input="maybe\ntp\nconstructed\n99\ntp\nconstructed\n1\n",
    )
    assert result.exit_code == 0, result.output
    shown, _, after = result.output.partition("WROTE")
    assert "hidden until you enter a label" in shown
    assert '"verdict": "true"' not in shown and "confirmed" not in shown
    assert "not a label: maybe" in shown and "CITATION_NOT_IN_FINDING" in shown
    assert "blinded=true" in after and '"status": "confirmed"' in after
    (record,) = [r for _, r, _ in read_records(default_records_dir(source))]
    assert record is not None and record.blinded
    assert record.cited_evidence_ids == finding.evidence_ids[:1]


def test_cli_unblinded_mode_records_blinded_false(
    review_copy: Callable[[str], Path], reviewer_key_file: tuple[Path, Path]
) -> None:
    bundle = review_copy("agent-indirect-html")
    private, _ = reviewer_key_file
    result = runner.invoke(
        app,
        [
            "adjudicate",
            str(bundle),
            "--reviewer-key",
            str(private),
            "--reviewer-key-id",
            "test-reviewer",
            "--unblinded",
        ],
        input="ct\nconstructed\n\n",
    )
    assert result.exit_code == 0, result.output
    assert "UNBLINDED oracle verdict" in result.output.partition("WROTE")[0]
    (record,) = [r for _, r, _ in read_records(default_records_dir(load_source(bundle)))]
    assert record is not None and not record.blinded


def test_cli_refuses_a_harness_key_id_before_prompting(
    review_copy: Callable[[str], Path], reviewer_key_file: tuple[Path, Path]
) -> None:
    bundle = review_copy("agent-indirect-html")
    key_id = json.loads((bundle / "manifest.json").read_text())["key_id"]
    private, _ = reviewer_key_file
    result = runner.invoke(
        app,
        ["adjudicate", str(bundle), "--reviewer-key", str(private), "--reviewer-key-id", key_id],
    )
    assert result.exit_code == 1 and "REVIEWER_KEY_NOT_SEPARATE" in result.output


def test_cli_needs_a_reviewer_key_to_adjudicate(review_copy: Callable[[str], Path]) -> None:
    result = runner.invoke(app, ["adjudicate", str(review_copy("agent-indirect-html"))])
    assert result.exit_code == 1 and "--reviewer-key" in result.output


def test_precision_report_with_no_countable_record_exits_nonzero(
    review_copy: Callable[[str], Path], reviewer_key_file: tuple[Path, Path], tmp_path: Path
) -> None:
    empty = tmp_path / "records"
    empty.mkdir()
    _, public = reviewer_key_file
    result = runner.invoke(
        app,
        [
            "precision-report",
            str(empty),
            "--bundle",
            str(review_copy("agent-indirect-html")),
            "--trusted-key",
            f"r={public}",
        ],
    )
    assert result.exit_code == 1 and "not computable" in result.output


def test_keygen_never_overwrites_and_keeps_the_private_key_private(tmp_path: Path) -> None:
    private, public = tmp_path / "k.pem", tmp_path / "k.pub.pem"
    result = runner.invoke(app, ["adjudication-keygen", str(private), str(public)])
    assert result.exit_code == 0, result.output
    assert private.stat().st_mode & 0o077 == 0
    assert load_reviewer_key(private, "k").key_id == "k"
    again = runner.invoke(app, ["adjudication-keygen", str(private), str(public)])
    assert again.exit_code == 1


def test_terminal_output_neutralises_escape_sequences() -> None:
    hostile = "ok\x1b[2J\x1b]52;c;ZXZpbA==\x07done\x9b31m"
    rendered = terminal_safe(hostile)
    assert "\x1b" not in rendered and "\x07" not in rendered and "\x9b" not in rendered
    assert rendered.startswith("ok\\x1b[2J") and "\\x07done" in rendered
