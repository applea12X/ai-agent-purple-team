"""The held-out mutation set: digest-pinned, fully denied, and outside every tuning path."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.holdout import HoldoutError, load_holdout, run_holdout
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.supportlab import KEY_ID, supportlab_manifest

HOLDOUT_PATH = ROOT / "scenarios" / "holdout" / "mutations.json"

#: The pinned digest of the committed mutation set. An edit to the set fails here, which is the
#: point: updating the holdout is a deliberate commit that changes this literal in the same
#: change, never a quiet drift. (The same mechanism pins the judge's frozen label corpus.)
PINNED_DIGEST = "84eec57888559ff5723128c2ae04701270443a5ded07d23bf0e1e8574fe37577"


@pytest.fixture(scope="module")
def signed_manifest() -> object:
    key = Ed25519PrivateKey.generate()
    manifest = supportlab_manifest(key, seed=42)
    ManifestVerifier({KEY_ID: key.public_key()}).verify(manifest)
    return manifest


def test_holdout_digest_is_pinned() -> None:
    assert load_holdout(HOLDOUT_PATH).holdout_digest() == PINNED_DIGEST


def test_every_mutation_is_denied_and_the_base_is_permitted(signed_manifest: object) -> None:
    holdout = load_holdout(HOLDOUT_PATH)
    base, results = run_holdout(holdout, signed_manifest)  # type: ignore[arg-type]
    assert base.action_id == "holdout-base"
    permitted = [result.case_id for result in results if result.permitted]
    assert not permitted, f"mutations permitted: {permitted}"
    assert len(results) == len(holdout.cases)
    # Denials carry distinct, meaningful reasons rather than one blanket code.
    assert len({result.reason_code for result in results}) >= 5


def test_a_denied_base_raises_rather_than_passing_vacuously(signed_manifest: object) -> None:
    holdout = load_holdout(HOLDOUT_PATH)
    manifest = signed_manifest.model_copy(  # type: ignore[attr-defined]
        update={"allowed_operations": frozenset({"document.read"})}
    )
    with pytest.raises(HoldoutError, match="base action was denied"):
        run_holdout(holdout, manifest)


def test_holdout_stays_out_of_every_tuning_path() -> None:
    """No source module outside the holdout executor and its CLI reads the holdout directory.

    The set is meaningless if calibration or judge tuning can see it; this greps the package
    the way the agent module's no-adapter rule is enforced.
    """
    allowed = {"control/holdout.py", "phase4_cli.py"}
    offenders = []
    for path in sorted((ROOT / "src" / "purpleloop").rglob("*.py")):
        relative = path.relative_to(ROOT / "src" / "purpleloop").as_posix()
        if "holdout" in path.read_text() and relative not in allowed:
            offenders.append(relative)
    assert not offenders, offenders


def test_mutation_fields_are_a_closed_set(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"schema_version": "1.4.0", "cases": [{"case_id": "x", "description": "d",'
        ' "field": "arguments", "value": "anything"}]}'
    )
    with pytest.raises(ValueError, match="validation error"):
        load_holdout(bad)
