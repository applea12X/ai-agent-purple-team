"""The human-readable policy descriptor in policies/ must not drift from the engine."""

from __future__ import annotations

import json
import re

from purpleloop.control.policy import DefaultDenyPolicy
from purpleloop.runtime.demo import ROOT

POLICY_SRC = ROOT / "src" / "purpleloop" / "control" / "policy.py"


def test_descriptor_lists_exactly_the_engine_reason_codes() -> None:
    descriptor = json.loads((ROOT / "policies" / "default-deny.json").read_text())
    source = POLICY_SRC.read_text()
    engine_codes = set(re.findall(r'_deny\("([A-Z_]+)"\)', source)) | set(
        re.findall(r'return "([A-Z_]+)"', source)
    )
    assert set(descriptor["reason_codes"]) == engine_codes
    assert descriptor["version_field"] == DefaultDenyPolicy.VERSION
    # Every declared Phase 2 reason code is a real engine reason code.
    assert set(descriptor["phase2_reason_codes"]) <= engine_codes


def test_adversarial_catalogue_is_well_formed() -> None:
    catalogue = json.loads((ROOT / "policies" / "adversarial" / "mutations.json").read_text())
    assert catalogue["mutations"]
    assert all(m["expect_denied"] for m in catalogue["mutations"])
