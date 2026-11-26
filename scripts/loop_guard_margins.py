"""Measure how close the legitimate agent corpus comes to the runaway-loop limits (ADR 0018).

Runs every agent-lane corpus scenario offline, on the in-process fixture and the scripted model,
under the agent manifest 1.5 with the loop guard armed, and prints each scenario's peak
repetition count and peak no-progress streak next to its outcome. Without ``--attacker`` it also
compares each outcome with its pin in ``baselines/regression-outcomes.json``. No model is called.

    uv run python scripts/loop_guard_margins.py [--attacker] \
        [--repeat-limit N] [--no-progress-limit K]

The defaults (64 and 256, the largest values a manifest can sign) measure the peaks without the
guard ever tripping. Pass the limits you intend to sign to check them instead.
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purpleloop.control.attacker import BoundedAttacker
from purpleloop.control.manifest import ManifestVerifier
from purpleloop.control.phase3_tools import INTENT_OPERATIONS
from purpleloop.runtime.governance import agent_manifest_15, committed_admission
from purpleloop.runtime.pinning import (
    SUPPORTLAB_CONTROL,
    load_outcomes,
    outcome_of,
    pinned_scenarios,
)
from purpleloop.runtime.supportlab import (
    KEY_ID,
    InProcessSupportlab,
    actor_credentials,
    build_agent_runner,
)
from purpleloop.schemas.phase5 import LoopGuardGrant


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attacker", action="store_true", help="add the bounded attacker")
    parser.add_argument("--repeat-limit", type=int, default=64)
    parser.add_argument("--no-progress-limit", type=int, default=256)
    options = parser.parse_args()
    grant = LoopGuardGrant(
        repeat_limit=options.repeat_limit, no_progress_limit=options.no_progress_limit
    )
    pins = load_outcomes().by_scenario()
    peak_repeats = peak_streak = mismatches = trips = 0
    scenarios = [pinned for pinned in pinned_scenarios() if pinned.lane == "agent"]
    for pinned in scenarios:
        key = Ed25519PrivateKey.generate()
        manifest = agent_manifest_15(key, loop_guard=grant)
        tokens = actor_credentials()
        attacker = (
            BoundedAttacker(
                max_proposals=8,
                max_depth=3,
                operations=sorted(INTENT_OPERATIONS),
                own_tenant="org-a",
                other_tenants=("org-b",),
                resource_id="admin-a",
            )
            if options.attacker
            else None
        )
        with tempfile.TemporaryDirectory() as directory:
            runner = build_agent_runner(
                Path(directory),
                manifest,
                ManifestVerifier({KEY_ID: key.public_key()}),
                actor_tokens=tokens,
                control=SUPPORTLAB_CONTROL,
                fixture=InProcessSupportlab(tokens, SUPPORTLAB_CONTROL),
                admission=committed_admission(),
                attacker=attacker,
            )
            summary = asyncio.run(
                runner.run(
                    pinned.scenario,
                    manifest,
                    run_id=pinned.scenario_id,
                    output_dir=Path(directory),
                )
            )
        guard = runner.runtime.loop_guard(manifest)
        pinned_as = "n/a (attacker)"
        if not options.attacker:
            same = summary.baseline is not None and outcome_of("agent", summary) == pins.get(
                pinned.scenario_id
            )
            pinned_as = "equal" if same else "DIFFERENT"
            mismatches += not same
        trips += guard.tripped is not None
        peak_repeats = max(peak_repeats, guard.peak_repeats)
        peak_streak = max(peak_streak, guard.peak_streak)
        print(
            f"{pinned.scenario_id:34} {summary.status:12} {summary.reason:24} "
            f"repeats={guard.peak_repeats} streak={guard.peak_streak} pin={pinned_as}"
        )
    print(
        f"scenarios={len(scenarios)} limits={grant.repeat_limit}/{grant.no_progress_limit} "
        f"attacker={options.attacker} peak_repeats={peak_repeats} peak_streak={peak_streak} "
        f"trips={trips} pin_mismatches={mismatches if not options.attacker else 'n/a'}"
    )
    return 1 if trips or mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
