"""Defense applicability for the benchmark subset (WP5.6), kept apart from the authored corpus.

A defense profile in this project is pre-approved per scenario: the runner and the fixture both
refuse to apply a profile to a scenario its registry entry does not name. The benchmark subset's
scenarios need the same pre-approval, but adding their ids to ``phase3_tools.AGENT_DEFENSES``
would change the authored agent lane's registry -- which a Phase 3 test pins to the authored
corpus -- and would let the authored lane's contract name scenarios it never runs.

So the subset's applicability lives here, as data. The benchmark lane's contract reads only
this table, so it cannot apply a defense to an authored scenario; the fixture reads the union,
because it is the one fixture both lanes run against. ``AGENT_DEFENSES`` and
``COMBINED_DEFENSES`` are unchanged, and a test asserts it.
"""

from __future__ import annotations

from types import MappingProxyType

from purpleloop.control.phase3_tools import COMBINED_DEFENSES

#: Which promoted benchmark scenarios each profile is pre-approved for. A test asserts this names
#: exactly the promoted scenarios on disk, so a stale entry cannot authorize a defense for nothing.
BENCHMARK_DEFENSE_APPLICABILITY: MappingProxyType[str, frozenset[str]] = MappingProxyType(
    {
        "retrieval-provenance-guard": frozenset(
            {
                "ads-ticket-summary-exfiltrate-note",
                "ads-vendor-status-unapproved-refund",
                "ads-handover-unapproved-export",
            }
        ),
        "output-sanitization": frozenset({"ads-portal-check-exfiltrate-note"}),
        "workflow-approval": frozenset({"ads-diagnostics-unapproved-refund"}),
        "capability-scoping": frozenset({"ads-runbook-privilege-escalation"}),
    }
)

#: The benchmark lane's registry: the shared configuration values, the subset's scenario ids only.
BENCHMARK_DEFENSES: dict[str, tuple[frozenset[str], dict[str, bool]]] = {
    profile: (ids, dict(COMBINED_DEFENSES[profile][1]))
    for profile, ids in BENCHMARK_DEFENSE_APPLICABILITY.items()
}

#: What the supportlab fixture enforces: the authored registry plus the subset's entries. One
#: configuration value per profile, so a defense means the same thing on both lanes.
FIXTURE_DEFENSES: dict[str, tuple[frozenset[str], dict[str, bool]]] = {
    profile: (applicable | BENCHMARK_DEFENSE_APPLICABILITY.get(profile, frozenset()), config)
    for profile, (applicable, config) in COMBINED_DEFENSES.items()
}
