# Policies

Default-deny authorization and side-effect policy, expressed as typed Python rules behind the
`PolicyEngine` protocol (see [ADR 0001](../docs/adr/0001-in-process-policy.md)). This directory
holds the human-readable policy descriptor and adversarial fixtures used to test that the engine
fails closed. The executable rules live in `src/purpleloop/control/policy.py`; the descriptor here
must not drift from that engine, and `tests/phase2/test_policy_descriptor.py` enforces it.

- `default-deny.json` — the reason-code catalogue and the ordered checks the engine applies.
- `adversarial/` — mutations that must each be denied before any adapter I/O.
