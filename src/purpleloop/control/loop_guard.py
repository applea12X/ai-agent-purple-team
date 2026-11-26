"""The runaway-loop detector: repeated or no-progress action-state hashes end the run.

PRD §7 ("Detect repeated/no-progress action-state hashes and stop runaway loops"), loose end
5.3, ADR 0018. Until Phase 5 every loop was prevented by structure -- acyclic plans with signed
node and depth limits, signed intent and attacker caps, hard budgets and wall time -- and nothing
noticed a run that spent those bounds doing the same thing over and over. This module is the
detector. It is pure bookkeeping over digests: no clock, no I/O, no model, so the same action
sequence always trips at the same action.

**What is hashed.** An action's *fingerprint* is the digest of its canonical, typed content --
adapter, operation, method, target, side-effect class, credential handle, and the JCS-canonical
arguments -- with every per-run identity removed (``action_id``, ``idempotency_key``) and the
budget left out, since nothing the target sees depends on it. A model that re-asks for the same
tool call under a fresh node id therefore has the same fingerprint every time. A step refused at
compile time, before it became an action, is fingerprinted from its typed fields the same way;
one rejected before it was even typed, by the operation name it gave.

**What "state" is.** The kernel cannot see the target's database, and the fixture's own state
hash exists only at the leg boundaries where the runner snapshots it, so neither can say whether
the action just taken changed anything. What the kernel *does* hold, for every action, is the
outcome it recorded: the status and the redacted result data of a completed action (the same
bytes the ``RESULT`` event carries, without latency). The state digest is a chained digest over
the **distinct** outcomes the kernel has observed in the current window; it advances only when
an action produces an outcome the window has not seen. A completed write's outcome includes its
fingerprint, so a different write always counts as a change and the same write repeated does
not; a read counts as a change only when it returns something new. A denied, failed, or
refused action changes nothing. The *action-state hash* is the digest of the fingerprint and
the state digest before the action: the same action, asked for again, in a situation the
kernel has observed nothing new about.

**Windows.** One window per stage. The runner's stages are a fixed sequence no action can
change, and the paired design deliberately repeats the clean task (after a verified reset, and
again for utility under attack), so a cross-stage repeat is the method working, not a loop.

**Checks.** (a) *repetition*: the N-th occurrence of one action-state hash in a window is refused
before dispatch. (b) *no progress*: the K-th consecutive action in a window that does not
advance the state digest trips after its outcome is known. Either one latches the guard: the
kernel refuses every later target-plane action of the run, so a runner that ignored the trip
still could not keep going.

Disarmed when the signed manifest carries no ``phase5.loop_guard`` -- every manifest 1.0-1.4 and
every 1.5 document written before the grant existed -- in which case it computes nothing and
records nothing (ADR 0018 gives the reasons).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from purpleloop.schemas.action import ActionRequest, SideEffectClass
from purpleloop.schemas.common import digest_data
from purpleloop.schemas.phase1 import Step
from purpleloop.schemas.phase5 import LoopGuardGrant

RUNAWAY_LOOP_DETECTED = "RUNAWAY_LOOP_DETECTED"
#: Shadow mode reports a would-be loop under this code and stops nothing: no action executes.
RUNAWAY_LOOP_WOULD_TRIP = "RUNAWAY_LOOP_WOULD_TRIP"
#: The fixture control plane. Its calls (provision, seed, snapshot, telemetry, defense, reset,
#: teardown) are issued only by ``FixtureController`` on a fixed lifecycle -- a ``Step`` cannot
#: name this adapter -- and repeat by design, so they are neither counted nor refused: teardown
#: must still run after a trip.
CONTROL_ADAPTER = "control"
#: The state digest at the start of every window.
WINDOW_ORIGIN = "0" * 64

Check = Literal["repetition", "no-progress"]


def action_fingerprint(action: ActionRequest) -> str:
    """The digest of what an action asks the target to do, without per-run identity."""
    return digest_data(
        {
            "kind": "action",
            "adapter": action.adapter,
            "operation": action.operation,
            "method": action.method,
            "target": action.target.model_dump(mode="json", exclude_none=True),
            "side_effect": action.side_effect.value,
            "credential_handle": action.credential_handle,
            "arguments": action.arguments,
        }
    )


def step_fingerprint(step: Step) -> str:
    """The digest of a step refused before it became an action, without its node identity."""
    return digest_data(
        {
            "kind": "step",
            "adapter": step.adapter,
            "operation": step.operation,
            "asset_id": step.asset_id,
            "target_tenant": step.target_tenant,
            "resource_id": step.resource_id,
            "arguments": step.arguments,
        }
    )


def rejected_fingerprint(name: str) -> str:
    """The digest of a tool intent rejected before it was typed, by the name it was given."""
    return digest_data({"kind": "rejected-intent", "name": name})


def outcome_digest(
    fingerprint: str, side_effect: SideEffectClass, status: str, data: dict[str, Any]
) -> str:
    """What a completed action told the kernel. A write's outcome is bound to the write itself."""
    return digest_data(
        {
            "write": fingerprint if side_effect != SideEffectClass.READ else None,
            "status": status,
            "data": data,
        }
    )


def action_state_hash(fingerprint: str, state: str) -> str:
    return digest_data({"action": fingerprint, "state": state})


@dataclass(frozen=True)
class LoopTrip:
    """One detection, as recorded in the ``RUNAWAY_LOOP_DETECTED`` event."""

    check: Check
    stage: str | None
    fingerprint: str
    state_digest: str
    action_state_hash: str
    observed: int
    limit: int

    def evidence(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "window_stage": self.stage,
            "action_fingerprint": self.fingerprint,
            "state_digest": self.state_digest,
            "action_state_hash": self.action_state_hash,
            "observed": self.observed,
            "limit": self.limit,
        }


@dataclass
class _Window:
    stage: str | None
    state: str = WINDOW_ORIGIN
    seen: set[str] = field(default_factory=set)
    counts: dict[str, int] = field(default_factory=dict)
    streak: int = 0


class LoopGuard:
    """Per-run detector state. Owned by ``SafetyRuntime``; one per signed manifest digest."""

    def __init__(self, grant: LoopGuardGrant | None) -> None:
        self.grant = grant
        self.tripped: LoopTrip | None = None
        #: The highest repetition count and no-progress streak any window reached. Read-only
        #: evidence for choosing thresholds (``scripts/loop_guard_margins.py``); never a verdict.
        self.peak_repeats = 0
        self.peak_streak = 0
        self._window = _Window(stage=None)
        self._pending: tuple[str, str, str] | None = None

    @property
    def armed(self) -> bool:
        return self.grant is not None

    def _roll(self, stage: str | None) -> _Window:
        if self._window.stage != stage:
            self._window = _Window(stage=stage)
        return self._window

    def boundary(self, fingerprint: str, stage: str | None) -> LoopTrip | None:
        """Count one action at its boundary; a trip here means the action must not dispatch.

        Returns the repetition trip when this occurrence is the N-th. It does not latch: the
        caller decides (execute latches; shadow reports and goes on).
        """
        assert self.grant is not None
        window = self._roll(stage)
        hashed = action_state_hash(fingerprint, window.state)
        window.counts[hashed] = window.counts.get(hashed, 0) + 1
        self.peak_repeats = max(self.peak_repeats, window.counts[hashed])
        self._pending = (fingerprint, window.state, hashed)
        if window.counts[hashed] == self.grant.repeat_limit:
            return LoopTrip(
                check="repetition",
                stage=stage,
                fingerprint=fingerprint,
                state_digest=window.state,
                action_state_hash=hashed,
                observed=window.counts[hashed],
                limit=self.grant.repeat_limit,
            )
        return None

    def observe(self, outcome: str | None) -> LoopTrip | None:
        """Record the outcome of the action last counted; ``None`` means nothing changed.

        Returns the no-progress trip when this was the K-th consecutive unchanged action.
        """
        assert self.grant is not None and self._pending is not None
        fingerprint, state, hashed = self._pending
        self._pending = None
        window = self._window
        if outcome is not None and outcome not in window.seen:
            window.seen.add(outcome)
            window.state = digest_data({"state": window.state, "outcome": outcome})
            window.streak = 0
            return None
        window.streak += 1
        self.peak_streak = max(self.peak_streak, window.streak)
        if window.streak >= self.grant.no_progress_limit:
            return LoopTrip(
                check="no-progress",
                stage=window.stage,
                fingerprint=fingerprint,
                state_digest=state,
                action_state_hash=hashed,
                observed=window.streak,
                limit=self.grant.no_progress_limit,
            )
        return None

    def latch(self, trip: LoopTrip) -> None:
        if self.tripped is None:
            self.tripped = trip
