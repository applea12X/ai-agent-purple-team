# ADR 0016: Telemetry is a ledger projection outside the trusted computing base

Status: accepted for Phase 5 (WP5.3).

## Context

The PRD names OpenTelemetry as a technology choice (§4) and the plan adds a self-hosted
observability profile (§2.4). An export path creates two hazards. Spans become a place where
secrets and canaries leak, because instrumentation usually runs in more code paths than the
evidence ledger is written from. And a dashboard becomes a competing source of truth that can
disagree with the signed bundle. The kernel's rule everywhere else is fail-closed. Applied to
telemetry, that rule would let a collector outage or a slow disk change a run's outcome, which
would make an untrusted component part of every verdict.

## Decision

1. **The ledger is authoritative and telemetry is a projection of it.** Spans and metrics are
   computed only from the `EvidenceEvent` that `EvidenceLedger.append` returns, which is the
   redacted event exactly as persisted. The hook is `TelemetryLedger`, an `EvidenceLedger`
   subclass. `attach_telemetry` swaps it in for a runner's ledger before the run starts. It
   writes the same bytes and returns the same values, so nothing the kernel reads changes. No
   module under `adapters/`, `fixture/`, `runtime/`, `control/`, `scoring/`, or `schemas/`
   imports telemetry, and a test asserts this. Telemetry therefore cannot contain anything the
   ledger does not.
2. **Data minimization on top of redaction.** Free-text `data` is never exported. An event span
   carries `data`'s SHA-256 (JCS), its identifier-shaped keys, and numeric or boolean leaves to
   depth two. Detector spans also carry observed rule ids and logical-tick times. A redaction
   defect in a writer can therefore leak through telemetry only as far as it already leaked
   into the ledger's structured fields, and the planted-leak test shows both halves of that.
3. **Telemetry is outside the TCB, so export failure is non-fatal.** Any fault in projection,
   encoding, or export is caught after the evidence write. The first fault opens a per-run
   circuit: no further export is attempted, and spans are counted as dropped. A cumulative time
   budget (default 2 s, with per-call timeouts clipped to what remains) bounds what a slow sink
   can cost, so telemetry cannot push a run into its wall-time budget. The run continues. This
   inverts the kernel's fail-closed rule on purpose: an observer that can veto the observed is
   no longer an observer.
4. **The failure is recorded beside the evidence, not in it.** `TELEMETRY_EXPORT_FAILED` (at the
   first failure) and `TELEMETRY_SPANS_DROPPED` (at termination, with counts) are LIFECYCLE
   events written by actor `telemetry-exporter` to a separate hash-chained, anchored ledger,
   `telemetry-status.jsonl`, in the run directory. They are not written to `evidence.jsonl`.
   Inserting an event into the evidence chain would shift every later sequence number and
   parent hash, change `event_replay_hash`, and let a collector's health move the
   replay-determinism measurement. Two identical runs would then "disagree" because a collector
   blinked. The status ledger's timestamps are the triggering event's timestamps, so identical
   runs with an identically failing sink write identical status ledgers.
5. **The consequence for bundle digests, stated exactly.** With a healthy sink, the bundle is
   byte-identical with telemetry on and off: every inventoried member and the inventory itself.
   When an export fails, the run directory gains `telemetry-status.jsonl` and its anchor. Both
   are inventoried, so the inventory and anything that digests it differ by exactly those two
   entries, and every other member is byte-identical. We chose to seal the failure into the
   bundle rather than keep it outside, so that a reviewer holding only the bundle can see that
   its telemetry projection is incomplete.
6. **No new egress.** The default sink is a local file of OTLP JSON lines. The HTTP sink can be
   built only from a signed, valid Manifest 1.5 whose `phase5.telemetry` names a loopback
   collector asset. Its constructor takes a manifest and a verifier, never a URL. The collector
   profile (`compose.observability.yaml`) is off by default, sits on the fixture's internal
   network with a loopback-published ingress, has no network exporter, and is absent from every
   CI lane.
7. **Names are versioned and generated.** The `purpleloop.*` namespace (`NAMESPACE_VERSION`) is
   documented in `docs/telemetry-namespace.md`. The doc's tables are rendered from `EventKind`,
   and a test fails on drift. The event-kind mapping is a rule (`purpleloop.event.<kind>`), not
   a table, so an event kind added later (WP5.1's) exports without a code change.
8. **Figures derived from telemetry are advisory by type.** `WallClockDetectionLatency` carries
   `provenance: advisory` and the label "wall clock on this machine", is reported beside the
   logical-tick figure (never in place of it), and is refused at every gate input.

## Consequences

- A reviewer never has to trust a dashboard. A span can be checked against the bundle, because
  its `spanId` is a prefix of the event hash and `purpleloop telemetry-export` regenerates the
  same spans from a verified bundle.
- An outage of the observability stack is visible (in the status ledger and in
  `analyze`'s `telemetry_export_failures` column) and harmless.
- Telemetry is lossy by design. A run whose sink failed has incomplete spans, and no consumer
  may treat span counts as evidence counts.
- When the circuit opens, the profile records that failure and stops sending. It does not retry
  or buffer for later delivery. `telemetry-export` is the recovery path, and it rebuilds the
  projection from the sealed bundle.
- Until WP5.1 lets a lane admit Manifest 1.5, the run is admitted under the lane's 1.3
  manifest. The collector grant lives in a separate 1.5 manifest that the CLI signs with the
  same ephemeral key. That key is one author's key. It shows the grant mechanism works. It is
  not a second party's approval.
