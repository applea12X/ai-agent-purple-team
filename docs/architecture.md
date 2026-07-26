# Phase 0 Architecture

## Trust boundaries

The authorization verifier, tool registry, target guard, policy engine, budget ledger, kill
switch, credential broker, trusted adapters, redactor, and evidence writer form the Phase 0
trusted computing base. Action requests, model fixtures, target content, URLs, and adapter
results are untrusted data.

## Fail-closed flow

1. Verify the canonical Ed25519 signature, UTC validity window, and available revocation status.
2. Match the action to an authorized adapter and operation, then to a trusted tool definition.
3. Canonicalize the URL and enforce its method, resource path, tenant, asset, egress, and exact
   exclusions.
4. Atomically reserve budget and spawn all adapter activity under kill-switch ownership.
5. Before the initial connection and every redirect, accept only a trusted `TargetObservation`
   with a consecutive hop number and at least one resolved address.
6. Reverify the manifest and policy, bind the observed URL to the same asset/tool/resource, and
   require every address to be explicitly allowlisted.
7. Redact target and credential secrets, append evidence atomically, and finalize the reservation.

Automatic redirect following is forbidden for future network adapters. They must resolve and
authorize each hop before connecting.

## Evidence and replay

Each evidence record contains an exact hash over its full canonical content and its parent hash.
The colocated anchor detects accidental or unsynchronized tail truncation but is not an external
signature. A separate semantic replay hash excludes timestamps, run/trace IDs, parent/event
hashes, and measured latency. The score hash covers the deterministic status, reason, and
redacted result. Exact evidence hashes and semantic replay hashes serve different purposes.

## Lifecycle guarantees

`KillSwitch.spawn` checks state and creates/registers work under one lock. Termination changes
state, cancels all owned tasks, and waits for their cancellation. The runtime applies the
remaining engagement wall-time as an execution deadline. Reservations are single-use and cannot
refund more than they reserved.
