# ADR 0003: Hash-chained JSONL evidence

## Decision

Phase 0 stores canonical evidence events as JSONL with monotonic sequence numbers, parent hashes, SHA-256 event hashes, and a separate final-hash anchor.

## Rationale

The format is inspectable and replayable while detecting modified, reordered, duplicated, partially written, and tail-truncated event streams.

## Consequence

The ledger is tamper-evident, not immutable. A later phase may anchor the final digest in a signed attestation or external append-only store.
