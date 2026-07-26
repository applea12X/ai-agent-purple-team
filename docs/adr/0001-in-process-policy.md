# ADR 0001: In-process default-deny policy

## Decision

Phase 0 uses pure, typed Python policy rules behind a `PolicyEngine` protocol. Deny rules take precedence, every result has a stable reason code, and policy unavailability denies execution.

## Rationale

This keeps the trusted computing base small while target canonicalization, policy ordering, and failure behavior are established. OPA/Rego can be added behind the protocol after these semantics are covered by conformance tests.

## Consequence

Phase 0 is not a general policy-authoring platform. External policy bundles and distributed policy decisions are deferred.
