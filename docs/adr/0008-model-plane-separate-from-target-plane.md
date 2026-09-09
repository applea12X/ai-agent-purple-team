# ADR 0008: The model plane is separate from the target plane

Status: accepted for Phase 3.

## Context

Every containment guarantee measured through Phase 2 — including "external egress to `1.1.1.1:443`
refused" — is about the **fixture**. Phase 3 introduces the project's first outbound call, because
a real model lives on a network. Adding that capability to the existing target path would have
quietly deleted the strongest control in the project: the fixture's no-egress posture.

## Decision

Two planes, never merged.

**Target plane.** `supportlab`, PostgreSQL, and the upstream container keep the exact Phase 2
posture: internal-only network, no published ports, no egress, loopback ingress relay. Not one
line of that compose contract changed in Phase 3, and the Phase 2 isolation test runs unchanged as
a regression. Target assets stay loopback under manifest 1.3 — the schema still refuses any other
host — so gaining a model plane buys the target plane nothing.

**Model plane.** A model endpoint is declared in `phase3.model_assets` as an exact
`scheme://host:port` origin and is reached only by `ModelClient`. `HttpAdapter`'s `http`-only
preflight is untouched. The schema refuses any overlap between a model origin and a target asset's
origin, so the two cannot be made to coincide by configuration.

**The model plane is not plan-addressable.** A model endpoint is never a signed target asset, so no
compiled action can aim at one — a captured planner cannot direct traffic at the model endpoint,
because there is no asset id that resolves to it. Only a trusted collaborator inside an adapter can
raise a model observation, and the runtime authorizes it before any connection opens.

**The fixture never calls a model.** The agent's model calls are made by the harness on the agent's
behalf and handed back as data.

## Authorization and accounting

`SafetyRuntime.authorize_model` runs before the socket opens. It verifies the manifest, canonicalizes
the URL, requires an exact signed origin, and refuses a resolution that lands on a signed target
endpoint — which is how a rebind would try to aim a model call at the fixture. The request is charged
to the run budget whether it is permitted or denied, and recorded either way, so a blocked call is
never silently dropped. Tokens and cost are charged through the same `BudgetLedger` inside the
enclosing reservation, so a cap breach fails the action closed rather than surfacing as an accounting
discrepancy at the end of a run. A model endpoint that responds with a redirect is a denial, not a hop.

## Consequence

An offline engagement authorizes **no** model endpoint at all: `model_assets` stays empty and the
schema refuses a networked provider profile without one. The absence of the grant is the control.
There is no code path from a networked profile back to the offline provider, because a silent
downgrade would report a network result as a deterministic one.

A cost of this split is that `ModelClient` is not a registered plan-reachable adapter, so it cannot
run the shared adapter contract suite by dispatch. Its deadline, cancellation, redaction, bounded
output, and no-fallback behaviour are covered by dedicated tests instead, in
`tests/phase3/test_model_plane.py`. That is a deliberate exemption recorded here rather than a
skipped requirement: making the client plan-reachable would require signing a model endpoint as a
target asset, which is precisely what this ADR forbids.

The guard this ADR describes is exercised by test, not only by inspection: a signed origin is
permitted and charged; an unsigned origin is denied and charged; a signed origin whose resolution
lands on a signed target endpoint is refused as `MODEL_ENDPOINT_RESOLVES_TO_TARGET`; a manifest
granting no model plane refuses every endpoint; and each decision is recorded as a policy event
carrying its resolved addresses. Those tests were added after the phase was otherwise complete,
when an audit found the runtime path had never executed — the schema half of the split was tested
and the runtime half was not.
