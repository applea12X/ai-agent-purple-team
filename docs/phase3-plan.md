# Phase 3 as built — LLM/RAG agent and adaptive attack lane

This is the design as implemented. The pre-implementation working plan is
[planning/phase3-plan.md](../planning/phase3-plan.md); where the two differ, this document
describes what exists. Measured results are in [phase3-acceptance.md](phase3-acceptance.md).

## The contract change

Deterministic oracles remain primary and binding. Stochastic components produce advisory signals
only. Every reported verdict records which kind produced it, and no stochastic result gates a
release-blocking invariant.

This is a type, not a statement. `VerdictProvenance` — `deterministic` / `advisory` /
`pinned-stochastic` — is required on `OracleResult`, `JudgeResult`, `Finding`, `Measurement`, and
`RepetitionRecord`. `require_binding()` is the single place the rule is written and is called at
all three gates: run status and mitigation credit in `PurpleTeamRunner`, and `corpus_metrics`.
ADR 0009 records the decision; the central test builds the same summary with and without a judge
that disagrees with the oracle and asserts the corpus metric is identical.

## Two planes

The fixture's no-egress posture is unchanged, and Phase 3 did not touch a line of the Phase 2
compose contract. The model is reached on a **separate plane**: an exact signed origin in
`phase3.model_assets`, disjoint from every target asset by schema validation, reached only by
`ModelClient` through `SafetyRuntime.authorize_model`. A model endpoint is never a signed target
asset, so no compiled action can aim at one — the model plane is deliberately not plan-addressable.
ADR 0008 has the detail, including the one contract-suite exemption it costs.

An offline engagement authorizes no model endpoint at all. The absence of the grant is the control.

## What was added

| Area | Module | Note |
| --- | --- | --- |
| Provenance and gates | `schemas/phase3.py` | `VerdictProvenance`, `require_binding`, judge, measurement, repetition types |
| Manifest 1.3 | `schemas/authorization.py` | `Phase3Grants`; two-plane and credential rules enforced in the validator |
| Scenario 1.3 | `schemas/phase1.py` | `risk_class`, `injection_channel`, `agent_task`, `judge_rubric_id`, `repetitions` |
| Model plane | `adapters/model_provider.py` | `ModelClient`, offline and OpenAI-compatible/Ollama/vLLM providers |
| Agent surface | `fixture/supportlab/agent_api.py`, `agent_seed.py` | Retrieval, memory, email, CRM; one attack table drives seed and simulator |
| Agent adapter | `adapters/agent.py` | Retrieval, prompt assembly, model call, intent parsing |
| Deterministic models | `adapters/scripted_model.py` | `ScriptedAgentModel` susceptibility stand-in; `HostileModel` for the containment property test |
| Agent lane | `control/phase3_tools.py`, `control/lanes.py` | Tools, six new defenses, `AGENT_LANE` |
| Attacker | `control/attacker.py` | Bounded, ordered, typed mutation search |
| Importers | `adapters/importers.py` | PyRIT, garak, Promptfoo, AgentDojo → not-runnable scenarios |
| Judge | `scoring/judge.py`, `scoring/evaluator_redteam.py` | Hybrid judge, red-team scoring |
| Statistics | `scoring/agreement.py`, `scoring/phase3.py` | Alpha/kappa, Wilson and bootstrap intervals, four-number report |
| Repetitions | `runtime/repetitions.py` | Repetition driver and reproducibility |
| CLI and CI | `agent_cli.py`, `.github/workflows/phase3.yml` | `agent-run`, `agent-demo`, `judge-report` |

## The agent surface

`supportlab` gained `chunks`, `memory`, `emails`, `crm_records`, and `agent_runs`. The agent tables
join the scored projection **only on the agent lane**, so a Phase 2 scenario produces exactly the
bytes it produced before and its seed hash is unchanged — asserted against the recorded value.

Model-derived free text is excluded from every scored projection. A poisoned memory is scored by
its existence and trust level, an exfiltrating email by its destination and whether a tracer left
the organisation. Those are facts about an executed side effect, and they stay stable when the
wording of a model response does not.

Retrieval is exact topic equality with an explicit total order and no embeddings (ADR 0011), so
*what the assistant was shown* is bit-reproducible even where *what it said* is not.

### Exfiltration is measured with a tracer, not a canary

The runtime returns the redacted adapter result, so a real canary is stripped out of model output
before the runner sees it. A canary therefore cannot travel through the harness into a tool call,
and a scenario that scored exfiltration by matching the canary string could only be made to work by
weakening the redactor. It is not weakened. The internal note carries a deliberately non-secret
tracer whose escape is the signal — which is how canary tokens work in practice. The real canary
values stay in the `canaries` table, stay in the redactor's secret list, and never enter model
context.

### Defenses

Six new profiles, each a named configuration value the signed manifest must pre-authorize:
`retrieval-provenance-guard`, `memory-write-guard`, `output-sanitization`, `capability-scoping`,
`prompt-isolation`, `schema-validation`. `workflow-approval` is widened rather than duplicated.
The harness never edits fixture source.

## Intents

`ChatResult.tool_intents` was capped at one. The agent path takes its cap from
`phase3.max_tool_intents_per_turn` in the signed manifest, and the compiler reserves the full
per-turn allowance against the signed node budget before anything runs. Raising the cap raises the
*number* of authorized actions, never the authority of any one of them: each intent still passes
`compile_step` → `SafetyRuntime` individually.

`AgentToolIntent` validates its arguments against the operation's typed model at parse time and
enforces which operations address a resource. It has no field that could name an adapter, a target,
a credential, or a budget. Validation runs before the per-turn cap is applied, so padding the list
cannot push an invalid intent out of inspection, and every refusal is recorded as evidence.

## The judge

Deterministic oracle first; the judge runs only where the oracle returned `inconclusive`. Its input
is typed, bounded, and delimited, with untrusted spans wrapped and markup escaped so evidence
cannot forge its own delimiter. Citations are validated against what was supplied; an invented
citation abstains outright. Abstention is a first-class outcome that records its reason. ADR 0010
has the full rule set, including why the frozen-label digest is pinned in the test file.

`ScriptedJudge` is a stand-in with one declared failure mode, not a model. What the red-team corpus
measures with it is the harness's evaluator hardening, and the acceptance record says so.

## Reporting

Clean utility, utility under attack, attack success, and executed unauthorized side effects are
four measurements of four different things and are never composited. `utility_under_attack` is
measured by re-running the legitimate task after the attack, on the state the attack left behind,
under a distinct action and idempotency identity.

Every stochastic figure carries its n, seed policy, model pin, and exclusion count, enforced by the
schema. Proportions use a Wilson interval; counts use a seeded percentile bootstrap; both methods
are named where the number appears. A repetition that does not complete is recorded with its reason
and reported beside every number it reduces.

The HTML report puts advisory content in a visually distinct panel labelled "not binding, gates
nothing".

## What is tested versus what is claimed

Two claims in this phase were, at first, assertions about code rather than executed facts, and both
were found by auditing for exactly that. The model plane's runtime guard had no test reaching it,
because the offline provider reports no endpoint; and `adapters/agent.py` documented a structural
test that did not exist. Both now execute. The general rule this phase adopted: if a docstring or a
decision record says a test enforces something, that test must be findable by name.

The residual, deliberate gap is that every model-facing number here came from a deterministic
stand-in. That is Phase 4 debt (PRD WP4.0), stated in the acceptance record rather than left for a
reader to infer.

## Debt cleared from Phase 1 and 2

- `Finding.reproducible` is answered from the repetition set and carries a
  `reproducibility_basis` saying what it is based on.
- The `PYTHONHASHSEED` matrix covers the new lane.
- Detection delay is still logical ticks and still says so, now beside real token counts.
