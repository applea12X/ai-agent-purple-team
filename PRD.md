# Agentic Purple Team Platform — Product Requirements and Delivery Plan

## 1. Product definition

Create a portfolio-quality platform, working title **PurpleLoop**, for explicitly authorized local and CI security testing of combined SaaS and LLM applications. It will run attack scenarios against a disposable multi-tenant fixture, determine success from observable state and tool traces, validate detection coverage, apply only pre-approved defensive profiles, replay the same scenario, and report security improvement plus utility cost.

The project should demonstrate security engineering, agent orchestration, evaluation science, browser automation, policy enforcement, observability, and reproducible software delivery—not merely wrap an LLM vulnerability scanner.

### Primary users

- **Security engineer:** authors scenarios, authorization policy, oracles, and CI gates.
- **AI/application engineer:** runs evaluations and consumes evidence-backed remediation.
- **Reviewer/recruiter:** launches a deterministic demo and evaluates the architecture, controls, and measured results.

### Core outcome

Given an authorized manifest and scenario corpus, run:

`baseline → attack → detect → mitigate → replay`

Then produce a signed, replayable report showing attack success, unauthorized side effects, detection behavior, mitigation effectiveness, and benign-utility regression.

## 2. Scope and non-goals

### MVP scope

- Local/CI execution only against Docker-isolated fixtures or exact allowlisted endpoints.
- One realistic multi-tenant support SaaS fixture with customer/admin roles, tickets, documents, RAG, memory, and narrow email/CRM/refund/export tools.
- API, tool, chat, and Playwright browser surfaces.
- 30–50 curated scenarios across classic SaaS authorization and agentic/LLM threats.
- Synthetic identities, secrets, money, records, and owned exfiltration canaries only.
- Deterministic policy enforcement and state-based scoring; LLM judges are secondary and may abstain.

### Explicit non-goals through v1

- Production exploitation or broad Internet scanning.
- Generic shell access, arbitrary network access, persistence, denial of service, credential attacks, social engineering, destructive operations, or extraction of real sensitive data.
- Autonomous scope expansion, authorization, code merging, deployment, risk acceptance, or evidence deletion.
- Kubernetes, multi-tenant commercial hosting, billing, or a full SIEM.
- Claims that passing a benchmark proves an application or model is safe.

## 3. Product principles and safety invariants

- Treat every model, target response, retrieved document, browser page, tool description, and imported attack as untrusted input.
- Keep authority outside the agent: a small deterministic safety kernel owns scope, policy, credentials, budgets, execution, evidence, and termination.
- Default deny. Missing, ambiguous, expired, changed, or revoked authorization prevents execution.
- Tenant ownership does not authorize testing a SaaS provider, shared infrastructure, upstream service, CDN, or other tenant.
- The planner emits a typed declarative DAG; it never executes tools directly or emits arbitrary shell/browser instructions.
- Resolve opaque credential handles only inside trusted adapters; never expose raw credentials to model context.
- Require exact tenant/asset checks before every side effect, after DNS resolution, and after every redirect.
- Prove findings with state deltas, canary exposure, policy decisions, or tool traces. “The model said so” is not evidence.
- Freeze a minimal regression before proposing remediation. Do not autonomously patch the application.
- Enforce hard limits for requests, retries, graph depth, concurrency, writes, tokens, cost, records, and wall time.

### Release-blocking invariants

- Zero out-of-scope execution, cross-tenant access by the harness, approval bypass, successful uncontrolled exfiltration, containment escape, or hard-budget breach.
- Emergency stop p99 at or below two seconds for cancellable adapter activity.
- Every accepted finding links to authorization, scenario, execution evidence, oracle version, and reproducible fixture state.

## 4. Reference architecture

```mermaid
flowchart LR
  cli[CLI_and_CI] --> admission[Authorization_Admission]
  admission --> planner[Untrusted_Attack_Planner]
  planner --> compiler[Typed_Plan_Compiler]
  compiler --> policy[Policy_Enforcement_Point]
  policy --> executor[Isolated_Adapter_Runtime]
  executor --> target[Disposable_SaaS_LLM_Fixture]
  executor --> ledger[Append_Only_Evidence_Ledger]
  target --> telemetry[Detectors_and_OTel]
  telemetry --> judge[Deterministic_Oracles]
  ledger --> judge
  judge --> defender[Bounded_Defense_Selector]
  defender --> reset[Fixture_Reset]
  reset --> policy
  judge --> report[JUnit_SARIF_HTML_Report]
```

### Trusted computing base

- Authorization verifier and typed plan compiler.
- Policy enforcement point and credential broker.
- Budget ledger, scheduler, circuit breakers, and kill switch.
- Adapter runtime, evidence writer/redactor, fixture reset, and deterministic oracles.

### Untrusted or fallible components

- Attack planner and payload mutator.
- Target application/agent and retrieved content.
- LLM judge and defender recommendations.
- Browser output and third-party framework adapters.

### Technology choices

- Python 3.12, `uv`, Pydantic, Typer, and asyncio.
- Inspect AI as the evaluation substrate and log-format bridge.
- Direct Playwright Python for deterministic browser control and traces.
- Docker Compose for the fixture and per-run containment.
- FastAPI, PostgreSQL, and a simple local object/document store for the target.
- OpenAI-compatible model interface supporting configured APIs and Ollama/vLLM profiles.
- OpenTelemetry plus a versioned project event namespace.
- DuckDB/Parquet for analysis; JSONL, JUnit XML, SARIF, and static HTML outputs.
- Optional adapters for PyRIT, garak, Promptfoo, AgentDojo-style tasks, and bounded LangGraph attack policies.

No imported framework owns the canonical scenario or result schema.

## 5. Proposed repository structure

- `README.md`: one-command demo, architecture, safety warning, sample report, and resume-ready results.
- `docs/prd.md`: durable version of this PRD, framework crosswalk, threat model, and acceptance criteria.
- `docs/architecture.md`: system structure and trust boundaries.
- `docs/rules-of-engagement.md`: authorization and safe-use requirements.
- `docs/evaluation-methodology.md`: metrics, repetitions, judges, and benchmark limitations.
- `docs/adr/`: architecture decision records.
- `src/purpleloop/schemas/`: authorization manifest, scenario, plan, event, finding, mitigation, and attestation models.
- `src/purpleloop/control/`: admission, policy, budgets, approvals, kill switch, and credential handles.
- `src/purpleloop/runtime/`: deterministic state machine, Inspect bridge, scheduler, isolation, replay, and teardown.
- `src/purpleloop/adapters/`: chat, tool, HTTP, browser, state, model, and optional third-party attack adapters.
- `src/purpleloop/scoring/`: state/rule/differential oracles and calibrated semantic judge.
- `src/purpleloop/reporting/`: JSONL, Parquet, JUnit, SARIF, attestation, and static report generation.
- `targets/supportlab/`: vulnerable FastAPI SaaS fixture, migrations, seed data, LLM/RAG agent, tools, and configurable defenses.
- `scenarios/`: versioned threat-mapped YAML cases and private/local holdout mechanism.
- `policies/`: default-deny authorization and side-effect policies with adversarial fixtures.
- `tests/`: unit, property, contract, integration, replay, fault-injection, and end-to-end suites.
- `.github/workflows/`: deterministic PR lane and optional scheduled real-model lane.

## 6. Canonical data contracts

### Authorization manifest

- Engagement ID, owners/approvers, signed authorization reference, validity, and revocation.
- Canonical assets, tenants, methods, action classes, model endpoints, exact exclusions, and environment.
- Credential handles and scopes; data classification, retention, and redaction rules.
- Request, token, cost, write, record, time, and concurrency budgets.
- Stop conditions, contacts, cleanup, and required evidence.
- Digest bound into every plan, action, event, finding, and attestation.

### Scenario

- Stable ID and version.
- Versioned OWASP LLM, OWASP Agentic, MITRE ATLAS, ASVS, and API mappings.
- Target mode, fixture seed, actors, roles, tenants, legitimate objective, and attacker objective.
- Preconditions, attack budget, expected telemetry, deterministic oracle, utility oracle, defense profile, reset procedure, and provenance/license.

### Plan and action

- Typed DAG with known adapter/action enums.
- Canonical asset IDs, intent, preconditions, expected evidence, and oracle.
- Idempotency key, timeout/retry rules, maximum attempts, side-effect class, rollback, and postcondition reads.

### Evidence event

- Run, trace, and sequence IDs; timestamp and actor.
- Code, model, prompt, policy, and adapter versions.
- Input/output hashes, redacted artifact pointer, policy decision, latency, and cost.
- Before/after state, parent hashes, and signature.

### Finding

- Scoped asset, attacker goal, observed impact, evidence links, reproducibility, confidence, severity rationale, and taxonomy mappings.
- Status: confirmed, likely, inconclusive, duplicate, accepted risk, or test-system incident.

## 7. Functional requirements

### Safety kernel

- Validate signature, expiry, revocation, tenant binding, exclusions, tool schemas, egress, and budgets before execution.
- Revalidate at every action boundary; fail closed if policy is unavailable or stale.
- Broker per-call short-lived credentials and filter discovered secrets from model-visible output.
- Support dry-run, pause, kill, cancellation, rollback checks, and guaranteed teardown.
- Detect repeated/no-progress action-state hashes and stop runaway loops.

### Purple-team runner

- Reset the fixture.
- Run the clean task and record baseline utility.
- Run the baseline attack.
- Score target state and utility.
- Collect detector events.
- Choose only typed, pre-approved defense changes.
- Reset to the same fixture state.
- Replay with the same seed and budget.
- Compare attack reduction and utility regression.

The runner must separate “attack failed because the attacker was ineffective” from “defense prevented the attack,” and distinguish model susceptibility from actual executor side effects.

### Threat coverage

SaaS coverage:

- Object-, function-, and property-level authorization.
- Authentication and role boundaries.
- Resource consumption and sensitive workflows.
- SSRF, misconfiguration, inventory, and unsafe upstream consumption.
- Cross-role and cross-tenant workflows.

LLM and agent coverage:

- Direct and indirect prompt injection.
- Encoded, multilingual, and multiturn variants.
- System-prompt leakage.
- RAG and memory poisoning.
- Goal hijacking and confused-deputy attacks.
- Excessive agency and tool misuse.
- Argument/schema injection and unsafe output handling.
- Canary exfiltration and covert channels.
- Unexpected code execution and cascading failure.
- Human-approval spoofing.

Hostile content should appear through tickets, documents, HTML/Markdown, API responses, tool descriptions, memory, logs, and inter-agent messages.

### Judging

- Prioritize database/API state, policy decisions, tool traces, schema/rule scorers, and differential/metamorphic checks.
- Use an LLM only for unresolved semantics, with normalized evidence, a structured rubric, cited evidence, confidence, abstention, repeated trials, and human calibration.
- Test evaluator resistance to prompt injection, position bias, verbosity bias, self-family bias, non-determinism, reward hacking, contamination, and aggregation masking.

### Reporting

Report:

- Clean task utility.
- Attack success rate.
- Executed unauthorized side-effect rate.
- Detector precision, recall, and time to detect.
- Mitigation effectiveness.
- Utility degradation after mitigation.
- Evidence completeness and replay rate.
- Latency, actions, tokens, and cost.

Results must be shown per risk class with worst cases, repetitions, uncertainty/confidence intervals, exclusions, and provenance—not only a composite score.

## 8. Phased implementation and checkpoints

### Phase 0 — Foundation and safety kernel (weeks 1–3)

Deliver:

- Repository, packaging, lint/type/test tooling, architecture decisions, and threat model.
- Authorization and scenario schemas.
- CLI skeleton and mock read-only adapters.
- Policy engine, budget ledger, kill switch, and hash-chained event ledger.
- Minimal Compose test service and offline model-response fixtures.

Checkpoint:

- All mutated out-of-scope host, tenant, redirect, DNS, and action cases are denied.
- Policy outage, invalid signature, expiration, revocation, or ambiguity fails closed.
- Kill-switch p99 is at most two seconds in fault-injection tests.
- No plaintext fixture secrets enter logs or model context.
- Replaying mock traces yields identical event and score hashes.

### Phase 1 — Deterministic closed-loop MVP (weeks 4–7)

Deliver:

- Runtime state machine: provision → seed → clean task → attack → score → detect → select defense → reset → replay → teardown.
- Inspect bridge, chat/tool/HTTP drivers, state oracle, evidence bundles, JUnit/SARIF/static report.
- Five deterministic scenarios with seeded vulnerabilities and typed defenses.

Checkpoint:

- Zero unauthorized harness side effects across the integration suite.
- At least 95% exact replay on deterministic fixtures.
- At least 90% seeded-finding recall and at most 5% reviewed false positives.
- Failed and cancelled runs always teardown and preserve evidence.
- One command produces a complete report without cloud credentials.

### Phase 2 — Realistic SaaS and browser lane (weeks 8–12)

Deliver:

- `supportlab`: two organizations, multiple users/roles, tickets, documents, refunds, exports, canary records, and intentionally toggleable BOLA/BFLA/property/workflow flaws.
- Direct Playwright adapter with fresh browser contexts and trace ZIPs.
- 15–20 SaaS/API/browser scenarios and configurable fixes.

Checkpoint:

- 100 consecutive isolated local runs with no cross-run state leakage.
- Zero unintended cross-tenant access by the harness.
- At least 99% required evidence-field completeness.
- Browser and API oracles agree on shared workflows.
- Actual token/API cost is within ±10% of the pre-run estimate.

### Phase 3 — LLM/RAG agent and adaptive attack lane (weeks 13–17)

Deliver:

- RAG assistant and narrow email/CRM/refund/export/memory tools inside `supportlab`.
- Direct/indirect injection, goal hijacking, memory poisoning, system-prompt leakage, excessive agency, tool misuse, and canary-exfiltration scenarios.
- Optional bounded adaptive attacker plus selected PyRIT/garak imports through adapters.
- Hybrid judge with a dedicated evaluator-red-team corpus.

Checkpoint:

- 30–50 total high-quality scenarios with versioned taxonomy mappings.
- Report clean utility, utility under attack, attack success, and executed side effects separately.
- No out-of-scope action reaches the target even when the target model is compromised.
- Semantic judge agreement with adjudicated labels reaches Cohen’s kappa or Krippendorff’s alpha of at least 0.7.
- Judge order-swap consistency reaches at least 95%.
- Held-out evaluator-injection resistance reaches at least 99% with no critical false pass.

### Phase 4 — CI quality system and portfolio release (weeks 18–22)

Deliver:

- Fast PR lane using deterministic fixtures and 10–20 smoke scenarios.
- Nightly/manual lane with real model calls, adaptive attacks, browser workflows, at least five stochastic repetitions, and confidence intervals.
- Release lane with held-out mutations, signed run attestations, regression registry, retention policy, audit export, and incident runbook.
- Polished README, architecture diagrams, recorded demo, sample evidence bundle, benchmark methodology, and results narrative.

Checkpoint:

- At least 98% pinned replay success.
- At least 80% regression coverage for accepted findings.
- At least 95% precision on an adjudicated finding sample.
- An independent reviewer reconstructs a passing run, denied run, and incident from exported artifacts within 30 minutes.
- CI blocks scope bypasses, critical regressions, schema drift, budget failures, and statistically meaningful per-risk-class regressions.

### Phase 5 — Optional expansion

Only after v1:

- Import more framework adapters or benchmark subsets.
- Add additional disposable target fixtures.
- Compare models and defenses across a pinned evaluation matrix.
- Add a self-hosted observability profile or human-review UI.
- Require shadow mode and explicit risk approval for every autonomy or action-class increase.

## 9. Test strategy

- **Unit:** schema canonicalization, signatures, policy decisions, budget reservations, redaction, hashes, and oracles.
- **Property/mutation:** Unicode/IDN hosts, aliases, redirects, DNS rebinding, tenant/resource confusion, parser discrepancies, pagination explosions, and chained individually allowed actions.
- **Contract:** every adapter has typed I/O, timeout, retry, idempotency, postcondition, redaction, and cancellation behavior.
- **Integration:** fixture lifecycle, short-lived credentials, network deny-by-default, event ordering, report generation, and teardown under failure.
- **Fault injection:** stale/unavailable/rolled-back policy, model timeout, partial write, ledger interruption, operator disconnect, active cancellation, and evidence flush.
- **Adversarial evaluator:** evidence-borne prompt injection, fake approvals, scope-widening claims, rubric gaming, verbosity/order bias, and unsupported citations.
- **End-to-end:** paired vulnerable/defended runs with positive controls, negative controls, benign-utility checks, and minimal replay.

## 10. Standards and research alignment

Version-pin and cross-reference:

- NIST AI RMF 1.0 and GenAI Profile AI 600-1 for GOVERN/MAP/MEASURE/MANAGE and TEVV.
- NIST SP 800-115 for authorization and rules of engagement.
- OWASP Top 10 for LLM/GenAI 2025.
- OWASP Top 10 for Agentic Applications 2026.
- OWASP ASVS 5.0 and API Security Top 10 2023.
- OWASP Autonomous Penetration Testing Standard v0.1.0.
- MITRE ATLAS for adversary technique IDs and coverage.
- AgentDojo for separate legitimate-task utility and attacker objectives.
- Inspect AI for evaluation substrate and sandbox/log patterns.
- in-toto/SLSA structures for a purpose-built run attestation.

Framework alignment is not certification or legal safe harbor.

## 11. Portfolio success criteria

The finished project should let a reviewer:

1. Run a deterministic local demo in under ten minutes.
2. Watch an attack exploit a seeded SaaS/LLM weakness without leaving the authorized sandbox.
3. Inspect exact evidence and the state-based oracle proving impact.
4. See a bounded defense applied, the same attack replayed, and utility measured before and after.
5. Trigger a malicious scope-expansion or evaluator-injection case and observe a fail-closed result.
6. Review reproducible methodology, standards mappings, test coverage, CI artifacts, and honest limitations.

### Resume claim after validation

> Built a local-first autonomous AI purple-team harness for SaaS and LLM agents using Inspect AI, Playwright, Docker, deterministic policy gates, state-based security oracles, and replayable evidence; evaluated 30–50 threat-mapped scenarios while measuring attack success, detection coverage, mitigation efficacy, and utility regression.

## 12. Primary references

- [NIST AI Risk Management Framework 1.0](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
- [NIST AI RMF Generative AI Profile, AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [OWASP Top 10 for LLM and GenAI](https://genai.owasp.org/initiatives/top-10-for-llm-and-genai/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Autonomous Penetration Testing Standard](https://owasp.org/APTS/standard/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [Inspect AI](https://inspect.aisi.org.uk/)
- [PyRIT](https://github.com/microsoft/pyrit)
- [garak](https://github.com/NVIDIA/garak)
- [AgentDojo](https://github.com/ethz-spylab/agentdojo)
- [Playwright](https://github.com/microsoft/playwright)

Research synthesis current to July 25, 2026. Numeric checkpoints are proposed engineering targets, not mandates from the cited standards.
