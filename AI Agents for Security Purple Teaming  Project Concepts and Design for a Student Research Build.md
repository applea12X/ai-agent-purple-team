# AI Agents for Security Purple Teaming: Project Concepts and Design for a Student Research Build

## Executive Summary

AI agents can be used to automate parts of red, blue, and purple teaming for AI-heavy and cloud environments, turning periodic exercises into continuous detection-validation loops. Recent work on automated LLM red-teaming shows that learning-based agents can systematically search for vulnerabilities across multiple adversarial categories, outperforming manual expert red teams in coverage and efficiency. This report outlines what a semester-scale project for a college student could look like: focusing on an "always-on" agentic purple team for a constrained environment (e.g., cloud sandbox or LLM app), with clear architecture, governance controls, and evaluation methodology.[^1][^2][^3][^4]

## Background: Purple Teaming and Agentic AI

Purple teaming combines offensive red team simulations with defensive blue team detection and response, but in a collaborative, feedback-driven mode rather than strictly adversarial testing. In AI security contexts, purple teams coordinate jailbreaking attempts, prompt injection, data exfiltration, and other attacks against LLM applications while simultaneously tuning detection rules, guardrails, and response playbooks. Agentic purple teaming extends this by using autonomous AI agents to continuously emulate attacks and trigger remediation in the same workflow, shrinking the gap between vulnerability discovery and mitigation.[^3][^5][^4]

## Research Landscape: AI Agents in Purple Teaming

Industry vendors and researchers have started to explore "always-on" purple teams where AI agents autonomously execute red and blue teaming workflows. A recent blog from Lasso Security describes an agentic purple teaming platform in which autonomous agents launch AI-specific attacks (prompt injection, model theft, data leakage) and then automatically apply guardrails or policies to remediate discovered issues. Educational and industry talks (e.g., RSA Conference sessions on "Always-On Purple Team" and media from cloud security vendors) demonstrate architectures where AI agents collaborate on threat intel, adversary emulation, and detection engineering in real time.[^6][^7][^3]

For LLM-specific security, academic work formulates automated red-teaming as an adversarial prompt search problem, using learning-based agents to generate, execute, and score adversarial prompts across categories such as reward hacking, deceptive alignment, data exfiltration, sandbagging, inappropriate tool use, and chain-of-thought manipulation. Systematic reviews of LLM red-teaming propose taxonomies of attacks and evaluation frameworks for datasets, metrics, and benchmarks, providing a structured foundation for purple team exercises that combine attack catalogs with detection coverage measurement.[^2][^8][^1]

## Governance and Risk Considerations for AI Agents

AI agents used in purple team exercises need explicit governance because they act as non-human identities that can chain tools and expand their scope beyond what was intended. Guidance from agentic AI security groups recommends treating the agent as a governed identity with a narrow mission, short-lived credentials, strict tool whitelists, and explicit stop conditions, rather than as a reusable script with broad privileges. Agent governance should align with emerging frameworks such as the OWASP Agentic AI Top 10, CSA MAESTRO, and NIST AI Risk Management Framework, emphasizing runtime controls, identity discipline, and traceability.[^9]

Concrete best practices include issuing credentials per exercise phase and revoking them automatically, logging every tool call with agent identity and session metadata, and using policy-as-code to enforce real-time access decisions. Edge cases often arise when agents have access to production-adjacent systems, shared secrets stores, or agent-to-agent orchestration layers, where even well-scoped tests can cause unintended persistence or data exposure if identity boundaries are weak. For a student project, these governance concepts can be implemented in simplified form (e.g., local sandbox accounts, ephemeral API keys, scoped roles) to demonstrate safe agent behavior.[^9]

## Project Vision: Student-Scale Agentic Purple Team

A realistic project for a college student is to design and implement a small-scale "always-on" agentic purple team for a constrained environment, such as:

- A cloud sandbox account (e.g., minimal AWS research environment) focused on a handful of services (IAM users/roles, S3 buckets, EC2, CloudTrail logs).
- A LLM-powered web application (e.g., RAG chatbot or code assistant) with defined prompts, tools, and data sources.

The core vision is an autonomous agent that periodically or continuously:

- Executes adversary emulation tasks (red side) using scripted or LLM-generated attack patterns.
- Validates that detection rules, logging, and guardrails (blue side) fired correctly for each attack.
- Records coverage metrics and recommendations for tuning detections and policies (purple side).

By focusing on a bounded environment and a limited attack catalog, the project can demonstrate how agentic purple teaming compresses the red/blue feedback loop and provide a framework that could be extended to more complex enterprise scenarios.[^3][^6]

## Candidate Project Scopes

### Scope A: AI Agent Purple Team for Cloud Sandbox

In this variant, the project builds an AI agent that runs purple team exercises in a research AWS account or equivalent cloud sandbox.[^10][^6]

Attack catalog:

- Privilege escalation scenarios (e.g., misuse of IAM policies, over-permissioned roles).
- Data exfiltration from tagged "sensitive" S3 buckets.
- Misconfigured logging or monitoring (CloudTrail disabled, missing GuardDuty coverage).

Detection objectives:

- Validate that CloudTrail, GuardDuty, or custom detection scripts generate alerts for the simulated attacks.
- Confirm that relevant logs contain sufficient context (identity, IP, action) to support investigation.

The AI agent:

- Chooses attack scenarios from a catalog or generates variants using an LLM meta-prompt (e.g., "Craft an IAM privilege escalation scenario within this policy template").[^1]
- Executes attacks via cloud SDK or IaC templates under tightly scoped credentials.
- Triggers or evaluates detection rules, then logs results to a coverage dashboard.

### Scope B: AI Agent Purple Team for LLM Application

In this variant, the project focuses on an LLM app (e.g., chatbot with tools) and uses an agent to perform automated red-teaming combined with detection and guardrail validation.[^5][^1]

Attack catalog:

- Jailbreak prompts to bypass safety policies.
- Prompt injections in tool-using contexts (e.g., RAG or function-calling scenarios).
- Data exfiltration attempts against sensitive knowledge bases.

Detection and guardrails:

- Input validation, output filtering, and model-level safety settings.
- Monitoring of logs for suspicious prompts or responses.

The AI agent:

- Uses meta-prompts to generate adversarial prompts targeting specific threat categories.[^1]
- Sends prompts to the app, collects responses, and scores them using a vulnerability detection function similar to academic work (e.g., lexical patterns, semantic similarity to risk descriptors).[^2][^1]
- Records which attacks succeeded, which were blocked, and maps results to guardrail configuration changes.

## System Architecture for the Project

A generic architecture for the project can be described in layered components:[^7][^3]

1. **Target System Layer**: Cloud sandbox or LLM app, instrumented with logging and detection (e.g., SIEM, custom log store, guardrails).
2. **Attack Catalog & Scenario Engine**: A database or configuration of attack playbooks, each with preconditions, steps, and expected detection signals.
3. **AI Agent Layer**: One or more agents built using an LLM framework (e.g., agent libraries, orchestration tools) that can:
   - Select scenarios.
   - Generate concrete inputs or payloads.
   - Orchestrate tool calls (cloud SDK, HTTP clients, Log APIs).
4. **Detection Validation Layer**: Code or agent functions that query logs and detection systems to determine whether attacks were correctly spotted.
5. **Governance & Control Plane**: Identity and access management for the agent, logging of all actions, and policy-as-code enforcement to constrain the agent's behavior.[^9]
6. **Reporting & Metrics Layer**: Coverage scores (e.g., percentage of attacks detected), vulnerability lists, and time-to-detection metrics presented via a simple UI or notebook.

## Methodology: How the Agentic Purple Team Operates

A student project should define a repeatable exercise methodology that the agent follows, similar to structured red-teaming protocols in literature.[^5][^1]

Typical workflow:

1. **Seed Collection**: Curate initial attack seeds from public red/purple team catalogs, LLM red-teaming papers, and cloud or LLM-specific threat matrices (e.g., MITRE ATLAS).[^2][^1]
2. **Scenario Selection and Generation**: Use meta-prompts or configuration rules to choose a scenario and generate payloads (e.g., adversarial prompts, cloud commands).[^1]
3. **Attack Execution**: Agent executes the scenario with controlled credentials or sandboxed endpoints.
4. **Vulnerability Detection**: For LLM apps, apply lexical and semantic analysis to responses; for cloud targets, check logs and alerts for expected detection events.[^4][^1]
5. **Coverage Scoring**: Compute metrics like detection rate per attack category, false negative counts, and log quality indicators.[^2][^1]
6. **Feedback and Guardrail Tuning**: Propose specific guardrail or detection rule adjustments based on observed gaps (e.g., regex patterns for prompts, IAM hardening templates).
7. **Iteration and Continuous Operation**: Schedule repeated runs (e.g., daily, weekly) to simulate continuous purple teaming and observe coverage trends over time.[^4][^3]

## Governance Design for the Project

Even in a student sandbox, governance design is important to avoid unintended persistence or data exposure.[^9]

Key elements:

- **Scoped Mission**: Define explicit objectives (e.g., "validate detection for three IAM attack patterns") and forbid actions outside this scope (e.g., resource deletion).
- **Ephemeral Identity**: Use short-lived credentials or sandbox accounts that are provisioned for each exercise and torn down afterward.[^9]
- **Tool Whitelisting**: Restrict which APIs and tools the agent can call, and audit all calls with identity and session metadata.[^9]
- **Session Boundaries**: Establish start/stop conditions for each run, preventing the agent from continuing beyond the test window.
- **Policy-as-Code**: Implement simple policy checks that gate potentially dangerous actions, such as modifying IAM policies or accessing non-sandbox data.

## Evaluation Plan and Metrics

To make the project rigorous, define evaluation metrics aligned with academic red-teaming work and industry purple teaming best practices.[^4][^1][^2]

Possible metrics:

- Number of unique attack scenarios executed per run.
- Detection rate per attack category (e.g., jailbreak, data exfiltration, privilege escalation).
- Time between attack execution and detection.
- Quality and completeness of logs (presence of identity, resource, action details).
- Guardrail effectiveness (percentage of adversarial prompts blocked or sanitized).

Students can compare manual versus agent-driven exercises, demonstrating whether the agent increases coverage or reduces effort compared to purely manual testing. They can also track changes in detection coverage over multiple runs as guardrails and detection rules are iteratively tuned.[^3][^1]

## Implementation Considerations and Technology Choices

Practical implementation choices include:

- Using popular LLM APIs or open-source models for the agent's reasoning and prompt generation.[^1]
- Selecting a lightweight agent framework or building a custom orchestration layer in Python.
- For cloud scenarios, using SDKs (e.g., boto3 for AWS) in a research account that is tightly constrained.
- For LLM apps, integrating the agent with application endpoints via HTTP and instrumenting logging.

The project can also incorporate existing open-source LLM red-teaming frameworks that provide attack catalogs and evaluation functions, extending them with purple team detection validation and governance features.[^11][^1]

## Potential Extensions and Future Work

After a successful initial build, the project could be extended with:

- Multi-agent coordination where separate red and blue agents collaborate but maintain distinct roles.[^7]
- Support for additional environments such as CI/CD pipelines, where agents simulate supply chain attacks and validate pipeline detection and hardening.
- Integration with SOC workflows (e.g., auto-generation of investigation playbooks based on detected attacks).
- Exploration of agent drift and misalignment risks, using the purple team setup itself to study how agents exceed their intended scope.[^12][^9]

These extensions connect the project to broader research on agentic AI threats and non-human identity management, while still being incremental and manageable for future semesters or independent study.

## Conclusion

AI agents are increasingly used to automate both attack simulation and detection validation in AI security, enabling continuous purple teaming for LLM apps and cloud environments. A well-scoped student project can implement a simplified agentic purple team, focusing on a constrained environment, explicit governance controls, and clear evaluation methodology, providing hands-on experience at the intersection of AI, security engineering, and applied research.[^6][^3][^4][^1][^9]

---

## References

1. [Learning-Based Automated Adversarial Red-Teaming for ... - arXiv](https://arxiv.org/html/2512.20677v3)

2. [Red teaming large language models: A comprehensive ...](https://www.sciencedirect.com/science/article/abs/pii/S0306457325001803)

3. [Agentic Purple Teaming: Red and Blue Teaming Reinvented](https://www.lasso.security/blog/lasso-agentic-purple-teaming) - With Agentic Purple Teaming, autonomous agents simulate AI-specific attacks and trigger immediate re...

4. [Purple Teaming in AI Security — Definition & Best Practices](https://aisecurityandsafety.org/en/glossary/purple-teaming/) - A collaborative security testing methodology that combines offensive red team attack simulations wit...

5. [Planning red teaming for large language models (LLMs) ...](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/red-teaming) - Learn about how red teaming and adversarial testing are an essential practice in the responsible dev...

6. [Can an AI Agent Run a Purple Team Exercise?](https://permiso.io/blog/can-an-ai-agent-run-a-purple-team-exercise?hs_amp=true) - Purple team exercises combine red team tactics with blue team detection validation. The red side exe...

7. [The Always-On Purple Team: AI Agents on the Loose](https://www.youtube.com/watch?v=kgks1vEEutk) - Erik Van Buggenhout, Author & Senior Instructor & Co-Founder, SANS Institute and NVISO
Jeroen Vandel...

8. [An End-to-End Overview of Red Teaming for Large ...](https://aclanthology.org/2025.trustnlp-main.23.pdf)

9. [How should security teams govern AI agents in purple team exercises?](https://nhimg.org/faq/how-should-security-teams-govern-ai-agents-in-purple-team-exercises/) - Treat the agent as a governed identity, not a script. Give it a narrow scope, explicit session bound...

10. [Episode 06 - Can an AI Agent Run a Purple Team Exercise in AWS?](https://www.youtube.com/watch?v=7W9uKrgoS1E) - The episode closes with a hands-on purple team exercise where Rufio operates inside an AWS research ...

11. [GitHub - Genez-io/genezio-deepteam: The LLM Red Teaming Framework](https://github.com/Genez-io/genezio-deepteam) - The LLM Red Teaming Framework. Contribute to Genez-io/genezio-deepteam development by creating an ac...

12. [Rethinking Cybersecurity Red and Blue Teaming in the ...](https://arxiv.org/html/2506.13434v1)

