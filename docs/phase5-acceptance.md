# Phase 5 Acceptance Record — index

Date: November 26, 2026. Integration branch `phase-5`, from `main` at `a79f185`.

Measured on a local macOS development environment (Apple M3 Pro, macOS 27.2, Python 3.12, Docker
Desktop, Ollama 0.40.16). Phase 5 was built as separate work packages, each on its own branch,
each closed by its own acceptance note under [phase5/](phase5/). This file is the index. It
restates only the headline result of each note and says where every figure comes from. **Every
number below is copied from the note it cites, where it was measured by a command written next to
it, except the integrated quality gate at the end, which was run on the merged tree for this
record.** When a note and this index disagree, the note is authoritative.

Status vocabulary: **met** (measured, threshold reached) · **partly** (measured, part of the
threshold open, with the reason) · **blocked** (cannot be run here: the reason is one of *hosted
credential*, *different model family not installed*, *human*, *upstream data*) · **left to the
author** (an action only the repository owner may take) · **not met** (measured, threshold missed).

## Checkpoints (planning/phase5-plan.md §6)

| WP | Checkpoint | Threshold | Result | Record |
| --- | --- | --- | --- | --- |
| 5.0 | Author-closable Phase 4 rows | All met | **Met, except 5.0.12** (left to the author, below). 5.0.1, 5.0.2, 5.0.3, 5.0.5, 5.0.6, 5.0.7, 5.0.10, 5.0.11 recorded from commands run. | rows below |
| 5.0 | Real API cost vs estimate | ±10%, non-vacuous | **Blocked: hosted credential.** Token estimate on the local pin: −0.20% on a separate run (met), but price is 0, so the cost half is vacuous. | [real-model](phase5/wp5.0-real-model-acceptance.md) |
| 5.0 | Precision on adjudicated findings | ≥ 95%, Wilson bound, method stated | **Blocked: human.** `adjudicate` tooling built and tested; no real label exists. | [wp5.0.8](phase5/wp5.0.8-acceptance.md) |
| 5.0 | Reviewer reconstruction | 3 sets in ≤ 30 min | **Blocked: human.** Protocol, samples, and a UI path are in place. | [wp5.4](phase5/wp5.4-acceptance.md) |
| 5.0 | v1 exists | Tag + CI-key attestation naming the commit | **Left to the author.** No tag, no merge to `main`, no CI attestation key provisioned. | 5.0.12 below |
| 5.1 | Shadow never executes | 0 adapter calls | **Met: 0** dispatches, 0 fixture requests, 0 model calls over the 25-scenario agent corpus (650 actions suppressed). | [wp5.1](phase5/wp5.1-acceptance.md) |
| 5.1 | Uncovered increase refused | 100% of generated widenings | **Met: 6 of 6** increase kinds refused at admission and end to end; property tests over generated widenings. | [wp5.1](phase5/wp5.1-acceptance.md) |
| 5.2 | Matrix run exists | ≥ 2 real pins + 3 stand-ins, ≥ 5 reps | **Partly.** Stand-ins met (375 verified trials, 5 reps). Real rows on a 12-scenario subset: qwen2.5 60/60; deepseek-r1 38/60 (cap and timeouts). **Blocked: different model family not installed** — both real pins are Qwen-lineage. | [wp5.2](phase5/wp5.2-acceptance.md) |
| 5.2 | Defense dependence classified | Every agent defense | **Met for the stand-in rows:** 7 of 7 defenses, 25 of 25 scenarios, Holm-corrected. No real row changed a classification. | [wp5.2](phase5/wp5.2-acceptance.md) |
| 5.3 | No leak through telemetry | 0 findings | **Met: 0 findings** over the full agent and supportlab exports and the collector output; a planted leak is caught. | [wp5.3](phase5/wp5.3-acceptance.md) |
| 5.3 | Telemetry changes nothing | Byte-identical outcomes and verdicts | **Met:** byte-identical bundles on and off (6 cases) and under 8 fault modes. | [wp5.3](phase5/wp5.3-acceptance.md) |
| 5.4 | UI is inert and read-only | 0 executable payloads; bytes unchanged | **Met:** 0 executable payloads (1,588 payloads, 4,442 pages); every bundle byte and mtime unchanged after a full session. | [wp5.4](phase5/wp5.4-acceptance.md) |
| 5.5 | Containment holds | 0 escapes | **Met: 10 of 10** escape attempts contained, under **hardened runc** (gVisor is not installed on this host). | [wp5.5](phase5/wp5.5-acceptance.md) |
| 5.5 | New lane corpus | Recall ≥ 90%, FP ≤ 5%, replay ≥ 98% | **Met:** recall 1.000 (10/10), FP 0.000, replay 30/30. | [wp5.5](phase5/wp5.5-acceptance.md) |
| 5.6 | Imported subset runnable | Promoted / attempted, both reported | **Partly.** Authored AgentDojo-style cases: 6 promoted of 8 attempted. **Imported half blocked: upstream data** (no AgentDojo data available locally). | [wp5.6](phase5/wp5.6-acceptance.md) |
| All | Prior suites and lanes | Pass unchanged; `phase0`–`phase4` workflows untouched | **Met** in the integrated run below; no file under the prior test directories or `phase0`–`phase4.yml` was edited (the SHA guard test pins them). | Quality gate |
| All | Coverage | ≥ 85% branch | **Met: 91.99%** in the integrated run (1,299 passed, 8 gated skips). | Quality gate |

## WP5.0 — closing v1 (Phase 4 debt), row by row

| Row | What | Status | Record |
| --- | --- | --- | --- |
| 5.0.1 | Full suite measured once on the Phase 4 tree | Met: 472 passed, 3 skipped, 89.40% | [wp5.0.1](phase5/wp5.0.1-acceptance.md) |
| 5.0.2 | Sampled real-model corpus | Met on the local pin: qwen2.5:7b-instruct `845dbda0ea48`, 25 scenarios × 5, three runs, 300 bundles. Run 1 found 4 defects (2 application, 2 harness); after the fixes, the same seeds gave defended-replay attack 0/50 and new seeds 1/125 (an oracle false positive). | [real-model](phase5/wp5.0-real-model-acceptance.md) |
| 5.0.3 | Token calibration | Met: 462 in / 91 out per call (n 750); −0.20% on a separate run | [real-model](phase5/wp5.0-real-model-acceptance.md) |
| 5.0.4 | Hosted real cost | **Blocked: hosted credential** | — |
| 5.0.5 | Real judge | Partly: deepseek-r1, α 0.304 [−0.067, 0.608], κ 0.667 (n 6), 0 critical false passes; **1 of 3 pre-registered trials completed** (timeout). Cross-family delta **blocked: different model family not installed**. | [real-model](phase5/wp5.0-real-model-acceptance.md) |
| 5.0.6 | Compromised-model property, real model | Met: 0 violations over 300 bundles; no invented operation names | [real-model](phase5/wp5.0-real-model-acceptance.md) |
| 5.0.7 | CI-observed gate proofs | Met: 1 control and 5 red branches run in GitHub Actions, each failing at the gate step with its intended reason. The `pr-fast` 10-minute target is **not met** (median 1,672 s over 48 runs). | [wp5.0.7](phase5/wp5.0.7-acceptance.md) |
| 5.0.8 | Adjudication census | Tooling met; census **blocked: human** | [wp5.0.8](phase5/wp5.0.8-acceptance.md) |
| 5.0.9 | Independent reviewer session | **Blocked: human** | [wp5.4](phase5/wp5.4-acceptance.md) |
| 5.0.10 | Per-finding regression pinning | Met: 48 per-scenario pins; one injected regression names exactly one finding | [wp5.0.10](phase5/wp5.0.10-acceptance.md) |
| 5.0.11 | Recorded demo | Met: `docs/demo/phase-demo.cast` | [wp5.0.11](phase5/wp5.0.11-acceptance.md) |
| 5.0.12 | Merge, tag, CI-key attestation, resume claim, v1 baseline under a held key | **Left to the author** (below) | — |
| audit | Every loose end from Phases 0–5 has an owner | Met: each row is closed, partly closed with the reason, blocked with the reason, or an accepted limit with its cite | [loose-ends](phase5/loose-ends.md), [loose-ends-2](phase5/wp5.0-loose-ends-2-acceptance.md), [drill](phase5/drill-acceptance.md) |
| PRD §7 | Runaway-loop detector in the kernel | Built (ADR 0018), off by default, signed thresholds | [runaway-loop](phase5/runaway-loop-acceptance.md) |

## Defects found in earlier phases' code, and fixed

Each is described, with its root cause and the test that pins the fix, in the record cited.

- `RunSummary.cost_microusd` was never set (model-config worker; `runtime/runner.py`).
- The Phase 4 scope and budget gates matched evidence across runs in a suite, so one run could
  mask another ([drill](phase5/drill-acceptance.md)).
- The risk-class gate passed a removed scenario; it now refuses with `SCENARIOS_REMOVED`
  ([wp5.1](phase5/wp5.1-acceptance.md)).
- The Phase 2 browser emergency stop had never been measured
  ([loose-ends-2](phase5/wp5.0-loose-ends-2-acceptance.md)).
- Runbook steps that could not be followed, and gaps in the retention policy
  ([drill](phase5/drill-acceptance.md)).
- `retrieval-provenance-guard` was prompt-only at the export, refund, and CRM sinks;
  `memory-write-guard` trusted the model's own provenance label; a suite's outcome was taken from
  repetition 0 only; refund injections named no ticket
  ([real-model](phase5/wp5.0-real-model-acceptance.md)).

## What this phase does not show

- **No hosted model was called.** Every real-model figure is from local Ollama pins, both
  Qwen-lineage. Cost figures are vacuous (price 0). Nothing here measures a different model
  family.
- **No human took part.** Precision, reviewer reconstruction, human judge calibration, and a
  second-person risk approver are untested. The tooling for each is built and tested.
- **No release exists.** `phase-5` is not merged, nothing is tagged, and the capability baseline
  and attestations are signed with ephemeral keys. The nightly lane has never been dispatched in
  GitHub Actions.
- **The imported benchmark half was not run**, because no upstream data was available.
- **Containment was measured under hardened runc, not gVisor.**

## Left to the author

1. **v1 (WP5.0.12):** merge `phase-5` (and through it, Phase 4) to `main`, tag `v1.0.0` on a
   clean commit, provision the `PURPLELOOP_ATTESTATION_KEY` repository secret so the `release` job
   signs with a held key, and re-sign the v1 capability baseline with a held approver key (it is
   signed with an ephemeral key today).
2. **The PRD §11 resume claim** says "30–50 threat-mapped scenarios". The v1 lanes have 48
   distinct scenario ids (phase1 5, supportlab 18, agent 25); with the codelab lane the tree has
   58. Whether the claim counts the Phase 5 lane is the author's wording choice.
3. **Precision threshold method:** with a Wilson lower bound, a perfect 48-of-48 census gives
   0.9259, below 0.95; a lower bound of at least 0.95 needs n ≥ 73. The point estimate would be
   1.0. Which one the checkpoint uses is the author's decision
   ([wp5.0.8](phase5/wp5.0.8-acceptance.md)).
4. **Committed sample Inspect logs embed the author's home path** (loose-ends row 6.6). Scrubbing
   them means regenerating and re-attesting both sample sets.
5. **A hosted credential** (`PURPLELOOP_MODEL_API_KEY`) and **a model from a different family**
   unblock 5.0.4, the cross-family judge delta, the matrix's two-family checkpoint, and the
   nightly real run. Model selection is deferred to Phase 6.

## Integrated quality gate (merged `phase-5`)

Run by the orchestrator on the merged `phase-5` tree at `1b23447` (every work-package branch
merged, the real-model branch last). The working tree differed from that commit only in the
documentation edits that accompany this record; no code changed between the run and the commit
that records it.

- `uv run ruff check .`: all checks passed. `uv run ruff format --check .`: 309 files already
  formatted. `uv run mypy`: no issues in 132 source files.
- `uv run pytest tests/phase5 -q --no-cov`: **826 passed, 5 skipped** in 431.65 s.
- `uv run pytest --junitxml=artifacts/junit-phase5-final.xml -q`: **1,307 collected, 1,299
  passed, 8 skipped, 0 failed, 0 errors** in 1,725.87 s (pytest's clock). **Branch-aware coverage
  91.99%** against the 85% floor.
- The 8 skips are all environment-gated: the three container/PostgreSQL tests skipped since
  Phase 3, the live-Chromium browser e-stop trial, and the four codelab container tests (all need
  `PURPLELOOP_CONTAINER_TESTS=1`). The container lanes were run with that flag by their own work
  packages and are recorded in their notes ([wp5.5](phase5/wp5.5-acceptance.md),
  [loose-ends-2](phase5/wp5.0-loose-ends-2-acceptance.md)); they were **not run** in this
  integrated pass.
- Every Phase 0–4 test file and the `phase0`–`phase4` workflows are unchanged and ran inside the
  1,299; the workflow SHA guard test passed.
