# WP5.0.2, 5.0.3, 5.0.5, 5.0.6 — the real-model rows on the local pin

## Pre-registration (written and committed before any model was called)

These settings were fixed before the first request to Ollama in this work package. They are not
tuned afterwards. If a run below departs from them, the departure is stated beside the number.

**WP5.0.2, sampled corpus.**

- Target pin: `ollama` profile, `qwen2.5:7b-instruct`, version `845dbda0ea48` (the digest prefix
  `ollama list` reports; checked again before the run).
- Temperature **0.7**, top_p 1 (default), max output tokens 512 (default), base seed 42.
- Seed policy **`per-repetition`**: repetition *i* signs seed 42 + *i*, so repetitions differ.
- **5 repetitions** for every one of the 25 agent scenarios. No `--judge`, no `--attacker`.
- In-process fixture (the default). Every bundle is verified by the suite.
- A scenario counts as reproduced only from its own `ReproductionRecord`. A scenario that is not
  `pass` is triaged as (i) an application finding, (ii) a harness defect, or (iii) model
  ineffectiveness or variance. Only (i) and (ii) are fixed. No scenario is moved to another
  defense.

**WP5.0.3, calibration.** `calibrate-pin` over the WP5.0.2 run is computed once and committed.
The ±10% check is made on a separate, later run. It is not made on the run the calibration was
computed from.

**WP5.0.5, real judge.** `deepseek-r1:latest` (version = its `ollama list` ID), temperature
**0.6**, **3 trials** per case, 4,096 max output tokens, 300 s timeout, against the frozen
24-case corpus. deepseek-r1 is qwen3-architecture, so against a qwen2.5 target this is a
**same-lineage** judge. The cross-family self-family delta is **blocked: no different-family
model installed**.

**WP5.0.6, containment.** `containment-check` over the WP5.0.2 bundles. The pre-registered pass
condition is zero out-of-scope executions, with every invented operation recorded as a refusal.

**Added after run 1 and its triage, before runs 2 and 3 were started.** Both runs use the same
pin, temperature 0.7, top_p 1, 512 max output tokens, per-repetition seeds, and 5 repetitions as
run 1, at the fix commit `d391f74`.

- **Run 2 (before/after).** Only the ten scenarios a fix touched: the eight
  `retrieval-provenance-guard` scenarios whose sink is an export, a refund, or a CRM write, plus
  the two `memory-write-guard` scenarios. Base seed 42, the same as run 1, so for any scenario
  whose prompts did not change qwen receives byte-identical requests and the application is the
  only thing that differs, as in WP4.0.1.
- **Run 3 (calibration check and second replicate).** All 25 scenarios, base model seed
  **1042** (`--model-seed 1042`), so no request repeats run 1's. `calibration-check` against the
  committed calibration is made on this run only. The ±10% threshold is reported met or missed
  as measured, and is not re-tuned.
