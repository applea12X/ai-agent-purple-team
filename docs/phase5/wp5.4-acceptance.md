# WP5.4 — Human-review UI

Date: November 24, 2026

Built on branch `worktree-agent-ae5b2a9b94bb7d7d6`, from `phase-5` at `8f000e0`, on the same
local macOS machine as WP5.0.1. Every number below comes from a command run in this session. No
model was called. Design and trust model: [ADR 0017](../adr/0017-review-ui.md).

## Checkpoint (plan §6)

| Checkpoint | Threshold | Measured | Command |
| --- | --- | --- | --- |
| UI is inert | 0 executable payloads | **0.** 1588 distinct corpus payloads were placed in every untrusted position and 4442 pages were parsed. Every payload reached a page as text, and no page held a disallowed tag, an `on*` attribute, a non-same-origin link, a `javascript:` URL, a comment, or a raw `<script`/`<iframe`/`<svg`/`<img`/`<object`/`<embed`/`<base`/`<style`. | `make review-check` (`test_every_corpus_payload_renders_inert`, `-s` prints the `XSS-CORPUS` line) |
| UI is read-only | bundle bytes unchanged | **Unchanged.** After a full session, the SHA-256 and `st_mtime_ns` of every file and directory under a suite bundle, an attested run bundle and an audit export's directory were identical. The session visited every page twice, revealed and labelled every finding, and revealed every run. `verify-bundle` passes on both bundles, and the suite's inventory digest and the attestation subject are unchanged. One record per finding was written, all outside the watched trees. | `test_a_full_adjudication_session_changes_no_bundle_byte` |

Where the 1588 payloads come from (distinct strings per origin, from the same run):
agent fixture seed (`fixture/supportlab/agent_seed.py` `ATTACKS`) 116, scenario YAMLs (every string in `scenarios/**/*.yaml`) 432, evaluator red-team corpus (`cases.json`) 78, real bundle events 1104, classic vectors 31; 1588 after de-duplication across origins. The `bundle_events` origin holds every string in every event of three real
offline bundles: `agent-indirect-html` and `agent-indirect-markdown`, generated fresh in the test
session, and the committed `docs/samples/passing-run`. Fresh bundles carry fresh timestamps and
hashes, so that origin's count varies by a few strings between runs. The test also requires
more than 500 payloads, at least one `<!--` payload from the fixture seed, and at least one
markup-bearing string among the real events, so it cannot pass vacuously.

## Tasks

| # | Task | Done |
| --- | --- | --- |
| 5.4.1 | Read-only bundle and audit-export views | Index, source, run, evidence-by-id and snapshot pages over run bundles, suite bundles, audit exports, and (new) ledger-only directories such as `docs/samples/denied-run`. The run page shows *What was attempted*, *Decisions and reason codes*, *Oracle inputs* (oracle specs and links to the redacted snapshots) and the full *Timeline*. Each event links to its evidence page by index. An unverified source is flagged **NOT VERIFIED** and gets no label form. |
| 5.4.2 | Adjudication write path | The only write. It calls `review.adjudication.write_adjudication`, the CLI's code path, which writes a signed `AdjudicationRecord` to `<bundle>.adjudications/`. A records directory inside any bundle is refused at startup. No bundle file is served or opened for writing. |
| 5.4.3 | Blinding | Oracle, detector and judge events, summary verdict fields, run status and reason, and the finding's status, impact and severity are masked until a label is recorded. An explicit reveal (per finding or per run) is remembered on the server, and later records say `blinded: false`. A refused label does not unblind. |
| 5.4.4 | Inert rendering | Escape-by-default builder with tag and attribute allowlists. No JavaScript on any page. CSP `default-src 'none'; style-src 'self'; img-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` on every response. Index-only URLs, and the XSS test above. |
| 5.4.5 | Reviewer protocol on the UI | `docs/reviewer-walkthrough.md` gains a UI path. A test opens all three sample sets in the UI. **The timed UI session is untested: it needs a human reviewer**, and so does the CLI-vs-UI comparison. |

## Measured

| Item | Command | Result |
| --- | --- | --- |
| Review lane (UI + adjudication tests) | `make review-check` | 56 passed in 54.92 s; `purpleloop.review` branch coverage **91.46%** (floor 85%); `XSS-CORPUS payloads=1588 … pages=4442` |
| UI tests alone | `uv run pytest tests/phase5/test_review_ui.py -q --no-cov` | 20 passed in 29.45 s |
| Phase 5 tests | `uv run pytest tests/phase5 -q --no-cov` | 319 passed in 157.11 s (2:37) |
| Full suite | `uv run pytest --junitxml=artifacts/junit-wp5.4.xml` | **791 passed, 3 skipped** in 1104.06 s (18:24; `time`: 18:25.86 wall, 1050.74 s user) at `78790c6`; total branch coverage **91.42%** (floor 85%) |
| Lint and types | `uv run ruff check . && uv run ruff format --check . && uv run mypy` | all checks passed; 233 files formatted; mypy: no issues in 99 source files |
| A real server, by hand | `uv run purpleloop review <agent-demo suite bundle> --port 8799`, then `curl` | `/`, `/s/0`, `/s/0/r/0`, `/s/0/f/0`: 200; `/docs`: 404; `Host: evil.example`: 421; the finding page shows `Blinded.` and `Read-only` (no key given). `lsof` shows the listener on `127.0.0.1:8799` only. Response headers carry the CSP and `nosniff`, `no-referrer`, `DENY`, `no-store`. |
| Bind refusal | `test_the_server_refuses_every_bind_but_loopback_v4`, `test_the_cli_refuses_a_non_loopback_bind` | `0.0.0.0`, `::`, `::1`, `localhost`, `192.168.1.10` and `""` all refused, and `review --host 0.0.0.0` exits 1 |
| Request guards | `test_foreign_hosts_cross_site_posts_and_missing_tokens_are_refused` | foreign `Host` 421, cross-site `Origin` 403, wrong token 403, `PUT` 405, 70 KiB body 413, and no record written |

## Defects found

- **`denied-run` could not be opened.** The first version loaded only sealed bundles, and the
  committed denied-run sample has a ledger and no inventory, so the walkthrough's UI path could
  not cover one of its three sets. Fixed with a view-only `ledger` source whose hash chain is
  verified first. It is pinned by `test_the_three_reviewer_samples_open_in_the_ui`, which also
  checks that a tampered ledger shows nothing.
- **Audit-export events were reachable as "evidence".** The evidence-by-id route served export
  decision rows, which carry no event hash. It now returns 404 for export sources
  (`test_views_show_timeline_decisions_oracle_inputs_and_evidence`).
- No defect was found in earlier phases' code.

## What this does not show

- **No human used it.** The timed reviewer session on the UI (5.4.5) and the comparison with
  the CLI path are **untested: they need a human reviewer**. Nothing here measures whether the
  UI is easier or faster than the CLI.
- **Inertness is checked by parsing, not by a browser.** The test uses Python's `html.parser`,
  plus the CSP, which blocks script regardless. No real browser rendered the pages and no
  mutation-XSS differential across browser parsers was run. The defence in depth is that the
  CSP grants no script source at all.
- **The payload set is the corpus plus 31 classic vectors**, not a fuzzer. Positions not
  covered by the hostile-source construction would not be exercised. The construction covers
  every field the page functions render: source path and verification text, run name, scenario
  fields, every event field, finding id, class, shown fields, verdict, snapshots, and the
  rationale on a refused post.
- **Blinding state lives in memory.** A restart forgets an explicit reveal that was not
  followed by a label. Records already written are re-read.
- **Local only, by design.** No authentication. Anyone with a shell on the machine can reach
  `127.0.0.1`. The form token and Origin check protect against other browser tabs, not against
  local processes.
