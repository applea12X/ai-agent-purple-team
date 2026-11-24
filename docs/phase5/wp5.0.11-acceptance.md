# WP5.0.11 (WP4.5.3) — Recorded demo

Date: November 24, 2026

Recorded on the same local macOS machine as WP5.0.1, on branch `worktree-agent-acd8f62c4fc3b4b3e`
at `ae2ddc2`. No model was called.

## What was recorded

`docs/demo/phase-demo.cast` is an asciicast v2 file, 28,244 bytes, 2 MB limit. asciinema is not
a project dependency and was not installed. `scripts/record_demo.py` is a small recorder that
uses only the standard library (`pty`, `select`, `subprocess`) and writes the same documented
format. Each command runs on its own pseudo-terminal with a 100×30 window. The recorder writes
two kinds of line of its own, both marked: a `$ <command>` line before each command (there is no
interactive shell to echo it) and a dim `# exit <code>` line after it. Everything between those
markers is the command's own pty output, byte for byte, with arrival times. The header carries
metadata only: version, size, timestamp, title, `idle_time_limit`, and `TERM`.

The command, run once:

```
uv run python scripts/record_demo.py docs/demo/phase-demo.cast \
  --title "PurpleLoop: one-command smoke demo, then fail-closed cases" \
  "uv run purpleloop smoke-demo --output-dir /tmp/purpleloop-demo/smoke" \
  "uv run purpleloop check-action docs/samples/denied-run/manifest.json docs/samples/denied-run/action.json docs/samples/denied-run/authorization-public.pem --key-id demo-key" \
  "uv run purpleloop holdout-check" \
  "uv run purpleloop judge-report --output-dir /tmp/purpleloop-demo/judge"
```

| Segment | What it shows (from the cast) | Exit |
| --- | --- | --- |
| `smoke-demo` (the README's one-command demo, PRD §11 item 1) | 14 of 14 scenarios across all three lanes `passed`, `wall time 12.131s against the stated 600s target`, then a verified smoke bundle | 0 |
| `check-action` on the committed denied-run sample (fail-closed at admission) | `DENY EXPIRED_MANIFEST` | 1 |
| `holdout-check` (scope-expansion attempts, PRD §11 item 5) | the base action permitted as a positive control, then 17 near-miss widenings denied (`OUT_OF_SCOPE` ×6, `TOOL_SCHEMA_MISMATCH`, `PATH_TRAVERSAL`, `RESOURCE_OWNERSHIP_MISMATCH`, …), `17/17 mutations denied` | 0 |
| `judge-report` (evaluator injection, the other half of PRD §11 item 5) | `resistance=1.000 (negative control 0.583) … n=24`: none of the 24 held-out evaluator-injection cases flipped the scripted judge's verdict. With the delimiting mitigation removed (the negative control), 14 of 24 held, as Phase 3 recorded | 0 |

The output directories were put under `/tmp` on purpose. The first take wrote to `artifacts/`
and printed the absolute checkout path, which contains the author's home directory. A second
take had no `judge-report` segment. Both were discarded, and the committed take is a third,
complete re-run. No take was edited.

`tests/phase5/test_demo_recording.py` (5 tests, 0.56 s) checks four things. The cast parses
strictly as asciicast v2, with non-decreasing times and `"o"` events only, and is under 2 MB.
The smoke segment shows 14 `passed` lines and exits 0. The admission segment exits 1 with
`DENY EXPIRED_MANIFEST`, the holdout segment shows `OUT_OF_SCOPE` and 17/17 denied, and the
judge segment shows `resistance=1.000` at n=24. No home directory appears. A fifth test runs the recorder on a real pty and checks that it reports a TTY
and records exit codes 0 and 3.

## What this does not show

- It is not a screen video. It is a terminal recording, so a viewer sees the CLI output and no
  browser surface.
- The cast was not played back in asciinema-player in this session, because no player is
  installed. Validity was checked against the format by the parser test, not by a player.
- The fail-closed admission case uses the committed expired-manifest sample. Live scope
  expansion is shown by `holdout-check`.
- The evaluator-injection figure is for the offline scripted judge. It measures the harness's
  input hardening, not any real model's resistance (Phase 3 acceptance, "what this does not
  show").

## Status

**WP5.0.11 closed.** A recording of real commands, including an admission refusal, 17
scope-widening denials, and the evaluator-injection check, is committed and linked from the
README.
