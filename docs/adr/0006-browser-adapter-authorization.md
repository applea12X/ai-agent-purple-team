# ADR 0006: Browser adapter authorization model

Status: accepted for Phase 2.

## Decision

The browser is a first-class adapter under the same authority as HTTP and tool adapters. It never
selects its own target. Plans carry typed browser steps — navigate, fill, click, read — resolved
from a signed asset ID and a trusted flow registry. Free-form JavaScript, arbitrary URLs, and
arbitrary selectors from planner output are rejected **at compile time**, by name and by typed
argument schema, before any browser process exists.

Two drivers satisfy one session protocol. `HtmlFormDriver` renders the fixture's server-side HTML
in process and is exact; the deterministic lane uses it. `PlaywrightDriver` drives pinned Chromium
with route-level interception; the browser lane uses it.

## Authorization and containment

- Every navigation, redirect, and subresource origin is authorized through the runtime target
  guard **before** the request happens. A document hop takes part in consecutive hop sequencing; a
  subresource is authorized against the action's signed asset and the signed subresource-origin
  allowlist. An unauthorized origin is aborted at the routing layer, recorded as a policy denial,
  and charged to the run budget — never silently dropped.
- Fresh context per leg: no shared profile or storage state, downloads disabled, fixed viewport,
  locale, and timezone, animations disabled, and the page clock frozen so client-side timestamps
  cannot leak into DOM assertions.
- Scored output derives only from application state and typed DOM assertions, never from screenshot
  comparison, timing, or pixels.
- The browser process is killed in the adapter's `finally` path on completion, failure, timeout,
  budget exhaustion, or cancellation. Because it is an out-of-process child, browser-lane emergency
  stop is measured and reported separately from Phase 0's in-process cancellation p99.
- Per-leg trace ZIP and screenshots are written into the run directory, redacted (secrets replaced
  in every trace entry and screenshot metadata path), and referenced by digest in the inventory.

## Consequence

The browser lane reports its own replay rate separately, with a stated reason for any gap, and is
not folded into the API lane's number. The `HtmlFormDriver` is bit-exact and its replay rate is
1.0; the `PlaywrightDriver` runs only in the container/browser lane and is a named coverage
exclusion in the acceptance record.
