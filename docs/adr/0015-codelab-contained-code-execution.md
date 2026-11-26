# ADR 0015: codelab — code runs in a fixture-owned sandbox container, never in the fixture or the harness

Status: accepted for Phase 5 (WP5.5).

## Context

The PRD names "unexpected code execution and cascading failure" as threat coverage, and until
WP5.5 no fixture could execute code, so the threat was covered only as a containment property
(plan §0). Plan §2.6 asks for a second disposable fixture with a sandboxed "run analysis
snippet" tool, findings read as state, a containment-escape suite against a real surface, and —
because `code-exec` is a new action class — the first real use of the WP5.1 risk-approval path.
The plan's non-goals still hold: the **harness** never executes code.

Two facts about this machine shaped the decision. Docker Desktop on macOS offers `runc` only
(`docker info`: `Runtimes: runc io.containerd.runc.v2`); gVisor is not available. And the default
seccomp profile is in force (`Seccomp: 2` inside a container; `name=seccomp,profile=builtin`).

## Decision

### 1. Three processes, three trust levels

| Process | Runs | Never |
| --- | --- | --- |
| Harness (`purpleloop`) | the kernel, the runner, the codelab adapter, the stub sandbox in process | parses or runs a snippet; imports the supervisor; starts any process but `docker` |
| Fixture app (`purpleloop.fixture.codelab.app`, own container) | retrieval context, the two defenses that read code (`ast.parse` for the static policy, substring matching for the provenance guard), run and report records | runs a snippet |
| Sandbox (`targets/codelab/sandbox/`, own container) | the supervisor and, per job, `python -I -S -B -c <snippet>` | reaches a network, a writable path outside its tmpfs, or anything of the fixture's but one socket |

A test parses every codelab module in the package and fails on a call to `exec`, `eval`,
`compile`, or `__import__`, an import of `subprocess`/`multiprocessing`, or a process start other
than the `docker` CLI. The supervisor lives outside the package, so it cannot be imported.

### 2. The sandbox container

`compose.codelab.yaml`, service `codelab-sandbox`: `network_mode: none`, `ipc: none` (no
`/dev/shm`), `read_only: true`, one tmpfs `/scratch` (16 MiB, mode 0700, owned by the sandbox
uid), `cap_drop: [ALL]` with nothing added, `no-new-privileges`, the default seccomp profile (no
`seccomp=` override anywhere), `pids_limit: 64`, `mem_limit`/`memswap_limit: 256m`, `cpus: 0.5`,
`nofile` and `core` ulimits. It runs as uid 10003; the fixture runs as 10004.

The supervisor is PID 1. Per job it writes the job's files into a fresh tmpfs directory, starts
the snippet in a new session with an empty environment, closed descriptors, and rlimits (CPU,
256 MiB address space, 1 MiB file size, 64 descriptors, no core), waits the wall time (3 s),
kills the process group, then **kills and reaps every other process in the container** — which
catches a child that left the session — and only then lists the files the snippet left behind.
Output is read back through descriptors the supervisor created, so a snippet cannot swap the
capture path for a link to `/proc/1/environ`. The supervisor clears its dumpable flag first, so
a same-uid snippet cannot read its memory or environment.

### 3. The channel, and why it is a socket the fixture listens on

`network_mode: none` leaves no network to talk over. The channel is a Unix socket **the fixture
listens on**, in a named volume the fixture mounts read-write and the sandbox mounts read-only
(`nocopy`). The sandbox can therefore connect but cannot create, replace, or delete anything in
the volume, and the tmpfs stays its only writable path. The supervisor authenticates with a
per-deployment token; any other connection is refused and counted, and the count is exposed on
the control plane so the escape suite can read it from outside. A snippet that finds the socket
reaches exactly one listener, which wants a token it cannot read.

### 4. Runtime selection and recording

`runtime: ${CODELAB_SANDBOX_RUNTIME:-runc}`. The CI container job sets `runsc` when the runner's
Docker lists it. The escape report records the runtime from `docker inspect`
(`HostConfig.Runtime`), never from the variable, and states `gvisor: true|false`. On this machine
it is **hardened runc**.

### 5. The deterministic lane uses a stub that cannot run code

`StubSandbox` has the sandbox's interface and looks the exact snippet text up in
`seed.SIMULATIONS`, replaying the recorded effect computed from the job's own files; anything
else returns exit 127 "not simulated". A container test runs every simulated snippet in the real
sandbox and requires the same exit code, output, and files (`calibrate_stub`), and the container
corpus must agree with the in-process one on every status and oracle hash. Containment is never
claimed from the stub.

### 6. Findings are state

The fixture records each run: whether its output carried the planted credential canary (planted
by the fixture into the job as `.secrets/warehouse-token`), whether the sandbox listed the
execution marker (`.codelab-marker`), and each report's destination. The oracles are closed
`count` operators over those lists. A test replaces every recorded effect with an inert one and
the findings disappear, whatever the model said.

### 7. The defenses are fixture-enforced, and registered apart

`control/phase5_tools.CODELAB_DEFENSES` (version `codelab-defenses-v1`) is a separate registry,
pre-authorized by the signed manifest like every other. `AGENT_DEFENSES` and
`COMBINED_DEFENSES` are unchanged. All three defenses hold at the sink:
`untrusted-code-guard` (refuse a snippet carrying a line the fixture served as untrusted),
`snippet-static-policy` (a syntax-tree allowlist), and `sandbox-output-isolation` (quarantine
sandbox output *and* refuse code runs and external reports from a turn that read it). The
delimitation-blind stand-in is credited on all ten, which is the WP4.0.1 lesson applied from the
start rather than discovered later.

### 8. Admission: manifest 1.5 only, one exact approval

`CODELAB_LANE.manifest_versions == {1.5.0}` and `scenario_versions == {1.4.0}`. `analysis.run`
is registered in `OPERATION_ACTION_CLASSES` as `code-exec`, so the class is derived even when a
manifest declares only read and write. The codelab manifest's delta against the committed v1
baseline is exactly `{new-action-class, new-adapter-or-operation, new-target-fixture}`; no run
is admitted until one approval covers it. The intent vocabulary is lane data
(`LaneContract.intents`); `None` keeps the agent lane's, so earlier lanes are unchanged.

## Consequences

- The escape suite measures hardened runc on Docker Desktop's Linux VM. It says nothing about
  gVisor, which did not run here, nor about a kernel exploit: a kernel bug reachable through the
  default seccomp profile is out of reach of a scenario suite.
- The channel is a real, if narrow, path into the fixture. It is measured (forged sessions are
  refused and counted) rather than assumed away.
- Separate keys are not separate people: the approver key is ephemeral and held by the single
  author for the length of one command.
- The shadow report cannot show `code-exec` reached: nothing responds in shadow, so the
  `analysis.run` intents that would follow a model turn are unreachable slots. The approval
  covers an action class its shadow evidence never saw exercised — stated, not solved.
