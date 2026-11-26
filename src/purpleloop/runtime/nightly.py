"""The nightly lane: signed scope, classified outcomes, and the tracking issue.

Closes loose ends 4.23-4.25 (``docs/phase5/loose-ends.md``). Phase 4's nightly job hard-codes one
agent scenario in workflow YAML. Here the scenario subset and the repetition count come from the
``nightly_scope`` of a signed Manifest 1.4 (``scenarios/nightly/manifest.json``), verified against
the committed public key before anything runs. Widening or narrowing the nightly is therefore a
re-signed manifest, never a quiet YAML edit, exactly as ``NightlyScope`` documents.

The scope may name scenarios of two lanes:

* ``agent`` scenarios run through ``purpleloop agent-run`` against the networked endpoint, with the
  signed repetitions, the judge, and the attacker. With no endpoint configured each is a recorded
  ``skip-no-credential``, never a silent fallback to the offline model.
* ``supportlab`` scenarios are the shared API/browser workflows. They need no model credential,
  so they always run, on the served fixture with real Chromium in CI.

Every scenario ends in the closed Phase 4 outcome vocabulary. Any outcome other than ``pass`` or
the recorded ``skip-no-credential`` means the night needs a tracking issue.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from purpleloop.control.manifest import (
    ManifestError,
    ManifestVerifier,
    load_manifest,
    sign_manifest,
)
from purpleloop.runtime.demo import ROOT
from purpleloop.runtime.supportlab import supportlab_agent_manifest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.phase1 import load_scenario, scenario_paths
from purpleloop.schemas.phase4 import (
    NightlyScope,
    Phase4Grants,
    RetentionRule,
    StochasticRunOutcome,
)

NIGHTLY_DIR = ROOT / "scenarios" / "nightly"
NIGHTLY_MANIFEST = NIGHTLY_DIR / "manifest.json"
NIGHTLY_PUBLIC_KEY = NIGHTLY_DIR / "authorization-public.pem"
NIGHTLY_KEY_ID = "nightly-scope"
NIGHTLY_ENGAGEMENT = "purpleloop-nightly"
ISSUE_TITLE = "Nightly lane: non-pass outcome"
REPORT_NAME = "nightly.json"
LANE_DIRECTORIES: dict[str, Path] = {
    "agent": ROOT / "scenarios" / "agent",
    "supportlab": ROOT / "scenarios" / "supportlab",
}
#: The outcomes that need no issue. A missing credential is recorded, not hidden, but it is the
#: expected state of a fork or of this repository before a hosted endpoint exists.
QUIET_OUTCOMES = frozenset({"pass", "skip-no-credential"})
Lane = Literal["agent", "supportlab"]

#: The signed retention rules, one per artifact kind, as ``docs/retention-policy.md`` sets them.
#: ``bundles`` is the per-run CI duration; a release bundle is held by its attestation instead.
RETENTION_RULES: tuple[RetentionRule, ...] = (
    RetentionRule(artifact_kind="raw-ledgers", days=0, rationale="every finding links into it"),
    RetentionRule(artifact_kind="attestations", days=0, rationale="provenance of a bundle"),
    RetentionRule(
        artifact_kind="bundles",
        days=90,
        rationale="per-run CI bundles are reproducible from pinned code and seed",
    ),
    RetentionRule(
        artifact_kind="browser-artifacts", days=90, rationale="debugging aids, never scored"
    ),
    RetentionRule(
        artifact_kind="model-transcripts",
        days=30,
        rationale="bulkiest and provider-sensitive; digests stay in the ledger",
    ),
)


@dataclass(frozen=True)
class ScopedScenario:
    scenario_id: str
    lane: Lane
    path: Path


@dataclass(frozen=True)
class NightlyPlan:
    """A verified nightly scope, resolved to scenario files."""

    manifest_digest: str
    valid_until: datetime
    repetitions: int
    rotation: str
    scenarios: tuple[ScopedScenario, ...]

    def lane(self, lane: Lane) -> tuple[ScopedScenario, ...]:
        return tuple(item for item in self.scenarios if item.lane == lane)

    def as_json(self) -> dict[str, Any]:
        return {
            "manifest_digest": self.manifest_digest,
            "valid_until": self.valid_until.isoformat(),
            "repetitions": self.repetitions,
            "rotation": self.rotation,
            "scenarios": [
                {
                    "scenario_id": item.scenario_id,
                    "lane": item.lane,
                    "path": item.path.relative_to(ROOT).as_posix(),
                }
                for item in self.scenarios
            ],
        }


def build_nightly_manifest(
    key: Ed25519PrivateKey,
    scope: NightlyScope,
    *,
    now: datetime | None = None,
    valid_days: int = 365,
) -> AuthorizationManifest:
    """The signed nightly authority: Manifest 1.4 over the agent lane's grants plus the scope."""
    issued = (now or datetime.now(UTC)).replace(microsecond=0)
    base = supportlab_agent_manifest(key, now=issued)
    manifest = base.model_copy(
        update={
            "schema_version": "1.4.0",
            "engagement_id": NIGHTLY_ENGAGEMENT,
            "key_id": NIGHTLY_KEY_ID,
            "issued_at": issued,
            "valid_from": issued,
            "valid_until": issued + timedelta(days=valid_days),
            "signature": "",
            "phase4": Phase4Grants(
                attestation_key_ids=frozenset({"ci-release"}),
                retention=RETENTION_RULES,
                nightly_scope=scope,
            ),
        }
    )
    # Re-validate: model_copy does not run validators, and the 1.4 rules must hold.
    return sign_manifest(AuthorizationManifest.model_validate(manifest.model_dump()), key)


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ManifestError("UNKNOWN_SIGNING_KEY", "the nightly public key is not Ed25519")
    return key


def verified_manifest(
    manifest_path: Path, public_key_path: Path, *, now: datetime | None = None
) -> AuthorizationManifest:
    """Load and verify a signed manifest under exactly one trusted key, the committed one."""
    manifest = load_manifest(manifest_path)
    verifier = ManifestVerifier({manifest.key_id: load_public_key(public_key_path)})
    return verifier.verify(manifest, now=now)


def resolve_scenario(scenario_id: str) -> ScopedScenario:
    for lane, directory in LANE_DIRECTORIES.items():
        for path in scenario_paths(directory):
            if load_scenario(path).scenario_id == scenario_id:
                return ScopedScenario(scenario_id, lane, path)  # type: ignore[arg-type]
    raise ValueError(f"nightly scope names an unknown scenario: {scenario_id}")


def read_nightly_scope(
    manifest_path: Path = NIGHTLY_MANIFEST,
    public_key_path: Path = NIGHTLY_PUBLIC_KEY,
    *,
    now: datetime | None = None,
) -> NightlyPlan:
    """The nightly scope from signed data, or an error naming why there is none.

    Raises :class:`ManifestError` for a bad signature, an expired or not-yet-valid manifest, or a
    manifest older than 1.4; ``ValueError`` for a missing scope or an unknown scenario id.
    """
    manifest = verified_manifest(manifest_path, public_key_path, now=now)
    if manifest.phase4 is None or manifest.phase4.nightly_scope is None:
        raise ValueError("the signed manifest carries no nightly_scope")
    scope = manifest.phase4.nightly_scope
    return NightlyPlan(
        manifest_digest=manifest.manifest_digest(),
        valid_until=manifest.valid_until,
        repetitions=scope.repetitions,
        rotation=scope.rotation,
        scenarios=tuple(resolve_scenario(item) for item in sorted(scope.scenario_ids)),
    )


# --- running the night ------------------------------------------------------------------------

AgentExecutor = Callable[[ScopedScenario, Path, int, str, str], StochasticRunOutcome]
BrowserExecutor = Callable[[ScopedScenario, Path], Awaitable[StochasticRunOutcome]]


def outcome_from_stderr(stderr: str, scenario_id: str) -> StochasticRunOutcome:
    """``agent-run`` always prints ``OUTCOME {json}``; the last one is the classification."""
    for line in reversed(stderr.splitlines()):
        if line.startswith("OUTCOME "):
            return StochasticRunOutcome.model_validate_json(line.removeprefix("OUTCOME "))
    return StochasticRunOutcome(
        outcome="fail",
        reason_code="NO_OUTCOME_RECORDED",
        detail=stderr[-2000:],
        scenario_id=scenario_id,
    )


def run_agent_subprocess(
    item: ScopedScenario, output: Path, repetitions: int, endpoint: str, profile: str
) -> StochasticRunOutcome:  # pragma: no cover - networked lane; tests inject an executor
    """One agent scenario through the real CLI, so the nightly runs exactly what agent-run does."""
    argv: Sequence[str] = (
        sys.executable,
        "-m",
        "purpleloop.cli",
        "agent-run",
        str(item.path),
        str(output),
        "--repetitions",
        str(repetitions),
        "--judge",
        "--attacker",
        "--endpoint",
        endpoint,
        "--profile",
        profile,
    )
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    sys.stderr.write(completed.stderr)
    sys.stdout.write(completed.stdout)
    return outcome_from_stderr(completed.stderr, item.scenario_id)


async def run_browser_workflow(
    item: ScopedScenario, output: Path, *, served: bool = True
) -> StochasticRunOutcome:
    """One shared API/browser workflow scenario on the supportlab fixture."""
    from purpleloop.supportlab_cli import SupportlabMode, run_one

    mode = SupportlabMode.SERVED if served else SupportlabMode.IN_PROCESS
    try:
        summary = await run_one(item.path, output, mode)
    except (OSError, ValueError, RuntimeError) as exc:
        return StochasticRunOutcome(
            outcome="fail",
            reason_code=str(getattr(exc, "reason_code", "") or type(exc).__name__)[:100],
            detail=str(exc)[:2000],
            scenario_id=item.scenario_id,
        )
    return StochasticRunOutcome(
        outcome="pass" if summary.status == "passed" else "fail",
        reason_code=(summary.reason or summary.status.upper())[:100],
        scenario_id=item.scenario_id,
    )


def skipped(item: ScopedScenario) -> StochasticRunOutcome:
    return StochasticRunOutcome(
        outcome="skip-no-credential",
        reason_code="STOCHASTIC_LANE_UNAVAILABLE",
        detail="PURPLELOOP_MODEL_ENDPOINT is unset; the agent scenario is skipped, not downgraded",
        scenario_id=item.scenario_id,
    )


def scope_failure(exc: Exception) -> StochasticRunOutcome:
    return StochasticRunOutcome(
        outcome="fail",
        reason_code=str(getattr(exc, "reason_code", "") or "NIGHTLY_SCOPE_INVALID")[:100],
        detail=str(exc)[:2000],
    )


async def run_night(
    output_dir: Path,
    *,
    manifest_path: Path = NIGHTLY_MANIFEST,
    public_key_path: Path = NIGHTLY_PUBLIC_KEY,
    endpoint: str | None,
    profile: str = "openai-compatible",
    agent_executor: AgentExecutor = run_agent_subprocess,
    browser_executor: BrowserExecutor = run_browser_workflow,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run every scenario the signed scope names and write ``nightly.json``."""
    await asyncio.to_thread(output_dir.mkdir, parents=True, exist_ok=True)
    started = datetime.now(UTC)
    outcomes: list[dict[str, Any]] = []
    plan: NightlyPlan | None = None
    try:
        plan = read_nightly_scope(manifest_path, public_key_path, now=now)
    except (ManifestError, ValueError, OSError) as exc:
        # No verified scope means no authority to run anything: record why and stop.
        outcomes.append({"lane": None, **scope_failure(exc).model_dump(mode="json")})
    if plan is not None:
        for item in plan.lane("supportlab"):
            result = await browser_executor(item, output_dir / item.scenario_id)
            outcomes.append({"lane": item.lane, **result.model_dump(mode="json")})
        for item in plan.lane("agent"):
            result = (
                agent_executor(
                    item, output_dir / item.scenario_id, plan.repetitions, endpoint, profile
                )
                if endpoint
                else skipped(item)
            )
            outcomes.append({"lane": item.lane, **result.model_dump(mode="json")})
    report = {
        "schema": "purpleloop.nightly/1",
        "started_at": started.isoformat(timespec="seconds"),
        "scope": plan.as_json() if plan is not None else None,
        "endpoint_configured": bool(endpoint),
        "outcomes": outcomes,
        "needs_issue": any(item["outcome"] not in QUIET_OUTCOMES for item in outcomes),
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    await asyncio.to_thread((output_dir / REPORT_NAME).write_text, text)
    return report


# --- the tracking issue -----------------------------------------------------------------------


def render_issue_body(report: dict[str, Any] | None, *, run_url: str) -> str:
    """The tracking-issue text for one night. ``None`` means the lane recorded nothing at all."""
    lines = [f"Nightly run: {run_url}", ""]
    if report is None:
        lines += [
            "**The lane ended before it recorded any classified outcome** (no `nightly.json`).",
            "That is itself a non-pass night: check the job log for the step that failed.",
        ]
        return "\n".join(lines) + "\n"
    scope = report.get("scope")
    if scope:
        lines += [
            f"Signed scope: manifest `{scope['manifest_digest'][:16]}`, "
            f"{scope['repetitions']} repetitions, valid until {scope['valid_until']}.",
            "",
        ]
    else:
        lines += ["**No verified nightly scope**: nothing was authorized to run.", ""]
    lines += ["| Scenario | Lane | Outcome | Reason |", "| --- | --- | --- | --- |"]
    for item in report["outcomes"]:
        mark = "" if item["outcome"] in QUIET_OUTCOMES else " **(non-pass)**"
        reason = str(item["reason_code"]).replace("|", "/")
        lines.append(
            f"| {item.get('scenario_id') or '—'} | {item.get('lane') or '—'} | "
            f"`{item['outcome']}`{mark} | `{reason}` |"
        )
    details = [item for item in report["outcomes"] if item["outcome"] not in QUIET_OUTCOMES]
    for item in details:
        if item.get("detail"):
            detail = str(item["detail"])[:500].replace("```", "'''")
            lines += ["", f"`{item.get('scenario_id') or 'scope'}` detail:", "```", detail, "```"]
    lines += [
        "",
        "Triage by outcome class (`docs/incident-runbook.md`): `endpoint-error` is not a "
        "scenario failure (section 5); a recurring `budget-stop` is a signed-cap or estimate "
        "problem (section 3); `fail` is a scenario or harness result to reproduce from seed.",
    ]
    return "\n".join(lines) + "\n"


GhRunner = Callable[[Sequence[str]], str]


def gh_runner(gh: str) -> GhRunner:  # pragma: no cover - exercised through a fake gh in tests
    def run(args: Sequence[str]) -> str:
        completed = subprocess.run(  # noqa: S603 -- fixed gh argv, no shell
            [gh, *args], capture_output=True, text=True, check=True
        )
        return completed.stdout

    return run


def file_or_update_issue(
    body: str, *, run: GhRunner, body_path: Path, title: str = ISSUE_TITLE
) -> tuple[str, str]:
    """Comment on the open tracking issue with this exact title, or open one. Returns the action.

    Authenticates the way ``gh`` does in Actions: from ``GH_TOKEN`` in the job environment. This
    code never reads, prints, or passes a token.
    """
    body_path.write_text(body, encoding="utf-8")
    listing = run(
        [
            "issue",
            "list",
            "--state",
            "open",
            "--search",
            f'"{title}" in:title',
            "--json",
            "number,title",
            "--limit",
            "50",
        ]
    )
    matches = [item for item in json.loads(listing or "[]") if item.get("title") == title]
    if matches:
        number = str(min(int(item["number"]) for item in matches))
        run(["issue", "comment", number, "--body-file", str(body_path)])
        return "commented", number
    created = run(["issue", "create", "--title", title, "--body-file", str(body_path)])
    return "created", created.strip()
