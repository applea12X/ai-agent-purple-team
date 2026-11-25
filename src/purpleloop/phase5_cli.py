"""Phase 5 CLI: contract inspection, shadow runs, and signed risk approvals.

Registered into the main ``purpleloop`` app the same way ``phase4_cli`` is. Each Phase 5 work
package appends its own commands inside :func:`register` (WP5.0.8 ``adjudicate``, WP5.4
``review``). WP5.1 adds the governance path, in the order a person uses it:

1. ``shadow-run`` -- build (or load) the requested manifest 1.5, run its shadow twin over the
   agent corpus, and write a verified shadow bundle holding the report an approval names;
2. ``approve`` -- verify that bundle, compute the delta against the committed baseline, and sign
   a ``RiskApproval`` with the approver's key;
3. ``approval-check`` -- run admission exactly as the runtime does, and say admitted or refused.

``capability-baseline`` re-signs the v1 surface (a deliberate, reviewed bump) and
``approver-keygen`` writes a key pair for an approver. No command here calls a model.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from purpleloop.schemas.phase5 import CONTRACT_VERSIONS, ActionClass, RiskApproval


def _private_key(path: Path) -> Ed25519PrivateKey:
    loaded = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("an approver key must be Ed25519")
    return loaded


def register(app: typer.Typer) -> None:
    @app.command("phase5-contracts")
    def phase5_contracts(as_json: bool = typer.Option(False, "--json")) -> None:
        """Print every Phase 5 contract and the version this code implements."""
        if as_json:
            typer.echo(json.dumps(dict(CONTRACT_VERSIONS), sort_keys=True))
            return
        for name, version in CONTRACT_VERSIONS:
            typer.echo(f"{name} {version}")

    @app.command("capability-baseline")
    def capability_baseline(
        check: bool = typer.Option(
            False, "--check", help="Verify the committed baseline instead of re-signing it"
        ),
        output: Path | None = typer.Option(None, help="Baseline path (default: committed)"),  # noqa: B008
        public_key_output: Path | None = typer.Option(None, help="Public key path"),  # noqa: B008
    ) -> None:
        """Sign the v1 capability surface with an ephemeral key, or check the committed one."""
        from purpleloop.control.approvals import load_baseline
        from purpleloop.control.phase5_signing import SignedDocumentError, verify_record_signature
        from purpleloop.reporting.bundle import write_json
        from purpleloop.runtime import governance

        baseline_path = output or governance.BASELINE_PATH
        key_path = public_key_output or governance.BASELINE_PUBLIC_KEY_PATH
        if check:
            try:
                baseline = load_baseline(baseline_path)
                verify_record_signature(
                    baseline, {baseline.key_id: governance.load_public_key(key_path)}
                )
            except (OSError, ValueError, SignedDocumentError) as exc:
                typer.echo(f"INVALID: {exc}", err=True)
                raise typer.Exit(1) from None
            current = governance.v1_capability_surface()
            if current != baseline.surface:
                typer.echo("DRIFT: the v1 lane manifests no longer match the baseline", err=True)
                raise typer.Exit(1)
            typer.echo(
                f"VALID baseline {baseline.baseline_digest()} key={baseline.key_id} "
                f"({baseline.key_provenance}); matches the v1 lane manifests"
            )
            return
        baseline, pem = governance.sign_v1_baseline()
        write_json(baseline_path, baseline.model_dump(mode="json", exclude_none=True))
        key_path.write_bytes(pem)
        typer.echo(
            f"WROTE {baseline_path} digest={baseline.baseline_digest()} key={baseline.key_id} "
            "(ephemeral: the private key was discarded)"
        )

    @app.command("approver-keygen")
    def approver_keygen(private_out: Path, public_out: Path) -> None:
        """Write an Ed25519 approver key pair. Keep the private key out of the repository."""
        key = Ed25519PrivateKey.generate()
        private_out.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(private_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        public_out.write_bytes(
            key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        typer.echo(f"WROTE {private_out} (0600) and {public_out}")

    @app.command("shadow-run")
    def shadow_run(
        output_dir: Path,
        scenario: list[str] = typer.Option([], help="Scenario ids (default: the agent corpus)"),  # noqa: B008
        proposal_source: str = typer.Option(
            "bounded-search", help="bounded-search or model-driven (scripted offline model)"
        ),
        action_class: list[str] = typer.Option(  # noqa: B008
            [], help="Extra action classes to request (read and write are always present)"
        ),
        attacker: bool = typer.Option(True, help="Run the attacker's proposals"),
        manifest: Path | None = typer.Option(  # noqa: B008
            None, help="A requested manifest 1.5 (JSON) instead of the built-in agent manifest"
        ),
        seed: int = 42,
    ) -> None:
        """Run the requested manifest's shadow twin over the agent corpus; nothing executes."""
        from purpleloop.adapters.scripted_attacker import ScriptedAttackerModel
        from purpleloop.agent_cli import SCENARIOS
        from purpleloop.control.approvals import shadow_twin
        from purpleloop.control.attacker import BoundedAttacker, ModelDrivenAttacker
        from purpleloop.control.capabilities import capability_delta
        from purpleloop.control.lanes import AGENT_LANE
        from purpleloop.control.manifest import ManifestVerifier, sign_manifest
        from purpleloop.control.phase3_tools import INTENT_OPERATIONS
        from purpleloop.runtime import governance
        from purpleloop.runtime.runtime import SafetyRuntime
        from purpleloop.runtime.shadow import ShadowBundleError, ShadowRunner
        from purpleloop.runtime.supportlab import (
            InProcessSupportlab,
            actor_credentials,
            build_agent_runner,
        )
        from purpleloop.schemas.authorization import AuthorizationManifest
        from purpleloop.schemas.phase1 import load_scenario, scenario_paths

        if proposal_source not in {"bounded-search", "model-driven"}:
            typer.echo("INVALID: proposal source must be bounded-search or model-driven", err=True)
            raise typer.Exit(2)
        key = Ed25519PrivateKey.generate()
        try:
            if manifest is not None:
                requested = AuthorizationManifest.model_validate(
                    json.loads(manifest.read_text(encoding="utf-8"))
                )
            else:
                requested = governance.agent_manifest_15(
                    key,
                    seed=seed,
                    proposal_source="model-driven" if proposal_source == "model-driven" else None,
                    action_classes=(
                        ActionClass.READ,
                        ActionClass.WRITE,
                        *(ActionClass(item) for item in action_class),
                    ),
                )
            # The twin is signed under the requested manifest's own key id with a key that exists
            # only for this run; its digest -- not its signature -- is what an approval binds.
            twin = sign_manifest(shadow_twin(requested), key)
            verifier = ManifestVerifier({twin.key_id: key.public_key()})
            admission = governance.committed_admission()
            baseline = admission.baseline
            paths = scenario_paths(SCENARIOS)
            scenarios = [load_scenario(path) for path in paths]
            if scenario:
                wanted = set(scenario)
                scenarios = [item for item in scenarios if item.scenario_id in wanted]
                if {item.scenario_id for item in scenarios} != wanted:
                    raise ValueError("unknown scenario id")
        except (OSError, ValueError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None

        def runtime_factory(directory: Path) -> SafetyRuntime:
            tokens = actor_credentials()
            control = actor_credentials()["customer-a"]
            return build_agent_runner(
                directory,
                twin,
                verifier,
                actor_tokens=tokens,
                control=control,
                fixture=InProcessSupportlab(tokens, control),
                admission=admission,
            ).runtime

        phase3 = twin.phase3
        caps = (
            phase3.max_attacker_proposals if phase3 else 0,
            phase3.max_attacker_depth if phase3 else 0,
        )

        def attacker_factory() -> BoundedAttacker | ModelDrivenAttacker:
            common = {
                "operations": sorted(INTENT_OPERATIONS),
                "own_tenant": "org-a",
                "other_tenants": ("org-b",),
                "resource_id": "admin-a",
            }
            if proposal_source == "model-driven":
                return ModelDrivenAttacker(
                    ScriptedAttackerModel(),
                    governance.ATTACKER_PIN,
                    objective="Change another tenant's records or exfiltrate a canary.",
                    max_proposals=caps[0],
                    max_depth=caps[1],
                    **common,  # type: ignore[arg-type]
                )
            return BoundedAttacker(max_proposals=caps[0], max_depth=caps[1], **common)  # type: ignore[arg-type]

        runner = ShadowRunner(
            runtime_factory,
            lane=AGENT_LANE,
            attacker_factory=attacker_factory if attacker else None,
        )
        run_id = "shadow-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        try:
            report = asyncio.run(
                runner.run(
                    scenarios,
                    twin,
                    run_id=run_id,
                    output_dir=output_dir,
                    public_key_pem=key.public_key().public_bytes(
                        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                    ),
                    requested=requested,
                )
            )
        except (OSError, ValueError, ShadowBundleError) as exc:
            typer.echo(f"FAILED: {exc}; partial evidence: {output_dir.resolve()}", err=True)
            raise typer.Exit(1) from None
        delta = sorted(item.value for item in capability_delta(baseline.surface, requested))
        dispatches = sum(counter.dispatches for counter in runner.counters.values())
        typer.echo(f"scenarios {len(report.scenario_digests)}")
        typer.echo(f"suppressed executions {report.suppressed_executions}")
        typer.echo(f"adapter dispatches {dispatches} (report adapter_calls {report.adapter_calls})")
        typer.echo(f"unreachable steps {report.unreachable_steps}")
        typer.echo(
            f"proposals {report.proposals_total}, rejected {report.proposals_rejected} "
            f"(rate {report.proposal_rejection_rate:.4f})"
        )
        typer.echo(
            f"action classes reached {sorted(c.value for c in report.action_classes_reached)}"
        )
        typer.echo(f"capability delta vs baseline {delta or 'none'}")
        typer.echo(f"shadow report digest {report.report_digest()}")
        typer.echo(f"Verified shadow bundle: {output_dir.resolve()}")

    @app.command("approve")
    def approve(
        shadow_bundle: Path,
        approver_key: Path = typer.Option(..., help="Approver Ed25519 private key PEM"),  # noqa: B008
        approver_key_id: str = typer.Option(...),
        approver: str = typer.Option(..., help="Who holds the key, in plain words"),
        rationale: str = typer.Option(...),
        out: Path = typer.Option(...),  # noqa: B008
        approval_id: str = "approval-1",
        ttl_hours: float = 24.0,
    ) -> None:
        """Sign a risk approval of the shadow bundle's requested delta, on its shadow report."""
        from purpleloop.control.approvals import ApprovalRefused, grant_approval
        from purpleloop.reporting.bundle import write_json
        from purpleloop.runtime import governance
        from purpleloop.runtime.shadow import (
            ShadowBundleError,
            load_requested_manifest,
            verify_shadow_bundle,
        )

        try:
            report = verify_shadow_bundle(shadow_bundle)
            requested = load_requested_manifest(shadow_bundle)
            baseline, _ = governance.committed_baseline()
            approval = grant_approval(
                requested,
                report,
                baseline,
                _private_key(approver_key),
                approver_key_id=approver_key_id,
                approver=approver,
                rationale=rationale,
                approval_id=approval_id,
                ttl=timedelta(hours=ttl_hours),
            )
        except ApprovalRefused as exc:
            typer.echo(f"REFUSED {exc.reason_code}: {exc}", err=True)
            raise typer.Exit(1) from None
        except (OSError, ValueError, ShadowBundleError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        write_json(out, approval.model_dump(mode="json", exclude_none=True))
        typer.echo(
            f"APPROVED {sorted(item.value for item in approval.capability_delta)} "
            f"digest={approval.approval_digest()} "
            f"expires={approval.expires_at.isoformat()} -> {out}"
        )

    @app.command("approval-check")
    def approval_check(
        shadow_bundle: Path,
        approval: list[Path] = typer.Option([], help="Risk approval JSON files"),  # noqa: B008
        approver_public_key: Path | None = typer.Option(None),  # noqa: B008
        approver_key_id: str | None = None,
        manifest: Path | None = typer.Option(  # noqa: B008
            None, help="Check this manifest instead of the bundle's requested one plus approvals"
        ),
        at: str | None = typer.Option(None, help="ISO instant to check at (default: now)"),
    ) -> None:
        """Run capability admission exactly as the runtime does; exit 1 when refused."""
        from purpleloop.control.approvals import with_approvals
        from purpleloop.runtime import governance
        from purpleloop.runtime.shadow import (
            ShadowBundleError,
            load_requested_manifest,
            verify_shadow_bundle,
        )
        from purpleloop.schemas.authorization import AuthorizationManifest

        try:
            report = verify_shadow_bundle(shadow_bundle)
            approvals = [
                RiskApproval.model_validate(json.loads(path.read_text(encoding="utf-8")))
                for path in approval
            ]
            keys = (
                {approver_key_id: governance.load_public_key(approver_public_key)}
                if approver_public_key is not None and approver_key_id is not None
                else {}
            )
            if manifest is not None:
                checked = AuthorizationManifest.model_validate(
                    json.loads(manifest.read_text(encoding="utf-8"))
                )
            else:
                checked = with_approvals(load_requested_manifest(shadow_bundle), approvals)
            admission = governance.committed_admission(
                approver_keys=keys, approvals=approvals, shadow_reports=(report,)
            )
            instant = datetime.fromisoformat(at) if at else datetime.now(UTC)
        except (OSError, ValueError, ShadowBundleError) as exc:
            typer.echo(f"INVALID: {exc}", err=True)
            raise typer.Exit(1) from None
        decision = admission.decide(checked, now=instant)
        delta = sorted(item.value for item in decision.delta)
        if decision.admitted:
            typer.echo(f"ADMITTED {decision.reason_code} delta={delta or 'none'}")
            return
        typer.echo(f"REFUSED {decision.reason_code}")
        raise typer.Exit(1)
