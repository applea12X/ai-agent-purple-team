"""The v1 capability surface, the committed baseline, and manifest 1.5 for the agent lane.

WP5.1, ADR 0014. This is the layer that knows which manifests *are* v1: the four lane manifests
the project ran before Phase 5 -- the Phase 1 demo (1.1), supportlab (1.2), the offline agent
lane (1.3), and the agent lane pointed at a local Ollama endpoint (1.3, the WP4.0.1 and nightly
stochastic configuration). Their union is the approved baseline every 1.5 delta is computed
against. ``control`` cannot hold this, because the manifest builders live in ``runtime``.

The committed baseline in ``baselines/capability-baseline.json`` was signed with an
**ephemeral** key that was discarded after signing -- the same honest precedent as the Phase 4
release attestation. It proves the surface was signed once and not edited since; it says nothing
about who approved it beyond the ``approver`` field's plain words. Re-signing it with a held key
at the v1 tag is WP5.0.12's job.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from purpleloop.adapters.agent import SYSTEM_PROMPT_HASH
from purpleloop.control.approvals import ApprovalAdmission, load_baseline, sign_baseline
from purpleloop.control.capabilities import capability_surface, union_surfaces
from purpleloop.control.manifest import sign_manifest
from purpleloop.runtime.demo import ROOT, demo_manifest
from purpleloop.runtime.supportlab import supportlab_agent_manifest, supportlab_manifest
from purpleloop.schemas.authorization import AuthorizationManifest
from purpleloop.schemas.capability import CapabilityBaseline, CapabilitySurface
from purpleloop.schemas.phase3 import DecodingParameters, ModelPin
from purpleloop.schemas.phase4 import Phase4Grants, RetentionRule
from purpleloop.schemas.phase5 import (
    ActionClass,
    LoopGuardGrant,
    Phase5Grants,
    ProposalSource,
    RiskApproval,
    RunMode,
    ShadowReport,
)

BASELINE_PATH = ROOT / "baselines" / "capability-baseline.json"
BASELINE_PUBLIC_KEY_PATH = ROOT / "baselines" / "capability-baseline-public.pem"
BASELINE_KEY_ID = "v1-baseline-ephemeral"
#: The local model origin the v1 stochastic lane signed (WP4.0.1, ``make agent-stochastic``).
V1_LOCAL_MODEL_ORIGIN = "http://127.0.0.1:11434"
#: Attestation key id written into 1.5 agent manifests; never an approver key.
ATTESTATION_KEY_ID = "ci-attestation"
#: The offline pin the model-driven attacker profile runs on (``ScriptedAttackerModel``).
ATTACKER_PIN = ModelPin(
    pin_id="offline-attacker",
    provider="offline",
    model_id="scripted-attacker",
    model_version="scripted-v1",
    decoding=DecodingParameters(seed=42),
    system_prompt_hash=SYSTEM_PROMPT_HASH,
)

V1_SOURCES: tuple[str, ...] = (
    "runtime.demo.demo_manifest (manifest 1.1, Phase 1 lane)",
    "runtime.supportlab.supportlab_manifest (manifest 1.2, supportlab lane, seed 42)",
    "runtime.supportlab.supportlab_agent_manifest (manifest 1.3, offline agent lane, seed 42)",
    "runtime.supportlab.supportlab_agent_manifest with model_endpoint "
    f"{V1_LOCAL_MODEL_ORIGIN} (manifest 1.3, local stochastic agent lane, seed 42)",
)


def v1_lane_manifests(now: datetime | None = None) -> tuple[AuthorizationManifest, ...]:
    """The four v1 lane manifests, signed with a throwaway key (only their surface is used)."""
    key = Ed25519PrivateKey.generate()
    local_pin = ModelPin(
        pin_id="networked",
        provider="ollama",
        model_id="local-model",
        decoding=DecodingParameters(seed=42),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
    )
    return (
        demo_manifest(key, now=now),
        supportlab_manifest(key, now=now),
        supportlab_agent_manifest(key, now=now),
        supportlab_agent_manifest(
            key, now=now, model_endpoint=V1_LOCAL_MODEL_ORIGIN, model_pin=local_pin
        ),
    )


def v1_capability_surface() -> CapabilitySurface:
    """The approved v1 surface: the union of the v1 lane manifests' surfaces."""
    return union_surfaces(capability_surface(manifest) for manifest in v1_lane_manifests())


def sign_v1_baseline(
    *, now: datetime | None = None, approver: str = "the project's single author"
) -> tuple[CapabilityBaseline, bytes]:
    """Sign the v1 surface with an ephemeral key, returning the baseline and its public key.

    The private key exists only inside this call. Nothing is written; ``purpleloop
    capability-baseline`` writes the two returned values, and that write is the reviewed bump.
    """
    key = Ed25519PrivateKey.generate()
    baseline = sign_baseline(
        v1_capability_surface(),
        key,
        key_id=BASELINE_KEY_ID,
        key_provenance="ephemeral",
        approver=approver,
        derived_from=V1_SOURCES,
        rationale=(
            "The capability surface the project ran before Phase 5. Every manifest 1.5 delta is "
            "computed against it. Signed with an ephemeral key discarded after signing; re-sign "
            "with a held key at the v1 tag."
        ),
        now=now,
    )
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return baseline, pem


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def committed_baseline() -> tuple[CapabilityBaseline, dict[str, Ed25519PublicKey]]:
    baseline = load_baseline(BASELINE_PATH)
    return baseline, {baseline.key_id: load_public_key(BASELINE_PUBLIC_KEY_PATH)}


def committed_admission(
    *,
    approver_keys: Mapping[str, Ed25519PublicKey] | None = None,
    approvals: Iterable[RiskApproval] = (),
    shadow_reports: Iterable[ShadowReport] = (),
) -> ApprovalAdmission:
    """Admission against the committed v1 baseline, with whatever approvals are on hand."""
    baseline, keys = committed_baseline()
    return ApprovalAdmission.of(
        baseline,
        keys,
        approver_keys=approver_keys,
        approvals=approvals,
        shadow_reports=shadow_reports,
    )


def agent_manifest_15(
    key: Ed25519PrivateKey,
    *,
    seed: int = 42,
    now: datetime | None = None,
    run_mode: RunMode = "execute",
    action_classes: Iterable[ActionClass] = (ActionClass.READ, ActionClass.WRITE),
    proposal_source: ProposalSource | None = None,
    risk_approvals: Iterable[str] = (),
    loop_guard: LoopGuardGrant | None = None,
    attestation_key_ids: Iterable[str] = (ATTESTATION_KEY_ID,),
    overrides: Mapping[str, Any] | None = None,
    phase3_overrides: Mapping[str, Any] | None = None,
) -> AuthorizationManifest:
    """The agent-lane manifest at 1.5: the 1.3 grants plus Phase 4 and Phase 5 grants, signed.

    With every default, its capability delta against the v1 baseline is empty -- the same
    surface, now carried by a manifest that can say ``shadow`` and name approvals. ``loop_guard``
    arms the kernel's runaway-loop detector (ADR 0018); it changes no capability. A
    ``model-driven`` proposal source also signs :data:`ATTACKER_PIN`. ``overrides`` and
    ``phase3_overrides`` replace top-level and Phase 3 fields before validation; they are how a
    test or a work package widens one axis at a time.
    """
    base = supportlab_agent_manifest(key, seed=seed, now=now)
    data = base.model_dump(mode="python", exclude_none=True)
    phase3 = dict(data["phase3"])
    if proposal_source == "model-driven":
        phase3["model_pins"] = (*base.phase3.model_pins, ATTACKER_PIN) if base.phase3 else ()
    phase3.update(phase3_overrides or {})
    data.update(
        schema_version="1.5.0",
        signature="",
        phase3=phase3,
        phase4=Phase4Grants(
            attestation_key_ids=frozenset(attestation_key_ids),
            retention=(
                RetentionRule(
                    artifact_kind="raw-ledgers", days=7, rationale="synthetic fixture evidence"
                ),
            ),
        ),
        phase5=Phase5Grants(
            action_classes=frozenset(action_classes),
            run_mode=run_mode,
            proposal_source=proposal_source,
            risk_approvals=frozenset(risk_approvals),
            loop_guard=loop_guard,
        ),
    )
    data.update(overrides or {})
    return sign_manifest(AuthorizationManifest.model_validate(data), key)


def resign(manifest: AuthorizationManifest, key: Ed25519PrivateKey) -> AuthorizationManifest:
    """Validate and sign an unsigned manifest (a shadow twin, or one naming its approvals)."""
    return sign_manifest(AuthorizationManifest.model_validate(manifest.model_dump()), key)


def utc_now() -> datetime:
    return datetime.now(UTC)
