from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from purpleloop.control import DefaultDenyPolicy
from purpleloop.schemas import ActionRequest, ActionTarget, AuthorizationManifest


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    label=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        min_size=1,
        max_size=20,
    ).filter(lambda value: value.lower() != "fixture"),
)
def test_mutated_hosts_never_inherit_scope(
    manifest: AuthorizationManifest, action: ActionRequest, label: str
) -> None:
    target = ActionTarget(
        url=f"http://{label}.local:8080/records/record-1",
        tenant_id="tenant-a",
        resource_id="record-1",
    )
    decision = DefaultDenyPolicy().evaluate(manifest, action.model_copy(update={"target": target}))
    assert not decision.permitted


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    tenant=st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True).filter(
        lambda value: value != "tenant-a"
    )
)
def test_mutated_tenants_never_inherit_scope(
    manifest: AuthorizationManifest, action: ActionRequest, tenant: str
) -> None:
    target = action.target.model_copy(update={"tenant_id": tenant})
    decision = DefaultDenyPolicy().evaluate(manifest, action.model_copy(update={"target": target}))
    assert not decision.permitted


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    redirect_host=st.sampled_from(
        ["evil.local", "fixture.local.evil.test", "127.0.0.1", "169.254.169.254"]
    )
)
def test_redirects_outside_scope_are_denied(
    manifest: AuthorizationManifest, action: ActionRequest, redirect_host: str
) -> None:
    target = action.target.model_copy(
        update={"url": f"http://{redirect_host}:8080/records/record-1"}
    )
    decision = DefaultDenyPolicy().evaluate(manifest, action.model_copy(update={"target": target}))
    assert not decision.permitted
