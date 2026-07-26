from __future__ import annotations

import ipaddress
import posixpath
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

from purpleloop.schemas.action import ActionTarget, TargetObservation
from purpleloop.schemas.authorization import AssetScope


class TargetError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


@dataclass(frozen=True)
class CanonicalTarget:
    scheme: str
    host: str
    port: int
    path: str
    query: str
    url: str


def canonicalize_url(url: str) -> CanonicalTarget:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise TargetError("INVALID_TARGET", "target must be absolute HTTP(S)")
    if parts.username or parts.password or parts.fragment:
        raise TargetError("AMBIGUOUS_TARGET", "userinfo and fragments are forbidden")
    host = parts.hostname.rstrip(".").lower().encode("idna").decode("ascii")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise TargetError("INVALID_PORT", "target port is invalid") from exc
    decoded = unquote(parts.path or "/")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if decoded.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    if ".." in decoded.split("/"):
        raise TargetError("PATH_TRAVERSAL", "target path contains traversal")
    canonical_url = urlunsplit((parts.scheme, f"{host}:{port}", normalized, parts.query, ""))
    return CanonicalTarget(parts.scheme, host, port, normalized, parts.query, canonical_url)


def match_scope(target: ActionTarget, assets: tuple[AssetScope, ...]) -> AssetScope:
    canonical = canonicalize_url(target.url)
    matches = [
        asset
        for asset in assets
        if asset.scheme == canonical.scheme
        and asset.host == canonical.host
        and asset.port == canonical.port
        and _path_is_within(canonical.path, asset.path_prefix)
        and target.tenant_id in asset.tenant_ids
        and (not asset.resource_ids or target.resource_id in asset.resource_ids)
    ]
    if len(matches) != 1:
        reason = "OUT_OF_SCOPE" if not matches else "AMBIGUOUS_SCOPE"
        raise TargetError(reason, "target must match exactly one authorized asset")
    scope = matches[0]
    return scope


def validate_observation(
    observation: TargetObservation,
    target: ActionTarget,
    assets: tuple[AssetScope, ...],
) -> AssetScope:
    expected_scope = match_scope(target, assets)
    observed_target = target.model_copy(update={"url": observation.url})
    scope = match_scope(observed_target, assets)
    if scope.asset_id != expected_scope.asset_id:
        raise TargetError("REDIRECT_SCOPE_DRIFT", "observation changed the authorized asset")
    if not observation.resolved_addresses:
        raise TargetError("DNS_EVIDENCE_MISSING", "trusted DNS evidence is required")
    allowed = {str(address) for address in scope.allowed_resolved_addresses}
    for address in observation.resolved_addresses:
        address_text = str(address)
        if _is_sensitive(address) and address_text not in allowed:
            raise TargetError("FORBIDDEN_ADDRESS", "resolved address is not explicitly authorized")
        if address_text not in allowed:
            raise TargetError("DNS_SCOPE_DRIFT", "resolved address changed outside the allowlist")
    return scope


def _path_is_within(path: str, prefix: str) -> bool:
    normalized_prefix = prefix.rstrip("/") or "/"
    if normalized_prefix == "/":
        return path.startswith("/")
    return path == normalized_prefix or path.startswith(f"{normalized_prefix}/")


def _is_sensitive(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )
