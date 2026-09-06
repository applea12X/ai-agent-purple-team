# ADR 0004: Versioned fixture authority and fixed ingress

Status: accepted for Phase 1.

Manifest 1.1 permits exact synthetic READ/WRITE operations and pre-authorized defense profiles.
Manifest 1.0 canonical bytes and default read-only action validation remain compatible.
Destructive actions are forbidden in both versions. There is no general-purpose HTTP proxy,
model-selected URL, shell action, arbitrary remediation, or credential-bearing model context.

All target and control operations use SafetyRuntime. Shared reservations include control-plane
calls; cleanup also has host-owned authority to dispose of the containment boundary after a
budget or kill-switch stop. This authority cannot select a new target or modify application
source.

On the observed Docker Engine 29.2.1, an internal-only bridge accepted HostConfig.PortBindings
but did not create NetworkSettings.Ports mappings. Therefore the untrusted fixture remains on
an internal network and a separate fixed-destination relay publishes the loopback ports. The
relay has read-only storage, no credentials, fixed backends, bounded bytes/time, and no
forward-proxy configuration. Only the relay is connected to the ingress network.

This follows Docker's separation between internal backend networks and externally reachable
frontends: https://docs.docker.com/engine/network/. Containment tests verify that the fixture
cannot reach an external IP and that customer credentials cannot use the control listener.
The relay is part of the trusted adapter/containment boundary and is documented as such.
