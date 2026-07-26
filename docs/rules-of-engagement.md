# Rules of Engagement

- Run only against the bundled fixture or an exact disposable asset in a signed, unexpired,
  non-revoked manifest.
- Use synthetic identities, records, secrets, and canaries only.
- Phase 0 permits `GET`, `HEAD`, or `OPTIONS` schema inputs, but the trusted tool registry
  currently authorizes only its declared read-only `GET` operations.
- Do not add automatic redirects, arbitrary egress, generic shell access, credential attacks,
  persistence, destructive actions, or production credentials.
- Treat a policy, revocation, DNS, tool-schema, scope, budget, or evidence failure as a test-system
  incident and stop.
- Preserve evidence and perform the manifest cleanup procedure after every run.
- A passing Phase 0 suite validates the harness invariants; it does not prove a target or model is
  secure.
