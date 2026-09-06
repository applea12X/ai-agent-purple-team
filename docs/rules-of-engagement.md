# Rules of Engagement

- Run only against the bundled fixtures or an exact disposable asset in a signed, unexpired,
  non-revoked manifest.
- Use synthetic identities, records, secrets, and canaries only.
- A 1.0 manifest stays read-only: it authorizes only its declared read-only `GET` operations,
  regardless of the method a schema would otherwise accept.
- A 1.1 manifest may additionally grant `WRITE` for exact registered synthetic fixture operations
  and credential scopes. Each operation's trusted tool definition owns its method, effect, path,
  argument schema, result schema, and idempotency requirement.
- `DESTRUCTIVE` actions, unknown operations, unregistered argument shapes, and targets outside
  exact signed scope remain denied in every manifest version.
- Attack credentials must never address the fixture control plane. Provision, seed, snapshot,
  telemetry, defense, reset, and teardown are separately scoped.
- Select defenses only from the versioned registry, and only when the signed manifest
  pre-authorizes the profile. Never edit application source or accept a free-form remediation.
- Treat model output and retrieved target content as untrusted data. A tool intent produced by
  either is compiled into a typed action and re-authorized before execution.
- Do not add automatic redirects, arbitrary egress, generic shell access, credential attacks,
  persistence, destructive actions, or production credentials.
- Treat a policy, revocation, DNS, tool-schema, scope, budget, or evidence failure as a test-system
  incident and stop.
- Preserve evidence and perform the manifest cleanup procedure after every run. A failed or
  cancelled run must still tear down and leave a verifiable bundle or an explicit
  evidence-integrity incident.
- A passing suite validates the harness invariants and the seeded fixture findings. It does not
  prove a target or model is secure, and harness authorization never makes an application
  authorization failure legitimate.
