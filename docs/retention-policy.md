# Evidence retention policy

Retention classes are signed data: Manifest 1.4 carries a `retention` rule per artifact kind
(`Phase4Grants.retention`), and the audit-export tooling reads them from the manifest rather
than from this document. This document records the default durations and their rationale.

`days = 0` means kept for the life of the repository.

| Artifact kind | Default | Rationale |
| --- | --- | --- |
| `raw-ledgers` | 0 (repo life) | Hash-chained evidence ledgers are small and load-bearing: every accepted finding links into them, and replay verification reads them. Deleting one orphans every conclusion drawn from it. |
| `attestations` | 0 (repo life) | An attestation is the provenance record for a bundle; it is a few kilobytes and worthless if it can expire before the claim it supports does. |
| `bundles` | 0 (repo life) for release bundles; CI artifact retention (90 days by default) for per-run CI bundles | A release bundle is a portfolio deliverable. CI bundles are reproducible from the pinned code and seeds, so the code-plus-seed is the durable record and the bundle is a convenience. |
| `browser-artifacts` | 90 days | Trace ZIPs and screenshots are bulky and derivative: the scored assertions come from state and DOM, never from pixels (WP2.2), so the traces support debugging, not conclusions. |
| `model-transcripts` | 30 days, digests retained indefinitely | Real-model prompts and responses are the bulkiest artifacts and the only ones whose content a provider could consider sensitive. The `MODEL` events retain prompt and response digests for the life of the ledger, so a retained transcript can always be re-verified against its digest, and a deleted one is detectably absent rather than silently altered. |

Rules that hold regardless of duration:

- Deletion is only ever by retention class and age, never by run outcome. Deleting the
  evidence of a failed run is an incident (see `docs/incident-runbook.md`), not housekeeping.
- Nothing under an open finding or an unresolved incident is deleted, whatever its age.
- Redaction happens at write time, not at retention time; retention never substitutes for
  redaction.
