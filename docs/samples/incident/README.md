# Sample: an evidence-integrity incident

**This bundle was deliberately corrupted to build a training sample**: one byte of event 3 in
`evidence.jsonl` was altered after the bundle was sealed, and this README was added after
sealing. It is not a real run result and must not be accepted as one -- which is exactly what
verification concludes:

    uv run purpleloop verify-ledger docs/samples/incident/evidence.jsonl
    # INVALID LEDGER_INVALID -- the hash chain breaks at the altered event

    uv run purpleloop verify-bundle docs/samples/incident
    # INVALID: artifact inventory differs from directory -- the sealed inventory
    # no longer describes what is on disk

The correct reviewer conclusion is that no finding from this bundle can be accepted.
