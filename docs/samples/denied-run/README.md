# Sample: a run denied at admission

The signed authorization expired before the run started. `evidence.jsonl` carries the single
`ADMISSION` event with decision `deny` and reason `EXPIRED_MANIFEST`; nothing executed and no
adapter I/O happened. Verify the chain with:

    uv run purpleloop verify-ledger docs/samples/denied-run/evidence.jsonl
