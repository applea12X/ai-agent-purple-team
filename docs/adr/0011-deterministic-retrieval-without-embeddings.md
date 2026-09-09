# ADR 0011: Deterministic retrieval, no embeddings

Status: accepted for Phase 3.

## Decision

Retrieval on the agent lane is exact topic equality with an explicit total ordering
(`ORDER BY seq, id`). There is no embedding model and no vector index.

## Rationale

Phase 3's contract is that deterministic components stay deterministic and stochastic ones are
labelled. Retrieval and generation are separable: with lexical retrieval, *what the assistant was
shown* is bit-reproducible even when *what it said* is not. That means an indirect-injection finding
can always be traced to the exact chunk that delivered it, and a defended replay is comparing like
with like.

Embedding-based retrieval would move retrieval into the stochastic class — different embedding
versions, different neighbour sets, different prompts — for no gain in scenario coverage. Every
threat in the Phase 3 corpus is about *what the assistant does with retrieved hostile content*, not
about how the content was ranked.

## Provenance

Every chunk carries `source_kind`, `source_id`, and `trust_level` into the retrieval response and
into the `MODEL` evidence event. Provenance is reported truthfully regardless of the
`retrieval_provenance` flag: that flag governs whether the caller is told to *quarantine* untrusted
content, not whether the fixture tells the truth about it. Evidence must not depend on a defense
setting.

## Consequence

The corpus states this limit rather than implying vector-search coverage it does not have. If a
later phase wants embedding retrieval, it is a new work package with its own determinism story, and
retrieval would then report its own replay rate separately — the way the browser lane does.
