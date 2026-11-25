"""Human review: read-only views over evidence, and signed adjudication labels (ADR 0017).

The package has one write path. :func:`purpleloop.review.adjudication.write_adjudication` signs
an :class:`~purpleloop.schemas.phase5.AdjudicationRecord` and stores it beside -- never inside --
the bundle it labels. The ``purpleloop adjudicate`` CLI and the ``purpleloop review`` web UI both
call it, so the two cannot disagree about what a record is or where it goes.

- :mod:`.sources` loads a run bundle, a suite bundle, or an audit export into a read-only view,
  verifying it first. It never opens a bundle file for writing.
- :mod:`.adjudication` is the write path, the key-separation check, and blinding state.
- :mod:`.precision` turns signed records into the precision figure for the 5.0.8 checkpoint.
- :mod:`.markup` builds HTML that escapes by default; :mod:`.app` is the FastAPI server.

A human label is not a verdict. Nothing here is imported by ``reporting.gates``, and the gates
refuse an ``AdjudicationRecord`` (and the precision report) by type.
"""
