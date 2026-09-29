"""
SIH26159 SecureMailScope — Data provenance vocabulary.

Every value the API returns declares where it came from:

  ``observed``      parsed from the uploaded capture (real packets on the wire)
  ``derived``       computed from observed values by a documented formula
  ``demo_fixture``  synthetic sample data shipped for demonstration

The product is an air-gapped analyser, so anything that genuinely cannot be
recovered from one capture (multi-hop relay history, published DNS policy
records, a baseline time series) is served from a deterministic demo fixture and
labelled as such. Nothing labelled ``demo_fixture`` is ever presented as an
observation, and the scoring engine never consumes it: scores come only from
``observed`` and ``derived`` values.
"""

from __future__ import annotations

OBSERVED = "observed"
DERIVED = "derived"
DEMO = "demo_fixture"

DEMO_NOTICE = (
    "Demo fixture data. Not derived from the uploaded capture."
)


def label(source: str) -> dict:
    """Standard provenance block attached to demo-backed payloads."""
    return {
        "data_source": source,
        "is_demo": source == DEMO,
        "notice": DEMO_NOTICE if source == DEMO else None,
    }
