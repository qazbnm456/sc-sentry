"""sc-sentry, adapted to be scored by the contract-assay benchmark.

Optional: `pip install "sc-sentry[assay]"`. The harness itself -- `sc-sentry
audit` -- needs none of this. Here are the same checks exposed as
contract-assay `Detector`s, a sweep over a benchmark corpus that writes its
runs file, and a scorer front-end.

The adapter adds no judgement of its own. Candidates and rejections come from
`sc_sentry.checks`; this package only restates them in the benchmark's types.
"""

from __future__ import annotations

try:
    import contract_assay  # noqa: F401
except ImportError as missing:  # pragma: no cover - the message is the point
    raise ImportError(
        "sc_sentry.assay adapts sc-sentry to the contract-assay benchmark and needs it "
        'installed: pip install "sc-sentry[assay]" (contract-assay is not on PyPI yet, '
        "so install it from a clone first -- see the README)."
    ) from missing
