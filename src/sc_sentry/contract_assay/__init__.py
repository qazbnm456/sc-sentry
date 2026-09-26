"""sc-sentry, adapted to be scored by the contract-assay benchmark.

Optional: `pip install "sc-sentry[contract-assay]"`. The harness itself -- `sc-sentry
audit` -- needs none of this. Here are the same checks exposed as
contract-assay `Detector`s, a sweep over a benchmark corpus that writes its
runs file, and a scorer front-end.

The adapter adds no judgement of its own. Candidates and rejections come from
`sc_sentry.checks`; this package only restates them in the benchmark's types.
"""

from __future__ import annotations

MISSING = (
    "sc-sentry-contract-assay adapts sc-sentry to the contract-assay benchmark and needs "
    'it installed: pip install "sc-sentry[contract-assay]". contract-assay is not on '
    "PyPI and its repository is private, so install it from a clone you have read "
    "access to first -- see the README."
)
"""Said by the command when the extra is absent. Not raised at import: the
command has to be importable to say it, and a traceback in front of one
sentence of advice buries the advice."""
