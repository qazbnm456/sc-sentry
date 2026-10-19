"""sc-sentry, adapted to be scored by the contract-assay benchmark.

Optional: `pip install "sc-sentry[contract-assay]"`. The harness itself (`sc-sentry audit`) needs
none of this. The package holds the same checks exposed as contract-assay `Detector`s, a sweep over
a benchmark corpus that writes its runs file, and a scorer front-end.

The adapter adds no judgement of its own. Candidates and rejections come from `sc_sentry.checks`,
and this package only restates them in the benchmark's types.
"""

from __future__ import annotations

MISSING = (
    "sc-sentry-contract-assay adapts sc-sentry to the contract-assay benchmark and needs "
    'it installed: pip install "sc-sentry[contract-assay]". A run also needs the '
    "corpus, which is in a clone of the contract-assay repository. See the README."
)
"""Printed by the command when the extra is absent. It is not raised at import, because the
command has to be importable to print it, and a traceback in front of one sentence of advice buries
the advice."""
