"""Smart Contract Sentry: one Solidity unit, one vulnerability class, one cited span.

The package is four parts, and the split is the design:

- `skills/` -- what each class *is*, including the shapes that look like it and
  are not, and how to cite. Prose, editable by somebody who is not reading
  Python, pulled in by the planner just in time.
- `sites.py` -- nine tree-sitter-backed tools that answer precisely. Every
  candidate the planner considers has to come from one of them.
- `detectors.py` -- the deterministic half the benchmark scores through:
  `evidence()` records what is true of the source, `verdict()` rejects what the
  class definition does not cover.
- `run.py` -- the loop. A class with no candidate sites in a unit costs nothing,
  because a planner asked to audit a file with no sites of what it seeks will
  invent one.

Scoring is not here. `contract_assay` scores this, and a harness that scores
itself has measured its own opinion.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
