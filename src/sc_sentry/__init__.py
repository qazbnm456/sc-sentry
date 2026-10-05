"""Smart Contract Sentry: an RLM harness that hunts vulnerabilities in Solidity.

Give it a file and the classes to look for; it answers with findings that cite
the exact lines, each with the model's confidence and whether the class
definition let it stand. Output is its own JSON or SARIF.

The parts, and the split is the design:

- `skills/` -- what each class *is*, including the shapes that look like it and
  are not, and how to cite. Prose, editable by somebody who is not reading
  Python, pulled in by the planner just in time.
- `solidity/` -- tree-sitter parsing, no compiler needed.
- `checks.py` -- per class, where it could be and which citations its
  definition rules out. The deterministic half.
- `sites.py` -- the tools the planner answers precisely with. Every candidate
  it considers has to come from one of them.
- `audit.py` -- the loop. A class with no candidate sites in a file costs
  nothing, because a planner asked to audit a file with no sites of what it
  seeks will invent one.
- `cli.py` -- `sc-sentry audit`.

`sc_sentry.contract_assay` adapts all of this to the contract-assay benchmark, as an
optional extra. The harness does not need it.
"""

from __future__ import annotations

__version__ = "0.3.0"

__all__ = ["__version__"]
