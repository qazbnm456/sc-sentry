"""Smart Contract Sentry: an RLM harness that hunts vulnerabilities in Solidity.

Give it a file and the classes to look for, and it answers with findings that cite the exact lines,
each with a confidence and whether the class definition let it stand. Output is its own JSON or
SARIF.

The parts:

- `skills/`: what each class *is*, including the shapes that look like it and are not, and how to
  cite. It is prose that somebody who is not reading Python can edit, and the model reads it as the
  class definition.
- `solidity/`: tree-sitter parsing, with no compiler needed.
- `checks.py`: for each class, where it could be and which citations its definition rules out. This
  is the deterministic half.
- `triage.py` and `static.py`: the model's verdicts on the candidate functions, and the candidates
  as findings with no model.
- `sites.py`: the tools the planner in `explore` answers precisely with. Every candidate it
  considers has to come from one of them.
- `audit.py`: the loop over classes. A class with no candidate sites in a file costs nothing,
  because a model asked to audit a file with no sites of what it seeks will invent one.
- `cli.py`: `sc-sentry audit`.

`sc_sentry.contract_assay` adapts all of this to the contract-assay benchmark, as an optional extra.
The harness does not need it.
"""

from __future__ import annotations

__version__ = "0.7.0"

__all__ = ["__version__"]
