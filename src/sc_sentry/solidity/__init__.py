"""Solidity parsing: what a source unit declares, and the shapes the checks ask about.

Syntactic only -- tree-sitter, no compiler, no network -- so it works on any
single file, whether or not its project builds. `parser` indexes declarations;
`syntax` answers shape queries over them (calls, writes, loops, guards).

Adapted from the author's own `contract-assay` (`evidence/solidity.py` and
`evidence/syntax.py`, MIT), so that this harness stands on its own: finding the
candidate sites a class could be at is the harness's judgement, and it should
not need a benchmark installed to make it.
"""

from sc_sentry.solidity.syntax import Locator, Site, Syntax

__all__ = ["Locator", "Site", "Syntax"]
