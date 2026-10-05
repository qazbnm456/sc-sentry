"""A site a class could be at, with what established it.

Its own module because the per-class finders in `candidates/` build these and `checks.py`
imports the finders, so the types have to sit below both.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from sc_sentry.solidity import Site

__all__ = ["Candidate", "Detail", "Span"]

Detail = Mapping[str, str | int | float | bool]


@dataclass(frozen=True, slots=True)
class Span:
    """What a rejection reads: a candidate's kind, lines and function."""

    predicate: str
    start_line: int
    end_line: int
    function: str | None


@dataclass(frozen=True, slots=True)
class Candidate:
    """A site a class could be at, with what established it."""

    predicate: str
    site: Site
    detail: Detail = field(default_factory=dict)

    @property
    def span(self) -> Span:
        return Span(
            self.predicate, self.site.start_line, self.site.end_line, self.site.host.function
        )
