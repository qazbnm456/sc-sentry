"""Per class: where it could be, and which citations the class rules out.

This is the deterministic half of the harness. `candidates` finds the sites a class could be at,
and a class with none in a unit costs no model call, because a planner asked to audit a file with
no sites of what it seeks will invent one. `rejects` rules out what the class definition does not
cover by **asking the candidates** rather than re-deriving the observation: a decision that
re-derives what an observation established will eventually derive it differently, and the two
layers then disagree silently.

Rejections are deliberately narrow. Rejecting a true finding costs recall with no compensating
signal, while rejecting a false one saves somebody a review. Each rejection below is one the class
definition settles, not one about likelihood.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import lru_cache

from sc_sentry.candidate import Candidate, Span
from sc_sentry.candidates import (
    access_control,
    arithmetic_rounding,
    denial_of_service,
    oracle_integrity,
    reentrancy,
    slippage,
    unchecked_external_call,
)
from sc_sentry.candidates.citable import citable_site
from sc_sentry.classes import VulnClass
from sc_sentry.solidity import Site, Syntax

__all__ = ["CHECKS", "Candidate", "CandidateFunction", "Check", "Span", "parse"]


@lru_cache(maxsize=32)
def parse(source: str) -> Syntax | None:
    """Parsed once per unit, not once per citation."""
    return Syntax.of(source)


def _candidate(predicate: str, site: Site, **detail: object) -> Candidate:
    return Candidate(
        predicate,
        site,
        {k: v for k, v in detail.items() if isinstance(v, str | int | float | bool)},
    )


def _covers(spans: Sequence[Span], start: int, end: int, predicate: str | None = None) -> bool:
    """Whether a candidate overlaps the cited lines.

    Overlap rather than equality: a citation of a whole statement where the candidate is one
    expression inside it has cited the same thing.
    """
    for span in spans:
        if predicate is not None and span.predicate != predicate:
            continue
        if span.start_line <= end and start <= span.end_line:
            return True
    return False


def _same_function(parsed: Syntax | None, spans: Sequence[Span], start: int) -> bool:
    """Whether the citation is inside a function that holds a candidate."""
    if parsed is None:
        return False
    cited = parsed.callable_at(start)
    named = {span.function for span in spans}
    return cited is not None and bool(cited.names) and cited.names[0] in named


@dataclass(frozen=True, slots=True)
class CandidateFunction:
    """The candidates of one class that sit in one function, and the one worth citing.

    The benchmark locates a defect to a function, and a cap counts findings, so a function
    holding six candidates should cost one finding and not six. `best` is the candidate that
    stands for the function: the one `priority` ranks highest, the earliest on a tie.
    """

    contract: str | None
    function: str | None
    best: Candidate
    candidates: tuple[Candidate, ...]


@dataclass(frozen=True, slots=True)
class Check:
    """One class: how to find its candidates, and what rules a citation out.

    `rejects` returns the name of what was not established at the citation, or `None` when the
    citation stands. `priority`, when a class has one, says how likely a candidate is to be an
    instance, higher first. Without it, candidates keep source order.
    """

    vuln: VulnClass
    summary: str
    candidates: Callable[[Syntax], list[Candidate]]
    rejects: Callable[[Syntax | None, Sequence[Span], int, int], str | None]
    priority: Callable[[Candidate], float] | None = None

    def find(self, source: str) -> list[Candidate]:
        parsed = parse(source)
        return [] if parsed is None else self.candidates(parsed)

    def functions(self, source: str) -> list[CandidateFunction]:
        """The candidates grouped by function, the likeliest function first."""
        return group_by_function(self.find(source), self.priority)


def group_by_function(
    candidates: Sequence[Candidate], priority: Callable[[Candidate], float] | None = None
) -> list[CandidateFunction]:
    """One entry per `(contract, function)`, ordered by priority and then by position."""
    rank = priority or (lambda _: 0.0)
    groups: dict[tuple[str | None, str | None], list[Candidate]] = {}
    for candidate in candidates:
        host = candidate.site.host
        groups.setdefault((host.contract, host.function), []).append(candidate)
    entries = []
    for (contract, function), members in groups.items():
        best = min(members, key=lambda m: (-rank(m), m.site.start_line))
        entries.append(
            CandidateFunction(contract, function, best, tuple(sorted(members, key=_by_line)))
        )
    return sorted(entries, key=lambda e: (-rank(e.best), e.best.site.start_line))


def _by_line(candidate: Candidate) -> int:
    return candidate.site.start_line


def _covered(what: str) -> Callable[[Syntax | None, Sequence[Span], int, int], str | None]:
    def rejects(_: Syntax | None, spans: Sequence[Span], start: int, end: int) -> str | None:
        return None if _covers(spans, start, end) else what

    return rejects


# --- reentrancy -----------------------------------------------------------


def _reentrancy_rejects(
    _: Syntax | None, spans: Sequence[Span], start: int, end: int
) -> str | None:
    # Either end of the pair is a legitimate citation: the call is what has to move, and the
    # write is what has to move before it.
    if _covers(spans, start, end, "state_write_after_an_external_call") or _covers(
        spans, start, end, "external_call"
    ):
        return None
    return "call_or_write"


# --- oracle integrity -----------------------------------------------------


def _oracle_rejects(
    parsed: Syntax | None, spans: Sequence[Span], start: int, end: int
) -> str | None:
    # The skill says to cite the line that USES the value, which may be below the read, so the
    # function is the unit of agreement here, not the line.
    if parsed is None:
        return None
    if _same_function(parsed, spans, start) or _covers(spans, start, end):
        return None
    return "external_value_read_in_this_function"


# --- arithmetic rounding --------------------------------------------------


# --- slippage -------------------------------------------------------------


def _slippage_rejects(
    parsed: Syntax | None, spans: Sequence[Span], start: int, end: int
) -> str | None:
    # The bound may be computed above the call, and the skill says to cite the computation, so a
    # citation in the same function agrees.
    if _same_function(parsed, spans, start) or _covers(spans, start, end):
        return None
    return "exchange_call_in_this_function"


# --- denial of service ----------------------------------------------------


# --- insecure randomness --------------------------------------------------

_CHAIN_STATE = ("timestamp", "number", "prevrandao", "difficulty", "coinbase", "blockhash")


def _randomness(parsed: Syntax) -> list[Candidate]:
    out = [
        _candidate("chain_state_read", citable_site(parsed, site), member=member)
        for site, obj, member in parsed.member_reads
        if obj == "block" and member in _CHAIN_STATE
    ]
    out += [
        _candidate("hash_of_chain_state", citable_site(parsed, c.site), callee=c.callee)
        for c in parsed.calls
        if c.callee in {"keccak256", "blockhash", "sha256"}
    ]
    return out


CHECKS: dict[VulnClass, Check] = {
    check.vuln: check
    for check in (
        Check(
            VulnClass.ACCESS_CONTROL,
            "A state-changing path with nothing establishing the caller's right to it.",
            access_control.candidates,
            _covered("reachable_state_write"),
            priority=access_control.priority,
        ),
        Check(
            VulnClass.ARITHMETIC_ROUNDING,
            "Arithmetic whose result is wrong in a direction that matters.",
            arithmetic_rounding.candidates,
            _covered("division"),
            priority=arithmetic_rounding.priority,
        ),
        Check(
            VulnClass.DENIAL_OF_SERVICE,
            "A path an outsider can make permanently unusable for somebody else.",
            denial_of_service.candidates,
            _covered("loop_call_or_revert"),
            priority=denial_of_service.priority,
        ),
        Check(
            VulnClass.INSECURE_RANDOMNESS,
            "A value used as unpredictable that somebody can influence.",
            _randomness,
            _covered("influenceable_value"),
        ),
        Check(
            VulnClass.ORACLE_INTEGRITY,
            "A value read from outside and used without establishing it can be trusted.",
            oracle_integrity.candidates,
            _oracle_rejects,
            priority=oracle_integrity.priority,
        ),
        Check(
            VulnClass.REENTRANCY,
            "A state write after an external call in the same function.",
            reentrancy.candidates,
            _reentrancy_rejects,
            priority=reentrancy.priority,
        ),
        Check(
            VulnClass.SLIPPAGE,
            "An exchange with no enforced bound on what comes back.",
            slippage.candidates,
            _slippage_rejects,
            priority=slippage.priority,
        ),
        Check(
            VulnClass.UNCHECKED_EXTERNAL_CALL,
            "A call whose failure is discarded.",
            unchecked_external_call.candidates,
            _covered("discarded_call_result"),
            priority=unchecked_external_call.priority,
        ),
    )
}
