"""Per class: where it could be, and which citations the class rules out.

The deterministic half of the harness. `candidates` finds the sites a class
could be at -- a class with none in a unit costs no model call, because a
planner asked to audit a file with no sites of what it seeks will invent one.
`rejects` rules out what the class definition does not cover, by **asking the
candidates** rather than re-deriving the observation: a decision that
re-derives what an observation established will eventually derive it
differently, and the two layers then disagree silently.

Rejections are deliberately narrow. Rejecting a true finding costs recall with
no compensating signal; rejecting a false one saves somebody a review. Each
rejection below is one the class definition settles, not one about likelihood.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache

from sc_sentry.classes import VulnClass
from sc_sentry.solidity import Site, Syntax

__all__ = ["CHECKS", "Candidate", "CandidateFunction", "Check", "Span", "parse"]

Detail = Mapping[str, str | int | float | bool]


@lru_cache(maxsize=32)
def parse(source: str) -> Syntax | None:
    """Parsed once per unit, not once per citation."""
    return Syntax.of(source)


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


def _candidate(predicate: str, site: Site, **detail: object) -> Candidate:
    return Candidate(
        predicate,
        site,
        {k: v for k, v in detail.items() if isinstance(v, str | int | float | bool)},
    )


def _covers(spans: Sequence[Span], start: int, end: int, predicate: str | None = None) -> bool:
    """Whether a candidate overlaps the cited lines.

    Overlap rather than equality: a citation of a whole statement where the
    candidate is one expression inside it has cited the same thing.
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

    The benchmark locates a defect to a function, and a cap counts findings, so a
    function holding six candidates should cost one finding and not six. `best` is the
    candidate that stands for the function: the one `priority` ranks highest, the
    earliest on a tie.
    """

    contract: str | None
    function: str | None
    best: Candidate
    candidates: tuple[Candidate, ...]


@dataclass(frozen=True, slots=True)
class Check:
    """One class: how to find its candidates, and what rules a citation out.

    `rejects` returns the name of what was not established at the citation, or
    `None` when the citation stands. `priority`, when a class has one, says how likely a
    candidate is to be an instance, higher first; without it candidates keep source order.
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


# --- access control -------------------------------------------------------


def _access_control(parsed: Syntax) -> list[Candidate]:
    reachable = {
        fn.site.host.function
        for fn in parsed.functions
        if fn.is_externally_reachable and not fn.is_read_only
    }
    return [
        _candidate(
            "state_write_on_an_externally_reachable_path",
            w.site,
            target=w.target_root or "",
            function=w.site.host.function or "",
        )
        for w in parsed.writes
        if w.site.host.function in reachable
    ]


def _covered(what: str) -> Callable[[Syntax | None, Sequence[Span], int, int], str | None]:
    def rejects(_: Syntax | None, spans: Sequence[Span], start: int, end: int) -> str | None:
        return None if _covers(spans, start, end) else what

    return rejects


# --- reentrancy -----------------------------------------------------------


def _reentrancy(parsed: Syntax) -> list[Candidate]:
    first_call: dict[str | None, int] = {}
    for c in parsed.calls:
        fn = c.site.host.function
        first_call[fn] = min(first_call.get(fn, 10**9), c.site.start_line)
    out = [_candidate("external_call", c.site, callee=c.callee or "") for c in parsed.calls]
    for w in parsed.writes:
        after = first_call.get(w.site.host.function)
        if after is not None and w.site.start_line > after:
            out.append(
                _candidate(
                    "state_write_after_an_external_call",
                    w.site,
                    call_line=after,
                    target=w.target_root or "",
                )
            )
    return out


def _reentrancy_rejects(
    _: Syntax | None, spans: Sequence[Span], start: int, end: int
) -> str | None:
    # Either end of the pair is a legitimate citation: the call is what has to
    # move, and the write is what has to move before it.
    if _covers(spans, start, end, "state_write_after_an_external_call") or _covers(
        spans, start, end, "external_call"
    ):
        return None
    return "call_or_write"


# --- unchecked external call ----------------------------------------------


def _unchecked(parsed: Syntax) -> list[Candidate]:
    out: list[Candidate] = []
    for c in parsed.calls:
        if c.is_low_level and not c.bound_names:
            out.append(
                _candidate("low_level_call_with_no_bound_result", c.site, callee=c.callee or "")
            )
        elif c.is_bare_statement:
            # The shape with no symptom at the call site: an interface call
            # returning a discardable bool, used as a statement.
            out.append(_candidate("call_result_used_as_a_statement", c.site, callee=c.callee or ""))
    return out


# --- oracle integrity -----------------------------------------------------

_READS = (
    "latestRoundData",
    "latestAnswer",
    "latestRound",
    "getReserves",
    "slot0",
    "getAmountsOut",
    "quote",
    "getPrice",
    "price",
    "consult",
    "observe",
    "getPriceUnsafe",
    "getPriceNoOlderThan",
)


def _oracle(parsed: Syntax) -> list[Candidate]:
    out = [
        _candidate("external_value_read", c.site, callee=c.callee)
        for c in parsed.calls
        if c.callee in _READS
    ]
    out += [
        _candidate("external_value_read", site, member=member)
        for site, _obj, member in parsed.member_reads
        if member in _READS
    ]
    return out


def _oracle_rejects(
    parsed: Syntax | None, spans: Sequence[Span], start: int, end: int
) -> str | None:
    # The skill says to cite the line that USES the value, which may be below
    # the read, so the function is the unit of agreement here, not the line.
    if parsed is None:
        return None
    if _same_function(parsed, spans, start) or _covers(spans, start, end):
        return None
    return "external_value_read_in_this_function"


# --- arithmetic rounding --------------------------------------------------


def _arithmetic(parsed: Syntax) -> list[Candidate]:
    out: list[Candidate] = []
    for a in parsed.arithmetic:
        if a.divides_then_scales:
            out.append(_candidate("division_before_scaling", a.site, operator=a.operator or ""))
        elif "/" in (a.operand_operators or ()) or a.operator == "/":
            out.append(_candidate("division", a.site, operator=a.operator or ""))
    return out


# --- slippage -------------------------------------------------------------

_SWAPS = (
    "swap",
    "swapExactTokensForTokens",
    "swapTokensForExactTokens",
    "swapExactETHForTokens",
    "swapExactTokensForETH",
    "exactInputSingle",
    "exactInput",
    "exactOutputSingle",
    "addLiquidity",
    "removeLiquidity",
    "addLiquidityETH",
    "removeLiquidityETH",
    "exchange",
    "swapExactTokensForTokensSupportingFeeOnTransferTokens",
)


def _slippage(parsed: Syntax) -> list[Candidate]:
    out: list[Candidate] = []
    for c in parsed.calls:
        if c.callee in _SWAPS or (c.callee or "").startswith("swap"):
            zeros = [a.text for a in c.arguments if a.is_zero_literal]
            out.append(
                _candidate(
                    "exchange_call", c.site, callee=c.callee or "", zero_arguments=len(zeros)
                )
            )
    return out


def _slippage_rejects(
    parsed: Syntax | None, spans: Sequence[Span], start: int, end: int
) -> str | None:
    # The bound may be computed above the call, and the skill says to cite the
    # computation. Same function is the agreement.
    if _same_function(parsed, spans, start) or _covers(spans, start, end):
        return None
    return "exchange_call_in_this_function"


# --- denial of service ----------------------------------------------------


def _denial_of_service(parsed: Syntax) -> list[Candidate]:
    out = [
        _candidate("loop", ls.site, bound_on=",".join(ls.bound_identifiers or ()))
        for ls in parsed.loops
    ]
    loop_spans = [(ls.site.start_line, ls.site.end_line) for ls in parsed.loops]
    out += [
        _candidate("external_call_inside_a_loop", c.site, callee=c.callee or "")
        for c in parsed.calls
        if any(a <= c.site.start_line <= b for a, b in loop_spans)
    ]
    out += [_candidate("revert_condition", g.site) for g in parsed.guards]
    return out


# --- insecure randomness --------------------------------------------------

_CHAIN_STATE = ("timestamp", "number", "prevrandao", "difficulty", "coinbase", "blockhash")


def _randomness(parsed: Syntax) -> list[Candidate]:
    out = [
        _candidate("chain_state_read", site, member=member)
        for site, obj, member in parsed.member_reads
        if obj == "block" and member in _CHAIN_STATE
    ]
    out += [
        _candidate("hash_of_chain_state", c.site, callee=c.callee)
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
            _access_control,
            _covered("reachable_state_write"),
        ),
        Check(
            VulnClass.ARITHMETIC_ROUNDING,
            "Arithmetic whose result is wrong in a direction that matters.",
            _arithmetic,
            _covered("division"),
        ),
        Check(
            VulnClass.DENIAL_OF_SERVICE,
            "A path an outsider can make permanently unusable for somebody else.",
            _denial_of_service,
            _covered("loop_call_or_revert"),
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
            _oracle,
            _oracle_rejects,
        ),
        Check(
            VulnClass.REENTRANCY,
            "A state write after an external call in the same function.",
            _reentrancy,
            _reentrancy_rejects,
        ),
        Check(
            VulnClass.SLIPPAGE,
            "An exchange with no enforced bound on what comes back.",
            _slippage,
            _slippage_rejects,
        ),
        Check(
            VulnClass.UNCHECKED_EXTERNAL_CALL,
            "A call whose failure is discarded.",
            _unchecked,
            _covered("discarded_call_result"),
        ),
    )
}
