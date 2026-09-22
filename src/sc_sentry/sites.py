"""Tools the planner calls, over the benchmark's own parser.

This is the half of the harness that makes a recursive planner the right shape
for the task rather than the wrong one. A planner handed a prose instruction and
a string has no way to make progress except to read the string and guess; the
same planner with a parser under it asks precise questions, gets precise
answers, and converges in a turn or two.

Every site carries `text` -- the **exact** source it spans -- and that is what
decides the score. A finding is scored only if the harness can re-read the
source at the locator and find the quote, and a model transcribing from memory
is wrong about half the time. These tools hand back the exact text with the
exact lines beside it, so the planner quotes what it was given rather than what
it remembers.

Lines are 1-indexed and inclusive, matching the locator the benchmark expects.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from contract_assay.evidence.syntax import Site, Syntax


def _where(site: Site) -> dict[str, Any]:
    """The four fields a finding needs, straight off the site.

    Returned together, and always the same four, so a planner never has to pair
    a span from one answer with a quote from another -- which is the mistake
    that produces a finding whose quote is real and whose lines are not.
    """
    return {
        "start_line": site.start_line,
        "end_line": site.end_line,
        "function": site.host.function,
        "quote": site.text,
    }


def tools_for(source: str) -> list[Callable[..., Any]]:
    """The tool list for one source unit, closed over that unit.

    Closed over, so a tool cannot be pointed at a file the round did not assign.
    """
    lines = source.split("\n")
    parsed = Syntax.of(source)

    def outline() -> dict[str, Any]:
        """How big this unit is and what it declares. Cheap orientation; call it first."""
        return {
            "lines": len(lines),
            "parsed": parsed is not None,
            "state_variables": sorted(parsed.state_variables) if parsed else [],
            "functions": [
                {
                    "name": fn.declaration.names[0] if fn.declaration.names else "?",
                    "start_line": fn.site.start_line,
                    "end_line": fn.site.end_line,
                    "visibility": fn.visibility,
                    "modifiers": list(fn.modifiers or ()),
                    "externally_reachable": fn.is_externally_reachable,
                    "read_only": fn.is_read_only,
                }
                for fn in (parsed.functions if parsed else ())
            ],
        }

    def read_lines(start_line: int, end_line: int) -> str:
        """The EXACT source text of lines `start_line`..`end_line`, inclusive.

        Quote what this returns, unmodified. A quote that differs from the source
        at the lines you cite is discarded before it is scored, and the run then
        reads as a detector that found nothing.
        """
        a = max(int(start_line), 1)
        b = min(int(end_line), len(lines))
        return "" if b < a else "\n".join(lines[a - 1 : b])

    def state_writes() -> list[dict[str, Any]]:
        """Every assignment to contract state, with its exact text and function.

        For an access-control or a reentrancy finding this is usually the line to
        cite -- the one a fix moves or guards -- rather than the signature.
        """
        if parsed is None:
            return []
        return [
            {**_where(w.site), "target": w.target_root, "kind": w.target} for w in parsed.writes
        ]

    def external_calls() -> list[dict[str, Any]]:
        """Every call leaving the contract, with callee, receiver and exact text.

        `low_level` marks `.call`/`.delegatecall`/`.staticcall`/`.send`, which
        return a boolean and do **not** revert. `bound_names` is what the return
        was assigned to -- empty, or bound and never read, is the unchecked shape.
        """
        if parsed is None:
            return []
        return [
            {
                **_where(c.site),
                "receiver": c.receiver,
                "callee": c.callee,
                "low_level": c.is_low_level,
                "value_transfer": c.is_value_transfer,
                "bare_statement": c.is_bare_statement,
                "bound_names": list(c.bound_names or ()),
                "arguments": [a.text for a in c.arguments],
            }
            for c in parsed.calls
        ]

    def guards() -> list[dict[str, Any]]:
        """Every require / revert / bound check, with what identifiers it reads.

        Consult this before claiming nothing authorises a path. A guard in a
        modifier or a helper counts and will appear here rather than inline, and
        `identifiers` is how you tell a caller check from a bounds check.
        """
        if parsed is None:
            return []
        return [{**_where(g.site), "identifiers": list(g.identifiers or ())} for g in parsed.guards]

    def loops() -> list[dict[str, Any]]:
        """Every loop, with the identifiers its condition reads.

        The denial-of-service question is not whether a loop is long: it is who
        can lengthen it. `bound_identifiers` is what to check that against.
        """
        if parsed is None:
            return []
        return [
            {**_where(ls.site), "bound_identifiers": list(ls.bound_identifiers or ())}
            for ls in parsed.loops
        ]

    def arithmetic() -> list[dict[str, Any]]:
        """Every arithmetic expression, flagging the shape that dominates this class.

        `divides_then_scales` is a division whose result is then multiplied.
        Integer division truncates first, so every digit below the divisor is
        gone before the multiplication runs.
        """
        if parsed is None:
            return []
        return [
            {
                **_where(a.site),
                "operator": a.operator,
                "operand_operators": list(a.operand_operators or ()),
                "divides_then_scales": a.divides_then_scales,
                "divisors": list(a.divisors or ()),
                "multipliers": list(a.multipliers or ()),
            }
            for a in parsed.arithmetic
        ]

    def member_reads() -> list[dict[str, Any]]:
        """Every `x.y` read, which is where an oracle or a reserve read appears.

        `latestRoundData`, `slot0`, `getReserves`, `balanceOf`, `decimals` --
        the ones this class turns on.
        """
        if parsed is None:
            return []
        return [
            {**_where(site), "object": obj, "member": member}
            for site, obj, member in parsed.member_reads
        ]

    def callers_of(name: str) -> list[str]:
        """Functions that call `name`.

        An internal function nothing calls is not a reachable path, and a finding
        against one is not an instance of anything.
        """
        return list(parsed.callers_of(name)) if parsed else []

    return [
        outline,
        read_lines,
        state_writes,
        external_calls,
        guards,
        loops,
        arithmetic,
        member_reads,
        callers_of,
    ]
